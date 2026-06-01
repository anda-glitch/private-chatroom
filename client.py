import socket
import socks
import sys
import threading
import pyaudio
import opuslib
import queue
import time
from blessed import Terminal
from blessed import Terminal
from crypto import (
    generate_dh_private,
    generate_dh_public,
    compute_dh_shared_secret,
    derive_keys,
    encrypt_message,
    decrypt_message
)

# Audio Configuration
SAMPLE_RATE = 16000
CHANNELS = 1
CHUNK = 960
AUDIO_FORMAT = pyaudio.paInt16

term = Terminal()
msg_queue = queue.Queue()
audio_queue = queue.Queue(maxsize=10)

is_muted = False
is_running = threading.Event()
is_running.set()

send_lock = threading.Lock()

def recvall(conn, n):
    """Helper to read exactly n bytes from the socket."""
    data = b''
    while len(data) < n:
        try:
            chunk = conn.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        except Exception:
            return None
    return data

def safe_send(conn, payload):
    with send_lock:
        try:
            conn.sendall(payload)
            return True
        except Exception as e:
            msg_queue.put(f"[!] Send error: {e}")
            return False

def audio_playback_thread(p, conn_active):
    """Pulls decompressed audio from queue and plays it."""
    try:
        stream = p.open(format=AUDIO_FORMAT,
                        channels=CHANNELS,
                        rate=SAMPLE_RATE,
                        output=True,
                        frames_per_buffer=CHUNK)
        decoder = opuslib.Decoder(SAMPLE_RATE, CHANNELS)
    except Exception as e:
        msg_queue.put(f"[!] Speaker Error: {e}")
        return
        
    try:
        while is_running.is_set() and conn_active.is_set():
            try:
                # Wait for audio data with timeout
                compressed_data = audio_queue.get(timeout=0.5)
                # Decode
                pcm_data = decoder.decode(compressed_data, CHUNK)
                stream.write(pcm_data)
            except queue.Empty:
                continue
            except Exception as e:
                msg_queue.put(f"[!] Audio Playback Error: {e}")
    finally:
        try:
            stream.stop_stream()
            stream.close()
        except:
            pass

def audio_record_thread(p, conn, voice_key, conn_active):
    """Records audio, compresses, encrypts, and sends over TCP."""
    try:
        stream = p.open(format=AUDIO_FORMAT,
                        channels=CHANNELS,
                        rate=SAMPLE_RATE,
                        input=True,
                        frames_per_buffer=CHUNK)
        encoder = opuslib.Encoder(SAMPLE_RATE, CHANNELS, 'voip')
    except Exception as e:
        msg_queue.put(f"[!] Mic Error: {e} (Check microphone permissions!)")
        return
        
    try:
        while is_running.is_set() and conn_active.is_set():
            if is_muted:
                time.sleep(0.1)
                continue
                
            try:
                pcm_data = stream.read(CHUNK, exception_on_overflow=False)
                compressed_data = encoder.encode(pcm_data, CHUNK)
                
                # Encrypt and send as type V (Voice)
                enc_msg = encrypt_message(compressed_data, voice_key)
                payload = (len(enc_msg) + 1).to_bytes(4, 'big') + b'V' + enc_msg
                if not safe_send(conn, payload):
                    conn_active.clear()
                    break
            except Exception as e:
                msg_queue.put(f"[!] Audio Record Error: {e}")
                time.sleep(1) # avoid spamming if there's a persistent error
    finally:
        try:
            stream.stop_stream()
            stream.close()
        except:
            pass

def receive_thread(conn, text_key, voice_key, conn_active):
    """Receives data from server, decrypts, and dispatches to text/voice."""
    buffer = b""
    try:
        while is_running.is_set() and conn_active.is_set():
            try:
                conn.settimeout(0.5)
                chunk = conn.recv(4096)
                if not chunk:
                    msg_queue.put("*** Server disconnected. ***")
                    conn_active.clear()
                    break
                buffer += chunk
            except socket.timeout:
                continue
            except Exception as e:
                msg_queue.put(f"*** Connection error: {e} ***")
                conn_active.clear()
                break
            
            while len(buffer) >= 4:
                msg_len = int.from_bytes(buffer[:4], 'big')
                if len(buffer) < 4 + msg_len:
                    break
                
                payload = buffer[4:4+msg_len]
                buffer = buffer[4+msg_len:]
                
                if len(payload) < 1:
                    continue
                    
                msg_type = payload[0:1]
                enc_envelope = payload[1:]
                
                if msg_type == b'T':
                    decrypted = decrypt_message(enc_envelope, text_key)
                    if decrypted:
                        msg_queue.put(decrypted.decode('utf-8'))
                    else:
                        msg_queue.put("*** Decryption failed for text message. ***")
                elif msg_type == b'V':
                    decrypted = decrypt_message(enc_envelope, voice_key)
                    if decrypted:
                        try:
                            audio_queue.put_nowait(decrypted)
                        except queue.Full:
                            pass  # Drop the frame, queue is backed up
                    else:
                        msg_queue.put("*** Decryption failed for voice packet. ***")
    finally:
        conn_active.clear()

def ui_loop(conn, text_key, nick, conn_active):
    global is_muted
    input_text = ""
    messages = []
    
    with term.fullscreen(), term.cbreak(), term.hidden_cursor():
        while is_running.is_set() and conn_active.is_set():
            # Drain message queue
            while not msg_queue.empty():
                messages.append(msg_queue.get())
                
            # Keep only last few messages to fit screen
            max_msgs = term.height - 3
            display_msgs = messages[-max_msgs:]
            
            # Draw UI
            print(term.home + term.clear)
            for msg in display_msgs:
                print(msg)
                
            print(term.move_y(term.height - 2) + term.blue("─" * term.width))
            
            status = term.red("[MUTED (Ctrl+T or /mute)]") if is_muted else term.green("[MIC ON (Ctrl+T or /mute)]")
            prompt = f"{status} {nick} > {input_text}"
            print(term.move_y(term.height - 1) + prompt + term.clear_eol, end='', flush=True)
            
            # Handle input
            val = term.inkey(timeout=0.1)
            if val:
                if val.is_sequence:
                    if val.name == "KEY_ENTER":
                        if input_text.strip():
                            if input_text == "/leave":
                                is_running.clear()
                                conn_active.clear()
                                break
                            elif input_text == "/mute":
                                is_muted = not is_muted
                                input_text = ""
                                continue
                            
                            # Re-draw immediately to feel responsive
                            messages.append(f"You: {input_text}")
                            
                            enc_msg = encrypt_message(input_text.encode('utf-8'), text_key)
                            payload = (len(enc_msg) + 1).to_bytes(4, 'big') + b'T' + enc_msg
                            if not safe_send(conn, payload):
                                conn_active.clear()
                                break
                            input_text = ""
                    elif val.name == "KEY_BACKSPACE":
                        input_text = input_text[:-1]
                else:
                    if val == '\x14': # Ctrl+T
                        is_muted = not is_muted
                    else:
                        input_text += val

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 client.py <server_address> <room_code>")
        sys.exit(1)
        
    server_address = sys.argv[1]
    room_code = sys.argv[2]
    
    # Ask for nickname once
    nick = input("Enter your nickname: ").strip()
    if not nick:
        nick = "Anonymous"
        
    # Initialize Audio context once
    p = pyaudio.PyAudio()
    
    backoff = 1
    
    try:
        while is_running.is_set():
            # Check if using Tor (.onion)
            if server_address.endswith('.onion'):
                print(f"[*] Connecting to {server_address} via Tor SOCKS5 Proxy...")
                socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
                socket.socket = socks.socksocket
                port = 80
            else:
                print(f"[*] Connecting directly to {server_address}...")
                port = 9999
                
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                conn.connect((server_address, port))
            except Exception as e:
                print(f"[!] Connection failed: {e}")
                print(f"[*] Retrying in {backoff} seconds...")
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue
                
            print("[*] Connected! Performing Key Exchange...")
            
            try:
                # Diffie-Hellman Key Exchange
                # 1. Read server public key with length prefix
                raw_len = recvall(conn, 4)
                if not raw_len:
                    raise Exception("Connection closed during key exchange")
                key_len = int.from_bytes(raw_len, 'big')
                server_pub_bytes = recvall(conn, key_len)
                if not server_pub_bytes:
                    raise Exception("Connection closed during key exchange")
                
                server_pub = int(server_pub_bytes.decode('utf-8'))
                
                # 2. Generate and send client public key with length prefix
                client_priv = generate_dh_private()
                client_pub = generate_dh_public(client_priv)
                pub_bytes = str(client_pub).encode('utf-8')
                conn.sendall(len(pub_bytes).to_bytes(4, 'big') + pub_bytes)
                
                # 3. Compute shared secret
                shared_secret = compute_dh_shared_secret(client_priv, server_pub)
                text_key, voice_key = derive_keys(shared_secret)
                print("[*] E2EE Session Established.")
                
                # 4. Send Nickname and Room Code
                init_data = f"{nick}:{room_code}".encode('utf-8')
                enc_init = encrypt_message(init_data, text_key)
                conn.sendall(len(enc_init).to_bytes(4, 'big') + enc_init)
                
                # Connection is now active
                conn_active = threading.Event()
                conn_active.set()
                
                # Reset backoff on successful handshake
                backoff = 1
                
                # Start Threads
                t_recv = threading.Thread(target=receive_thread, args=(conn, text_key, voice_key, conn_active), daemon=True)
                t_audio_play = threading.Thread(target=audio_playback_thread, args=(p, conn_active), daemon=True)
                t_audio_rec = threading.Thread(target=audio_record_thread, args=(p, conn, voice_key, conn_active), daemon=True)
                
                t_recv.start()
                t_audio_play.start()
                t_audio_rec.start()
                
                # Start UI (blocks until leave or disconnect)
                ui_loop(conn, text_key, nick, conn_active)
                
                # Wait for threads to clean up before attempting reconnect
                conn_active.clear()
                try:
                    conn.close()
                except:
                    pass
                    
                t_recv.join(timeout=1.0)
                t_audio_play.join(timeout=1.0)
                t_audio_rec.join(timeout=1.0)
                
            except Exception as e:
                print(f"[!] Error during session: {e}")
                try:
                    conn.close()
                except:
                    pass
                print(f"[*] Reconnecting in {backoff} seconds...")
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                
    except KeyboardInterrupt:
        pass
    finally:
        is_running.clear()
        p.terminate()
        print("\nDisconnected.")

if __name__ == "__main__":
    main()
