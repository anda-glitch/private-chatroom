import socket
import socks
import sys
import threading
import pyaudio
import opuslib
import queue
import time
from blessed import Terminal
from crypto import generate_dh_private, generate_dh_public, compute_dh_shared_secret, encrypt_message, decrypt_message

# Audio Configuration
SAMPLE_RATE = 16000
CHANNELS = 1
CHUNK = 960
AUDIO_FORMAT = pyaudio.paInt16

term = Terminal()
msg_queue = queue.Queue()
audio_queue = queue.Queue()

is_muted = False
is_running = True

send_lock = threading.Lock()

def safe_send(conn, payload):
    with send_lock:
        try:
            conn.sendall(payload)
            return True
        except Exception as e:
            msg_queue.put(f"[!] Send error: {e}")
            return False

def audio_playback_thread(p):
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
        while is_running:
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

def audio_record_thread(p, conn, shared_secret):
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
        while is_running:
            if is_muted:
                time.sleep(0.1)
                continue
                
            try:
                pcm_data = stream.read(CHUNK, exception_on_overflow=False)
                compressed_data = encoder.encode(pcm_data, CHUNK)
                
                # Encrypt and send
                enc_msg = encrypt_message(b'V' + compressed_data, shared_secret)
                payload = len(enc_msg).to_bytes(4, 'big') + enc_msg
                safe_send(conn, payload)
            except Exception as e:
                msg_queue.put(f"[!] Audio Record Error: {e}")
                time.sleep(1) # avoid spamming if there's a persistent error
    finally:
        stream.stop_stream()
        stream.close()

def receive_thread(conn, shared_secret):
    """Receives data from server, decrypts, and dispatches to text/voice."""
    global is_running
    buffer = b""
    try:
        while is_running:
            chunk = conn.recv(4096)
            if not chunk:
                msg_queue.put("*** Server disconnected. ***")
                break
            buffer += chunk
            
            while len(buffer) >= 4:
                msg_len = int.from_bytes(buffer[:4], 'big')
                if len(buffer) < 4 + msg_len:
                    break
                
                payload = buffer[4:4+msg_len]
                buffer = buffer[4+msg_len:]
                
                decrypted = decrypt_message(payload, shared_secret)
                if decrypted:
                    msg_type = decrypted[0:1]
                    content = decrypted[1:]
                    
                    if msg_type == b'T':
                        msg_queue.put(content.decode('utf-8'))
                    elif msg_type == b'V':
                        # Limit audio queue to avoid large latency buildups
                        if audio_queue.qsize() < 10:
                            audio_queue.put(content)
                else:
                    msg_queue.put("*** Received malformed or tampered packet. ***")
    except Exception as e:
        msg_queue.put(f"*** Connection error: {e} ***")
    finally:
        is_running = False

def ui_loop(conn, shared_secret, nick):
    global is_muted, is_running
    input_text = ""
    messages = []
    
    with term.fullscreen(), term.cbreak(), term.hidden_cursor():
        while is_running:
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
            
            status = term.red("[MUTED]") if is_muted else term.green("[MIC ON]")
            prompt = f"{status} {nick} > {input_text}"
            print(term.move_y(term.height - 1) + prompt + term.clear_eol, end='', flush=True)
            
            # Handle input
            val = term.inkey(timeout=0.1)
            if val:
                if val.is_sequence:
                    if val.name == "KEY_ENTER":
                        if input_text.strip():
                            if input_text == "/leave":
                                is_running = False
                                break
                            
                            # Re-draw immediately to feel responsive
                            messages.append(f"You: {input_text}")
                            
                            enc_msg = encrypt_message(b'T' + input_text.encode('utf-8'), shared_secret)
                            payload = len(enc_msg).to_bytes(4, 'big') + enc_msg
                            if not safe_send(conn, payload):
                                break
                            input_text = ""
                    elif val.name == "KEY_BACKSPACE":
                        input_text = input_text[:-1]
                else:
                    # Mute toggle using capital M or alt+m depending on preference.
                    # We'll use 'M' specifically as requested.
                    if val == 'M' and input_text == "": # Only if typing nothing or allow anytime?
                        is_muted = not is_muted
                    else:
                        input_text += val

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 client.py <server_address> <room_code>")
        sys.exit(1)
        
    server_address = sys.argv[1]
    room_code = sys.argv[2]
    
    # Check if using Tor (.onion)
    if server_address.endswith('.onion'):
        print("[*] Connecting via Tor SOCKS5 Proxy...")
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
        port = 80
    else:
        print("[*] Connecting directly...")
        port = 9999
        
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect((server_address, port))
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)
        
    print("[*] Connected! Performing Key Exchange...")
    
    try:
        # Diffie-Hellman Key Exchange
        # 1. Read server public key
        server_pub_bytes = b""
        while b'\n' not in server_pub_bytes:
            chunk = conn.recv(1)
            if not chunk:
                raise Exception("Connection closed during key exchange")
            server_pub_bytes += chunk
        
        server_pub = int(server_pub_bytes.strip().decode('utf-8'))
        
        # 2. Generate and send client public key
        client_priv = generate_dh_private()
        client_pub = generate_dh_public(client_priv)
        conn.sendall(str(client_pub).encode('utf-8') + b'\n')
        
        # 3. Compute shared secret
        shared_secret = compute_dh_shared_secret(client_priv, server_pub)
        print("[*] E2EE Session Established.")
        
        # 4. Ask for nickname
        nick = input("Enter your nickname: ").strip()
        if not nick:
            nick = "Anonymous"
            
        # 5. Send Nickname and Room Code
        init_data = f"{nick}:{room_code}".encode('utf-8')
        conn.sendall(encrypt_message(init_data, shared_secret))
        
        # Initialize Audio
        p = pyaudio.PyAudio()
        
        # Start Threads
        t_recv = threading.Thread(target=receive_thread, args=(conn, shared_secret), daemon=True)
        t_audio_play = threading.Thread(target=audio_playback_thread, args=(p,), daemon=True)
        t_audio_rec = threading.Thread(target=audio_record_thread, args=(p, conn, shared_secret), daemon=True)
        
        t_recv.start()
        t_audio_play.start()
        t_audio_rec.start()
        
        # Start UI (blocks until exit)
        ui_loop(conn, shared_secret, nick)
        
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        global is_running
        is_running = False
        conn.close()
        print("\nDisconnected.")

if __name__ == "__main__":
    main()
