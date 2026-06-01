import socket
import threading
import sys
import os
import subprocess
import time
import secrets
import string
from crypto import (
    generate_dh_private,
    generate_dh_public,
    compute_dh_shared_secret,
    derive_keys,
    encrypt_message,
    decrypt_message
)

# Configuration
HOST = '127.0.0.1'
PORT = 9999
TORRC_PATH = '/opt/homebrew/etc/tor/torrc'
HIDDEN_SERVICE_DIR = '/opt/homebrew/var/lib/tor/chatroom/'

clients = {} # {conn: {'address': addr, 'nick': nick, 'room': room, 'text_key': text_key, 'voice_key': voice_key, 'send_lock': send_lock}}
rooms = {} # {room_code: [conn1, conn2, ...]}
clients_lock = threading.Lock()

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

def setup_tor_hidden_service():
    """Configures and restarts Tor to create a hidden service."""
    try:
        if not os.path.exists(TORRC_PATH):
            print(f"Warning: {TORRC_PATH} not found. Ensure Tor is installed via Homebrew.")
            return None
            
        with open(TORRC_PATH, 'r') as f:
            torrc = f.read()
            
        needed_config = f"\nHiddenServiceDir {HIDDEN_SERVICE_DIR}\nHiddenServicePort 80 {HOST}:{PORT}\n"
        
        hostname_path = os.path.join(HIDDEN_SERVICE_DIR, "hostname")
        config_present = "HiddenServiceDir /opt/homebrew/var/lib/tor/chatroom/" in torrc
        
        if not config_present:
            print("Adding hidden service config to torrc...")
            with open(TORRC_PATH, 'a') as f:
                f.write(needed_config)
            print("Restarting Tor...")
            subprocess.run(["brew", "services", "restart", "tor"], check=True)
            time.sleep(8) # Wait for Tor to generate hostname
        elif not os.path.exists(hostname_path):
            print("Restarting Tor (hostname file missing)...")
            subprocess.run(["brew", "services", "restart", "tor"], check=True)
            time.sleep(8)
        else:
            print("Tor hidden service already configured and active.")
            
        if os.path.exists(hostname_path):
            with open(hostname_path, 'r') as f:
                return f.read().strip()
        else:
            print("Could not find hostname file. Tor might still be starting.")
            return None
            
    except Exception as e:
        print(f"Error setting up Tor: {e}")
        return None

def safe_send(send_lock, conn, payload):
    """Sends a payload to a client thread-safely using their connection's send_lock."""
    with send_lock:
        try:
            conn.sendall(payload)
            return True
        except:
            return False

def broadcast_to_room(room_code, sender_conn, msg_type, content):
    """Broadcasts a message to all other clients in the room thread-safely without deadlocks."""
    to_forward = []
    with clients_lock:
        for other_conn in rooms.get(room_code, []):
            if other_conn != sender_conn and other_conn in clients:
                info = clients[other_conn]
                key = info['text_key'] if msg_type == b'T' else info['voice_key']
                to_forward.append((other_conn, key, info['send_lock']))
                
    for other_conn, key, send_lock in to_forward:
        enc_msg = encrypt_message(content, key)
        payload = (len(enc_msg) + 1).to_bytes(4, 'big') + msg_type + enc_msg
        safe_send(send_lock, other_conn, payload)

def handle_client(conn, addr):
    try:
        # Phase 3: Diffie-Hellman Key Exchange
        # Server sends its public key first with length prefix
        server_priv = generate_dh_private()
        server_pub = generate_dh_public(server_priv)
        pub_bytes = str(server_pub).encode('utf-8')
        conn.sendall(len(pub_bytes).to_bytes(4, 'big') + pub_bytes)
        
        # Receive client's public key with length prefix
        raw_len = recvall(conn, 4)
        if not raw_len:
            return
        key_len = int.from_bytes(raw_len, 'big')
        client_pub_bytes = recvall(conn, key_len)
        if not client_pub_bytes:
            return
        
        client_pub = int(client_pub_bytes.decode('utf-8'))
        shared_secret = compute_dh_shared_secret(server_priv, client_pub)
        text_key, voice_key = derive_keys(shared_secret)
        
        # Receive initial Nickname and Room Code payload
        raw_len = recvall(conn, 4)
        if not raw_len:
            return
        init_len = int.from_bytes(raw_len, 'big')
        if init_len > 8192:
            print("Initial payload too large, dropping connection.")
            return
            
        init_payload = recvall(conn, init_len)
        if not init_payload:
            return
            
        decrypted = decrypt_message(init_payload, text_key)
        if not decrypted:
            print("Handshake decryption failed.")
            return
            
        # Format: NICK:ROOM
        parts = decrypted.decode('utf-8').split(':', 1)
        if len(parts) != 2:
            print("Invalid handshake payload format.")
            return
            
        nick, room_code = parts
        
        with clients_lock:
            clients[conn] = {
                'address': addr,
                'nick': nick,
                'room': room_code,
                'text_key': text_key,
                'voice_key': voice_key,
                'send_lock': threading.Lock()
            }
            if room_code not in rooms:
                rooms[room_code] = []
            rooms[room_code].append(conn)
            
        print(f"[*] {nick} joined room {room_code}")
        
        # Announce join (sent to others as text)
        join_msg = f"*** {nick} has joined the room. ***"
        broadcast_to_room(room_code, conn, b'T', join_msg.encode('utf-8'))
                        
        # Main communication loop
        buffer = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buffer += chunk
            
            while len(buffer) >= 4:
                msg_len = int.from_bytes(buffer[:4], 'big')
                if len(buffer) < 4 + msg_len:
                    break # Wait for more data
                
                payload = buffer[4:4+msg_len]
                buffer = buffer[4+msg_len:]
                
                if len(payload) < 1:
                    continue
                    
                msg_type = payload[0:1]
                enc_envelope = payload[1:]
                
                if msg_type == b'T':
                    decrypted = decrypt_message(enc_envelope, text_key)
                    if decrypted:
                        text = decrypted.decode('utf-8')
                        formatted = f"{nick}: {text}"
                        print(f"[{room_code}] {formatted}")
                        broadcast_to_room(room_code, conn, b'T', formatted.encode('utf-8'))
                    else:
                        print(f"Decryption failed for text message from {nick}")
                elif msg_type == b'V':
                    # Voice data size check (Opus frame max is ~4KB + enc overhead)
                    if len(enc_envelope) > 4100:
                        print(f"[*] Oversized voice packet from {nick}, dropping")
                        continue
                        
                    decrypted = decrypt_message(enc_envelope, voice_key)
                    if decrypted:
                        broadcast_to_room(room_code, conn, b'V', decrypted)
                    else:
                        print(f"Decryption failed for voice packet from {nick}")
                else:
                    print(f"Unknown message type received from {nick}")
                    
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        cleanup_client(conn)

def cleanup_client(conn):
    nick = None
    room = None
    
    with clients_lock:
        if conn in clients:
            nick = clients[conn]['nick']
            room = clients[conn]['room']
            print(f"[*] {nick} disconnected.")
            if room in rooms and conn in rooms[room]:
                rooms[room].remove(conn)
            del clients[conn]
            
    # Send leave announcement outside of clients_lock
    if nick and room:
        leave_msg = f"*** {nick} has left the room. ***"
        broadcast_to_room(room, conn, b'T', leave_msg.encode('utf-8'))
            
    try:
        conn.close()
    except:
        pass

def generate_room_code():
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))

def start_server():
    print("Starting Tor Hidden Service...")
    onion_address = setup_tor_hidden_service()
    if onion_address:
        print(f"[*] Server available at: {onion_address}")
    else:
        print("[!] Tor setup failed or skipped. Running locally.")
        onion_address = "127.0.0.1"

    room_code = generate_room_code()
    print(f"[*] Generated Room Code: {room_code}")
    print(f"[*] Invite your friend with: python3 client.py {onion_address} {room_code}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Listening on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()
            print(f"[*] Accepted connection from {addr}")
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.close()
        sys.exit(0)

if __name__ == "__main__":
    start_server()
