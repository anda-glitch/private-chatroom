import socket
import threading
import sys
import os
import subprocess
import time
import secrets
import string
from crypto import generate_dh_private, generate_dh_public, compute_dh_shared_secret, encrypt_message, decrypt_message

# Configuration
HOST = '127.0.0.1'
PORT = 9999
TORRC_PATH = '/opt/homebrew/etc/tor/torrc'
HIDDEN_SERVICE_DIR = '/opt/homebrew/var/lib/tor/chatroom/'

clients = {} # {conn: {'address': addr, 'nick': nick, 'room': room, 'secret': shared_secret}}
rooms = {} # {room_code: [conn1, conn2, ...]}
clients_lock = threading.Lock()

def setup_tor_hidden_service():
    """Configures and restarts Tor to create a hidden service."""
    try:
        if not os.path.exists(TORRC_PATH):
            print(f"Warning: {TORRC_PATH} not found. Ensure Tor is installed via Homebrew.")
            return None
            
        with open(TORRC_PATH, 'r') as f:
            torrc = f.read()
            
        needed_config = f"\nHiddenServiceDir {HIDDEN_SERVICE_DIR}\nHiddenServicePort 80 {HOST}:{PORT}\n"
        
        if "HiddenServiceDir /opt/homebrew/var/lib/tor/chatroom/" not in torrc:
            print("Adding hidden service config to torrc...")
            with open(TORRC_PATH, 'a') as f:
                f.write(needed_config)
            
        # Ensure directories exist with 0o700 permissions
        try:
            os.makedirs(HIDDEN_SERVICE_DIR, mode=0o700, exist_ok=True)
            os.chmod(os.path.dirname(HIDDEN_SERVICE_DIR.rstrip('/')), 0o700)
            os.chmod(HIDDEN_SERVICE_DIR, 0o700)
        except Exception as e:
            print(f"Warning: Could not create/chmod hidden service directory: {e}")

        # Always try to restart if we don't see the hostname yet, or if we just added the config
        if "HiddenServiceDir /opt/homebrew/var/lib/tor/chatroom/" not in torrc or not os.path.exists(os.path.join(HIDDEN_SERVICE_DIR, "hostname")):
            print("Restarting Tor...")
            subprocess.run(["brew", "services", "restart", "tor"], check=True)
            time.sleep(5) # Wait for Tor to generate hostname
            
        hostname_path = os.path.join(HIDDEN_SERVICE_DIR, "hostname")
        if os.path.exists(hostname_path):
            with open(hostname_path, 'r') as f:
                return f.read().strip()
        else:
            print("Could not find hostname file. Tor might still be starting.")
            return None
            
    except Exception as e:
        print(f"Error setting up Tor: {e}")
        return None

def safe_send(conn, payload):
    """Sends a payload to a client thread-safely using their connection's send_lock."""
    with clients_lock:
        client_info = clients.get(conn)
    if client_info:
        with client_info['send_lock']:
            try:
                conn.sendall(payload)
                return True
            except:
                pass
    return False

def handle_client(conn, addr):
    try:
        # Phase 3: Diffie-Hellman Key Exchange
        # Server sends its public key first
        server_priv = generate_dh_private()
        server_pub = generate_dh_public(server_priv)
        conn.sendall(str(server_pub).encode('utf-8') + b'\n')
        
        # Receive client's public key
        client_pub_bytes = b""
        while b'\n' not in client_pub_bytes:
            chunk = conn.recv(1)
            if not chunk:
                return
            client_pub_bytes += chunk
        
        client_pub = int(client_pub_bytes.strip().decode('utf-8'))
        shared_secret = compute_dh_shared_secret(server_priv, client_pub)
        
        # Wait for Nickname and Room Code (Encrypted)
        init_payload = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                return
            init_payload += chunk
            decrypted = decrypt_message(init_payload, shared_secret)
            if decrypted:
                # Format: NICK:ROOM
                parts = decrypted.decode('utf-8').split(':', 1)
                if len(parts) == 2:
                    nick, room_code = parts
                    break
            if len(init_payload) > 8192:
                print("Initial payload too large, dropping connection.")
                return

        with clients_lock:
            clients[conn] = {
                'address': addr,
                'nick': nick,
                'room': room_code,
                'secret': shared_secret,
                'send_lock': threading.Lock()
            }
            if room_code not in rooms:
                rooms[room_code] = []
            rooms[room_code].append(conn)
            
        print(f"[*] {nick} joined room {room_code}")
        
        # Announce join
        join_msg = f"*** {nick} has joined the room. ***"
        
        to_announce = []
        with clients_lock:
            for other_conn in rooms.get(room_code, []):
                if other_conn != conn and other_conn in clients:
                    to_announce.append((other_conn, clients[other_conn]['secret']))
                    
        for other_conn, other_secret in to_announce:
            enc_msg = encrypt_message(join_msg.encode('utf-8'), other_secret)
            payload = len(enc_msg).to_bytes(4, 'big') + enc_msg
            safe_send(other_conn, payload)
                        
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
                
                # Decrypt message
                decrypted = decrypt_message(payload, shared_secret)
                if decrypted:
                    # Could be text or multiplexed voice
                    # Let's assume text for now. Prefix text with T, voice with V
                    msg_type = decrypted[0:1]
                    content = decrypted[1:]
                    
                    if msg_type == b'T':
                        text = content.decode('utf-8')
                        formatted = f"{nick}: {text}"
                        print(f"[{room_code}] {formatted}")
                        
                        # Re-encrypt for broadcast
                        to_forward = []
                        with clients_lock:
                            for other_conn in rooms.get(room_code, []):
                                if other_conn != conn and other_conn in clients:
                                    to_forward.append((other_conn, clients[other_conn]['secret']))
                                    
                        for other_conn, other_secret in to_forward:
                            enc_content = encrypt_message(b'T' + formatted.encode('utf-8'), other_secret)
                            out_payload = len(enc_content).to_bytes(4, 'big') + enc_content
                            safe_send(other_conn, out_payload)
                    elif msg_type == b'V':
                        # Voice data - broadcast to everyone else
                        to_forward = []
                        with clients_lock:
                            for other_conn in rooms.get(room_code, []):
                                if other_conn != conn and other_conn in clients:
                                    to_forward.append((other_conn, clients[other_conn]['secret']))
                                    
                        for other_conn, other_secret in to_forward:
                            enc_content = encrypt_message(b'V' + content, other_secret)
                            out_payload = len(enc_content).to_bytes(4, 'big') + enc_content
                            safe_send(other_conn, out_payload)
                else:
                    print(f"Invalid MAC or decryption failed from {nick}")
                    
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        cleanup_client(conn)

def cleanup_client(conn):
    nick = None
    room = None
    to_announce = []
    
    with clients_lock:
        if conn in clients:
            nick = clients[conn]['nick']
            room = clients[conn]['room']
            print(f"[*] {nick} disconnected.")
            if room in rooms and conn in rooms[room]:
                rooms[room].remove(conn)
            
            # Gather other clients' info while holding clients_lock
            for other_conn in rooms.get(room, []):
                if other_conn in clients:
                    to_announce.append((other_conn, clients[other_conn]['secret']))
                    
            del clients[conn]
            
    # Send leave announcements outside of clients_lock to avoid deadlock and blocking I/O
    if nick and room:
        leave_msg = f"*** {nick} has left the room. ***"
        for other_conn, other_secret in to_announce:
            enc_msg = encrypt_message(b'T' + leave_msg.encode('utf-8'), other_secret)
            payload = len(enc_msg).to_bytes(4, 'big') + enc_msg
            safe_send(other_conn, payload)
            
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
