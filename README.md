# Private Chatroom

An encrypted, peer-to-peer (via Tor hidden services) chatroom application supporting End-to-End Encrypted (E2EE) text and voice chat.

## Features

- **End-to-End Encryption (E2EE)**: Secure communication using:
  - Diffie-Hellman Key Exchange (RFC 3526 Group 14, 2048-bit MODP Group)
  - AES-256-CTR for encryption
  - HMAC-SHA256 for integrity verification
- **Multiplexed Audio & Text**: Stream real-time voice and send text simultaneously over a single connection.
- **Tor Onion Services Integration**: Built-in support to run the server as a Tor Hidden Service (`.onion`) on macOS, allowing connections behind NATs and firewalls without port forwarding, ensuring network metadata privacy.
- **Terminal UI**: Responsive, retro-styled CLI interface built with `blessed`.

## Requirements

- Python 3.8+
- macOS (for automated Tor hidden service integration via Homebrew)
- PortAudio (for `pyaudio` voice capture/playback)
- Tor (for onion routing)

### Prerequisites Installation (macOS)

```bash
# Install Homebrew dependencies
brew install portaudio tor

# Install Python requirements in your virtual environment
pip install pyaudio opuslib blessed cryptography PySocks
```

*Note: For audio compression, this project uses `opuslib` which relies on the `libopus` library. Ensure `libopus` is installed if on a different platform.*

## Usage

### 1. Starting the Server

To start the server, configure your host and start the server script:

```bash
python3 server.py
```

If Tor is installed and configured via Homebrew, the server will automatically configure a Tor hidden service and print your unique `.onion` address and a generated room code.

### 2. Connecting as a Client

Run the client script by passing the server address (either a local IP/hostname or a `.onion` address) and the room code:

```bash
python3 client.py <server_address> <room_code>
```

For example, connecting via Tor:
```bash
python3 client.py abcdefghijklmnop.onion A1B2C3
```

Connecting locally:
```bash
python3 client.py 127.0.0.1 A1B2C3
```

### Controls

- Type messages and press **Enter** to send.
- Press **Ctrl + T** or type `/mute` and press **Enter** to toggle microphone mute (highly compatible with mobile/Android virtual keyboards).
- Type `/leave` and press **Enter** to safely exit the chatroom.

## Technical Details

1. **Key Exchange**: On connection, the client and server exchange public keys using Diffie-Hellman. A shared secret is computed and hashed with SHA-256 to derive a 32-byte session key.
2. **Encryption Wrapper**: All messages (prefixed with `T` for Text and `V` for Voice) are encrypted using AES-256-CTR and authenticated with HMAC-SHA256, formatted as:
   ```
   [ IV (16 bytes) ] + [ HMAC (32 bytes) ] + [ Ciphertext (N bytes) ]
   ```
3. **Tor Hidden Service**: On startup, the server adds a hidden service configuration to the local Tor configuration (`torrc`), restarts the Tor service via Homebrew services, and reads the generated hostname.
