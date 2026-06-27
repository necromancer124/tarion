# Tarion P2P Chat

Tarion is a secure, hybrid peer-to-peer CLI chat protocol designed for high-performance encrypted communication using QUIC.

## 🚀 Architecture
- **Hybrid P2P**: Uses a central directory server (`tariond`) for discovery and signaling, but chat payloads are sent strictly P2P.
- **Transport**: Operates over QUIC (UDP port 63425) for built-in TLS 1.3 encryption.
- **NAT Traversal**: Implements UDP Hole Punching mediated by the server to bypass home routers.
- **TUI**: Built with the Charm ecosystem (Bubble Tea & Lip Gloss).

## 🛠 Installation & Setup
1. **Install Go**: Ensure Go 1.22+ is installed on your system.
2. **Build the Client**:
   ```bash
   go build -o tarion.exe main.go
   ```
3. **Configuration**:
   Edit `~/.config/tarion/config.json` to set your server address and username.

## 📖 Usage
- **Standard Launch**: Run `tarion.exe` to open the contact list.
- **Manual IP Chat**: Bypass the server and connect directly to a peer:
  ```bash
  tarion.exe -u "PeerName" -i "1.2.3.4:63425"
  ```

## ⌨️ Controls
- `↑/↓` : Navigate contacts.
- `Enter` : Open chat with selected user.
- `Esc` : Return to contact list from chat.
- `q` : Quit application.
- `?` : Open Help/Setup guide.

## 🔒 Privacy
- All chat histories are stored locally in `~/.config/tarion/history/`.
- No chat data ever touches the central server.
