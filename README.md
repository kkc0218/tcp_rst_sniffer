# 🔒 TCP SYN-Level RST Blocker

> A simple C-based tool that intercepts TCP SYN packets to a specified IP and port and immediately breaks the connection by sending crafted TCP RST packets in both directions.

---

## 🚀 Features

- ✅ Detects TCP connection attempts to a specific IP and port.
- 🔥 Immediately injects TCP RST packets (both directions) to block the session.
- 🛡 Effective before TLS handshake (prevents HTTPS negotiation).
- ⚙️ Built with `libpcap` and `libnet` for low-level packet manipulation.

---

## 🛠 Installation

### Dependencies

Make sure you have the following libraries installed:

```bash
# For Ubuntu/Debian
sudo apt install libpcap-dev libnet-dev

# For macOS (via Homebrew)
brew install libpcap libnet
