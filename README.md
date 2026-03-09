# f9gfw

A custom TCP/UDP proxy stack written in Zig 0.15.2 that creates an asymmetric protocol for network traffic obfuscation.

## Overview

f9gfw implements a novel TCP proxy architecture where:

- **Client→Server traffic** flows over UDP with encrypted TCP packets
- **Server→Client traffic** flows over standard TCP
- **NAT Traversal** uses TTL-limited TCP SYN packets that expire before reaching the destination, creating NAT entries without completing the handshake

This design allows traffic to traverse NAT boundaries while making the actual TCP handshake invisible to monitoring devices.

## Architecture

```
┌─────────────┐                    ┌─────────────┐
│   Client    │                    │   Server    │
│  (Windows)  │                    │   (Linux)   │
├─────────────┤                    ├─────────────┤
│ Local TCP   │                    │  UDP Socket │
│  Listener   │                    │  (io_uring) │
│      │      │                    │      │      │
│      ▼      │    UDP (encrypted) │      ▼      │
│   Tunnel    │ ─────────────────► │   Decrypt  │
│   Encrypt   │                    │      │      │
│      │      │                    │      ▼      │
│      ▼      │                    │ Raw Socket │
│ UDP Socket  │                    │  Inject    │
└─────────────┘                    └─────────────┘
```

### Components

| Component | Description |
|-----------|-------------|
| **crypto.zig** | ChaCha20-Poly1305 AEAD encryption |
| **packet.zig** | IPv4/TCP header parsing and checksum calculation |
| **protocol.zig** | Tunnel header format and packet types |
| **tunnel.zig** | Session management |
| **iouring.zig** | Linux io_uring async UDP I/O |
| **injector.zig** | Raw socket TCP packet injection |
| **winsock.zig** | Windows Winsock2 wrapper |
| **wfp.zig** | Windows Filtering Platform bindings |

## Building

### Prerequisites

- Zig 0.15.2 or later

### Build Commands

```bash
# Build for current platform
zig build

# Build server (Linux target)
zig build -Dtarget=x86_64-linux-gnu

# Build client (Windows target)
zig build -Dtarget=x86_64-windows-gnu

# Run unit tests
zig build test
```

## Usage

### Server (Linux)

The server must run on a Linux machine with root privileges (required for raw sockets).

```bash
sudo ./f9gfw -l <listen_ip> -p <port> -k <key>
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-l <ip>` | Listen IP address | `0.0.0.0` |
| `-p <port>` | Listen UDP port | `51820` |
| `-k <key>` | Pre-shared encryption key | *required* |
| `-h, --help` | Show help message | |

**Example:**

```bash
sudo ./f9gfw -l 0.0.0.0 -p 51820 -k mysecretkey
```

### Client (Windows)

```bash
f9gfwc.exe -l <local_port> -f <forward_addr> -c <proxy_addr> -p <proxy_port> -k <key> --ttl <ttl>
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-l <port>` | Local TCP listen port | `1080` |
| `-f <ip[:port]>` | Forward address (destination server) | *required* |
| `-c <ip[:port]>` | Proxy server address | *required* |
| `-p <port>` | Proxy UDP port | `51820` |
| `-k <key>` | Pre-shared encryption key | *required* |
| `--ttl <n>` | TTL for NAT traversal SYNs | `2` |
| `-h, --help` | Show help message | |

**Example:**

```bash
f9gfwc.exe -l 1080 -f 93.184.216.34:80 -c 192.168.1.100 -p 51820 -k mysecretkey --ttl 2
```

Then connect to the local proxy:

```bash
curl --proxy socks5://127.0.0.1:1080 http://example.com
```

## Protocol

### Tunnel Header Format

```
┌──────────────────────────────────────────────────────────────┐
│ Magic (4) │ Ver (1) │ Type (1) │ Session ID (4) │ ...       │
├──────────────────────────────────────────────────────────────┤
│ ... Checksum (2) │ Payload Length (2) │ Encrypted Payload   │
└──────────────────────────────────────────────────────────────┘
```

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 bytes | `0xF9 0x1A 0x2B 0x3C` |
| Version | 1 byte | Protocol version (1) |
| Type | 1 byte | Packet type (data/connect/disconnect/keepalive/ack) |
| Session ID | 4 bytes | Unique session identifier |
| Checksum | 2 bytes | Header + payload checksum |
| Payload Length | 2 bytes | Length of encrypted payload |
| Payload | variable | ChaCha20-Poly1305 encrypted data |

### Packet Types

| Type | Value | Description |
|------|-------|-------------|
| `data` | `0x01` | Data packet |
| `connect` | `0x02` | New connection request |
| `disconnect` | `0x03` | Connection close |
| `keepalive` | `0x04` | Keep-alive ping |
| `ack` | `0x05` | Acknowledgment |

## Security

- **Encryption**: ChaCha20-Poly1305 AEAD cipher provides authenticated encryption
- **Key Derivation**: SHA-256 hash of the pre-shared key (consider using HKDF or Argon2 for production)
- **Nonce Management**: Incrementing counter with random prefix

## Limitations

- Server requires root privileges on Linux (for raw sockets)
- Full WFP callout requires kernel-mode driver on Windows
- Current implementation uses user-mode packet capture approach

## Development

### Project Structure

```
f9gfw/
├── build.zig           # Build configuration
├── src/
│   ├── shared/         # Platform-independent code
│   │   ├── crypto.zig  # Encryption
│   │   ├── packet.zig  # Packet parsing
│   │   ├── protocol.zig# Protocol definitions
│   │   └── tunnel.zig  # Session management
│   ├── server/         # Linux server
│   │   ├── main.zig    # Entry point
│   │   ├── iouring.zig # Async I/O
│   │   └── injector.zig# Packet injection
│   └── client/         # Windows client
│       ├── main.zig    # Entry point
│       ├── winsock.zig # Socket wrapper
│       ├── tunnel.zig  # Tunnel logic
│       └── wfp.zig     # WFP bindings
└── tests/              # Unit tests
```

### Running Tests

```bash
zig build test
```

## License

MIT License - see [LICENSE](LICENSE) for details.
