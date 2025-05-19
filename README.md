# CNE_Project
A multithreaded chat server in C++ that supports multiple TCP clients with user registration, login, status tracking, and private messaging. It includes a UDP broadcast mechanism for network discovery and handles user commands like /help, /register, /login, /send, /status, and /getlog.  The server uses:  Winsock (Windows Sockets API) for socket communication.  Select-based I/O multiplexing to manage concurrent clients.  Command-based protocol, with messages prefixed by / and bounded to 255-byte length.  Atomic and thread-safe shutdown, supporting graceful termination via signal handling.  🔧 Key Features: Fixed-length message protocol with length-prefixing.  Client registration and login with credential checks.  User presence tracking: active/inactive status.  Per-user private messaging via /send <user> <msg>.  UDP broadcast (255.255.255.255) every 60s to announce the server.  Help and log retrieval via /help and /getlog.  Chunked response logic for long server messages.

 Multi-Client TCP Chat Server with UDP Discovery

## Overview
This is a C++ chat server built using the Winsock API that supports multiple TCP client connections. It provides robust features such as user authentication, command parsing, message chunking, and client status tracking. Additionally, it uses UDP broadcast to announce its presence to the local network.

## Features
- ✅ **User Registration & Login** via `/register` and `/login`
- ✅ **Private Messaging** using `/send <username> <message>`
- ✅ **Client Status Management** (active/inactive)
- ✅ **Command-Based Interface** with `/help`, `/status`, `/getlog`, and `/quit`
- ✅ **UDP Broadcast Discovery** (every 60 seconds)
- ✅ **Thread-safe server shutdown** via `SIGINT`
- ✅ **Chunked Message Transmission** for messages longer than 255 bytes

## Communication Protocol
- TCP: Client-server communication is handled over a TCP socket
- UDP: Server sends periodic broadcasts to `255.255.255.255` to advertise availability
- Messages use an 8-bit length prefix (max 255 bytes)

## Build & Run Instructions
### Prerequisites
- Windows OS
- Visual Studio or a compiler with Winsock2 support

### Compilation
Build the project using your preferred C++ compiler. Make sure to link against the Winsock library:
```sh
#pragma comment(lib, "Ws2_32.lib")
```

### Run the Server
```
Enter TCP Port number: 5000
Enter chat capacity: 10
Enter command character (press Enter for default '/'): /

Run the spaghettiRelay application in the example folder and switch to client mode
Enter the TCP Port number you used in the command prompt
Type commands in the chat box (not the response box)
```

## Supported Commands
```text
/help                   - Show help
/register u p           - Register user `u` with password `p`
/login u p              - Log in as user `u` with password `p`
/status                 - Show all users and status (Active/Inactive)
/getlist                - List active users
/getlog                 - View the server log file
/send user message      - Send a private message to another user
/logout                 - Logout from the server
/quit                   - Disconnect from the server
```

## Code Structure
- `Server.h / Server.cpp` — Main server class and message handlers
- `CNE_Project.cpp` — Entry point, signal handling, configuration
- `server_log.txt` — Log file used by `/getlog`

## Security Notes
- User passwords are stored in-memory only (no encryption or file storage)
- No rate limiting or authentication hardening implemented (suitable for local network use/demo)

---
## Author
Jaxon Chalfant