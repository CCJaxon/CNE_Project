#include "Server.h"
#include <sstream>
#include <algorithm>
#include <string>
#include <cctype>
#include <fstream>

Server::Server() : listeningSocket(INVALID_SOCKET), maxFd(0), chatCapacity(0), commandChar('~') {}

Server::~Server() {
    stop();
}

std::atomic<bool> isBroadcasting{ false };
std::thread broadcastThread;

void Server::startBroadcast(uint16_t port) {
    isBroadcasting = true;

    broadcastThread = std::thread([this, port]() {
        SOCKET udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udpSocket == INVALID_SOCKET) {
            std::cerr << "Failed to create UDP socket. Error: " << WSAGetLastError() << "\n";
            return;
        }

        // Enable broadcast on the socket
        int broadcastEnable = 1;
        if (setsockopt(udpSocket, SOL_SOCKET, SO_BROADCAST, (char*)&broadcastEnable, sizeof(broadcastEnable)) == SOCKET_ERROR) {
            std::cerr << "Failed to set broadcast option. Error: " << WSAGetLastError() << "\n";
            closesocket(udpSocket);
            return;
        }

        // Define the broadcast address
        sockaddr_in broadcastAddr = {};
        broadcastAddr.sin_family = AF_INET;
        broadcastAddr.sin_port = htons(port);
        broadcastAddr.sin_addr.s_addr = INADDR_BROADCAST;

        // Broadcast message
        std::string message = "Server running on port " + std::to_string(port);

        while (isBroadcasting) {
            int result = sendto(udpSocket, message.c_str(), static_cast<int>(message.size()), 0,
                (sockaddr*)&broadcastAddr, sizeof(broadcastAddr));
            if (result == SOCKET_ERROR) {
                std::cerr << "Failed to send broadcast message. Error: " << WSAGetLastError() << "\n";
            }
            else {
                std::cout << "Broadcast message sent: " << message << "\n";
            }

            // Wait for 60 seconds before sending the next broadcast
            std::this_thread::sleep_for(std::chrono::seconds(60));
        }

        closesocket(udpSocket);
    });
}

void Server::stopBroadcast() {
    isBroadcasting = false;
    if (broadcastThread.joinable()) {
        broadcastThread.join();
    }
}

int Server::init(uint16_t port, size_t capacity, char commandChar) {
    chatCapacity = capacity;
    this->commandChar = commandChar;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed with error: " << WSAGetLastError() << "\n";
        return ERR_WSASTARTUP;
    }

    listeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listeningSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed with error: " << WSAGetLastError() << "\n";
        WSACleanup();
        return ERR_SOCKET_CREATION;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(listeningSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed.\n";
        closesocket(listeningSocket);
        WSACleanup();
        return ERR_BIND;
    }

    if (listen(listeningSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed.\n";
        closesocket(listeningSocket);
        WSACleanup();
        return ERR_LISTEN;
    }

    char hostname[NI_MAXHOST];
    gethostname(hostname, sizeof(hostname));

    addrinfo hints = {}, * result;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(nullptr, std::to_string(port).c_str(), &hints, &result) != 0) {
        std::cerr << "getaddrinfo failed.\n";
        closesocket(listeningSocket);
        WSACleanup();
        return ERR_GETADDRINFO;
    }

    displayServerInfo(hostname, result, port);
    freeaddrinfo(result);

    FD_ZERO(&masterSet);
    FD_SET(listeningSocket, &masterSet);
    maxFd = listeningSocket;

    startBroadcast(port);
    return 0;
}

// Trims leading and trailing whitespace from a string
std::string trim(const std::string& str) {
    auto start = std::find_if_not(str.begin(), str.end(), [](unsigned char ch) {
        return std::isspace(ch) || ch == '\0';
        });

    auto end = std::find_if_not(str.rbegin(), str.rend(), [](unsigned char ch) {
        return std::isspace(ch) || ch == '\0';
        }).base();

        return (start < end ? std::string(start, end) : std::string());
}

void Server::run() {
    std::cout << "Server is running. Waiting for connections...\n";

    while (true) {
        fd_set readySet = masterSet;
        if (select(static_cast<int>(maxFd + 1), &readySet, nullptr, nullptr, nullptr) == SOCKET_ERROR) {
            std::cerr << "select() failed. Error: " << WSAGetLastError() << "\n";
            break;
        }

        for (int sock = 0; sock <= maxFd; ++sock) {
            if (!FD_ISSET(sock, &readySet)) continue;

            if (sock == listeningSocket) {
                // Accept a new client connection
                sockaddr_in clientAddr;
                int addrLen = sizeof(clientAddr);
                SOCKET clientSocket = accept(listeningSocket, (sockaddr*)&clientAddr, &addrLen);

                if (clientSocket == INVALID_SOCKET) {
                    std::cerr << "Accept failed. Error: " << WSAGetLastError() << "\n";
                    continue;
                }

                if (clients.size() >= chatCapacity) {
                    sendMessage(clientSocket, "Server is full. Try again later.\n");
                    closesocket(clientSocket);
                    std::cerr << "Connection rejected: Server at full capacity.\n";
                    continue;
                }

                FD_SET(clientSocket, &masterSet);
                maxFd = max(maxFd, static_cast<int>(clientSocket));
                clients[clientSocket] = "Anonymous";

                sendMessage(clientSocket, "Welcome to the server! Use '/' for commands.\n");
                std::cout << "INFO: New client connected: " << clientSocket << "\n";
            }
            else {
                // Process client messages
                std::string message;
                if (readMessage(sock, message) < 0) {
                    int errorCode = WSAGetLastError();
                    if (errorCode == WSAECONNRESET) {
                        std::cerr << "Client " << sock << " forcibly closed the connection.\n";
                    }
                    else {
                        std::cerr << "Failed to read from client " << sock << ". Error: " << errorCode << "\n";
                    }

                    // Handle disconnection
                    if (loggedInUsers.find(sock) != loggedInUsers.end()) {
                        std::string username = loggedInUsers[sock];
                        loggedInUsers.erase(sock);
                        userStatus[username] = false;
                        std::cout << "INFO: User " << username << " disconnected.\n";
                    }

                    FD_CLR(sock, &masterSet);
                    closesocket(sock);
                    clients.erase(sock);

                    std::cout << "INFO: Client disconnected: " << sock << "\n";
                }
                else {
                    // Trim and normalize the message
                    message = trim(message);
                    std::transform(message.begin(), message.end(), message.begin(), ::tolower);

                    // Handle client commands
                    if (message == "/help") {
                        std::string helpMessage =
                            "Available Commands and Formats:\n"
                            "/help\n"
                            "- Show this help message\n"
                            "/register <username> <password>\n"   
                            "- Register a new user (e.g., /register Alice password123)\n"
                            "/login <username> <password>\n"
                            "- Log in with your credentials (e.g., /login Alice password123)\n"
                            "/status\n"
                            "- Show all registered users and their status (active/inactive)\n"
                            "/quit\n"
                            "- Disconnect from the server\n"
                            "\nNotes:\n"
                            "- Replace <username> and <password> with your desired credentials.\n"
                            "- Use '/' followed by a command to interact with the server.\n";

                        sendChunkedMessage(sock, helpMessage);

                        size_t maxChunkSize = 255;
                        size_t totalSize = helpMessage.size();
                        size_t start = 0;

                        while (start < totalSize) {
                            size_t chunkSize = min(maxChunkSize, totalSize - start);
                            std::string chunk = helpMessage.substr(start, chunkSize);

                            if (sendMessage(sock, chunk) == -1) {
                                std::cerr << "Failed to send help message chunk to client " << sock << "\n";
                                break;
                            }
                            start += chunkSize;
                        }
                    }
                    else if (message.substr(0, 9) == "/register") {
                        std::istringstream iss(message);
                        std::string command, username, password;
                        iss >> command >> username >> password;

                        if (clients.size() >= chatCapacity) {
                            sendMessage(sock, "Registration failed: Server capacity reached.\n");
                        }
                        else if (users.find(username) != users.end()) {
                            sendMessage(sock, "Registration failed: Username already exists.\n");
                        }
                        else if (!username.empty() && !password.empty()) {
                            users[username] = password;
                            userStatus[username] = false;
                            sendMessage(sock, "Registration successful! You can now log in.\n");
                        }
                        else {
                            sendMessage(sock, "Registration failed: Invalid format. Use /register <username> <password>.\n");
                        }
                    }
                    else if (message.substr(0, 6) == "/login") {
                        std::istringstream iss(message);
                        std::string command, username, password;
                        iss >> command >> username >> password;

                        if (username.empty() || password.empty()) {
                            sendMessage(sock, "Login failed: Invalid format. Use /login <username> <password>.\n");
                        }
                        else if (users.find(username) == users.end()) {
                            sendMessage(sock, "Login failed: Username does not exist.\n");
                        }
                        else if (users[username] != password) {
                            sendMessage(sock, "Login failed: Incorrect password.\n");
                        }
                        else if (loggedInUsers.find(sock) != loggedInUsers.end()) {
                            sendMessage(sock, "You are already logged in as " + loggedInUsers[sock] + ".\n");
                        }
                        else {
                            loggedInUsers[sock] = username;
                            userStatus[username] = true;
                            sendMessage(sock, "Login successful! Welcome, " + username + ".\n");
                        }
                    }
                    else if (message == "/status") {
                        std::string response = "User Status:\n";
                        for (const auto& [username, status] : userStatus) {
                            response += username + " - " + (status ? "Active\n" : "Inactive\n");
                        }
                        sendMessage(sock, response);
                    }
                    else if (message == "/getlist") {
                        handleGetListCommand(sock);
                    }
                    else if (message == "/logout") {
                        handleLogoutCommand(sock);
                    }
                    else if (message == "/getlog") {
                        handleGetLogCommand(sock);
                    }
                    else if (message == "/quit") {
                        if (loggedInUsers.find(sock) != loggedInUsers.end()) {
                            std::string username = loggedInUsers[sock];
                            loggedInUsers.erase(sock);
                            userStatus[username] = false;
                            std::cout << "INFO: User " << username << " logged out.\n";
                        }

                        sendMessage(sock, "Goodbye! You are now inactive.\n");

                        FD_CLR(sock, &masterSet);
                        closesocket(sock);
                        clients.erase(sock);

                        std::cout << "INFO: Client " << sock << " disconnected.\n";
                    }
                    else if (message.substr(0, 5) == "/send") {
                        std::istringstream iss(message);
                        std::string command, targetUsername, content;
                        iss >> command >> targetUsername;
                        std::getline(iss, content);

                        // Trim leading spaces from the content
                        content = trim(content);

                        if (targetUsername.empty() || content.empty()) {
                            sendMessage(sock, "Invalid format. Use /send <username> <message>.\n");
                            break;
                        }

                        // Check if the target user is logged in
                        auto targetIt = std::find_if(loggedInUsers.begin(), loggedInUsers.end(),
                            [&](const auto& pair) { return pair.second == targetUsername; });

                        if (targetIt == loggedInUsers.end()) {
                            sendMessage(sock, "User '" + targetUsername + "' is not currently logged in.\n");
                            return;
                        }

                        // Retrieve the sender's username
                        std::string sender = loggedInUsers[sock];
                        if (sender.empty()) {
                            sendMessage(sock, "You must be logged in to send messages.\n");
                            return;
                        }

                        // Construct the private message
                        std::string privateMessage = "[Private from " + sender + "]: " + content;

                        // Send the private message to the target user
                        if (sendMessage(targetIt->first, privateMessage) == -1) {
                            std::cerr << "Failed to send private message from " << sender << " to " << targetUsername << "\n";
                        }
                        else {
                            sendMessage(sock, "Message sent to " + targetUsername + ".\n");
                            std::cout << "INFO: Private message from " << sender << " to " << targetUsername << ": " << content << "\n";
                        }
                        }
                    else {
                        sendMessage(sock, "Unknown command. Use /help for assistance.\n");
                    }
                }
            }
        }
    }
}

void Server::stop() {
    stopBroadcast(); // Stop the broadcast thread
    for (const auto& [sock, username] : loggedInUsers) {
        userStatus[username] = false; // Mark all users as inactive
        closesocket(sock);
    }
    loggedInUsers.clear();
    clients.clear();

    if (listeningSocket != INVALID_SOCKET) {
        closesocket(listeningSocket);
    }

    WSACleanup();
    std::cout << "Server stopped.\n";
}

int Server::sendMessage(SOCKET clientSocket, const std::string& message) {
    if (message.size() > 255) {
        std::cerr << "ERROR: Message size exceeds the maximum allowed length of 255 bytes.\n";
        return -1;
    }

    uint8_t length = static_cast<uint8_t>(message.size());
    int totalSent = 0;

    // Send the length of the message first
    while (totalSent < sizeof(length)) {
        int bytesSent = send(clientSocket, ((char*)&length) + totalSent, sizeof(length) - totalSent, 0);
        if (bytesSent == SOCKET_ERROR) {
            std::cerr << "ERROR: Failed to send message length. Socket: " << clientSocket
                << ", Error: " << WSAGetLastError() << "\n";
            return -1;
        }
        totalSent += bytesSent;
    }

    // Send the actual message
    totalSent = 0;
    while (totalSent < length) {
        int bytesSent = send(clientSocket, message.c_str() + totalSent, length - totalSent, 0);
        if (bytesSent == SOCKET_ERROR) {
            std::cerr << "ERROR: Failed to send message content. Socket: " << clientSocket
                << ", Error: " << WSAGetLastError() << "\n";
            return -1;
        }
        totalSent += bytesSent;
    }

    std::cout << "INFO: Successfully sent message to client " << clientSocket << " (Length: " << (int)length << ")\n";
    return 0;
}

int Server::readMessage(SOCKET clientSocket, std::string& message) {
    uint8_t length;
    int bytesRead = recv(clientSocket, (char*)&length, sizeof(length), 0);

    // Check if the length of the message was read successfully
    if (bytesRead <= 0) {
        int errorCode = WSAGetLastError();
        if (errorCode == WSAECONNRESET) {
            std::cerr << "ERROR: Client " << clientSocket << " forcibly closed the connection.\n";
        }
        else {
            std::cerr << "ERROR: Failed to read message length from client " << clientSocket
                << ". Error: " << errorCode << "\n";
        }
        return -1;
    }

    // Allocate buffer for message content
    std::vector<char> buffer(length, 0);
    int totalBytesRead = 0;

    // Read the actual message content
    while (totalBytesRead < length) {
        bytesRead = recv(clientSocket, buffer.data() + totalBytesRead, length - totalBytesRead, 0);

        if (bytesRead <= 0) {
            int errorCode = WSAGetLastError();
            if (errorCode == WSAECONNRESET) {
                std::cerr << "ERROR: Client " << clientSocket << " closed the connection while reading.\n";
            }
            else {
                std::cerr << "ERROR: Failed to read message content from client " << clientSocket
                    << ". Error: " << errorCode << "\n";
            }
            return -1;
        }

        totalBytesRead += bytesRead;
    }

    // Convert the buffer to a string
    message.assign(buffer.begin(), buffer.end());
    std::cout << "INFO: Received message from client " << clientSocket << " (Length: " << (int)length << ")\n";
    return 0;
}

void Server::displayServerInfo(const std::string& hostname, addrinfo* result, uint16_t port) {
    std::cout << "Server Information:\n";
    std::cout << "Hostname: " << hostname << "\n";
    std::cout << "Port: " << port << "\n";
    std::cout << "IP Addresses:\n";

    for (addrinfo* addr = result; addr != nullptr; addr = addr->ai_next) {
        char ipStr[INET6_ADDRSTRLEN];
        if (addr->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((sockaddr_in*)addr->ai_addr)->sin_addr, ipStr, sizeof(ipStr));
            std::cout << "IPv4: " << ipStr << "\n";
        }
        else if (addr->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((sockaddr_in6*)addr->ai_addr)->sin6_addr, ipStr, sizeof(ipStr));
            std::cout << "IPv6: " << ipStr << "\n";
        }
    }
}

void Server::handleGetListCommand(SOCKET clientSocket) {
    std::string activeUsers = "Active Users:\n";

    for (const auto& [sock, username] : loggedInUsers) {
        activeUsers += username + "\n";
    }

    if (sendMessage(clientSocket, activeUsers) == -1) {
        std::cerr << "Failed to send active users list to client " << clientSocket << "\n";
    }
}

void Server::handleLogoutCommand(SOCKET clientSocket) {
    if (loggedInUsers.find(clientSocket) != loggedInUsers.end()) {
        std::string username = loggedInUsers[clientSocket];
        loggedInUsers.erase(clientSocket);
        userStatus[username] = false;
        std::cout << "INFO: User " << username << " logged out.\n";
    }

    sendMessage(clientSocket, "Goodbye! You are now logged out.\n");
    shutdown(clientSocket, SD_SEND);
    FD_CLR(clientSocket, &masterSet);
    closesocket(clientSocket);
    clients.erase(clientSocket);
}

void Server::handleGetLogCommand(SOCKET clientSocket) {
    std::ifstream logFile("server_log.txt", std::ios::in);

    if (!logFile.is_open()) {
        sendMessage(clientSocket, "Log file not found or could not be opened.\n");
        std::cerr << "Failed to open log file for client " << clientSocket << "\n";
        return;
    }

    std::string line;
    std::string chunk;
    const size_t maxChunkSize = 255;

    while (std::getline(logFile, line)) {
        if (chunk.size() + line.size() + 1 > maxChunkSize) {
            if (sendMessage(clientSocket, chunk) == -1) {
                std::cerr << "Failed to send log chunk to client " << clientSocket << "\n";
                logFile.close();
                return;
            }
            chunk.clear();
        }
        chunk += line + "\n";
    }

    if (!chunk.empty()) {
        if (sendMessage(clientSocket, chunk) == -1) {
            std::cerr << "Failed to send chunk.\n";
            return;
        }
        chunk.clear();
    }

    logFile.close();
}

bool Server::sendChunkedMessage(SOCKET sock, const std::string& fullText) {
    const size_t maxChunkSize = 255;
    std::istringstream stream(fullText);
    std::string line, chunk;

    while (std::getline(stream, line)) {
        if (chunk.size() + line.size() + 1 > maxChunkSize) {
            if (sendMessage(sock, chunk) == -1) return false;
            chunk.clear();
        }
        chunk += line + "\n";
    }

    if (!chunk.empty()) {
        if (sendMessage(sock, chunk) == -1) return false;
    }

    return true;
}