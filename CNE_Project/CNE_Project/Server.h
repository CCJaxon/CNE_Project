#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <chrono>

// Link Winsock library
#pragma comment(lib, "Ws2_32.lib")

// Error Codes
#define ERR_WSASTARTUP -1
#define ERR_SOCKET_CREATION -2
#define ERR_BIND -3
#define ERR_LISTEN -4
#define ERR_GETADDRINFO -5
#define ERR_MESSAGE_TOO_LONG -6
#define ERR_SEND_FAILURE -7
#define ERR_RECV_FAILURE -8
#define ERR_CONNECTION_CLOSED -9
#define ERR_INVALID_MESSAGE_LENGTH -10
#define SUCCESS 0

class Server {
public:
    Server();
    ~Server();
    int init(uint16_t port, size_t capacity, char commandChar);
    void run();
    void stop();

private:
    SOCKET listeningSocket;
    fd_set masterSet;
    SOCKET maxFd;
    size_t chatCapacity;
    char commandChar;

    std::map<SOCKET, std::string> clients;
    std::map<SOCKET, std::string> loggedInUsers;
    std::unordered_map<std::string, std::string> users;
    std::unordered_map<std::string, bool> userStatus; // Tracks active (true) or inactive (false) status

    int sendMessage(SOCKET clientSocket, const std::string& message);
    int readMessage(SOCKET clientSocket, std::string& message);

    void handleGetListCommand(SOCKET clientSocket);
    void handleLogoutCommand(SOCKET clientSocket);
    void handleGetLogCommand(SOCKET clientSocket);
    void handleClientMessage(SOCKET sock, const std::string& message);

    bool sendChunkedMessage(SOCKET sock, const std::string& fullText);

    void displayServerInfo(const std::string& hostname, addrinfo* result, uint16_t port);

    std::atomic<bool> isBroadcasting;
    std::thread broadcastThread;

    void startBroadcast(uint16_t port);
    void stopBroadcast();
};