#include <iostream>
#include "Server.h"
#include <csignal>
static Server* serverInstance = nullptr;

void signalHandler(int signum) {
    if (serverInstance) {
        std::cout << "\nSignal " << signum << " received. Shutting down server...\n";
        serverInstance->stop();
    }
    exit(signum);
}

int main() {
    serverInstance = new Server();
    std::signal(SIGINT, signalHandler); // Handle Ctrl+C

    uint16_t port;
    size_t capacity;
    char commandChar = '/';

    std::cout << "Enter TCP Port number: ";
    std::cin >> port;
    std::cout << "Enter chat capacity: ";
    std::cin >> capacity;
    std::cout << "Enter command character (press Enter for default '/'): ";
    std::cin.ignore(); // Ignore newline from previous input
    std::string userInput;
    std::getline(std::cin, userInput);
    if (!userInput.empty()) {
        commandChar = userInput[0];
    }

    Server server;
    if (server.init(port, capacity, commandChar) == 0) {
        server.run();
    }
    else {
        std::cerr << "Failed to start the server.\n";
    }

    return 0;
}
