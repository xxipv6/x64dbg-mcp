#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <nlohmann/json.hpp>

namespace httplib {
class Server;
}

struct McpConfig;

class McpServer {
public:
    McpServer();
    ~McpServer();

    bool Start(const McpConfig& config);
    void Stop();

private:
    void ServerThread(McpConfig config);
    std::string HandleJsonRpc(const std::string& body);

    std::atomic<bool> running_{false};
    std::thread thread_;
    httplib::Server* server_ = nullptr;
};
