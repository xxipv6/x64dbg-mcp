#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <functional>
#include <nlohmann/json.hpp>

struct McpConfig;

using ToolHandler = std::function<nlohmann::json(const nlohmann::json& params)>;

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

    // Pointer to httplib::Server inside ServerThread, for shutdown signaling.
    void* server_ = nullptr;
};
