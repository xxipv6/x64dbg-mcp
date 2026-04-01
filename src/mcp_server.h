#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <functional>
#include <nlohmann/json.hpp>

struct McpConfig;

// ToolHandler is defined in tools/common.h (included via tool_dispatcher.h).
// If tools/common.h has already been included, ToolHandler is already available.
// Otherwise, provide a matching forward definition.
#ifndef TOOLS_COMMON_H
using ToolHandler = std::function<nlohmann::json(const nlohmann::json& params)>;
#endif

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
