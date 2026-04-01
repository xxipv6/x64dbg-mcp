#pragma once

#include <string>
#include <unordered_map>
#include <functional>
#include <nlohmann/json.hpp>

using ToolHandler = std::function<nlohmann::json(const nlohmann::json& params)>;

// Register all MCP tools with their handlers
void RegisterTools(std::unordered_map<std::string, ToolHandler>& tools);
