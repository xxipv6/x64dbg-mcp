#pragma once

#include "tools/common.h"

struct ToolDefinition {
    const char* name;
    const char* description;
    nlohmann::json input_schema;
};

// Register all MCP tools with their handlers.
// Defined in src/tools/register.cpp.
void RegisterTools(ToolMap& tools);

// Return all advertised MCP tool definitions.
const std::vector<ToolDefinition>& GetToolDefinitions();
