#pragma once
#include <string>
#include <windows.h>

struct McpConfig {
    std::string host = "127.0.0.1";
    int port = 8765;
    std::string log_level = "info";
};

// Load config from JSON file next to the plugin DLL.
// dllModule is the HMODULE of the plugin DLL.
// Thread-safe: safe to call from any thread after initial load.
McpConfig LoadConfig(HINSTANCE dllModule);
