#include "config.h"

#include <fstream>
#include <mutex>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Helper: resolve the directory of the running plugin DLL.
// ---------------------------------------------------------------------------
static std::string GetDllDirectory(HINSTANCE dllModule)
{
    char path[MAX_PATH] = {};
    GetModuleFileNameA(dllModule, path, MAX_PATH);

    // Strip the filename, keep only the directory.
    std::string fullPath(path);
    auto lastSep = fullPath.find_last_of("\\/");
    if (lastSep != std::string::npos)
        fullPath.resize(lastSep + 1);

    return fullPath;
}

// ---------------------------------------------------------------------------
// Helper: build the config file path.
// The config file always has the fixed name "x64dbg-mcp.json" and sits next
// to the plugin DLL.  We cannot derive it from the DLL filename because the
// DLL may be named "x64dbg-mcp.dp64" or "x32dbg-mcp.dp32" (double extension),
// which would break simple "replace-last-dot" logic.
// ---------------------------------------------------------------------------
static std::string GetConfigFilePath(HINSTANCE dllModule)
{
    return GetDllDirectory(dllModule) + "x64dbg-mcp.json";
}

// ---------------------------------------------------------------------------
// LoadConfig implementation.
// ---------------------------------------------------------------------------
McpConfig LoadConfig(HINSTANCE dllModule)
{
    // Defaults used when the file is missing or contains partial data.
    McpConfig config;

    std::string configPath = GetConfigFilePath(dllModule);

    std::ifstream file(configPath);
    if (!file.is_open())
        return config;

    try
    {
        json root = json::parse(file);

        if (root.contains("host") && root["host"].is_string())
            config.host = root["host"].get<std::string>();

        if (root.contains("port") && root["port"].is_number_integer())
            config.port = root["port"].get<int>();

        if (root.contains("log_level") && root["log_level"].is_string())
            config.log_level = root["log_level"].get<std::string>();
    }
    catch (const json::parse_error&)
    {
        // Malformed JSON -- fall back to defaults.
    }
    catch (const json::type_error&)
    {
        // Wrong type for a field -- partial defaults already set.
    }

    return config;
}
