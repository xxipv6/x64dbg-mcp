#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <functional>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

#include <bridgemain.h>
#include <_plugins.h>
#include <_dbgfunctions.h>

// ---------------------------------------------------------------------------
// Type alias for tool handlers
// ---------------------------------------------------------------------------

using ToolHandler = std::function<nlohmann::json(const nlohmann::json& params)>;
using ToolMap = std::unordered_map<std::string, ToolHandler>;

// ---------------------------------------------------------------------------
// Shared helpers (inline so each translation unit gets its own copy)
// ---------------------------------------------------------------------------

namespace tools {

inline duint ParseHexAddress(const std::string& addr)
{
    return static_cast<duint>(std::stoull(addr, nullptr, 0));
}

inline std::string BytesToHex(const unsigned char* data, size_t len)
{
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
    {
        if (i > 0) oss << ' ';
        oss << std::uppercase << std::setfill('0') << std::setw(2) << std::hex
            << static_cast<unsigned int>(data[i]);
    }
    return oss.str();
}

inline std::string BytesToAscii(const unsigned char* data, size_t len)
{
    std::string result;
    result.reserve(len);
    for (size_t i = 0; i < len; ++i)
    {
        unsigned char ch = data[i];
        result += (ch >= 0x20 && ch <= 0x7E) ? static_cast<char>(ch) : '.';
    }
    return result;
}

inline std::string RegToHex(ULONG_PTR val)
{
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::setfill('0') << std::hex;
#ifdef _WIN64
    oss << std::setw(16) << val;
#else
    oss << std::setw(8) << val;
#endif
    return oss.str();
}

inline std::vector<unsigned char> ParseHexBytes(const std::string& hexStr)
{
    std::vector<unsigned char> bytes;
    std::istringstream iss(hexStr);
    std::string token;
    while (iss >> token)
        bytes.push_back(static_cast<unsigned char>(std::stoul(token, nullptr, 16)));
    return bytes;
}

inline nlohmann::json ToolError(const char* tool, const std::exception& e)
{
    return {{"success", false}, {"error", std::string(tool) + ": " + e.what()}};
}

inline nlohmann::json SimpleCmd(const std::string& cmd)
{
    nlohmann::json result;
    bool ok = DbgCmdExec(cmd.c_str());
    result["success"] = ok;
    result["command"] = cmd;
    return result;
}

inline nlohmann::json StateCheckedCmd(
    const std::string& cmd,
    bool expectedDebugging,
    int timeoutMs = 1500,
    int pollIntervalMs = 50,
    bool direct = false)
{
    nlohmann::json result;
    bool ok = direct ? DbgCmdExecDirect(cmd.c_str()) : DbgCmdExec(cmd.c_str());
    result["command"] = cmd;
    result["success"] = false;
    result["timed_out"] = false;

    if (!ok)
    {
        result["error"] = "command failed";
        result["debugging"] = DbgIsDebugging();
        result["running"] = DbgIsRunning();
        return result;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    bool debugging = DbgIsDebugging();
    bool running = DbgIsRunning();
    while (std::chrono::steady_clock::now() < deadline)
    {
        debugging = DbgIsDebugging();
        running = DbgIsRunning();
        if (debugging == expectedDebugging)
        {
            result["success"] = true;
            result["debugging"] = debugging;
            result["running"] = running;
            return result;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs));
    }

    debugging = DbgIsDebugging();
    running = DbgIsRunning();
    result["debugging"] = debugging;
    result["running"] = running;
    result["timed_out"] = true;
    return result;
}

inline std::string AddrCmd(const char* prefix, duint addr)
{
    std::ostringstream oss;
    oss << prefix << " 0x" << std::hex << addr;
    return oss.str();
}

} // namespace tools
