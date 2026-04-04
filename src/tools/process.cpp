#include "common.h"

using namespace tools;

// ---------------------------------------------------------------------------
// Tool: attach
// ---------------------------------------------------------------------------

static nlohmann::json HandleAttach(const nlohmann::json& params)
{
    try
    {
        DWORD pid = params.at("pid").get<DWORD>();
        std::ostringstream cmd;
        cmd << "attach " << pid;
        return StateCheckedCmd(cmd.str(), true, 2000, 50, false);
    }
    catch (const std::exception& e) { return ToolError("attach", e); }
}

// ---------------------------------------------------------------------------
// Tool: detach
// ---------------------------------------------------------------------------

static nlohmann::json HandleDetach(const nlohmann::json&) { return StateCheckedCmd("detach", false); }

// ---------------------------------------------------------------------------
// Tool: inject_dll
// ---------------------------------------------------------------------------

static nlohmann::json HandleInjectDll(const nlohmann::json& params)
{
    try
    {
        std::string path = params.at("path").get<std::string>();
        std::ostringstream cmd;
        cmd << "dllinject \"" << path << "\"";
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return ToolError("inject_dll", e); }
}

// ---------------------------------------------------------------------------
// Tool: eject_dll
// ---------------------------------------------------------------------------

static nlohmann::json HandleEjectDll(const nlohmann::json& params)
{
    try
    {
        std::string path = params.at("path").get<std::string>();
        std::ostringstream cmd;
        cmd << "dlleject \"" << path << "\"";
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return ToolError("eject_dll", e); }
}

// ---------------------------------------------------------------------------
// Tool: apply_patch
// ---------------------------------------------------------------------------

static nlohmann::json HandleApplyPatch(const nlohmann::json& params)
{
    try
    {
        auto* dbgFuncs = DbgFunctions();
        if (!dbgFuncs || !dbgFuncs->MemPatch)
            return {{"success", false}, {"error", "MemPatch not available"}};

        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        std::string hexData = params.at("data").get<std::string>();
        std::vector<unsigned char> bytes = ParseHexBytes(hexData);
        if (bytes.empty())
            return {{"success", false}, {"error", "No valid hex bytes"}};

        std::vector<unsigned char> orig(bytes.size(), 0);
        std::vector<unsigned char> patched(bytes.size(), 0);
        if (!DbgMemRead(addr, orig.data(), static_cast<duint>(orig.size())))
            return {{"success", false}, {"error", "Failed to read original bytes"}};

        if (!dbgFuncs->MemPatch(addr, bytes.data(), static_cast<duint>(bytes.size())))
            return {{"success", false}, {"error", "MemPatch failed"}};

        if (!DbgMemRead(addr, patched.data(), static_cast<duint>(patched.size())))
            return {{"success", false}, {"error", "Failed to verify patched bytes"}};

        bool changed = patched == bytes;
        return {
            {"success", changed},
            {"address", RegToHex(addr)},
            {"requested", BytesToHex(bytes.data(), bytes.size())},
            {"original", BytesToHex(orig.data(), orig.size())},
            {"current", BytesToHex(patched.data(), patched.size())}
        };
    }
    catch (const std::exception& e) { return ToolError("apply_patch", e); }
}

// ---------------------------------------------------------------------------
// Tool: get_patches
// ---------------------------------------------------------------------------

static nlohmann::json HandleGetPatches(const nlohmann::json&)
{
    auto* dbgFuncs = DbgFunctions();
    if (!dbgFuncs || !dbgFuncs->PatchEnum)
        return {{"success", false}, {"error", "PatchEnum not available"}};

    // Enumerate patches via DBGFUNCTIONS
    size_t cbsize = 0;
    if (!dbgFuncs->PatchEnum(nullptr, &cbsize))
        return {{"success", false}, {"error", "PatchEnum size query failed"}};

    std::vector<DBGPATCHINFO> patches;
    size_t count = cbsize / sizeof(DBGPATCHINFO);
    if (count > 0)
    {
        patches.resize(count);
        if (!dbgFuncs->PatchEnum(patches.data(), nullptr))
            return {{"success", false}, {"error", "PatchEnum read failed"}};
    }

    nlohmann::json result;
    result["success"] = true;
    result["count"] = count;
    auto arr = nlohmann::json::array();
    for (int i = 0; i < count; ++i)
    {
        arr.push_back({
            {"module", std::string(patches[i].mod)},
            {"address", RegToHex(patches[i].addr)},
            {"old_byte", patches[i].oldbyte},
            {"new_byte", patches[i].newbyte}
        });
    }
    result["patches"] = arr;
    return result;
}

// ---------------------------------------------------------------------------
// Tool: set_exception
// ---------------------------------------------------------------------------

static nlohmann::json HandleSetException(const nlohmann::json& params)
{
    try
    {
        std::string code = params.at("code").get<std::string>();
        std::string action = params.at("action").get<std::string>(); // "ignore", "break", "log"
        std::ostringstream cmd;
        cmd << "SetExceptionBreakpoint " << code << ", " << action;
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return ToolError("set_exception", e); }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void RegisterProcessTools(ToolMap& tools)
{
    tools["attach"]          = HandleAttach;
    tools["detach"]          = HandleDetach;
    tools["inject_dll"]      = HandleInjectDll;
    tools["eject_dll"]       = HandleEjectDll;
    tools["apply_patch"]     = HandleApplyPatch;
    tools["get_patches"]     = HandleGetPatches;
    tools["set_exception"]   = HandleSetException;
}
