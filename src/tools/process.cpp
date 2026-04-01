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
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("attach: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: detach
// ---------------------------------------------------------------------------

static nlohmann::json HandleDetach(const nlohmann::json&) { return SimpleCmd("detach"); }

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
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("inject_dll: ") + e.what()}}; }
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
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("eject_dll: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: apply_patch
// ---------------------------------------------------------------------------

static nlohmann::json HandleApplyPatch(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        std::string hexData = params.at("data").get<std::string>();
        std::ostringstream cmd;
        cmd << "Fill 0x" << std::hex << addr << ", 0x" << ParseHexBytes(hexData).size() << ", \"" << hexData << "\"";
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("apply_patch: ") + e.what()}}; }
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
    std::vector<DBGPATCHINFO> patches;
    size_t count = 0;
    // PatchEnum returns count when patches=nullptr
    dbgFuncs->PatchEnum(nullptr, &count);
    if (count > 0)
    {
        patches.resize(count);
        dbgFuncs->PatchEnum(patches.data(), &count);
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
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("set_exception: ") + e.what()}}; }
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
