#include "common.h"

using namespace tools;

// ---------------------------------------------------------------------------
// Tool: bp_list
// ---------------------------------------------------------------------------

static nlohmann::json HandleBpList(const nlohmann::json& params)
{
    try
    {
        int bpType = params.value("type", 0);
        BPMAP bplist = {};
        int count = DbgGetBpList(static_cast<BPXTYPE>(bpType), &bplist);
        nlohmann::json result;
        result["success"] = count >= 0;
        result["count"] = bplist.count;
        auto bps = nlohmann::json::array();
        for (int i = 0; i < bplist.count; ++i)
        {
            auto& bp = bplist.bp[i];
            nlohmann::json b;
            b["address"] = RegToHex(bp.addr);
            b["enabled"] = bp.enabled;
            b["active"] = bp.active;
            b["name"] = std::string(bp.name);
            b["module"] = std::string(bp.mod);
            b["hit_count"] = bp.hitCount;
            b["fast_resume"] = bp.fastResume;
            b["silent"] = bp.silent;
            if (bp.breakCondition[0]) b["break_condition"] = std::string(bp.breakCondition);
            if (bp.logText[0]) b["log_text"] = std::string(bp.logText);
            bps.push_back(b);
        }
        result["breakpoints"] = bps;
        return result;
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("bp_list: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: set_bp
// ---------------------------------------------------------------------------

static nlohmann::json HandleSetBp(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        return SimpleCmd(AddrCmd("bp", addr));
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("set_bp: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: remove_bp
// ---------------------------------------------------------------------------

static nlohmann::json HandleRemoveBp(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        return SimpleCmd(AddrCmd("bc", addr));
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("remove_bp: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: enable_bp
// ---------------------------------------------------------------------------

static nlohmann::json HandleEnableBp(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        return SimpleCmd(AddrCmd("bpe", addr));
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("enable_bp: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: disable_bp
// ---------------------------------------------------------------------------

static nlohmann::json HandleDisableBp(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        return SimpleCmd(AddrCmd("bpd", addr));
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("disable_bp: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: set_cond_bp
// ---------------------------------------------------------------------------

static nlohmann::json HandleSetCondBp(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        std::string cond = params.at("condition").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        std::ostringstream cmd;
        cmd << "bpcnd 0x" << std::hex << addr << ", \"" << cond << "\"";
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("set_cond_bp: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: set_hw_bp
// ---------------------------------------------------------------------------

static nlohmann::json HandleSetHwBp(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        std::string type = params.value("type", std::string("x")); // x=execute, w=write, r=read
        std::string size = params.value("size", std::string("1"));  // 1,2,4,8
        std::ostringstream cmd;
        cmd << "bph 0x" << std::hex << addr << ", " << type << ", " << size;
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("set_hw_bp: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: remove_hw_bp
// ---------------------------------------------------------------------------

static nlohmann::json HandleRemoveHwBp(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        return SimpleCmd(AddrCmd("bphwc", addr));
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("remove_hw_bp: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void RegisterBreakpointTools(ToolMap& tools)
{
    tools["bp_list"]         = HandleBpList;
    tools["set_bp"]          = HandleSetBp;
    tools["remove_bp"]       = HandleRemoveBp;
    tools["enable_bp"]       = HandleEnableBp;
    tools["disable_bp"]      = HandleDisableBp;
    tools["set_cond_bp"]     = HandleSetCondBp;
    tools["set_hw_bp"]       = HandleSetHwBp;
    tools["remove_hw_bp"]    = HandleRemoveHwBp;
}
