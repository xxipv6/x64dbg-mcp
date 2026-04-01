#include "common.h"

using namespace tools;

// ---------------------------------------------------------------------------
// Tool: get_label
// ---------------------------------------------------------------------------

static nlohmann::json HandleGetLabel(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        char text[MAX_LABEL_SIZE] = {};
        bool ok = DbgGetLabelAt(addr, SEG_DEFAULT, text);
        nlohmann::json r = {{"success", ok}, {"address", addrStr}};
        if (ok) r["label"] = std::string(text);
        return r;
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("get_label: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: set_label
// ---------------------------------------------------------------------------

static nlohmann::json HandleSetLabel(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        std::string text = params.at("text").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        std::ostringstream cmd;
        cmd << "SetLabel 0x" << std::hex << addr << ", \"" << text << "\"";
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("set_label: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: get_comment
// ---------------------------------------------------------------------------

static nlohmann::json HandleGetComment(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        char text[MAX_COMMENT_SIZE] = {};
        bool ok = DbgGetCommentAt(addr, text);
        nlohmann::json r = {{"success", ok}, {"address", addrStr}};
        if (ok) r["comment"] = std::string(text);
        return r;
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("get_comment: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: set_comment
// ---------------------------------------------------------------------------

static nlohmann::json HandleSetComment(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        std::string text = params.at("text").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        std::ostringstream cmd;
        cmd << "SetComment 0x" << std::hex << addr << ", \"" << text << "\"";
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("set_comment: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: stack_comment
// ---------------------------------------------------------------------------

static nlohmann::json HandleStackComment(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        STACK_COMMENT comment = {};
        bool ok = DbgStackCommentGet(addr, &comment);
        nlohmann::json r = {{"success", ok}, {"address", addrStr}};
        if (ok) { r["color"] = std::string(comment.color); r["comment"] = std::string(comment.comment); }
        return r;
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("stack_comment: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: ref_find
// ---------------------------------------------------------------------------

static nlohmann::json HandleRefFind(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        std::string pattern = params.at("pattern").get<std::string>();
        std::ostringstream cmd;
        cmd << "reffind 0x" << std::hex << addr << ", \"" << pattern << "\"";
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("ref_find: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void RegisterAnalysisTools(ToolMap& tools)
{
    tools["get_label"]       = HandleGetLabel;
    tools["set_label"]       = HandleSetLabel;
    tools["get_comment"]     = HandleGetComment;
    tools["set_comment"]     = HandleSetComment;
    tools["stack_comment"]   = HandleStackComment;
    tools["ref_find"]        = HandleRefFind;
}
