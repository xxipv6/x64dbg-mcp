#include "common.h"

using namespace tools;

// ---------------------------------------------------------------------------
// Tool: get_threads
// ---------------------------------------------------------------------------

static nlohmann::json HandleGetThreads(const nlohmann::json&)
{
    THREADLIST tlist = {};
    DbgGetThreadList(&tlist);
    nlohmann::json result;
    result["success"] = true;
    result["count"] = tlist.count;
    result["current_thread"] = tlist.CurrentThread;
    auto threads = nlohmann::json::array();
    for (int i = 0; i < tlist.count; ++i)
    {
        auto& t = tlist.list[i];
        nlohmann::json th;
        th["number"] = t.BasicInfo.ThreadNumber;
        th["tid"] = t.BasicInfo.ThreadId;
        th["rip"] = RegToHex(t.ThreadCip);
        th["start_address"] = RegToHex(t.BasicInfo.ThreadStartAddress);
        th["local_base"] = RegToHex(t.BasicInfo.ThreadLocalBase);
        th["name"] = std::string(t.BasicInfo.threadName);
        th["suspend_count"] = t.SuspendCount;
        th["priority"] = t.Priority;
        th["last_error"] = t.LastError;
        threads.push_back(th);
    }
    result["threads"] = threads;
    return result;
}

// ---------------------------------------------------------------------------
// Tool: get_call_stack
// ---------------------------------------------------------------------------

static nlohmann::json HandleGetCallStack(const nlohmann::json&)
{
    auto* dbgFuncs = DbgFunctions();
    if (!dbgFuncs || !dbgFuncs->GetCallStack)
        return {{"success", false}, {"error", "GetCallStack not available"}};

    DBGCALLSTACK cs = {};
    dbgFuncs->GetCallStack(&cs);

    nlohmann::json result;
    result["success"] = true;
    result["total"] = cs.total;
    auto entries = nlohmann::json::array();
    for (int i = 0; i < cs.total; ++i)
    {
        auto& e = cs.entries[i];
        entries.push_back({
            {"address", RegToHex(e.addr)},
            {"from", RegToHex(e.from)},
            {"to", RegToHex(e.to)},
            {"comment", std::string(e.comment)}
        });
    }
    result["entries"] = entries;
    return result;
}

// ---------------------------------------------------------------------------
// Tool: switch_thread
// ---------------------------------------------------------------------------

static nlohmann::json HandleSwitchThread(const nlohmann::json& params)
{
    try
    {
        DWORD tid = params.at("tid").get<DWORD>();
        std::ostringstream cmd;
        cmd << "switchthread " << tid;
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("switch_thread: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: suspend_thread
// ---------------------------------------------------------------------------

static nlohmann::json HandleSuspendThread(const nlohmann::json& params)
{
    try
    {
        DWORD tid = params.at("tid").get<DWORD>();
        std::ostringstream cmd;
        cmd << "suspendthread " << tid;
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("suspend_thread: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: resume_thread
// ---------------------------------------------------------------------------

static nlohmann::json HandleResumeThread(const nlohmann::json& params)
{
    try
    {
        DWORD tid = params.at("tid").get<DWORD>();
        std::ostringstream cmd;
        cmd << "resumethread " << tid;
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("resume_thread: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void RegisterThreadTools(ToolMap& tools)
{
    tools["get_threads"]     = HandleGetThreads;
    tools["get_call_stack"]  = HandleGetCallStack;
    tools["switch_thread"]   = HandleSwitchThread;
    tools["suspend_thread"]  = HandleSuspendThread;
    tools["resume_thread"]   = HandleResumeThread;
}
