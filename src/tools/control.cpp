#include "common.h"

using namespace tools;

// ---------------------------------------------------------------------------
// Tool: step_over
// ---------------------------------------------------------------------------

static nlohmann::json HandleStepOver(const nlohmann::json&)  { return SimpleCmd("StepOver"); }

// ---------------------------------------------------------------------------
// Tool: step_into
// ---------------------------------------------------------------------------

static nlohmann::json HandleStepInto(const nlohmann::json&)  { return SimpleCmd("StepInto"); }

// ---------------------------------------------------------------------------
// Tool: step_out
// ---------------------------------------------------------------------------

static nlohmann::json HandleStepOut(const nlohmann::json&)   { return SimpleCmd("StepOut"); }

// ---------------------------------------------------------------------------
// Tool: continue
// ---------------------------------------------------------------------------

static nlohmann::json HandleContinue(const nlohmann::json&)  { return SimpleCmd("run"); }

// ---------------------------------------------------------------------------
// Tool: pause
// ---------------------------------------------------------------------------

static nlohmann::json HandlePause(const nlohmann::json&)     { return SimpleCmd("pause"); }

// ---------------------------------------------------------------------------
// Tool: stop
// ---------------------------------------------------------------------------

static nlohmann::json HandleStop(const nlohmann::json&)      { return SimpleCmd("StopDebug"); }

// ---------------------------------------------------------------------------
// Tool: run_to
// ---------------------------------------------------------------------------

static nlohmann::json HandleRunTo(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        return SimpleCmd(AddrCmd("rto", addr));
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("run_to: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void RegisterControlTools(ToolMap& tools)
{
    tools["step_over"]       = HandleStepOver;
    tools["step_into"]       = HandleStepInto;
    tools["step_out"]        = HandleStepOut;
    tools["continue"]        = HandleContinue;
    tools["pause"]           = HandlePause;
    tools["stop"]            = HandleStop;
    tools["run_to"]          = HandleRunTo;
}
