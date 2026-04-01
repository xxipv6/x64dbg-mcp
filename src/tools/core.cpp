#include "common.h"

using namespace tools;

// ---------------------------------------------------------------------------
// Tool: cmd_exec
// ---------------------------------------------------------------------------

static nlohmann::json HandleCmdExec(const nlohmann::json& params)
{
    try
    {
        std::string command = params.at("command").get<std::string>();
        return SimpleCmd(command);
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("cmd_exec: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: eval
// ---------------------------------------------------------------------------

static nlohmann::json HandleEval(const nlohmann::json& params)
{
    try
    {
        std::string expr = params.at("expression").get<std::string>();
        duint val = DbgValFromString(expr.c_str());
        return {{"success", true}, {"expression", expr}, {"value", RegToHex(val)}, {"decimal", std::to_string(val)}};
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("eval: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: is_debugging
// ---------------------------------------------------------------------------

static nlohmann::json HandleIsDebugging(const nlohmann::json&)
{
    return {{"success", true}, {"debugging", DbgIsDebugging()}, {"running", DbgIsRunning()}};
}

// ---------------------------------------------------------------------------
// Tool: get_registers
// ---------------------------------------------------------------------------

static nlohmann::json HandleGetRegisters(const nlohmann::json&)
{
    nlohmann::json result;
    REGDUMP_AVX512 regdump = {};
    if (!DbgGetRegDumpEx(&regdump, sizeof(regdump)))
        return {{"success", false}, {"error", "DbgGetRegDumpEx failed"}};

    const REGISTERCONTEXT_AVX512& ctx = regdump.regcontext;
    result["success"] = true;
    result["rax"] = RegToHex(ctx.cax);
    result["rcx"] = RegToHex(ctx.ccx);
    result["rdx"] = RegToHex(ctx.cdx);
    result["rbx"] = RegToHex(ctx.cbx);
    result["rsp"] = RegToHex(ctx.csp);
    result["rbp"] = RegToHex(ctx.cbp);
    result["rsi"] = RegToHex(ctx.csi);
    result["rdi"] = RegToHex(ctx.cdi);
#ifdef _WIN64
    result["r8"]  = RegToHex(ctx.r8);
    result["r9"]  = RegToHex(ctx.r9);
    result["r10"] = RegToHex(ctx.r10);
    result["r11"] = RegToHex(ctx.r11);
    result["r12"] = RegToHex(ctx.r12);
    result["r13"] = RegToHex(ctx.r13);
    result["r14"] = RegToHex(ctx.r14);
    result["r15"] = RegToHex(ctx.r15);
#endif
    result["rip"]    = RegToHex(ctx.cip);
    result["rflags"] = RegToHex(ctx.eflags);
    result["dr0"] = RegToHex(ctx.dr0);
    result["dr1"] = RegToHex(ctx.dr1);
    result["dr2"] = RegToHex(ctx.dr2);
    result["dr3"] = RegToHex(ctx.dr3);
    result["dr6"] = RegToHex(ctx.dr6);
    result["dr7"] = RegToHex(ctx.dr7);
    result["gs"] = RegToHex(ctx.gs);
    result["fs"] = RegToHex(ctx.fs);
    result["es"] = RegToHex(ctx.es);
    result["ds"] = RegToHex(ctx.ds);
    result["cs"] = RegToHex(ctx.cs);
    result["ss"] = RegToHex(ctx.ss);
    return result;
}

// ---------------------------------------------------------------------------
// Tool: set_register
// ---------------------------------------------------------------------------

static nlohmann::json HandleSetRegister(const nlohmann::json& params)
{
    try
    {
        std::string reg = params.at("register").get<std::string>();
        std::string val = params.at("value").get<std::string>();
        std::string cmd = reg + "=" + val;
        return SimpleCmd(cmd);
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("set_register: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: disasm
// ---------------------------------------------------------------------------

static nlohmann::json HandleDisasm(const nlohmann::json& params)
{
    nlohmann::json result;
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        BASIC_INSTRUCTION_INFO info = {};
        DbgDisasmFastAt(addr, &info);
        result["success"] = true;
        result["address"] = addrStr;
        result["instruction"] = std::string(info.instruction);
        result["size"] = info.size;
        result["branch"] = info.branch;
        result["call"] = info.call;
        result["type"] = info.type;
    }
    catch (const std::exception& e)
    {
        result["success"] = false;
        result["error"] = std::string("disasm: ") + e.what();
    }
    return result;
}

// ---------------------------------------------------------------------------
// Tool: mod_base
// ---------------------------------------------------------------------------

static nlohmann::json HandleModBase(const nlohmann::json& params)
{
    try
    {
        std::string name = params.at("module").get<std::string>();
        duint base = DbgModBaseFromName(name.c_str());
        return {{"success", base != 0}, {"module", name}, {"base", RegToHex(base)}};
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("mod_base: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: symbol_enum
// ---------------------------------------------------------------------------

struct SymbolEnumCtx { nlohmann::json symbols = nlohmann::json::array(); };

static bool SymbolEnumCb(const SYMBOLPTR_* symbol, void* user)
{
    auto* ctx = static_cast<SymbolEnumCtx*>(user);
    SYMBOLINFO info = {};
    DbgGetSymbolInfo(symbol, &info);
    nlohmann::json s;
    s["address"] = RegToHex(info.addr);
    if (info.decoratedSymbol) s["decorated"] = std::string(info.decoratedSymbol);
    if (info.undecoratedSymbol) s["undecorated"] = std::string(info.undecoratedSymbol);
    s["type"] = info.type;
    s["ordinal"] = info.ordinal;
    ctx->symbols.push_back(s);
    if (info.freeDecorated && info.decoratedSymbol) BridgeFree(info.decoratedSymbol);
    if (info.freeUndecorated && info.undecoratedSymbol) BridgeFree(info.undecoratedSymbol);
    return true;
}

static nlohmann::json HandleSymbolEnum(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint base = ParseHexAddress(addrStr);
        SymbolEnumCtx ctx;
        bool ok = DbgSymbolEnum(base, SymbolEnumCb, &ctx);
        return {{"success", ok}, {"address", addrStr}, {"count", ctx.symbols.size()}, {"symbols", ctx.symbols}};
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("symbol_enum: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void RegisterCoreTools(ToolMap& tools)
{
    tools["cmd_exec"]        = HandleCmdExec;
    tools["eval"]            = HandleEval;
    tools["is_debugging"]    = HandleIsDebugging;
    tools["get_registers"]   = HandleGetRegisters;
    tools["set_register"]    = HandleSetRegister;
    tools["disasm"]          = HandleDisasm;
    tools["mod_base"]        = HandleModBase;
    tools["symbol_enum"]     = HandleSymbolEnum;
}
