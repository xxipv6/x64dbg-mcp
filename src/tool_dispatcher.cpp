#include "tool_dispatcher.h"

#include <bridgemain.h>
#include <_plugins.h>
#include <_dbgfunctions.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static duint ParseHexAddress(const std::string& addr)
{
    return static_cast<duint>(std::stoull(addr, nullptr, 0));
}

static std::string BytesToHex(const unsigned char* data, size_t len)
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

static std::string BytesToAscii(const unsigned char* data, size_t len)
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

static std::string RegToHex(ULONG_PTR val)
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

static std::vector<unsigned char> ParseHexBytes(const std::string& hexStr)
{
    std::vector<unsigned char> bytes;
    std::istringstream iss(hexStr);
    std::string token;
    while (iss >> token)
        bytes.push_back(static_cast<unsigned char>(std::stoul(token, nullptr, 16)));
    return bytes;
}

// Helper: execute an x64dbg command and return status
static nlohmann::json SimpleCmd(const std::string& cmd)
{
    nlohmann::json result;
    bool ok = DbgCmdExec(cmd.c_str());
    result["success"] = ok;
    result["command"] = cmd;
    return result;
}

// Helper: build a command with a hex address argument
static std::string AddrCmd(const char* prefix, duint addr)
{
    std::ostringstream oss;
    oss << prefix << " 0x" << std::hex << addr;
    return oss.str();
}

// ---------------------------------------------------------------------------
// Tool: cmd_exec — execute raw x64dbg command
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
// Tool: mem_read
// ---------------------------------------------------------------------------

static nlohmann::json HandleMemRead(const nlohmann::json& params)
{
    nlohmann::json result;
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        size_t size = params.at("size").get<size_t>();
        duint addr = ParseHexAddress(addrStr);
        std::vector<unsigned char> buffer(size, 0);
        bool ok = DbgMemRead(addr, buffer.data(), static_cast<duint>(size));
        result["success"] = ok;
        result["address"] = addrStr;
        result["size"] = size;
        if (ok)
        {
            result["data"] = BytesToHex(buffer.data(), size);
            result["ascii"] = BytesToAscii(buffer.data(), size);
        }
    }
    catch (const std::exception& e)
    {
        result["success"] = false;
        result["error"] = std::string("mem_read: ") + e.what();
    }
    return result;
}

// ---------------------------------------------------------------------------
// Tool: mem_write
// ---------------------------------------------------------------------------

static nlohmann::json HandleMemWrite(const nlohmann::json& params)
{
    nlohmann::json result;
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        std::string hexData = params.at("data").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        std::vector<unsigned char> bytes = ParseHexBytes(hexData);
        if (bytes.empty())
            return {{"success", false}, {"error", "No valid hex bytes"}};
        bool ok = DbgMemWrite(addr, bytes.data(), static_cast<duint>(bytes.size()));
        result["success"] = ok;
        result["address"] = addrStr;
        result["bytes_written"] = bytes.size();
    }
    catch (const std::exception& e)
    {
        result["success"] = false;
        result["error"] = std::string("mem_write: ") + e.what();
    }
    return result;
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
// Tool: mem_map
// ---------------------------------------------------------------------------

static nlohmann::json HandleMemMap(const nlohmann::json&)
{
    MEMMAP memmap = {};
    bool ok = DbgMemMap(&memmap);
    nlohmann::json result;
    result["success"] = ok;
    if (ok)
    {
        result["count"] = memmap.count;
        auto regions = nlohmann::json::array();
        for (int i = 0; i < memmap.count; ++i)
        {
            auto& p = memmap.page[i];
            regions.push_back({
                {"base", RegToHex((ULONG_PTR)p.mbi.BaseAddress)},
                {"allocation_base", RegToHex((ULONG_PTR)p.mbi.AllocationBase)},
                {"size", RegToHex(p.mbi.RegionSize)},
                {"state", p.mbi.State},
                {"protect", p.mbi.Protect},
                {"type", p.mbi.Type},
                {"info", std::string(p.info)}
            });
        }
        result["regions"] = regions;
    }
    return result;
}

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
// Tool: get_label / get_comment / stack_comment
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
// Tool: mem_find (byte pattern search)
// ---------------------------------------------------------------------------

static nlohmann::json HandleMemFind(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint startAddr = ParseHexAddress(addrStr);
        std::string pattern = params.at("pattern").get<std::string>();
        size_t maxResults = params.value("max_results", 100);
        size_t searchSize = params.value("size", 0x10000);

        struct PB { unsigned char value; bool wildcard; };
        std::vector<PB> pbs;
        std::istringstream iss(pattern);
        std::string tok;
        while (iss >> tok)
        {
            PB pb;
            if (tok == "??" || tok == "?") { pb.wildcard = true; pb.value = 0; }
            else { pb.wildcard = false; pb.value = static_cast<unsigned char>(std::stoul(tok, nullptr, 16)); }
            pbs.push_back(pb);
        }
        if (pbs.empty())
            return {{"success", false}, {"error", "Empty pattern"}};

        const size_t chunk = 0x1000;
        std::vector<unsigned char> buf(chunk);
        auto matches = nlohmann::json::array();
        size_t found = 0;

        for (size_t off = 0; off < searchSize && found < maxResults; off += chunk)
        {
            duint raddr = startAddr + off;
            size_t toRead = std::min(chunk, searchSize - off);
            if (!DbgMemRead(raddr, buf.data(), static_cast<duint>(toRead))) continue;
            for (size_t i = 0; i + pbs.size() <= toRead && found < maxResults; ++i)
            {
                bool match = true;
                for (size_t j = 0; j < pbs.size() && match; ++j)
                    if (!pbs[j].wildcard && buf[i + j] != pbs[j].value) match = false;
                if (match) { matches.push_back(RegToHex(raddr + i)); ++found; i += pbs.size() - 1; }
            }
        }
        return {{"success", true}, {"address", addrStr}, {"pattern", pattern},
                {"search_size", searchSize}, {"found", found}, {"matches", matches}};
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("mem_find: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: str_search (string search)
// ---------------------------------------------------------------------------

static nlohmann::json HandleStrSearch(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint startAddr = ParseHexAddress(addrStr);
        std::string searchString = params.at("string").get<std::string>();
        bool wide = params.value("wide", false);
        size_t maxResults = params.value("max_results", 50);
        size_t searchSize = params.value("size", 0x100000);

        std::vector<unsigned char> pat;
        for (unsigned char c : searchString) { pat.push_back(c); if (wide) pat.push_back(0); }

        const size_t chunk = 0x1000;
        std::vector<unsigned char> buf(chunk);
        auto matches = nlohmann::json::array();
        size_t found = 0;

        for (size_t off = 0; off < searchSize && found < maxResults; off += chunk)
        {
            duint raddr = startAddr + off;
            size_t toRead = std::min(chunk, searchSize - off);
            if (!DbgMemRead(raddr, buf.data(), static_cast<duint>(toRead))) continue;
            for (size_t i = 0; i + pat.size() <= toRead && found < maxResults; ++i)
            {
                if (std::memcmp(buf.data() + i, pat.data(), pat.size()) == 0)
                {
                    size_t ctxStart = (i >= 16) ? i - 16 : 0;
                    size_t ctxEnd = std::min(i + pat.size() + 48, toRead);
                    nlohmann::json m;
                    m["address"] = RegToHex(raddr + i);
                    m["context_ascii"] = BytesToAscii(buf.data() + ctxStart, ctxEnd - ctxStart);
                    m["context_hex"] = BytesToHex(buf.data() + ctxStart, ctxEnd - ctxStart);
                    matches.push_back(m);
                    ++found; i += pat.size() - 1;
                }
            }
        }
        return {{"success", true}, {"address", addrStr}, {"string", searchString},
                {"wide", wide}, {"search_size", searchSize}, {"found", found}, {"matches", matches}};
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("str_search: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Control flow tools (via cmd_exec)
// ---------------------------------------------------------------------------

static nlohmann::json HandleStepOver(const nlohmann::json&)  { return SimpleCmd("StepOver"); }
static nlohmann::json HandleStepInto(const nlohmann::json&)  { return SimpleCmd("StepInto"); }
static nlohmann::json HandleStepOut(const nlohmann::json&)   { return SimpleCmd("StepOut"); }
static nlohmann::json HandleContinue(const nlohmann::json&)  { return SimpleCmd("run"); }
static nlohmann::json HandlePause(const nlohmann::json&)     { return SimpleCmd("pause"); }
static nlohmann::json HandleStop(const nlohmann::json&)      { return SimpleCmd("StopDebug"); }

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
// Breakpoint tools (via cmd_exec)
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
// Thread tools (via cmd_exec)
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
// Memory alloc/free (via cmd_exec)
// ---------------------------------------------------------------------------

static nlohmann::json HandleAllocMem(const nlohmann::json& params)
{
    try
    {
        size_t size = params.at("size").get<size_t>();
        std::ostringstream cmd;
        cmd << "alloc 0x" << std::hex << size;
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("alloc_mem: ") + e.what()}}; }
}

static nlohmann::json HandleFreeMem(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        return SimpleCmd(AddrCmd("free", addr));
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("free_mem: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Process tools (via cmd_exec)
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

static nlohmann::json HandleDetach(const nlohmann::json&) { return SimpleCmd("detach"); }

// ---------------------------------------------------------------------------
// Set label / comment (via cmd_exec)
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
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("set_label: ") + e.what()}}; }
}

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
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("set_comment: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// DLL injection (via cmd_exec)
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
// Set memory protection (via cmd_exec)
// ---------------------------------------------------------------------------

static nlohmann::json HandleSetMemProtect(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        size_t size = params.at("size").get<size_t>();
        std::string prot = params.at("protection").get<std::string>(); // e.g. "rwx"
        std::ostringstream cmd;
        cmd << "SetMemoryProtection 0x" << std::hex << addr << ", 0x" << size << ", \"" << prot << "\"";
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("set_mem_protect: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Save dump to file (via cmd_exec)
// ---------------------------------------------------------------------------

static nlohmann::json HandleDumpMem(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        size_t size = params.at("size").get<size_t>();
        std::string path = params.at("path").get<std::string>();
        std::ostringstream cmd;
        cmd << "savedata \"" << path << "\", 0x" << std::hex << addr << ", 0x" << size;
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("dump_mem: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Search references (via cmd_exec)
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
// Patch management (via cmd_exec)
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
// Exception handling (via cmd_exec)
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

void RegisterTools(std::unordered_map<std::string, ToolHandler>& tools)
{
    // Core
    tools["cmd_exec"]        = HandleCmdExec;
    tools["mem_read"]        = HandleMemRead;
    tools["mem_write"]       = HandleMemWrite;
    tools["get_registers"]   = HandleGetRegisters;
    tools["set_register"]    = HandleSetRegister;
    tools["disasm"]          = HandleDisasm;
    tools["eval"]            = HandleEval;
    tools["is_debugging"]    = HandleIsDebugging;

    // Modules & Symbols
    tools["mod_base"]        = HandleModBase;
    tools["symbol_enum"]     = HandleSymbolEnum;

    // Memory
    tools["mem_map"]         = HandleMemMap;
    tools["mem_find"]        = HandleMemFind;
    tools["str_search"]      = HandleStrSearch;
    tools["alloc_mem"]       = HandleAllocMem;
    tools["free_mem"]        = HandleFreeMem;
    tools["set_mem_protect"] = HandleSetMemProtect;
    tools["dump_mem"]        = HandleDumpMem;

    // Breakpoints
    tools["bp_list"]         = HandleBpList;
    tools["set_bp"]          = HandleSetBp;
    tools["remove_bp"]       = HandleRemoveBp;
    tools["enable_bp"]       = HandleEnableBp;
    tools["disable_bp"]      = HandleDisableBp;
    tools["set_cond_bp"]     = HandleSetCondBp;
    tools["set_hw_bp"]       = HandleSetHwBp;
    tools["remove_hw_bp"]    = HandleRemoveHwBp;

    // Control flow
    tools["step_over"]       = HandleStepOver;
    tools["step_into"]       = HandleStepInto;
    tools["step_out"]        = HandleStepOut;
    tools["continue"]        = HandleContinue;
    tools["pause"]           = HandlePause;
    tools["stop"]            = HandleStop;
    tools["run_to"]          = HandleRunTo;

    // Threads
    tools["get_threads"]     = HandleGetThreads;
    tools["get_call_stack"]  = HandleGetCallStack;
    tools["switch_thread"]   = HandleSwitchThread;
    tools["suspend_thread"]  = HandleSuspendThread;
    tools["resume_thread"]   = HandleResumeThread;

    // Labels & Comments
    tools["get_label"]       = HandleGetLabel;
    tools["set_label"]       = HandleSetLabel;
    tools["get_comment"]     = HandleGetComment;
    tools["set_comment"]     = HandleSetComment;
    tools["stack_comment"]   = HandleStackComment;

    // Process
    tools["attach"]          = HandleAttach;
    tools["detach"]          = HandleDetach;

    // Injection
    tools["inject_dll"]      = HandleInjectDll;
    tools["eject_dll"]       = HandleEjectDll;

    // Patches
    tools["apply_patch"]     = HandleApplyPatch;
    tools["get_patches"]     = HandleGetPatches;

    // References
    tools["ref_find"]        = HandleRefFind;

    // Exceptions
    tools["set_exception"]   = HandleSetException;
}
