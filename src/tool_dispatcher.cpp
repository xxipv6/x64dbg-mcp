#include "tool_dispatcher.h"

#include <bridgemain.h>
#include <_plugins.h>
#include <sstream>
#include <iomanip>
#include <vector>

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
        if (i > 0)
            oss << ' ';
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

// ---------------------------------------------------------------------------
// Tool: cmd_exec
// ---------------------------------------------------------------------------

static nlohmann::json HandleCmdExec(const nlohmann::json& params)
{
    nlohmann::json result;
    try
    {
        std::string command = params.at("command").get<std::string>();
        bool ok = DbgCmdExec(command.c_str());
        result["success"] = ok;
        result["command"] = command;
    }
    catch (const std::exception& e)
    {
        result["success"] = false;
        result["error"] = std::string("cmd_exec failed: ") + e.what();
    }
    return result;
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
        else
        {
            result["data"] = "";
            result["ascii"] = "";
        }
    }
    catch (const std::exception& e)
    {
        result["success"] = false;
        result["error"] = std::string("mem_read failed: ") + e.what();
    }
    return result;
}

// ---------------------------------------------------------------------------
// Tool: get_registers
// ---------------------------------------------------------------------------

static nlohmann::json HandleGetRegisters(const nlohmann::json& /*params*/)
{
    nlohmann::json result;

    REGDUMP_AVX512 regdump = {};
    bool ok = DbgGetRegDumpEx(&regdump, sizeof(regdump));

    if (!ok)
    {
        result["success"] = false;
        result["error"] = "DbgGetRegDumpEx failed";
        return result;
    }

    const REGISTERCONTEXT_AVX512& ctx = regdump.regcontext;

    result["success"] = true;

    // General purpose registers
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

    // Instruction pointer and flags
    result["rip"]    = RegToHex(ctx.cip);
    result["rflags"] = RegToHex(ctx.eflags);

    // Debug registers
    result["dr0"] = RegToHex(ctx.dr0);
    result["dr1"] = RegToHex(ctx.dr1);
    result["dr2"] = RegToHex(ctx.dr2);
    result["dr3"] = RegToHex(ctx.dr3);
    result["dr6"] = RegToHex(ctx.dr6);
    result["dr7"] = RegToHex(ctx.dr7);

    // Segment registers
    result["gs"] = RegToHex(ctx.gs);
    result["fs"] = RegToHex(ctx.fs);
    result["es"] = RegToHex(ctx.es);
    result["ds"] = RegToHex(ctx.ds);
    result["cs"] = RegToHex(ctx.cs);
    result["ss"] = RegToHex(ctx.ss);

    return result;
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
        result["error"] = std::string("disasm failed: ") + e.what();
    }
    return result;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void RegisterTools(std::unordered_map<std::string, ToolHandler>& tools)
{
    tools["cmd_exec"]      = HandleCmdExec;
    tools["mem_read"]      = HandleMemRead;
    tools["get_registers"] = HandleGetRegisters;
    tools["disasm"]        = HandleDisasm;
}
