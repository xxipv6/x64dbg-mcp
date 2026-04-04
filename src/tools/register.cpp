#include "../tool_dispatcher.h"

using json = nlohmann::json;

// Forward declarations from each sub-module
extern void RegisterCoreTools(ToolMap& tools);
extern void RegisterMemoryTools(ToolMap& tools);
extern void RegisterBreakpointTools(ToolMap& tools);
extern void RegisterControlTools(ToolMap& tools);
extern void RegisterThreadTools(ToolMap& tools);
extern void RegisterAnalysisTools(ToolMap& tools);
extern void RegisterProcessTools(ToolMap& tools);

namespace {

#define PARAMS(...) json::object({__VA_ARGS__})
#define REQ(...) json::array({__VA_ARGS__})
#define STR_DESC(n, d) {n, {{"type", "string"}, {"description", d}}}
#define INT_DESC(n, d) {n, {{"type", "integer"}, {"description", d}}}
#define BOOL_DESC(n, d) {n, {{"type", "boolean"}, {"description", d}}}
#define OBJ_SCHEMA_2(props, req) {{"type", "object"}, {"properties", props}, {"required", req}}
#define OBJ_SCHEMA_1(props) {{"type", "object"}, {"properties", props}, {"required", json::array()}}
#define OBJ_SCHEMA_GETMAC(_1,_2,NAME,...) NAME
#define OBJ_SCHEMA(...) OBJ_SCHEMA_GETMAC(__VA_ARGS__, OBJ_SCHEMA_2, OBJ_SCHEMA_1)(__VA_ARGS__)
#define NO_PARAMS json::object()

const std::vector<ToolDefinition> kToolDefinitions = {
    {"cmd_exec", "Execute any x64dbg command string (e.g. 'bp 0x401000', 'Find 0x401000, \"90 90\"').", OBJ_SCHEMA(PARAMS(STR_DESC("command", "x64dbg command to execute")), REQ("command"))},
    {"mem_read", "Read process memory at a given address. Returns hex dump and ASCII.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), INT_DESC("size", "Bytes to read")), REQ("address", "size"))},
    {"mem_write", "Write bytes to process memory at a given address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("data", "Space-separated hex bytes (e.g. \"90 90 90\")")), REQ("address", "data"))},
    {"get_registers", "Get all registers: GP regs, RIP, RFLAGS, debug regs, segment regs.", OBJ_SCHEMA(NO_PARAMS)},
    {"set_register", "Set a single register value.", OBJ_SCHEMA(PARAMS(STR_DESC("register", "Register name (e.g. \"rax\", \"rip\")"), STR_DESC("value", "Value to set (hex or expression)")), REQ("register", "value"))},
    {"disasm", "Disassemble a single instruction at the given address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},
    {"eval", "Evaluate a debugger expression (e.g. \"eax\", \"rip+0x10\", \"[[rsp]]\").", OBJ_SCHEMA(PARAMS(STR_DESC("expression", "Expression")), REQ("expression"))},
    {"is_debugging", "Check if debugger is active and if the debuggee is paused or running.", OBJ_SCHEMA(NO_PARAMS)},
    {"mod_base", "Get base address of a loaded module by name.", OBJ_SCHEMA(PARAMS(STR_DESC("module", "Module name (e.g. \"kernel32.dll\")")), REQ("module"))},
    {"symbol_enum", "Enumerate symbols (exports/imports) for a module at the given base address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Module base address (use mod_base)")), REQ("address"))},
    {"mem_map", "Get memory map of the debugged process (regions with protection info). Defaults to a concise view; supports filtering and pagination.", OBJ_SCHEMA(PARAMS(BOOL_DESC("all", "Return all matched regions. Default: false"), STR_DESC("base", "Exact region base address to match"), STR_DESC("info_contains", "Case-insensitive substring filter for region info"), INT_DESC("state", "Exact MEMORY_BASIC_INFORMATION.State value to match"), INT_DESC("protect", "Exact MEMORY_BASIC_INFORMATION.Protect value to match"), INT_DESC("type", "Exact MEMORY_BASIC_INFORMATION.Type value to match"), INT_DESC("offset", "Number of matched regions to skip. Default: 0"), INT_DESC("limit", "Max matched regions to return when all=false. Default: 100")))},
    {"mem_find", "Search for a byte pattern in memory. Supports ?? wildcard.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Start address"), STR_DESC("pattern", "Byte pattern (e.g. \"48 8B 05 ?? ?? ?? ??\")"), INT_DESC("size", "Search range bytes. Default: 65536"), INT_DESC("max_results", "Max matches. Default: 100")), REQ("address", "pattern"))},
    {"str_search", "Search for an ASCII or UTF-16 (wide) string in memory.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Start address"), STR_DESC("string", "String to search"), BOOL_DESC("wide", "UTF-16LE search. Default: false"), INT_DESC("size", "Range bytes. Default: 1048576"), INT_DESC("max_results", "Max matches. Default: 50")), REQ("address", "string"))},
    {"alloc_mem", "Allocate memory in the debugged process.", OBJ_SCHEMA(PARAMS(INT_DESC("size", "Bytes to allocate")), REQ("size"))},
    {"free_mem", "Free previously allocated memory.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address to free")), REQ("address"))},
    {"set_mem_protect", "Set memory protection for a region.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), INT_DESC("size", "Region size"), STR_DESC("protection", "Protection string (e.g. \"rwx\", \"rx\", \"r\")")), REQ("address", "size", "protection"))},
    {"dump_mem", "Save a memory region to a file under .\\plugins\\mcp_dump on the debugger host. The path parameter is treated as a filename or basename only.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), INT_DESC("size", "Bytes to dump"), STR_DESC("path", "Output filename or path basename; file is always written under .\\plugins\\mcp_dump")), REQ("address", "size", "path"))},
    {"bp_list", "List breakpoints. type: 0=all, 1=normal, 2=hardware, 3=memory, 4=dll.", OBJ_SCHEMA(PARAMS(INT_DESC("type", "BP type filter: 0=all,1=normal,2=hw,3=mem,4=dll")), REQ())},
    {"set_bp", "Set a software breakpoint at an address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},
    {"remove_bp", "Remove a software breakpoint at an address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},
    {"enable_bp", "Enable a disabled breakpoint.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},
    {"disable_bp", "Disable a breakpoint without removing it.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},
    {"set_cond_bp", "Set a conditional breakpoint that triggers only when condition is met.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("condition", "Condition expression (e.g. \"eax==0\")")), REQ("address", "condition"))},
    {"set_hw_bp", "Set a hardware breakpoint (execution, write, read, or access).", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("type", "Type: x=execute, w=write, r=read, a=access"), STR_DESC("size", "Size: 1, 2, 4, or 8 bytes")), REQ("address"))},
    {"remove_hw_bp", "Remove a hardware breakpoint.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},
    {"step_over", "Step over (skip function calls).", OBJ_SCHEMA(NO_PARAMS)},
    {"step_into", "Step into (enter function calls).", OBJ_SCHEMA(NO_PARAMS)},
    {"step_out", "Step out of current function.", OBJ_SCHEMA(NO_PARAMS)},
    {"continue", "Continue execution (run).", OBJ_SCHEMA(NO_PARAMS)},
    {"pause", "Pause the debuggee.", OBJ_SCHEMA(NO_PARAMS)},
    {"stop", "Stop debugging and terminate the session.", OBJ_SCHEMA(NO_PARAMS)},
    {"run_to", "Run until the specified address is reached.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address to run to")), REQ("address"))},
    {"get_threads", "Get thread list with TID, RIP, priority, suspend count, etc.", OBJ_SCHEMA(NO_PARAMS)},
    {"get_call_stack", "Get the current call stack.", OBJ_SCHEMA(NO_PARAMS)},
    {"switch_thread", "Switch the active thread.", OBJ_SCHEMA(PARAMS(INT_DESC("tid", "Thread ID")), REQ("tid"))},
    {"suspend_thread", "Suspend a thread.", OBJ_SCHEMA(PARAMS(INT_DESC("tid", "Thread ID")), REQ("tid"))},
    {"resume_thread", "Resume a suspended thread.", OBJ_SCHEMA(PARAMS(INT_DESC("tid", "Thread ID")), REQ("tid"))},
    {"get_label", "Get the label at an address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},
    {"set_label", "Set a label at an address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("text", "Label text")), REQ("address", "text"))},
    {"get_comment", "Get the comment at an address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},
    {"set_comment", "Set a comment at an address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("text", "Comment text")), REQ("address", "text"))},
    {"stack_comment", "Get the stack comment at a stack address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex stack address")), REQ("address"))},
    {"attach", "Attach to a running process by PID.", OBJ_SCHEMA(PARAMS(INT_DESC("pid", "Process ID")), REQ("pid"))},
    {"detach", "Detach from the debugged process (keeps it alive).", OBJ_SCHEMA(NO_PARAMS)},
    {"inject_dll", "Inject a DLL into the debugged process.", OBJ_SCHEMA(PARAMS(STR_DESC("path", "Full path to the DLL")), REQ("path"))},
    {"eject_dll", "Eject (unload) a DLL from the debugged process.", OBJ_SCHEMA(PARAMS(STR_DESC("path", "Full path or name of the DLL")), REQ("path"))},
    {"apply_patch", "Write (patch) bytes at an address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("data", "Hex bytes to write")), REQ("address", "data"))},
    {"get_patches", "List all applied patches.", OBJ_SCHEMA(NO_PARAMS)},
    {"ref_find", "Find references to a value/pattern starting at an address.", OBJ_SCHEMA(PARAMS(STR_DESC("address", "Start address"), STR_DESC("pattern", "Search pattern or value")), REQ("address", "pattern"))},
    {"set_exception", "Configure exception handling (ignore/break/log for a specific exception code).", OBJ_SCHEMA(PARAMS(STR_DESC("code", "Exception code (hex)"), STR_DESC("action", "Action: ignore, break, or log")), REQ("code", "action"))},
};

} // namespace

const std::vector<ToolDefinition>& GetToolDefinitions()
{
    return kToolDefinitions;
}

// ---------------------------------------------------------------------------
// Unified registration — called from main via tool_dispatcher.h
// ---------------------------------------------------------------------------

void RegisterTools(std::unordered_map<std::string, ToolHandler>& tools)
{
    RegisterCoreTools(tools);
    RegisterMemoryTools(tools);
    RegisterBreakpointTools(tools);
    RegisterControlTools(tools);
    RegisterThreadTools(tools);
    RegisterAnalysisTools(tools);
    RegisterProcessTools(tools);
}
