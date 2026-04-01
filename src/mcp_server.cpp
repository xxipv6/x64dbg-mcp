#include "mcp_server.h"
#include "config.h"
#include "tool_dispatcher.h"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <mutex>
#include <condition_variable>
#include <deque>
#include <cstdio>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

using json = nlohmann::json;

// Simple UUID v4 generator (random, no external dependency).
static std::string GenerateUUID()
{
    static const char hex[] = "0123456789abcdef";
    char buf[37] = {};
    for (int i = 0; i < 36; ++i)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
            buf[i] = '-';
        else
            buf[i] = hex[rand() % 16];
    }
    // Version 4
    buf[14] = '4';
    // Variant 1
    buf[19] = hex[8 + (rand() % 4)];

    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Tool metadata (descriptions advertised via tools/list)
// ---------------------------------------------------------------------------

struct ToolDef {
    std::string name;
    std::string description;
    json input_schema;
    size_t param_count; // number of required params for validation
};

// Helper macros for compact tool definitions
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

static const ToolDef kToolDefs[] = {
    // ── Core ──────────────────────────────────────────────────────────────
    {"cmd_exec", "Execute any x64dbg command string (e.g. 'bp 0x401000', 'Find 0x401000, \"90 90\"').",
        OBJ_SCHEMA(PARAMS(STR_DESC("command", "x64dbg command to execute")), REQ("command"))},

    {"mem_read", "Read process memory at a given address. Returns hex dump and ASCII.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), INT_DESC("size", "Bytes to read")), REQ("address", "size"))},

    {"mem_write", "Write bytes to process memory at a given address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("data", "Space-separated hex bytes (e.g. \"90 90 90\")")), REQ("address", "data"))},

    {"get_registers", "Get all registers: GP regs, RIP, RFLAGS, debug regs, segment regs.",
        OBJ_SCHEMA(NO_PARAMS)},

    {"set_register", "Set a single register value.",
        OBJ_SCHEMA(PARAMS(STR_DESC("register", "Register name (e.g. \"rax\", \"rip\")"), STR_DESC("value", "Value to set (hex or expression)")), REQ("register", "value"))},

    {"disasm", "Disassemble a single instruction at the given address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},

    {"eval", "Evaluate a debugger expression (e.g. \"eax\", \"rip+0x10\", \"[[rsp]]\").",
        OBJ_SCHEMA(PARAMS(STR_DESC("expression", "Expression")), REQ("expression"))},

    {"is_debugging", "Check if debugger is active and if the debuggee is paused or running.",
        OBJ_SCHEMA(NO_PARAMS)},

    // ── Modules & Symbols ─────────────────────────────────────────────────
    {"mod_base", "Get base address of a loaded module by name.",
        OBJ_SCHEMA(PARAMS(STR_DESC("module", "Module name (e.g. \"kernel32.dll\")")), REQ("module"))},

    {"symbol_enum", "Enumerate symbols (exports/imports) for a module at the given base address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Module base address (use mod_base)")), REQ("address"))},

    // ── Memory ────────────────────────────────────────────────────────────
    {"mem_map", "Get memory map of the debugged process (regions with protection info).",
        OBJ_SCHEMA(NO_PARAMS)},

    {"mem_find", "Search for a byte pattern in memory. Supports ?? wildcard.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Start address"), STR_DESC("pattern", "Byte pattern (e.g. \"48 8B 05 ?? ?? ?? ??\")"),
                        INT_DESC("size", "Search range bytes. Default: 65536"), INT_DESC("max_results", "Max matches. Default: 100")),
                  REQ("address", "pattern"))},

    {"str_search", "Search for an ASCII or UTF-16 (wide) string in memory.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Start address"), STR_DESC("string", "String to search"),
                        BOOL_DESC("wide", "UTF-16LE search. Default: false"), INT_DESC("size", "Range bytes. Default: 1048576"),
                        INT_DESC("max_results", "Max matches. Default: 50")),
                  REQ("address", "string"))},

    {"alloc_mem", "Allocate memory in the debugged process.",
        OBJ_SCHEMA(PARAMS(INT_DESC("size", "Bytes to allocate")), REQ("size"))},

    {"free_mem", "Free previously allocated memory.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address to free")), REQ("address"))},

    {"set_mem_protect", "Set memory protection for a region.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), INT_DESC("size", "Region size"),
                        STR_DESC("protection", "Protection string (e.g. \"rwx\", \"rx\", \"r\")")),
                  REQ("address", "size", "protection"))},

    {"dump_mem", "Save a memory region to a file.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), INT_DESC("size", "Bytes to dump"),
                        STR_DESC("path", "Output file path")),
                  REQ("address", "size", "path"))},

    // ── Breakpoints ───────────────────────────────────────────────────────
    {"bp_list", "List breakpoints. type: 0=all, 1=normal, 2=hardware, 3=memory, 4=dll.",
        OBJ_SCHEMA(PARAMS(INT_DESC("type", "BP type filter: 0=all,1=normal,2=hw,3=mem,4=dll")), REQ())},

    {"set_bp", "Set a software breakpoint at an address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},

    {"remove_bp", "Remove a software breakpoint at an address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},

    {"enable_bp", "Enable a disabled breakpoint.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},

    {"disable_bp", "Disable a breakpoint without removing it.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},

    {"set_cond_bp", "Set a conditional breakpoint that triggers only when condition is met.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("condition", "Condition expression (e.g. \"eax==0\")")),
                  REQ("address", "condition"))},

    {"set_hw_bp", "Set a hardware breakpoint (execution, write, read, or access).",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("type", "Type: x=execute, w=write, r=read, a=access"),
                        STR_DESC("size", "Size: 1, 2, 4, or 8 bytes")),
                  REQ("address"))},

    {"remove_hw_bp", "Remove a hardware breakpoint.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},

    // ── Control Flow ──────────────────────────────────────────────────────
    {"step_over", "Step over (skip function calls).",
        OBJ_SCHEMA(NO_PARAMS)},

    {"step_into", "Step into (enter function calls).",
        OBJ_SCHEMA(NO_PARAMS)},

    {"step_out", "Step out of current function.",
        OBJ_SCHEMA(NO_PARAMS)},

    {"continue", "Continue execution (run).",
        OBJ_SCHEMA(NO_PARAMS)},

    {"pause", "Pause the debuggee.",
        OBJ_SCHEMA(NO_PARAMS)},

    {"stop", "Stop debugging and terminate the session.",
        OBJ_SCHEMA(NO_PARAMS)},

    {"run_to", "Run until the specified address is reached.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address to run to")), REQ("address"))},

    // ── Threads ───────────────────────────────────────────────────────────
    {"get_threads", "Get thread list with TID, RIP, priority, suspend count, etc.",
        OBJ_SCHEMA(NO_PARAMS)},

    {"get_call_stack", "Get the current call stack.",
        OBJ_SCHEMA(NO_PARAMS)},

    {"switch_thread", "Switch the active thread.",
        OBJ_SCHEMA(PARAMS(INT_DESC("tid", "Thread ID")), REQ("tid"))},

    {"suspend_thread", "Suspend a thread.",
        OBJ_SCHEMA(PARAMS(INT_DESC("tid", "Thread ID")), REQ("tid"))},

    {"resume_thread", "Resume a suspended thread.",
        OBJ_SCHEMA(PARAMS(INT_DESC("tid", "Thread ID")), REQ("tid"))},

    // ── Labels & Comments ─────────────────────────────────────────────────
    {"get_label", "Get the label at an address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},

    {"set_label", "Set a label at an address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("text", "Label text")), REQ("address", "text"))},

    {"get_comment", "Get the comment at an address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address")), REQ("address"))},

    {"set_comment", "Set a comment at an address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("text", "Comment text")), REQ("address", "text"))},

    {"stack_comment", "Get the stack comment at a stack address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex stack address")), REQ("address"))},

    // ── Process ───────────────────────────────────────────────────────────
    {"attach", "Attach to a running process by PID.",
        OBJ_SCHEMA(PARAMS(INT_DESC("pid", "Process ID")), REQ("pid"))},

    {"detach", "Detach from the debugged process (keeps it alive).",
        OBJ_SCHEMA(NO_PARAMS)},

    // ── Injection ─────────────────────────────────────────────────────────
    {"inject_dll", "Inject a DLL into the debugged process.",
        OBJ_SCHEMA(PARAMS(STR_DESC("path", "Full path to the DLL")), REQ("path"))},

    {"eject_dll", "Eject (unload) a DLL from the debugged process.",
        OBJ_SCHEMA(PARAMS(STR_DESC("path", "Full path or name of the DLL")), REQ("path"))},

    // ── Patches ───────────────────────────────────────────────────────────
    {"apply_patch", "Write (patch) bytes at an address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Hex address"), STR_DESC("data", "Hex bytes to write")), REQ("address", "data"))},

    {"get_patches", "List all applied patches.",
        OBJ_SCHEMA(NO_PARAMS)},

    // ── References & Search ───────────────────────────────────────────────
    {"ref_find", "Find references to a value/pattern starting at an address.",
        OBJ_SCHEMA(PARAMS(STR_DESC("address", "Start address"), STR_DESC("pattern", "Search pattern or value")), REQ("address", "pattern"))},

    // ── Exceptions ────────────────────────────────────────────────────────
    {"set_exception", "Configure exception handling (ignore/break/log for a specific exception code).",
        OBJ_SCHEMA(PARAMS(STR_DESC("code", "Exception code (hex)"), STR_DESC("action", "Action: ignore, break, or log")), REQ("code", "action"))},
};

// ---------------------------------------------------------------------------
// SSE event queue -- allows the POST handler to push events that the
// long-lived GET /sse handler will relay to the single connected client.
// ---------------------------------------------------------------------------

class SSEEventQueue {
public:
    void Push(const std::string& event, const std::string& data)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_back("event: " + event + "\ndata: " + data + "\n\n");
        cv_.notify_one();
    }

    // Block until an event is available or the queue is stopped.
    // Returns the formatted SSE frame, or empty string on stop.
    std::string Wait()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return stopped_ || !queue_.empty(); });
        if (stopped_)
            return {};
        std::string frame = std::move(queue_.front());
        queue_.pop_front();
        return frame;
    }

    void Stop()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        cv_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::string> queue_;
    bool stopped_ = false;
};

// ---------------------------------------------------------------------------
// McpServer implementation
// ---------------------------------------------------------------------------

McpServer::McpServer()  = default;
McpServer::~McpServer() { Stop(); }

bool McpServer::Start(const McpConfig& config)
{
    if (running_.load())
        return false;

    running_.store(true);
    thread_ = std::thread(&McpServer::ServerThread, this, config);
    return true;
}

void McpServer::Stop()
{
    if (!running_.load())
        return;

    running_.store(false);

    // Signal the httplib::Server to stop listening so ServerThread can exit.
    if (server_)
    {
        auto* svr = static_cast<httplib::Server*>(server_);
        svr->stop();
    }

    if (thread_.joinable())
        thread_.join();
}

// ---------------------------------------------------------------------------
// JSON-RPC dispatch
// ---------------------------------------------------------------------------

static json MakeResponse(const json& id, const json& result)
{
    return {
        {"jsonrpc", "2.0"},
        {"id",      id},
        {"result",  result}
    };
}

static json MakeError(const json& id, int code, const std::string& message,
                      const json& data = nullptr)
{
    json err = {
        {"code",    code},
        {"message", message}
    };
    if (!data.is_null())
        err["data"] = data;

    return {
        {"jsonrpc", "2.0"},
        {"id",      id},
        {"error",   err}
    };
}

std::string McpServer::HandleJsonRpc(const std::string& body)  // renamed to match header
{
    // -- Register tools once (static) -----------------------------------------
    static std::unordered_map<std::string, ToolHandler> tools;
    static bool toolsRegistered = false;
    if (!toolsRegistered)
    {
        RegisterTools(tools);
        toolsRegistered = true;
    }

    // -- Parse ----------------------------------------------------------------
    json req;
    try
    {
        req = json::parse(body);
    }
    catch (const json::parse_error&)
    {
        json null_id = nullptr;
        return MakeError(null_id, -32700, "Parse error").dump();
    }

    json id = req.contains("id") ? req["id"] : json(nullptr);
    std::string method;
    if (req.contains("method") && req["method"].is_string())
        method = req["method"].get<std::string>();

    json params = req.contains("params") ? req["params"] : json::object();

    // -- Notifications (no response expected) ---------------------------------
    if (id.is_null())
        return {};

    // -- Method dispatch ------------------------------------------------------
    if (method == "initialize")
    {
        json result = {
            {"protocolVersion", "2024-11-05"},
            {"capabilities",
                {
                    {"tools", {{"listChanged", false}}}
                }
            },
            {"serverInfo",
                {
                    {"name",    "x64dbg-mcp"},
                    {"version", "0.1.0"}
                }
            }
        };
        return MakeResponse(id, result).dump();
    }

    if (method == "ping")
    {
        return MakeResponse(id, json::object()).dump();
    }

    if (method == "notifications/initialized")
    {
        // Notification -- no response.
        return {};
    }

    if (method == "tools/list")
    {
        json toolArray = json::array();
        for (const auto& td : kToolDefs)
        {
            toolArray.push_back({
                {"name",         td.name},
                {"description",  td.description},
                {"inputSchema",  td.input_schema}
            });
        }

        return MakeResponse(id, {{"tools", toolArray}}).dump();
    }

    if (method == "tools/call")
    {
        std::string toolName;
        if (params.contains("name") && params["name"].is_string())
            toolName = params["name"].get<std::string>();

        json toolParams = params.value("arguments", json::object());

        auto it = tools.find(toolName);
        if (it == tools.end())
        {
            return MakeError(id, -32601,
                             "Unknown tool: " + toolName).dump();
        }

        try
        {
            json toolResult = it->second(toolParams);

            // The MCP spec expects the result wrapped in a content array.
            // If the tool handler already returns a content-shaped object,
            // pass it through; otherwise wrap in a text content block.
            json content;
            if (toolResult.is_array())
            {
                content = toolResult;
            }
            else if (toolResult.is_object() && toolResult.contains("content"))
            {
                content = toolResult["content"];
            }
            else
            {
                // Wrap as a single text content block.
                std::string text;
                if (toolResult.is_string())
                    text = toolResult.get<std::string>();
                else
                    text = toolResult.dump(2);

                content = json::array({
                    {
                        {"type", "text"},
                        {"text", text}
                    }
                });
            }

            return MakeResponse(id, {{"content", content}}).dump();
        }
        catch (const std::exception& ex)
        {
            json errContent = json::array({
                {
                    {"type", "text"},
                    {"text", std::string("Tool error: ") + ex.what()}
                }
            });
            return MakeResponse(id,
                {{"content", errContent}, {"isError", true}}).dump();
        }
    }

    // Unknown method.
    return MakeError(id, -32601, "Method not found: " + method).dump();
}

// ---------------------------------------------------------------------------
// Server thread -- sets up httplib routes and listens.
// ---------------------------------------------------------------------------

void McpServer::ServerThread(McpConfig config)
{
    httplib::Server svr;

    // Increase timeouts for a debugging tool -- connections may be idle while
    // the user is single-stepping in x64dbg.
    svr.set_read_timeout(300);
    svr.set_write_timeout(60);
    svr.set_keep_alive_timeout(300);

    // Shared SSE state for the single connected client.
    auto sseQueue = std::make_shared<SSEEventQueue>();

    // -----------------------------------------------------------------------
    // GET /sse -- Server-Sent Events stream.
    //
    // On connection the server sends an "endpoint" event that tells the client
    // where to POST its JSON-RPC messages.  After that it relays any queued
    // SSE events (server-initiated notifications).
    // -----------------------------------------------------------------------
    svr.Get("/sse", [&sseQueue](const httplib::Request& /*req*/,
                                httplib::Response& res)
    {
        std::string sessionId = GenerateUUID();
        std::string endpointUrl = "/message?sessionId=" + sessionId;

        res.set_chunked_content_provider(
            "text/event-stream",
            [sessionId, endpointUrl, &sseQueue](size_t /*offset*/,
                                                httplib::DataSink& sink) -> bool
            {
                // Send the initial endpoint event.
                std::string initMsg =
                    "event: endpoint\ndata: " + endpointUrl + "\n\n";
                sink.write(initMsg.data(), initMsg.size());

                // Relay queued events until the connection is lost.
                while (true)
                {
                    std::string frame = sseQueue->Wait();
                    if (frame.empty())
                        break;  // Queue stopped / shutting down.

                    sink.write(frame.data(), frame.size());
                }
                return true;
            });
    });

    // -----------------------------------------------------------------------
    // POST /message -- JSON-RPC request endpoint.
    //
    // The client POSTs JSON-RPC here.  We process synchronously and return
    // the response directly in the HTTP body (HTTP 202 Accepted).
    // -----------------------------------------------------------------------
    svr.Post("/message", [this](const httplib::Request& req,
                                httplib::Response& res)
    {
        std::string rpcResponse = HandleJsonRpc(req.body);

        res.status = 202;
        res.set_content(rpcResponse.empty() ? "{}" : rpcResponse,
                        "application/json");
    });

    // -----------------------------------------------------------------------
    // POST /mcp -- Streamable HTTP transport (alternative single-endpoint).
    //
    // Some MCP clients prefer a single URL.  This handles the same JSON-RPC
    // protocol via a straightforward request/response exchange.
    // -----------------------------------------------------------------------
    svr.Post("/mcp", [this](const httplib::Request& req,
                            httplib::Response& res)
    {
        std::string rpcResponse = HandleJsonRpc(req.body);

        res.status = 200;
        res.set_content(rpcResponse.empty() ? "{}" : rpcResponse,
                        "application/json");
    });

    // -----------------------------------------------------------------------
    // CORS headers -- useful during development / testing.
    // -----------------------------------------------------------------------
    svr.set_default_headers({
        {"Access-Control-Allow-Origin",  "*"},
        {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"}
    });

    svr.Options("/sse",     [](const httplib::Request&, httplib::Response& res)
                            { res.status = 204; });
    svr.Options("/message", [](const httplib::Request&, httplib::Response& res)
                            { res.status = 204; });
    svr.Options("/mcp",     [](const httplib::Request&, httplib::Response& res)
                            { res.status = 204; });

    // Store server pointer for clean shutdown
    server_ = &svr;

    // -----------------------------------------------------------------------
    // Start listening (blocking until stop() is called).
    // -----------------------------------------------------------------------
    if (!svr.bind_to_port(config.host, config.port))
    {
        return;
    }

    // Bind succeeded -- log to stderr (visible in x64dbg log window if
    // the plugin redirects it).
    std::fprintf(stderr, "[x64dbg-mcp] listening on %s:%d\n",
                 config.host.c_str(), config.port);

    svr.listen_after_bind();

    // Clean up SSE queue on shutdown.
    sseQueue->Stop();

    std::fprintf(stderr, "[x64dbg-mcp] server stopped\n");
}
