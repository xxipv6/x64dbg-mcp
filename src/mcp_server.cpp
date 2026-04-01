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
};

static const ToolDef kToolDefs[] = {
    {
        "cmd_exec",
        "Execute an x64dbg command string.",
        {
            {"type", "object"},
            {"properties",
                {
                    {"command", {{"type", "string"}, {"description", "x64dbg command to execute"}}}
                }},
            {"required", json::array({"command"})}
        }
    },
    {
        "mem_read",
        "Read process memory at a given address.",
        {
            {"type", "object"},
            {"properties",
                {
                    {"address", {{"type", "string"}, {"description", "Hex address string (e.g. \"0x401000\")"}}},
                    {"size",    {{"type", "integer"}, {"description", "Number of bytes to read"}}}
                }},
            {"required", json::array({"address", "size"})}
        }
    },
    {
        "get_registers",
        "Get the current register dump from the debugger.",
        {
            {"type", "object"},
            {"properties", json::object()},
            {"required", json::array()}
        }
    },
    {
        "disasm",
        "Disassemble at the given address.",
        {
            {"type", "object"},
            {"properties",
                {
                    {"address", {{"type", "string"}, {"description", "Hex address string (e.g. \"0x401000\")"}}}
                }},
            {"required", json::array({"address"})}
        }
    },
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
