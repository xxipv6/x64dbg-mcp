# x64dbg-mcp

x MCP Server plugin for x64dbg that exposing debugger capabilities via MCP Tools over HTTP.

 Based on the MCP (2024-11-05) specification with HTTP+SSE transport.

 HTTP+SSE endpoints:
  - `GET /sse` - SSE stream for Server-initiated events
  - `POST /message` - JSON-RPC messages
  - `POST /mcp` - Streamable HTTP ( single-endpoint alternative)
endpoints.

 They all talk to each other using the tools to each other. This is not limited to tools used in JSON-RPC 2.0 over HTTP.

 If you need the MCP client, just send a `POST /mcp` with JSON-RPC messages.
 This is if you need an SSE-based MCP client, connect to `GET /sse` and post messages to `POST /message`.

 The The plugin handles `tools/list` and `tools/call` methods, If a tool name is unknown, it error is returned. If the tool execution fails, the error content is included in the result. ## Build Requirements
 - Visual Studio 2019+ with C++17 support
 - CMake 3.15+
- Windows SDK
 ## Build
```bash
# 32-bit build
cm mkdir build32 && cd build32
cmake -B build32 -A Win32 -G "Visual Studio 17 2022" ..

# 64-bit build
mkdir build64 && cd build64
cmake -B build64 -A x64 -G "Visual Studio 17 2022" ..
cm --build build64 --config Release
```
# x64dbg-mcp
