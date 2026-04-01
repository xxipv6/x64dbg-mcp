# x64dbg-mcp

x64dbg plugin that exposes debugger capabilities as [MCP](https://modelcontextprotocol.io/) Tools over HTTP.

Based on the MCP protocol (2024-11-05) with JSON-RPC 2.0 over HTTP+SSE transport.

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /sse` | SSE stream for server-initiated events |
| `POST /message` | JSON-RPC messages (SSE transport) |
| `POST /mcp` | Streamable HTTP single-endpoint transport |

## Tools (40+)

Core: `cmd_exec`, `eval`, `disasm`, `get_registers`, `set_register`, `is_debugging`

Memory: `mem_read`, `mem_write`, `mem_map`, `mem_find`, `str_search`, `alloc_mem`, `free_mem`, `set_mem_protect`, `dump_mem`

Breakpoints: `bp_list`, `set_bp`, `remove_bp`, `enable_bp`, `disable_bp`, `set_cond_bp`, `set_hw_bp`, `remove_hw_bp`

Control: `step_over`, `step_into`, `step_out`, `continue`, `pause`, `stop`, `run_to`

Threads: `get_threads`, `get_call_stack`, `switch_thread`, `suspend_thread`, `resume_thread`

Analysis: `get_label`, `set_label`, `get_comment`, `set_comment`, `stack_comment`, `ref_find`

Process: `attach`, `detach`, `inject_dll`, `eject_dll`, `apply_patch`, `get_patches`, `set_exception`

## Project Structure

```
x64dbg-mcp/
├── CMakeLists.txt          # Build system
├── cmake/                  # Build support (toolchains, .def files)
├── include/                # x64dbg SDK headers (MinGW-compatible)
├── src/                    # Plugin source code
│   └── tools/              # Tool implementations (modular)
├── third_party/            # Dependencies (cpp-httplib, nlohmann/json)
└── x64dbg-mcp.json         # Config template
```

## Build (Cross-Compile on Linux)

### Prerequisites

```bash
# Ubuntu/Debian
apt install cmake mingw-w64
```

### Generate Import Libraries

```bash
# From project root
mkdir -p lib
x86_64-w64-mingw32-dlltool -d cmake/x64dbg_plugin.def -l lib/libx64dbg_plugin.a
x86_64-w64-mingw32-dlltool -d cmake/x64bridge.def -l lib/libx64bridge.a
```

### Build

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-x64.cmake
make -j$(nproc)
```

Output: `bin/x64dbg-mcp.dp64`

## Build (Native MSVC on Windows)

```bash
cmake -B build64 -A x64 -G "Visual Studio 17 2022"
cmake --build build64 --config Release
```

## Install

1. Copy `x64dbg-mcp.dp64` to `x64dbg/plugins/` directory
2. Copy `x64dbg-mcp.json` to `x64dbg/plugins/` directory (edit host/port as needed)
3. Restart x64dbg

## Configuration

`x64dbg-mcp.json`:

```json
{
  "host": "127.0.0.1",
  "port": 8765,
  "log_level": "info"
}
```

## MCP Client Setup

For Claude Code, add to `.claude/settings.json`:

```json
{
  "mcpServers": {
    "x64dbg": {
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```
