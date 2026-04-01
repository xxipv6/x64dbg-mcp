# x64dbg-mcp

x64dbg 插件，通过 MCP（Model Context Protocol）协议将调试器功能暴露为 HTTP 接口上的 MCP Tools。

基于 MCP 协议 (2024-11-05)，使用 JSON-RPC 2.0 over HTTP+SSE 传输。

## 端点

| 端点 | 说明 |
|------|------|
| `GET /sse` | SSE 流，用于服务端推送事件 |
| `POST /message` | JSON-RPC 消息（SSE 传输模式） |
| `POST /mcp` | Streamable HTTP 单端点传输模式 |

## 工具列表（40+）

**核心**: `cmd_exec`, `eval`, `disasm`, `get_registers`, `set_register`, `is_debugging`

**内存**: `mem_read`, `mem_write`, `mem_map`, `mem_find`, `str_search`, `alloc_mem`, `free_mem`, `set_mem_protect`, `dump_mem`

**断点**: `bp_list`, `set_bp`, `remove_bp`, `enable_bp`, `disable_bp`, `set_cond_bp`, `set_hw_bp`, `remove_hw_bp`

**控制流**: `step_over`, `step_into`, `step_out`, `continue`, `pause`, `stop`, `run_to`

**线程**: `get_threads`, `get_call_stack`, `switch_thread`, `suspend_thread`, `resume_thread`

**分析**: `get_label`, `set_label`, `get_comment`, `set_comment`, `stack_comment`, `ref_find`

**进程**: `attach`, `detach`, `inject_dll`, `eject_dll`, `apply_patch`, `get_patches`, `set_exception`

## 项目结构

```
x64dbg-mcp/
├── CMakeLists.txt      # 构建配置
├── README.md           # 本文件
├── x64dbg-mcp.json     # 配置模板
├── cmake/              # 构建支持（工具链、.def 定义文件）
├── lib/                # 外部依赖（MinGW 导入库 .a）
├── include/            # 头文件（x64dbg SDK + 第三方库）
│   ├── nlohmann/       # JSON 库
│   ├── jansson/        # Jansson JSON（SDK 依赖）
│   ├── httplib.h       # HTTP 库
│   └── ...             # x64dbg SDK 头文件
└── src/                # 插件源码
    ├── main.cpp        # 插件入口
    ├── mcp_server.*    # MCP 服务端
    ├── config.*        # 配置管理
    ├── tool_dispatcher.h
    └── tools/          # 工具实现（模块化）
        ├── core.cpp
        ├── memory.cpp
        ├── breakpoints.cpp
        ├── control.cpp
        ├── threads.cpp
        ├── analysis.cpp
        └── process.cpp
```

## 构建（Linux 交叉编译）

### 安装依赖

```bash
# Ubuntu/Debian
apt install cmake mingw-w64
```

### 生成导入库

```bash
# 在项目根目录执行
mkdir -p lib
x86_64-w64-mingw32-dlltool -d cmake/x64dbg_plugin.def -l lib/libx64dbg_plugin.a
x86_64-w64-mingw32-dlltool -d cmake/x64bridge.def -l lib/libx64bridge.a
```

### 编译

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-x64.cmake
make -j$(nproc)
```

输出: `bin/x64dbg-mcp.dp64`

## 构建（Windows 原生 MSVC）

```bash
cmake -B build64 -A x64 -G "Visual Studio 17 2022"
cmake --build build64 --config Release
```

## 安装

1. 将 `x64dbg-mcp.dp64` 复制到 `x64dbg/plugins/` 目录
2. 将 `x64dbg-mcp.json` 复制到 `x64dbg/plugins/` 目录（按需修改 host/port）
3. 重启 x64dbg

## 配置

`x64dbg-mcp.json`:

```json
{
  "host": "127.0.0.1",
  "port": 8765,
  "log_level": "info"
}
```

## MCP 客户端配置

Claude Code 中添加到 `.claude/settings.json`:

```json
{
  "mcpServers": {
    "x64dbg": {
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```
