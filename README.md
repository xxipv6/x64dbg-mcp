# x64dbg MCP Plugin

x64dbg MCP（Model Context Protocol）插件，通过 MCP 协议将调试器功能暴露为 HTTP 接口上的 MCP Tools。

基于 MCP 协议 (2024-11-05)，使用 JSON-RPC 2.0 over HTTP+SSE 传输。

## 传输方式

| 端点 | 说明 |
|------|------|
| `GET /sse` | SSE 流，用于服务端推送事件 |
| `POST /message` | JSON-RPC 消息（SSE 传输模式） |
| `POST /mcp` | Streamable HTTP 单端点传输模式 |

## 工具列表（35）

### 核心

| 工具 | 说明 |
|------|------|
| `is_debugging` | 检查调试状态（是否正在调试/是否正在运行） |
| `cmd_exec` | 执行 x64dbg 命令 |
| `eval` | 计算表达式值 |
| `disasm` | 反汇编指定地址的指令 |
| `get_registers` | 获取所有寄存器值 |
| `set_register` | 设置寄存器值 |
| `mod_base` | 获取模块基址 |
| `symbol_enum` | 枚举模块符号 |

### 内存

| 工具 | 说明 |
|------|------|
| `mem_read` | 读取进程内存 |
| `mem_write` | 写入进程内存 |
| `mem_map` | 获取内存映射 |
| `mem_find` | 搜索字节模式 |
| `str_search` | 搜索字符串（ASCII / UTF-16） |
| `alloc_mem` | 在调试目标进程中分配内存（返回地址） |
| `free_mem` | 释放之前分配的内存 |
| `set_mem_protect` | 设置内存保护属性 |
| `dump_mem` | 将内存转储到文件 |

### 断点

| 工具 | 说明 |
|------|------|
| `bp_list` | 列出所有断点 |
| `set_bp` | 设置软件断点 |
| `remove_bp` | 删除断点 |
| `enable_bp` | 启用断点 |
| `disable_bp` | 禁用断点 |
| `set_cond_bp` | 设置条件断点 |
| `set_hw_bp` | 设置硬件断点 |
| `remove_hw_bp` | 删除硬件断点 |

### 控制流

| 工具 | 说明 |
|------|------|
| `step_over` | 单步步过（不进入函数） |
| `step_into` | 单步进入（进入函数） |
| `step_out` | 执行到返回 |
| `continue` | 继续运行 |
| `pause` | 暂停调试 |
| `stop` | 停止调试 |
| `run_to` | 运行到指定地址 |

### 线程

| 工具 | 说明 |
|------|------|
| `get_threads` | 获取线程列表 |
| `get_call_stack` | 获取调用栈 |
| `switch_thread` | 切换活动线程 |
| `suspend_thread` | 挂起线程 |
| `resume_thread` | 恢复线程 |

### 分析

| 工具 | 说明 |
|------|------|
| `get_label` | 获取地址标签 |
| `set_label` | 设置地址标签 |
| `get_comment` | 获取地址注释（优先用户注释） |
| `set_comment` | 设置地址注释 |
| `stack_comment` | 获取栈注释 |
| `ref_find` | 查找引用 |

### 进程
| 工具 | 说明 |
|------|------|
| `attach` | 附加到进程 |
| `detach` | 分离调试 |
| `inject_dll` | 注入 DLL |
| `eject_dll` | 卸载 DLL |
| `apply_patch` | 应用补丁（注册到 patch tracking） |
| `get_patches` | 获取所有补丁列表 |
| `set_exception` | 设置异常处理策略 |

## 项目结构

```
x64dbg-mcp/
├── CMakeLists.txt          # 构建配置
├── README.md           # 本文件
├── x64dbg-mcp.json     # 配置模板
├── cmake/              # 构建支持（工具链 .def 定义文件）
│   ├── toolchain-x64.cmake
│   └── toolchain-x86.cmake
├── lib/                # 外部依赖（MinGW 导入库 .a）
│   ├── x64/               # x64dbg 导入库
│   │   └── x86/               # x32dbg 导入库
├── include/            # 头文件
│   ├── bridgemain.h     # x64dbg SDK 桥接 Bridge API
│   ├── _plugins.h       # x64dbg 插件 SDK
│   ├── _dbgfunctions.h   # x64dbg 内部函数
│   ├── nlohmann/       # JSON 库（仅头文件）
│   ├── jansson/        # Jansson JSON（SDK 依赖）
│   └── httplib.h       # HTTP 库（仅头文件）
│   └── src/                # 插件源码
    ├── main.cpp
    ├── mcp_server.cpp
    ├── config.cpp
    └── tools/
        ├── core.cpp
        ├── memory.cpp
        ├── breakpoints.cpp
        ├── control.cpp
        ├── threads.cpp
        ├── analysis.cpp
        └── process.cpp
```

## 构建（Linux 交叉编译)

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
# x86 32
32 ( 生成 x32 导入库
i686-w64-mingw32-dlltool -d cmake/x32dbg_plugin.def -l lib/libx32dbg_plugin.a
i686-w64-mingw32-dlltool -d cmake/x32bridge.def -l lib/libx32bridge.a

```

### 编译
```bash
# x64
mkdir -p build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-x64.cmake
make -j$(nproc)

# x32
mkdir -p build32 && cd build32
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-x86.cmake
make -j$(nproc)
```

输出: `build/bin/x64dbg-mcp.dp64` 和 `build32/bin/x32dbg-mcp.dp32`

## 安装

1. 将 `x64dbg-mcp.dp64` 复制到 `x64dbg/plugins/` 目录
2. 将 `x64dbg-mcp.json` 复到到 `x64dbg/plugins/` 目录（按需修改 host/port)
3. 重启 x64dbg

### x32dbg

1. 将 `x32dbg-mcp.dp32` 复制到 `x32dbg/plugins/` 目录
2. 将 `x32dbg-mcp.json`（拷贝自 x64dbg-mcp.json） 复制到 `x32dbg/plugins/` 目录（按需修改 host/port)
3. 重启 x32dbg

## 配置

`x64dbg-mcp.json`:
```json
{
  "host": "127.0.0.1",
  "port": 8765,
  "log_level": "info"
}
```

### MCP 客户端配置
添加 `.claude/settings.json`:

```json
{
  "mcpServers": {
    "x64dbg": {
      "url": "http://127.0.0.1:8765"
    }
  }
}
```
