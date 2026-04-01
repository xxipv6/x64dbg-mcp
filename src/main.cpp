// x64dbg MCP Plugin - Main Entry Point
//
// This plugin starts an MCP (Model Context Protocol) server that exposes
// x64dbg debugging capabilities as MCP tools over HTTP. It allows external
// AI assistants and tools to control the debugger programmatically.
//
// Plugin lifecycle:
//   1. DllMain        - DLL load, captures module handle
//   2. pluginit       - SDK handshake, load config, start MCP server
//   3. plugsetup      - GUI integration (menu entries)
//   4. plugstop       - Graceful shutdown of MCP server

#include "_plugins.h"       // Plugin SDK types and API declarations
#include "bridgemain.h"     // Bridge type definitions (duint, etc.)
#include "config.h"         // McpConfig, LoadConfig
#include "mcp_server.h"     // McpServer

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static McpServer* g_mcp_server = nullptr;
static HINSTANCE g_hInstance = nullptr;

// ---------------------------------------------------------------------------
// DLL entry point
//
// Captures the module handle on DLL_PROCESS_ATTACH. This is the reliable way
// to obtain the HMODULE for the plugin DLL -- GetModuleHandle with a guessed
// name is fragile (the user may rename the file, or x86/x64 suffixes differ).
// ---------------------------------------------------------------------------

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_hInstance = hModule;

        // Disable thread library calls -- we do not need DLL_THREAD_ATTACH /
        // DLL_THREAD_DETACH notifications, and disabling them is a minor
        // performance optimisation recommended by MSDN.
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// pluginit (required export)
//
// Called by x64dbg immediately after the DLL is loaded.  We perform the SDK
// version handshake, load the JSON configuration file that sits next to the
// plugin DLL, and start the MCP HTTP server on a background thread.
// ---------------------------------------------------------------------------

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    // --- SDK handshake -------------------------------------------------------
    initStruct->sdkVersion  = PLUG_SDKVERSION;
    initStruct->pluginVersion = 1;
    strcpy_s(initStruct->pluginName, "x64dbg-mcp");

    // --- Load configuration --------------------------------------------------
    // g_hInstance was set in DllMain and is valid by the time pluginit runs.
    // LoadConfig() reads x64dbg-mcp.json from the directory containing the DLL.
    McpConfig config = LoadConfig(g_hInstance);

    // --- Create and start the MCP server -------------------------------------
    g_mcp_server = new McpServer();
    if (!g_mcp_server->Start(config)) {
        _plugin_logprintf("[x64dbg-mcp] Failed to start MCP server on %s:%d\n",
                          config.host.c_str(), config.port);
        delete g_mcp_server;
        g_mcp_server = nullptr;
        return false;
    }

    _plugin_logprintf("[x64dbg-mcp] Started MCP server on %s:%d (log level: %s)\n",
                      config.host.c_str(), config.port,
                      config.log_level.c_str());
    return true;
}

// ---------------------------------------------------------------------------
// plugstop (required export)
//
// Called by x64dbg when the user unloads the plugin or the debugger exits.
// Stops the MCP server and frees resources.
// ---------------------------------------------------------------------------

extern "C" __declspec(dllexport) bool plugstop()
{
    if (g_mcp_server) {
        g_mcp_server->Stop();
        delete g_mcp_server;
        g_mcp_server = nullptr;
    }

    _plugin_logputs("[x64dbg-mcp] Stopped MCP server");
    return true;
}

// ---------------------------------------------------------------------------
// plugsetup (optional export)
//
// Called after pluginit returns true.  Use this to integrate with the x64dbg
// GUI -- add menu entries, set up callbacks, etc.
// ---------------------------------------------------------------------------

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    // Register a menu entry that the user can click to see MCP server status.
    _plugin_menuaddentry(setupStruct->hMenu, 1, "MCP Server Status");
}

// ---------------------------------------------------------------------------
// CBMENUENTRY callback
//
// Handles menu entry clicks.  Entry ID 1 corresponds to the
// "MCP Server Status" item we added in plugsetup.
// ---------------------------------------------------------------------------

extern "C" __declspec(dllexport) void CBMENUENTRY(CBTYPE cbType,
                                                   PLUG_CB_MENUENTRY* info)
{
    if (info->hEntry == 1) {
        if (g_mcp_server) {
            _plugin_logputs("[x64dbg-mcp] MCP Server is running");
        } else {
            _plugin_logputs("[x64dbg-mcp] MCP Server is NOT running");
        }
    }
}
