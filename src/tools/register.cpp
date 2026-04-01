#include "common.h"

// Forward declarations from each sub-module
extern void RegisterCoreTools(ToolMap& tools);
extern void RegisterMemoryTools(ToolMap& tools);
extern void RegisterBreakpointTools(ToolMap& tools);
extern void RegisterControlTools(ToolMap& tools);
extern void RegisterThreadTools(ToolMap& tools);
extern void RegisterAnalysisTools(ToolMap& tools);
extern void RegisterProcessTools(ToolMap& tools);

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
