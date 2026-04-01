cmake_minimum_required(VERSION 3.15)
project(x64dbg-mcp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Common sources
# ---------------------------------------------------------------------------
set(SOURCES
    src/main.cpp
    src/mcp_server.cpp
    src/tool_dispatcher.cpp
    src/config.cpp
)

set(INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

# ---------------------------------------------------------------------------
# Helper function: create one plugin target (32-bit or 64-bit)
# ---------------------------------------------------------------------------
function(add_x64dbg_plugin TARGET_SUFFIX ARCH_SUFFIX)
    set(TARGET_NAME x64dbg-mcp${TARGET_SUFFIX})

    add_library(${TARGET_NAME} SHARED ${SOURCES})

    target_include_directories(${TARGET_NAME} PRIVATE ${INCLUDE_DIRS})

    # Static CRT (/MT instead of /MD)
    set_property(TARGET ${TARGET_NAME} PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded"
    )

    # Compiler flags
    target_compile_options(${TARGET_NAME} PRIVATE /W3)

    # Preprocessor definitions
    target_compile_definitions(${TARGET_NAME} PRIVATE
        BUILD_PLUGIN
        UNICODE
        _UNICODE
    )

    # Link libraries
    target_link_libraries(${TARGET_NAME} PRIVATE
        ws2_32
        dbghelp
    )

    # Output: bin/x64dbg-mcp.dp32 or bin/x64dbg-mcp.dp64
    set_target_properties(${TARGET_NAME} PROPERTIES
        OUTPUT_NAME "x64dbg-mcp"
        SUFFIX ".dp${ARCH_SUFFIX}"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endfunction()

# ---------------------------------------------------------------------------
# 32-bit plugin target
# ---------------------------------------------------------------------------
add_x64dbg_plugin("32" "32")

# ---------------------------------------------------------------------------
# 64-bit plugin target
# ---------------------------------------------------------------------------
add_x64dbg_plugin("64" "64")
