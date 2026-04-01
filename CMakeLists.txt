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
    src/tools/register.cpp
    src/tools/core.cpp
    src/tools/memory.cpp
    src/tools/breakpoints.cpp
    src/tools/control.cpp
    src/tools/threads.cpp
    src/tools/analysis.cpp
    src/tools/process.cpp
    src/config.cpp
)

set(INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# ---------------------------------------------------------------------------
# Detect cross-compilation: if a toolchain file is specified or the
# compiler name contains "mingw", build only the matching architecture.
# Otherwise build both x86 and x64 (native MSVC on Windows).
# ---------------------------------------------------------------------------

if(CMAKE_CXX_COMPILER MATCHES "mingw" OR CMAKE_CROSSCOMPILING)
    # Cross-compiling on Linux with MinGW — build a single target
    message(STATUS "Cross-compiling for Windows with ${CMAKE_CXX_COMPILER}")

    add_library(x64dbg-mcp SHARED ${SOURCES})

    target_include_directories(x64dbg-mcp PRIVATE ${INCLUDE_DIRS})

    # Preprocessor definitions
    target_compile_definitions(x64dbg-mcp PRIVATE
        BUILD_PLUGIN
        UNICODE
        _UNICODE
        _WIN32_WINNT=0x0601
        WIN32_LEAN_AND_MEAN
    )

    # Link libraries (Windows system libs via MinGW)
    # Two import libraries: _plugin_* from x64dbg.exe, Dbg*/Bridge* from x64bridge.dll
    target_link_libraries(x64dbg-mcp PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libx64dbg_plugin.a
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libx64bridge.a
        ws2_32
        dbghelp
        -static
        -static-libgcc
        -static-libstdc++
    )

    # Determine output name and suffix from the compiler target
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(PLUGIN_NAME "x64dbg-mcp")
        set(PLUGIN_SUFFIX ".dp64")
    else()
        set(PLUGIN_NAME "x32dbg-mcp")
        set(PLUGIN_SUFFIX ".dp32")
    endif()

    set_target_properties(x64dbg-mcp PROPERTIES
        PREFIX ""
        OUTPUT_NAME "${PLUGIN_NAME}"
        SUFFIX "${PLUGIN_SUFFIX}"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )

else()
    # Native MSVC build on Windows — build both 32-bit and 64-bit targets
    message(STATUS "Native Windows build — creating x86 and x64 targets")

    function(add_x64dbg_plugin TARGET_SUFFIX ARCH_SUFFIX PLUGIN_NAME)
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

        # Output: bin/x32dbg-mcp.dp32 or bin/x64dbg-mcp.dp64
        set_target_properties(${TARGET_NAME} PROPERTIES
            OUTPUT_NAME "${PLUGIN_NAME}"
            SUFFIX ".dp${ARCH_SUFFIX}"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
    endfunction()

    add_x64dbg_plugin("32" "32" "x32dbg-mcp")
    add_x64dbg_plugin("64" "64" "x64dbg-mcp")
endif()
