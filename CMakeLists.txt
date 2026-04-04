cmake_minimum_required(VERSION 3.15)
project(x64dbg-mcp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

# Common compile definitions
set(COMMON_DEFINITIONS
    BUILD_PLUGIN
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0601
    WIN32_LEAN_AND_MEAN
)

# Architecture-specific link libraries
set(X86_LIBS
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/x86/libx32dbg_plugin.a
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/x86/libx32bridge.a
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/x86/libx32dbg.a
    ws2_32
    dbghelp
)
set(X64_LIBS
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/x64/libx64dbg_plugin.a
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/x64/libx64bridge.a
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/x64/libx64dbg.a
    ws2_32
    dbghelp
)

function(configure_x64dbg_plugin TARGET_NAME PLUGIN_NAME ARCH_SUFFIX)
    add_library(${TARGET_NAME} SHARED ${SOURCES})
    target_include_directories(${TARGET_NAME} PRIVATE ${INCLUDE_DIRS})
    target_compile_definitions(${TARGET_NAME} PRIVATE ${COMMON_DEFINITIONS})
    set_target_properties(${TARGET_NAME} PROPERTIES
        PREFIX ""
        OUTPUT_NAME "${PLUGIN_NAME}"
        SUFFIX ".dp${ARCH_SUFFIX}"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )

    if(MSVC)
        set_property(TARGET ${TARGET_NAME} PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded"
        )
        target_compile_options(${TARGET_NAME} PRIVATE /W3)
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Cross-compilation: build the matching architecture only.
# ---------------------------------------------------------------------------
if(CMAKE_CROSSCOMPILING)
    message(STATUS "Cross-compiling for Windows with ${CMAKE_CXX_COMPILER}")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        configure_x64dbg_plugin(x64dbg-mcp "x64dbg-mcp" "64")
        target_link_libraries(x64dbg-mcp PRIVATE ${X64_LIBS})
        target_link_options(x64dbg-mcp PRIVATE -static -static-libgcc -static-libstdc++)
    else()
        configure_x64dbg_plugin(x32dbg-mcp "x32dbg-mcp" "32")
        target_link_libraries(x32dbg-mcp PRIVATE ${X86_LIBS})
        target_link_options(x32dbg-mcp PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
else()
    message(STATUS "Native Windows build -- creating x86 and x64 targets")
    configure_x64dbg_plugin(x64dbg-mcp-x86 "x32dbg-mcp" "32")
    target_link_libraries(x64dbg-mcp-x86 PRIVATE ws2_32 dbghelp)

    configure_x64dbg_plugin(x64dbg-mcp-x64 "x64dbg-mcp" "64")
    target_link_libraries(x64dbg-mcp-x64 PRIVATE ws2_32 dbghelp)
endif()
