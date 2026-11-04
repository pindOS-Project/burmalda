cmake_minimum_required(VERSION 3.16)
project(burmalda C)

# burmalda — Ferrix POSIX Server
#
# Built as a static library so it can be linked into ferrix-init
# (early bringup) or a standalone server process later.

add_library(burmalda STATIC
    src/burmalda.c
)

target_include_directories(burmalda PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_link_libraries(burmalda
    PUBLIC sel4
)

# -------------------------------------------------------------------------
# Optional standalone executable (future standalone server builds)
# -------------------------------------------------------------------------
if(BURMALDA_BUILD_STANDALONE)
    add_executable(burmalda_server src/main_standalone.c)
    target_link_libraries(burmalda_server
        burmalda
        sel4runtime
        muslc
    )
endif()
