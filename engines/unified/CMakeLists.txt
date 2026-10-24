# strata-unified-engine: one reviewed engine for qwen35moe + qwen4exp + gemma4 + glm5next +
# deepseek(ds4) + raon1 (design 2026-10-23, plan 2026-10-23). This is OUR tree, reviewed like
# the frontend -- not a submodule. Plan 0 (this foundation) is HOST-ONLY: the GGUF reader,
# the per-family geometry guard, the converged protocol dialect, the dispatch and the CLI /
# serve-loop skeleton build and test on the dev host and CI WITHOUT any CUDA toolkit.
#
# CUDA (the per-family graphs + shared kernels) lives behind STRATA_U_CUDA and is written and
# compiled later on the owner's GPU box; it is OFF here and never enabled in CI.
cmake_minimum_required(VERSION 3.28)
project(strata_unified_engine LANGUAGES CXX)

option(STRATA_U_CUDA "Build the CUDA graphs and kernels (GPU box only; the host lib and tests do not need it)" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(U_HOST_WARNINGS /W4 /WX /permissive- /utf-8 /EHsc /Zc:__cplusplus)
else()
    set(U_HOST_WARNINGS -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
endif()

# The host library: no CUDA, no weight reads. Parses + guards + dispatches + speaks the wire.
add_library(u_host STATIC
    src/u_file.cpp
    src/u_gguf.cpp
    src/u_geometry.cpp
    src/u_protocol.cpp
    src/u_dispatch.cpp)
target_include_directories(u_host PUBLIC src)
target_compile_options(u_host PRIVATE ${U_HOST_WARNINGS})

# The engine binary: CLI -> GGUF header -> geometry guard -> dispatch -> serve loop. On a host
# build it links the stub FamilyGraph (u_family.hpp), so it builds and serves without CUDA.
add_executable(strata-unified-engine src/u_main.cpp)
target_link_libraries(strata-unified-engine PRIVATE u_host)
target_compile_options(strata-unified-engine PRIVATE ${U_HOST_WARNINGS})

enable_testing()

add_executable(u_host_tests tests/u_host_tests.cpp)
target_include_directories(u_host_tests PRIVATE tests)
target_link_libraries(u_host_tests PRIVATE u_host)
target_compile_options(u_host_tests PRIVATE ${U_HOST_WARNINGS})

set(U_HOST_CASES
    gguf_parses_a_committed_header
    gguf_reads_a_header_from_disk
    geometry_guard_accepts_valid_key_sets
    geometry_guard_rejects_bad_key_sets
    protocol_round_trips_valid_lines
    protocol_rejects_malformed_and_unknown_lines
    dispatch_maps_known_archs_and_rejects_unknown)
foreach(case IN LISTS U_HOST_CASES)
    add_test(NAME u_host_tests.${case} COMMAND u_host_tests --case ${case})
endforeach()

if(STRATA_U_CUDA)
    # The GPU box builds the shared kernels and the per-family graphs here (plan 1+). Nothing
    # to compile in this foundation; the host library and tests above never depend on it.
    enable_language(CUDA)
    message(STATUS "strata-unified-engine: STRATA_U_CUDA is ON (GPU-box build); no kernels exist yet in Plan 0.")
endif()
