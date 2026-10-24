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
# CXX-guarded: identical for the all-C++ host build, and it keeps these C++-only
# warning flags off the nvcc command line once the STRATA_U_CUDA block below adds
# .cu sources to this same target (nvcc would reject -Wconversion / permissive-).
target_compile_options(strata-unified-engine PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${U_HOST_WARNINGS}>)

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
    # The GPU-box build (never CI): the shared generic kernels (src/kernels/*.cu, namespace
    # u::k), the shared expert facility (src/u_experts.cu, u::ExpertTier) and every per-family
    # graph (src/family/*.cu) compile into the engine target and the real FamilyGraph factories
    # link in. NVIDIA sm_75+ (Turing and newer, so __dp4a is a hardware instruction); cuBLAS for
    # the prefill GEMM; --use_fast_math as the pinned llama.cpp MMVQ oracle requires.
    #
    # A family LANE just drops src/family/<fam>_graph.hpp + <fam>.cu into the tree -- the globs
    # below pick the .cu up with no edit to this file. CONFIGURE_DEPENDS re-globs on build so a
    # newly added family is compiled without re-running cmake by hand.
    enable_language(CUDA)
    find_package(CUDAToolkit REQUIRED)
    set(CMAKE_CUDA_STANDARD 20)
    set(CMAKE_CUDA_STANDARD_REQUIRED ON)
    if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
        # sm_75 (Turing) .. sm_90 (Hopper); the box overrides with -DCMAKE_CUDA_ARCHITECTURES=89
        # for its own card. sm_75 is the floor (the owner's box is newer).
        set(CMAKE_CUDA_ARCHITECTURES 75 80 86 89 90)
    endif()
    if(MSVC)
        set(U_CUDA_WARNINGS -Werror=all-warnings --use_fast_math -Xcompiler=/W4,/WX,/utf-8,/EHsc)
    else()
        set(U_CUDA_WARNINGS -Werror=all-warnings --use_fast_math -Xcompiler=-Wall,-Wextra,-Werror)
    endif()

    file(GLOB U_KERNEL_CU CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/kernels/*.cu)
    file(GLOB U_FAMILY_CU CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/family/*.cu)

    # The engine target (u_main.cpp, linking u_host) gains the CUDA substrate and the family
    # graphs, and is compiled with STRATA_U_CUDA so make_family_graph (u_family.hpp) dispatches
    # to the real factories instead of the host stub.
    target_sources(strata-unified-engine PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/u_experts.cu
        ${U_KERNEL_CU}
        ${U_FAMILY_CU})
    target_compile_definitions(strata-unified-engine PRIVATE STRATA_U_CUDA)
    target_link_libraries(strata-unified-engine PRIVATE CUDA::cudart CUDA::cublas)
    # The CXX warnings are already attached (CXX-guarded) where the target is
    # defined; here we add only the CUDA ones for the .cu sources.
    target_compile_options(strata-unified-engine PRIVATE
        $<$<COMPILE_LANGUAGE:CUDA>:${U_CUDA_WARNINGS}>)
    set_target_properties(strata-unified-engine PROPERTIES CUDA_RUNTIME_LIBRARY Static)

    list(LENGTH U_FAMILY_CU U_FAMILY_COUNT)
    message(STATUS "strata-unified-engine: STRATA_U_CUDA ON; ${U_FAMILY_COUNT} family graph(s) found in src/family/. "
                   "The engine links once the families reached by make_family_graph are present.")
endif()
