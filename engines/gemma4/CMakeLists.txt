# strata-gemma4-engine (Gemma 4 plans 2-3): our own engine for the Gemma 4 26B-A4B family,
# speaking the strata_0143 stdio protocol. Standalone project: nothing of upstream/ is added
# or compiled (plan reconciliation R1, R7). NVIDIA only (CUDA 13, sm_89 on the owner's box).
cmake_minimum_required(VERSION 3.28)
project(strata_gemma4_engine LANGUAGES CXX)

option(G4_ENABLE_CUDA "Build the CUDA engine and kernel tests (the host tests build without CUDA)" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(G4_HOST_WARNINGS /W4 /WX /permissive- /utf-8 /EHsc /Zc:__cplusplus)
else()
    set(G4_HOST_WARNINGS -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
endif()

add_library(g4_host STATIC src/g4_file.cpp src/g4_gguf.cpp src/g4_model.cpp src/g4_cli.cpp)
target_include_directories(g4_host PUBLIC src)
target_compile_options(g4_host PRIVATE ${G4_HOST_WARNINGS})

enable_testing()

add_executable(g4_host_tests tests/g4_host_tests.cpp)
target_include_directories(g4_host_tests PRIVATE tests)
target_link_libraries(g4_host_tests PRIVATE g4_host)
target_compile_options(g4_host_tests PRIVATE ${G4_HOST_WARNINGS})

set(G4_HOST_CASES
    gguf_parses_a_valid_header gguf_refuses_bad_magic_version_and_truncation
    gguf_refuses_oversized_counts_and_strings gguf_refuses_bad_tensors tensor_bytes_follow_the_types
    model_guard_accepts_the_26b_a4b_shape model_guard_refuses_other_shapes
    cli_accepts_the_serve_flags cli_refuses_bad_and_test_only_flags_with_serve gen_lines_follow_the_q36_grammar
    sampler_matches_the_q36_rules reuse_keeps_exact_prefixes_within_the_ring
    sorted_candidates_sample_like_the_full_sampler unseeded_requests_draw_fresh_seeds info_line_reports_the_expert_split)
foreach(case IN LISTS G4_HOST_CASES)
    add_test(NAME g4_host_tests.${case} COMMAND g4_host_tests --case ${case})
endforeach()

if(G4_ENABLE_CUDA)
    enable_language(CUDA)
    find_package(CUDAToolkit REQUIRED)
    set(CMAKE_CUDA_STANDARD 20)
    set(CMAKE_CUDA_STANDARD_REQUIRED ON)
    if(MSVC)
        set(G4_CUDA_WARNINGS -Werror=all-warnings -Xcompiler=/W4,/WX,/utf-8,/EHsc)
    else()
        set(G4_CUDA_WARNINGS -Werror=all-warnings -Xcompiler=-Wall,-Wextra,-Werror)
    endif()

    add_library(g4_kernels STATIC src/g4_kernels.cu)
    target_include_directories(g4_kernels PUBLIC src)
    target_compile_options(g4_kernels PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:${G4_CUDA_WARNINGS}>)
    set_target_properties(g4_kernels PROPERTIES CUDA_RUNTIME_LIBRARY Static)

    add_executable(g4_kernel_tests tests/g4_kernel_tests.cu)
    target_include_directories(g4_kernel_tests PRIVATE tests)
    target_link_libraries(g4_kernel_tests PRIVATE g4_kernels)
    target_compile_options(g4_kernel_tests PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:${G4_CUDA_WARNINGS}>)
    set_target_properties(g4_kernel_tests PROPERTIES CUDA_RUNTIME_LIBRARY Static)
    set(G4_KERNEL_CASES
        matvec_matches_cpu_for_each_kind expert_matvec_reads_the_table_in_vram_and_pinned_ram norms_match_cpu
        embedding_and_small_ops_match_cpu router_picks_the_top_eight qkv_post_matches_cpu_for_both_layer_kinds
        decode_attention_matches_cpu prompt_softmax_masks_like_the_model dequant_and_gather_match_cpu
        topk_matches_a_cpu_ranking)
    foreach(case IN LISTS G4_KERNEL_CASES)
        add_test(NAME g4_kernel_tests.${case} COMMAND g4_kernel_tests --case ${case})
        set_tests_properties(g4_kernel_tests.${case} PROPERTIES LABELS gpu)
    endforeach()
endif()

if(G4_ENABLE_CUDA)
    add_executable(strata-gemma4-engine src/g4_main.cpp src/g4_engine.cu)
    target_link_libraries(strata-gemma4-engine PRIVATE g4_host g4_kernels CUDA::cublas)
    target_compile_options(strata-gemma4-engine PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${G4_HOST_WARNINGS}>
                                                       $<$<COMPILE_LANGUAGE:CUDA>:${G4_CUDA_WARNINGS}>)
    set_target_properties(strata-gemma4-engine PROPERTIES CUDA_RUNTIME_LIBRARY Static)
endif()

# Box-only checks against the real model (plans 2-3 Tasks 6-7): configure with
# -DG4_MODEL_FILE=<the Q8_K_XL gguf> -DG4_PYTHON=<python> to register them (label "model").
set(G4_MODEL_FILE "" CACHE FILEPATH "The Gemma 4 26B-A4B GGUF for the model-labelled tests (empty: not registered)")
set(G4_PYTHON "" CACHE FILEPATH "Python for the model-labelled tests")
if(G4_ENABLE_CUDA AND G4_MODEL_FILE AND G4_PYTHON)
    # "Write a short poem about the sea, with a title. Use exactly four lines." in the chat template, thinking off
    set(G4_POEM_IDS 2,105,2364,107,6974,496,2822,27355,1003,506,5442,236764,607,496,3822,236761,6890,7121,2390,4463,236761,106,107,105,4368,107,100,45518,107,101)
    set(G4_FRANCE_IDS 2,105,2364,107,3689,563,506,5279,529,7001,236881,25685,528,886,13315,236761,106,107,105,4368,107,100,45518,107,101)
    add_test(NAME g4_model.paths_agree COMMAND ${G4_PYTHON} -I ${CMAKE_CURRENT_SOURCE_DIR}/tools/g4_paths_agree.py
             $<TARGET_FILE:strata-gemma4-engine> ${G4_MODEL_FILE} ${G4_POEM_IDS})
    add_test(NAME g4_model.serve_smoke COMMAND ${G4_PYTHON} -I ${CMAKE_CURRENT_SOURCE_DIR}/tools/g4_serve_smoke.py
             $<TARGET_FILE:strata-gemma4-engine> ${G4_MODEL_FILE} ${G4_FRANCE_IDS})
    set_tests_properties(g4_model.paths_agree g4_model.serve_smoke PROPERTIES LABELS "gpu;model" TIMEOUT 900)
endif()
