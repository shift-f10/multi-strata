cmake_minimum_required(VERSION 3.20)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    project(secure_frontend VERSION 0.1.0 LANGUAGES CXX)
    include(CTest)
    option(STRATA_BUILD_SECURE_FRONTEND_TESTS "Build the portable frontend tests" ${BUILD_TESTING})
endif()

if(DEFINED STRATA_WERROR)
    set(_secure_frontend_werror_default ${STRATA_WERROR})
else()
    set(_secure_frontend_werror_default ON)
endif()
option(SECURE_FRONTEND_WERROR "Treat warnings as errors in the secure frontend" ${_secure_frontend_werror_default})

# SP4 §10.5: test-only hooks (record channel, raw manifest profile, publish
# fault injection, --cacert loopback test). OFF by default; the test presets
# turn it ON; linux-gcc-release proves the shipped (OFF) configuration.
option(SECURE_FRONTEND_TEST_HOOKS "Compile test-only hooks; never for shipped binaries" OFF)
if(SECURE_FRONTEND_TEST_HOOKS)
    add_compile_definitions(SECURE_FRONTEND_TEST_HOOKS=1)
endif()

function(secure_frontend_set_warnings target)
    # C++ only: an .rc source must not hand these flags to the RC compiler (SP2 G3).
    if(MSVC)
        target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4>)
        if(SECURE_FRONTEND_WERROR)
            target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/WX>)
        endif()
    else()
        target_compile_options(${target} PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Wpedantic>")
        if(SECURE_FRONTEND_WERROR)
            target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Werror>)
        endif()
    endif()
    if(WIN32)
        target_compile_definitions(${target} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    endif()
endfunction()

# --- Test helpers (SP1 §3.10) -------------------------------------------------
# Every test binary is a framework-free main() that takes `--case <name>`; each
# case is its own CTest test named <binary>.<case>, so acceptance IDs appear in
# `ctest -N`. Cases that need real Windows semantics (DACLs, DPAPI, junctions,
# Job Objects) carry ${SECURE_FRONTEND_WINDOWS_RUNTIME}; the wine preset
# excludes that label and the windows-msys2-clang CI job runs everything.
set(SECURE_FRONTEND_TEST_TMP "${CMAKE_CURRENT_BINARY_DIR}/test-tmp")
if(WIN32)
    set(SECURE_FRONTEND_WINDOWS_RUNTIME windows-runtime)
else()
    set(SECURE_FRONTEND_WINDOWS_RUNTIME "")
endif()

function(secure_frontend_add_test_executable name source)
    add_executable(${name} ${source})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_link_libraries(${name} PRIVATE ${ARGN})
    if(WIN32)
        # test_support.hpp builds private-DACL scratch directories (ConvertSidToStringSidW,
        # ConvertStringSecurityDescriptorToSecurityDescriptorW, OpenProcessToken).
        target_link_libraries(${name} PRIVATE advapi32)
    endif()
    target_compile_features(${name} PRIVATE cxx_std_20)
    secure_frontend_set_warnings(${name})
endfunction()

# secure_frontend_add_cases(<binary> <case>... [ARGS <arg>...] [LABELS <label>...] [TIMEOUT <seconds>])
function(secure_frontend_add_cases binary)
    cmake_parse_arguments(PARSE_ARGV 1 _sfac "" "TIMEOUT" "ARGS;LABELS")
    file(MAKE_DIRECTORY "${SECURE_FRONTEND_TEST_TMP}")
    foreach(_case IN LISTS _sfac_UNPARSED_ARGUMENTS)
        set(_test "${binary}.${_case}")
        add_test(NAME ${_test} COMMAND ${binary} --case ${_case} ${_sfac_ARGS})
        set_tests_properties(${_test} PROPERTIES ENVIRONMENT "SECURE_FRONTEND_TEST_TMP=${SECURE_FRONTEND_TEST_TMP}")
        if(_sfac_LABELS)
            set_tests_properties(${_test} PROPERTIES LABELS "${_sfac_LABELS}")
        endif()
        if(_sfac_TIMEOUT)
            set_tests_properties(${_test} PROPERTIES TIMEOUT ${_sfac_TIMEOUT})
        endif()
    endforeach()
endfunction()

# secure_frontend_add_library(<name> SOURCES <src>... [LINKS <lib>...])  (SP3)
function(secure_frontend_add_library name)
    cmake_parse_arguments(PARSE_ARGV 1 _sfal "" "" "SOURCES;LINKS")
    add_library(${name} ${_sfal_SOURCES})
    target_compile_features(${name} PUBLIC cxx_std_20)
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
    if(_sfal_LINKS)
        target_link_libraries(${name} PUBLIC ${_sfal_LINKS})
    endif()
    secure_frontend_set_warnings(${name})
endfunction()

add_library(secure_frontend_config
    src/config.cpp
    src/secret_source.cpp
)

add_library(secure_frontend_token_reader
    src/token_reader.cpp
)

add_library(secure_frontend_http_policy
    src/http_policy.cpp
)

add_library(secure_frontend_http_request_handler
    src/http_request_handler.cpp
)

secure_frontend_add_library(secure_frontend_api_core
    SOURCES src/api_errors.cpp src/http_wire.cpp src/http_request_head.cpp
    LINKS secure_frontend_json)
secure_frontend_add_library(secure_frontend_socket_io SOURCES src/socket_io.cpp LINKS secure_frontend_api_core)
if(WIN32)
    target_link_libraries(secure_frontend_socket_io PUBLIC ws2_32)
endif()

add_library(secure_frontend_api_router
    src/api_router.cpp
)

add_library(secure_frontend_engine_process
    src/engine_process.cpp
)

add_library(secure_frontend_engine_protocol_client
    src/engine_protocol_client.cpp
)

add_library(secure_frontend_engine_stdio_process
    src/cgroup_scope.cpp
    src/engine_stdio_process.cpp
    src/exit_status.cpp
)

add_library(secure_frontend_http_socket_server
    src/http_socket_server.cpp
    src/connection_handler.cpp
    src/process_defaults.cpp
)

add_library(secure_frontend_paths src/canonical_path_common.cpp)
target_sources(secure_frontend_paths PRIVATE src/canonical_path_posix.cpp src/canonical_path_windows.cpp src/windows_security.cpp)
target_compile_features(secure_frontend_paths PUBLIC cxx_std_20)
target_include_directories(secure_frontend_paths PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

add_library(secure_frontend_model_inventory
    src/model_inventory.cpp
)

add_library(secure_frontend_engine_arguments
    src/engine_arguments.cpp
)

add_library(secure_frontend_json
    src/json.cpp
)

secure_frontend_add_library(secure_frontend_parity
    SOURCES src/parity_table.cpp)

add_library(secure_frontend_typed_config src/frontend_config.cpp src/config_file.cpp)
target_compile_features(secure_frontend_typed_config PUBLIC cxx_std_20)
target_include_directories(secure_frontend_typed_config PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_typed_config PUBLIC secure_frontend_config secure_frontend_json
    secure_frontend_model_inventory secure_frontend_engine_arguments secure_frontend_parity)
target_link_libraries(secure_frontend_typed_config PUBLIC secure_frontend_paths)
# SP4 §3.9: pull.proxy is parsed by parse_proxy (ProxySetting).
target_link_libraries(secure_frontend_typed_config PUBLIC secure_frontend_manifest_core)
# SP3 §5.1: listener.host_aliases / cors_origins entries use the HTTP policy grammar.
target_link_libraries(secure_frontend_typed_config PUBLIC secure_frontend_http_policy)

add_library(secure_frontend_server_cli src/server_cli.cpp)
target_sources(secure_frontend_server_cli PRIVATE src/frontend_init.cpp)
target_compile_features(secure_frontend_server_cli PUBLIC cxx_std_20)
target_include_directories(secure_frontend_server_cli PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_server_cli PUBLIC secure_frontend_typed_config)
target_link_libraries(secure_frontend_server_cli PUBLIC secure_frontend_token_store)

add_library(secure_frontend_chat_schema
    src/chat_schema.cpp
)

add_library(secure_frontend_tokenizer_pack
    src/tokenizer_pack.cpp
)

add_library(secure_frontend_qwen_prompt_renderer
    src/qwen_prompt_renderer.cpp
)

add_library(secure_frontend_glm_prompt_renderer
    src/glm_prompt_renderer.cpp
)

add_library(secure_frontend_chat_generation_plan
    src/chat_generation_plan.cpp
)

add_library(secure_frontend_chat_execution
    src/chat_execution.cpp
)

add_library(secure_frontend_engine_supervisor
    src/descendant_sweep.cpp
    src/engine_environment.cpp
    src/engine_supervisor.cpp
    src/vision_supervisor.cpp
    src/privilege_check.cpp
    src/restart_policy.cpp
    src/shutdown_signal.cpp
    src/supervisor_wake.cpp
)
add_library(secure_frontend_secrets src/secret_bytes.cpp src/token_generator.cpp src/token_verifier.cpp)
target_compile_features(secure_frontend_secrets PUBLIC cxx_std_20)
target_include_directories(secure_frontend_secrets PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

add_library(secure_frontend_token_store src/token_store.cpp)
target_compile_features(secure_frontend_token_store PUBLIC cxx_std_20)
target_include_directories(secure_frontend_token_store PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

# SP5 M1 Task 12: the image_url payload gate (data URL -> strict base64 -> caps -> 0600 staging).
add_library(secure_frontend_image_payload src/image_payload.cpp)
target_compile_features(secure_frontend_image_payload PUBLIC cxx_std_20)
target_include_directories(secure_frontend_image_payload PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_image_payload PUBLIC secure_frontend_sha256 secure_frontend_secrets
    secure_frontend_engine_supervisor)
target_link_libraries(secure_frontend_token_store PUBLIC secure_frontend_paths secure_frontend_secrets)
target_link_libraries(secure_frontend_token_store PUBLIC secure_frontend_token_reader)

add_library(secure_frontend_subsystem_limits src/subsystem_limits.cpp)
target_compile_features(secure_frontend_subsystem_limits PUBLIC cxx_std_20)
target_include_directories(secure_frontend_subsystem_limits PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_subsystem_limits PUBLIC secure_frontend_typed_config
    secure_frontend_http_socket_server secure_frontend_chat_execution secure_frontend_chat_schema
    secure_frontend_engine_supervisor secure_frontend_image_payload)

add_executable(secure-frontend-smoke src/smoke_main.cpp)

# This deliberately small executable exposes only the authenticated smoke-test
# API.  It is not linked to the legacy Python service or any downloader.
add_executable(strata-secure-smoke-server
    src/smoke_server_main.cpp
)

# The production-shaped native listener.  It keeps the engine behind the
# authenticated HTTP boundary and deliberately links no legacy Python service.
add_executable(strata-secure-server
    src/secure_server_main.cpp
)

target_compile_features(secure_frontend_http_policy PUBLIC cxx_std_20)
target_include_directories(secure_frontend_http_policy
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_http_policy PUBLIC secure_frontend_api_core secure_frontend_config)

target_compile_features(secure_frontend_http_request_handler PUBLIC cxx_std_20)
target_include_directories(secure_frontend_http_request_handler
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_http_request_handler PUBLIC secure_frontend_http_policy secure_frontend_secrets)
target_link_libraries(secure_frontend_http_request_handler PUBLIC secure_frontend_api_core)

target_compile_features(secure_frontend_http_socket_server PUBLIC cxx_std_20)
target_include_directories(secure_frontend_http_socket_server
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_http_socket_server PUBLIC secure_frontend_socket_io secure_frontend_http_request_handler
    secure_frontend_config secure_frontend_api_core secure_frontend_sse)
# SP3 Task 11: admission state (§2.3) and the lingering-close list (§2.4).
# Task 12: the pool itself (§2.1, §2.8) — accept thread + fixed workers.
secure_frontend_add_library(secure_frontend_connection_pool
    SOURCES src/admission.cpp src/linger_list.cpp src/connection_pool.cpp
    LINKS secure_frontend_http_socket_server secure_frontend_socket_io secure_frontend_api_core)
# SP3 Task 13: SupervisorPort (one mutex into SP2, D-1) and the FIFO generation gate (§2.5).
secure_frontend_add_library(secure_frontend_generation_gate
    SOURCES src/supervisor_port.cpp src/generation_gate.cpp
    LINKS secure_frontend_engine_supervisor secure_frontend_api_core)

secure_frontend_add_library(secure_frontend_chat_route
    SOURCES src/chat_route.cpp
    LINKS secure_frontend_generation_gate secure_frontend_chat_execution secure_frontend_chat_schema
          secure_frontend_chat_generation_plan secure_frontend_secrets secure_frontend_api_core
          secure_frontend_image_payload)
target_link_libraries(secure_frontend_chat_route PUBLIC secure_frontend_chat_stream)

secure_frontend_add_library(secure_frontend_request_log
    SOURCES src/request_log.cpp
    LINKS secure_frontend_connection_pool)

target_compile_features(secure_frontend_api_router PUBLIC cxx_std_20)
target_include_directories(secure_frontend_api_router
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_api_router PUBLIC secure_frontend_http_policy secure_frontend_http_request_handler)
target_link_libraries(secure_frontend_api_router PUBLIC secure_frontend_api_core)

target_compile_features(secure_frontend_engine_process PUBLIC cxx_std_20)
target_include_directories(secure_frontend_engine_process
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(secure_frontend_engine_protocol_client PUBLIC cxx_std_20)
target_include_directories(secure_frontend_engine_protocol_client
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(secure_frontend_engine_stdio_process PUBLIC cxx_std_20)
target_include_directories(secure_frontend_engine_stdio_process
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_engine_stdio_process PUBLIC secure_frontend_engine_protocol_client)

target_compile_features(secure_frontend_model_inventory PUBLIC cxx_std_20)
target_include_directories(secure_frontend_model_inventory
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(secure_frontend_engine_arguments PUBLIC cxx_std_20)
target_include_directories(secure_frontend_engine_arguments
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_engine_arguments PUBLIC secure_frontend_model_inventory)
target_link_libraries(secure_frontend_engine_arguments PUBLIC secure_frontend_paths)
# SP5 M1 Task 5: compose_effort_end_arguments encodes "system" with the tokenizer pack.
target_link_libraries(secure_frontend_engine_arguments PUBLIC secure_frontend_tokenizer_pack)
target_compile_features(secure_frontend_json PUBLIC cxx_std_20)
target_include_directories(secure_frontend_json PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_chat_schema PUBLIC secure_frontend_json secure_frontend_api_core)
target_link_libraries(secure_frontend_tokenizer_pack PUBLIC secure_frontend_json secure_frontend_paths)
target_compile_features(secure_frontend_chat_schema PUBLIC cxx_std_20)
target_include_directories(secure_frontend_chat_schema
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(secure_frontend_tokenizer_pack PUBLIC cxx_std_20)
target_include_directories(secure_frontend_tokenizer_pack
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_compile_features(secure_frontend_qwen_prompt_renderer PUBLIC cxx_std_20)
target_include_directories(secure_frontend_qwen_prompt_renderer
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_qwen_prompt_renderer PUBLIC secure_frontend_chat_schema)
target_compile_features(secure_frontend_glm_prompt_renderer PUBLIC cxx_std_20)
target_include_directories(secure_frontend_glm_prompt_renderer
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_glm_prompt_renderer PUBLIC secure_frontend_chat_schema)
target_compile_features(secure_frontend_chat_generation_plan PUBLIC cxx_std_20)
target_include_directories(secure_frontend_chat_generation_plan
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_chat_generation_plan
    PUBLIC secure_frontend_chat_schema secure_frontend_qwen_prompt_renderer secure_frontend_glm_prompt_renderer secure_frontend_tokenizer_pack)
target_compile_features(secure_frontend_chat_execution PUBLIC cxx_std_20)
target_include_directories(secure_frontend_chat_execution
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_chat_execution
    PUBLIC secure_frontend_chat_generation_plan secure_frontend_engine_protocol_client secure_frontend_tokenizer_pack)
# SP3 M2 Task 5: the one generation loop shared by the complete and stream paths.
secure_frontend_add_library(secure_frontend_generation_run SOURCES src/generation_run.cpp
    LINKS secure_frontend_engine_protocol_client secure_frontend_tokenizer_pack secure_frontend_utf8_stream secure_frontend_api_core)
target_link_libraries(secure_frontend_chat_execution PUBLIC secure_frontend_generation_run)
target_compile_features(secure_frontend_engine_supervisor PUBLIC cxx_std_20)
target_include_directories(secure_frontend_engine_supervisor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_engine_supervisor
    PUBLIC secure_frontend_chat_execution secure_frontend_engine_stdio_process)
# engine_environment.cpp: SP1's windows_security helpers (the --state-dir check).
target_link_libraries(secure_frontend_engine_supervisor PRIVATE secure_frontend_paths)
target_link_libraries(secure-frontend-smoke PRIVATE secure_frontend_config secure_frontend_token_reader
    secure_frontend_http_policy secure_frontend_http_request_handler secure_frontend_http_socket_server
    secure_frontend_api_router secure_frontend_model_inventory)
target_compile_features(secure-frontend-smoke PRIVATE cxx_std_20)
target_link_libraries(strata-secure-smoke-server PRIVATE secure_frontend_config secure_frontend_token_reader
    secure_frontend_http_policy secure_frontend_http_request_handler secure_frontend_http_socket_server
    secure_frontend_api_router secure_frontend_model_inventory)
target_compile_features(strata-secure-smoke-server PRIVATE cxx_std_20)
target_link_libraries(strata-secure-server PRIVATE secure_frontend_config secure_frontend_token_reader
    secure_frontend_http_policy secure_frontend_http_request_handler secure_frontend_http_socket_server
    secure_frontend_api_router secure_frontend_model_inventory secure_frontend_tokenizer_pack
    secure_frontend_engine_protocol_client secure_frontend_engine_stdio_process secure_frontend_chat_schema
    secure_frontend_chat_generation_plan secure_frontend_chat_execution secure_frontend_engine_arguments)
target_link_libraries(strata-secure-server PRIVATE secure_frontend_server_cli secure_frontend_typed_config)
target_link_libraries(strata-secure-server PRIVATE secure_frontend_subsystem_limits secure_frontend_engine_supervisor)
target_link_libraries(strata-secure-server PRIVATE secure_frontend_socket_io secure_frontend_api_core)
target_link_libraries(strata-secure-server PRIVATE secure_frontend_connection_pool secure_frontend_chat_route secure_frontend_request_log)
target_compile_features(strata-secure-server PRIVATE cxx_std_20)
# Spec A2: UTF-8 argv from the wide command line on Windows, shared by
# strata-secure-server and strata (CommandLineToArgvW: shell32).
add_library(secure_frontend_utf8_argv src/utf8_argv.cpp)
target_compile_features(secure_frontend_utf8_argv PUBLIC cxx_std_20)
target_include_directories(secure_frontend_utf8_argv PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
if(WIN32)
    target_link_libraries(secure_frontend_utf8_argv PUBLIC shell32)
endif()
secure_frontend_set_warnings(secure_frontend_utf8_argv)
target_link_libraries(strata-secure-server PRIVATE secure_frontend_utf8_argv)

target_link_libraries(secure_frontend_config PUBLIC secure_frontend_paths)
target_link_libraries(secure_frontend_model_inventory PUBLIC secure_frontend_paths)

target_compile_features(secure_frontend_config PUBLIC cxx_std_20)
target_include_directories(secure_frontend_config
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(secure_frontend_token_reader PUBLIC cxx_std_20)
target_include_directories(secure_frontend_token_reader
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_token_reader PUBLIC secure_frontend_config)
target_link_libraries(secure_frontend_token_reader PUBLIC secure_frontend_paths)
target_link_libraries(secure_frontend_token_reader PUBLIC secure_frontend_secrets)

if(WIN32)
    target_link_libraries(secure_frontend_config PUBLIC ws2_32)
    target_link_libraries(secure_frontend_http_socket_server PUBLIC ws2_32)
    target_link_libraries(secure_frontend_token_reader PUBLIC advapi32)
    target_link_libraries(secure_frontend_engine_stdio_process PUBLIC advapi32 secure_frontend_secrets)
    # SP2 R4: win_launch::launch_in_job, the engine's CreateProcessW + Job sequence (SP4 seam).
    target_sources(secure_frontend_engine_stdio_process PRIVATE src/win_child_launch.cpp)
    target_link_libraries(secure_frontend_paths PUBLIC advapi32)
    target_link_libraries(secure_frontend_secrets PUBLIC bcrypt)
    target_link_libraries(secure_frontend_token_reader PUBLIC crypt32)
    target_link_libraries(secure_frontend_token_store PUBLIC crypt32 advapi32)
endif()

foreach(_target IN ITEMS
        secure_frontend_paths secure_frontend_config secure_frontend_token_reader secure_frontend_http_policy
        secure_frontend_http_request_handler secure_frontend_api_router secure_frontend_engine_process
        secure_frontend_engine_protocol_client secure_frontend_engine_stdio_process
        secure_frontend_http_socket_server secure_frontend_model_inventory secure_frontend_engine_arguments
        secure_frontend_json secure_frontend_typed_config secure_frontend_server_cli secure_frontend_chat_schema
        secure_frontend_tokenizer_pack secure_frontend_qwen_prompt_renderer secure_frontend_glm_prompt_renderer
        secure_frontend_chat_generation_plan secure_frontend_chat_execution secure_frontend_engine_supervisor
        secure_frontend_subsystem_limits secure_frontend_secrets secure_frontend_token_store
        secure-frontend-smoke strata-secure-smoke-server strata-secure-server)
    secure_frontend_set_warnings(${_target})
endforeach()

# --- SP4 acquisition libraries ---
add_library(secure_frontend_sha256 src/sha256.cpp)
target_compile_features(secure_frontend_sha256 PUBLIC cxx_std_20)
target_include_directories(secure_frontend_sha256 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
secure_frontend_set_warnings(secure_frontend_sha256)

add_library(secure_frontend_manifest_core src/acquire_reason.cpp src/acquire_url.cpp)
target_compile_features(secure_frontend_manifest_core PUBLIC cxx_std_20)
target_include_directories(secure_frontend_manifest_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(secure_frontend_manifest_core PRIVATE src/engine_version.cpp src/acquire_manifest.cpp src/model_index_model.cpp)
target_link_libraries(secure_frontend_manifest_core PUBLIC secure_frontend_sha256)
# SP1 model-ID grammar and reserved device names (validate_model_id, is_windows_reserved_component).
target_link_libraries(secure_frontend_manifest_core PUBLIC secure_frontend_model_inventory)
secure_frontend_set_warnings(secure_frontend_manifest_core)

add_library(secure_frontend_acquire_core src/address_policy.cpp src/download_response.cpp src/downloader_command.cpp
    src/fetch_schedule.cpp src/staging_plan.cpp src/bundle_text.cpp src/manifest_diff.cpp
    src/confinement_plan.cpp)
target_compile_features(secure_frontend_acquire_core PUBLIC cxx_std_20)
target_include_directories(secure_frontend_acquire_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_acquire_core PUBLIC secure_frontend_manifest_core)
secure_frontend_set_warnings(secure_frontend_acquire_core)

# Models store primitives (spec §4; Windows parity spec §11).
if(WIN32)
    set(_sf_models_store_platform src/models_store_windows.cpp)
else()
    set(_sf_models_store_platform src/models_store_posix.cpp)
endif()
add_library(secure_frontend_acquire src/models_store_common.cpp ${_sf_models_store_platform})
target_sources(secure_frontend_acquire PRIVATE src/model_index_write.cpp src/acquire_publish.cpp src/bundle_io.cpp)
# SP4 Task 21 (spec §3.3-§3.7): per-file fetch over an abstract hop transport; getaddrinfo resolver.
target_sources(secure_frontend_acquire PRIVATE src/fetch_file.cpp src/system_resolver.cpp)
# SP4 Task 22 (spec §1.3, §3.7, §4.6, §6.1): pull orchestration over the hop transport.
target_sources(secure_frontend_acquire PRIVATE src/acquire_pull.cpp)
target_compile_features(secure_frontend_acquire PUBLIC cxx_std_20)
target_include_directories(secure_frontend_acquire PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_acquire PUBLIC secure_frontend_acquire_core secure_frontend_model_store
    secure_frontend_token_store secure_frontend_tokenizer_pack)
# PullSettings (frontend_config.hpp) for run_pull.
target_link_libraries(secure_frontend_acquire PUBLIC secure_frontend_typed_config)
if(WIN32)
    target_link_libraries(secure_frontend_acquire PUBLIC advapi32 ws2_32)
endif()
secure_frontend_set_warnings(secure_frontend_acquire)

# SP4 Tasks 25/26 (spec §3.1-§3.3): the confined system curl. Linked only by
# secure_frontend_strata_cli and tests; strata-secure-server never links it (§7.1).
add_library(secure_frontend_downloader src/downloader_common.cpp)
target_compile_features(secure_frontend_downloader PUBLIC cxx_std_20)
target_include_directories(secure_frontend_downloader PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_downloader PUBLIC secure_frontend_acquire)
if(WIN32)
    # Task 26: win_launch::launch_in_job lives in secure_frontend_engine_stdio_process (ruling B3).
    target_sources(secure_frontend_downloader PRIVATE src/downloader_windows.cpp)
    target_link_libraries(secure_frontend_downloader PUBLIC secure_frontend_engine_stdio_process advapi32)
else()
    target_sources(secure_frontend_downloader PRIVATE src/downloader_posix.cpp)
    # secure_frontend_engine_process provides EngineCommand for posix_launch::prepare.
    target_link_libraries(secure_frontend_downloader PUBLIC secure_frontend_engine_process)
endif()
secure_frontend_set_warnings(secure_frontend_downloader)

# SP4 §2.3 / ruling R-1: the engine version is the committed ../upstream.version
# (one line, "v<x.y.z[.n]>"). When upstream/ has a reachable exact tag it must equal
# the file (FATAL_ERROR only on a mismatch); a missing tag never fails configure.
set(SECURE_STRATA_ENGINE_VERSION "" CACHE STRING "Override x.y.z[.n]; empty = ../upstream.version")
if(SECURE_STRATA_ENGINE_VERSION STREQUAL "")
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../upstream.version" _sf_pinned LIMIT_COUNT 1)
    if(NOT _sf_pinned MATCHES "^v[0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?$")
        message(FATAL_ERROR "upstream.version must hold one line v<x.y.z[.n]>")
    endif()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../upstream.version")
    set(_sf_describe_rc 1)
    # Only a checked-out submodule is asked: an empty upstream/ must never let git walk up to the superproject's tags.
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../upstream/.git")
        execute_process(COMMAND git -C "${CMAKE_CURRENT_SOURCE_DIR}/../upstream" describe --tags --exact-match
            RESULT_VARIABLE _sf_describe_rc OUTPUT_VARIABLE _sf_tag ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()
    if(_sf_describe_rc EQUAL 0 AND NOT _sf_tag STREQUAL _sf_pinned)
        message(FATAL_ERROR "upstream/ is at ${_sf_tag} but upstream.version says ${_sf_pinned}; bump upstream.version with the submodule")
    endif()
    string(SUBSTRING "${_sf_pinned}" 1 -1 SECURE_FRONTEND_ENGINE_VERSION_TEXT)
else()
    if(NOT SECURE_STRATA_ENGINE_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?$")
        message(FATAL_ERROR "SECURE_STRATA_ENGINE_VERSION must be x.y.z or x.y.z.n")
    endif()
    set(SECURE_FRONTEND_ENGINE_VERSION_TEXT "${SECURE_STRATA_ENGINE_VERSION}")
endif()
configure_file(cmake/engine_version.hpp.in
    "${CMAKE_CURRENT_BINARY_DIR}/generated/secure_frontend/engine_version_generated.hpp" @ONLY)

include(cmake/SecureFrontendCatalog.cmake)
set(_sf_catalog_fixture "")
if(SECURE_FRONTEND_TEST_HOOKS)
    set(_sf_catalog_fixture FIXTURE "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/catalog")
endif()
secure_frontend_generate_catalog("${CMAKE_CURRENT_BINARY_DIR}/generated/catalog_data.cpp"
    PRODUCTION "${CMAKE_CURRENT_SOURCE_DIR}/catalog" ${_sf_catalog_fixture})

add_library(secure_frontend_model_store src/manifest_json.cpp src/catalog.cpp src/manifest_trust.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/generated/catalog_data.cpp")
target_compile_features(secure_frontend_model_store PUBLIC cxx_std_20)
target_include_directories(secure_frontend_model_store PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_include_directories(secure_frontend_model_store PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(secure_frontend_model_store PUBLIC secure_frontend_manifest_core secure_frontend_json secure_frontend_paths)
# SP4 §4.9 delta b.
target_sources(secure_frontend_model_store PRIVATE src/model_index_store.cpp)
# SP4 §2.3 / F-58: the one engine gate (list/show state, run, managed launch).
target_sources(secure_frontend_model_store PRIVATE src/engine_gate.cpp)
secure_frontend_set_warnings(secure_frontend_model_store)

# SP4 Task 24b (spec §2.3, §2.4, §4.9 c/d): the engine launch composed from the installed
# manifest (or SP1's inventory path under --expert). Server-safe: no acquisition library.
add_library(secure_frontend_launch src/launch_composition.cpp)
target_compile_features(secure_frontend_launch PUBLIC cxx_std_20)
target_include_directories(secure_frontend_launch PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_launch PUBLIC secure_frontend_model_store secure_frontend_typed_config
    secure_frontend_engine_arguments secure_frontend_model_inventory)
secure_frontend_set_warnings(secure_frontend_launch)
target_link_libraries(strata-secure-server PRIVATE secure_frontend_launch)

# SP5 M1 Task 13 (Ruling T13-b): the supervised serve path as a library — the one
# boot `strata-secure-server` and `strata serve` share (server_bootstrap.hpp).
secure_frontend_add_library(secure_frontend_server_bootstrap
    SOURCES src/server_bootstrap.cpp
    LINKS secure_frontend_config secure_frontend_token_reader secure_frontend_secrets
          secure_frontend_http_policy secure_frontend_http_request_handler secure_frontend_http_socket_server
          secure_frontend_api_router secure_frontend_model_inventory secure_frontend_tokenizer_pack
          secure_frontend_engine_protocol_client secure_frontend_engine_stdio_process secure_frontend_chat_schema
          secure_frontend_chat_generation_plan secure_frontend_chat_execution secure_frontend_engine_arguments
          secure_frontend_typed_config secure_frontend_subsystem_limits secure_frontend_engine_supervisor
          secure_frontend_socket_io secure_frontend_api_core secure_frontend_connection_pool
          secure_frontend_chat_route secure_frontend_request_log secure_frontend_launch)
target_link_libraries(strata-secure-server PRIVATE secure_frontend_server_bootstrap)

# SP4 Task 23 (spec §1.5): the strata CLI's verbs.
add_library(secure_frontend_strata_cli src/strata_cli.cpp)
target_compile_features(secure_frontend_strata_cli PUBLIC cxx_std_20)
target_include_directories(secure_frontend_strata_cli PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_strata_cli PUBLIC secure_frontend_acquire secure_frontend_typed_config
    secure_frontend_server_bootstrap
    secure_frontend_server_cli)  # SP5 M1 Tasks 13/14: shared boot; frontend_init's token store for `key`
target_link_libraries(secure_frontend_strata_cli PUBLIC secure_frontend_launch)
# SP4 Task 27: pull, run, update --models and doctor drive the confined downloader.
target_sources(secure_frontend_strata_cli PRIVATE src/strata_cli_network.cpp)
target_link_libraries(secure_frontend_strata_cli PUBLIC secure_frontend_downloader)
# SP7 M1 Tasks 1-3: service verbs and the full doctor live beside the network verbs.
target_link_libraries(secure_frontend_strata_cli PUBLIC secure_frontend_service_ops secure_frontend_doctor)
# SP7 M1 Task 4/5: the uninstall verb.
target_link_libraries(secure_frontend_strata_cli PUBLIC secure_frontend_uninstall)
if(WIN32)
    target_link_libraries(secure_frontend_strata_cli PUBLIC ws2_32)
endif()
secure_frontend_set_warnings(secure_frontend_strata_cli)

# SP7 M1 Task 1 (spec D-5): the per-user service unit — rendering, and the
# enable/disable/status verbs that use it (Task 2).
secure_frontend_add_library(secure_frontend_service_ops SOURCES src/service_ops.cpp)

# SP7 M1 Task 3 (spec D-7): the doctor check set — pure checks over an injected
# ProbeBundle; the verb composes them (strata_cli_network).
secure_frontend_add_library(secure_frontend_doctor SOURCES src/doctor_checks.cpp
    LINKS secure_frontend_typed_config)

# SP7 M1 Task 4 (spec D-6): the uninstall planner — ordered removals under allowed
# roots, the health-probe stop decision, the --purge typed gate.
secure_frontend_add_library(secure_frontend_uninstall SOURCES src/uninstall_plan.cpp
    LINKS secure_frontend_typed_config)
if(WIN32)
    target_link_libraries(secure_frontend_uninstall PUBLIC ws2_32)
endif()

# PX §2: the one user-facing binary. SP4 provides only its acquisition verbs (Controller note 1);
# strata-secure-server never links secure_frontend_acquire or secure_frontend_strata_cli (§7.1).
add_executable(strata src/strata_main.cpp)
target_link_libraries(strata PRIVATE secure_frontend_strata_cli secure_frontend_utf8_argv)
target_compile_features(strata PRIVATE cxx_std_20)
secure_frontend_set_warnings(strata)

# SP3 M2 — streaming.
secure_frontend_add_library(secure_frontend_utf8_stream SOURCES src/utf8_stream_decoder.cpp)
secure_frontend_add_library(secure_frontend_sse SOURCES src/sse_encoder.cpp src/stream_socket.cpp src/chunked_stream_sink.cpp
    LINKS secure_frontend_json secure_frontend_api_core secure_frontend_utf8_stream secure_frontend_socket_io)
secure_frontend_add_library(secure_frontend_chat_stream SOURCES src/chat_stream.cpp src/lease_hold.cpp
    LINKS secure_frontend_sse secure_frontend_generation_run secure_frontend_engine_supervisor secure_frontend_generation_gate secure_frontend_chat_execution)
# SP3 M2 (R-B): loopback-only client for strata run, the tests and strata-api-probe. Never linked into the serve path.
secure_frontend_add_library(secure_frontend_api_client SOURCES src/loopback_address.cpp src/api_client.cpp src/run_target.cpp
    LINKS secure_frontend_config secure_frontend_socket_io secure_frontend_api_core secure_frontend_json)

if(STRATA_BUILD_SECURE_FRONTEND_TESTS)
    enable_testing()

    # SP3 M2: SSE encoder, UTF-8 stream decoder, sink and stream pump units. Pure: unlabeled, also run under wine.
    secure_frontend_add_test_executable(secure_frontend_sse_tests tests/sse_test.cpp secure_frontend_utf8_stream secure_frontend_sse secure_frontend_chat_stream)
    set(SECURE_FRONTEND_SSE_CASES
        utf8_split_across_tokens_is_held_then_released utf8_invalid_sequence_becomes_replacement_character
        utf8_incomplete_tail_dropped_on_length_and_cancel utf8_incomplete_tail_on_stop_becomes_one_replacement
        sse_events_never_contain_raw_newline sse_coalesced_control_heavy_text_respects_event_cap sse_chunk_framing_units
        sse_chunked_framing_and_terminal_chunk sink_buffers_on_would_block_and_flushes_later
        sink_write_stall_marks_client_gone sink_send_failure_and_peer_probe_are_gone
        sse_role_content_final_done_sequence sse_include_usage_adds_usage_chunk sse_ids_and_created_constant_per_stream
        stream_with_no_tokens_has_role_final_done stream_slow_reader_coalesces_deltas stream_tail_deadline_cuts_without_terminal_chunk
        stream_client_gone_sends_stop keepalive_never_splits_a_pending_event stream_error_events_follow_text_and_end_with_done
        stream_shutdown_sends_error_event_and_done)
    secure_frontend_add_cases(secure_frontend_sse_tests ${SECURE_FRONTEND_SSE_CASES} TIMEOUT 120)

    secure_frontend_add_test_executable(secure_frontend_paths_tests tests/paths_test.cpp secure_frontend_paths)
    secure_frontend_add_cases(secure_frontend_paths_tests
        relative_path_accepts_portable_forms cfg02_rejects_traversal_and_absolute cfg02_rejects_nul_and_control_bytes
        cfg04_rejects_reserved_and_device_names cfg04_rejects_trailing_dot_space_and_8dot3 cfg04_rejects_ads_and_drive_forms)
    secure_frontend_add_cases(secure_frontend_paths_tests
        cfg02_rejects_relative_root cfg02_sibling_prefix_root_rejected cfg04_rejects_unc_device_and_extended_roots
        cfg04_final_path_on_network_share_is_actionable)
    target_link_libraries(secure_frontend_paths_tests PRIVATE secure_frontend_token_reader)
    secure_frontend_add_cases(secure_frontend_paths_tests paths_handle_non_ascii_and_long_names
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    secure_frontend_add_cases(secure_frontend_paths_tests cfg02_create_within_root_writes_nothing_outside
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # SP1 delta f (SP4 §5.3): RootPolicy::external for bundle directories.
    secure_frontend_add_cases(secure_frontend_paths_tests external_root_skips_ownership_checks
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(WIN32)
        secure_frontend_add_cases(secure_frontend_paths_tests
            auth02_windows_token_file_reads_with_private_dacl cfg03_rejects_junction_below_root
            cfg03_rejects_symlink_below_root
            LABELS windows-runtime)
        set_tests_properties(secure_frontend_paths_tests.cfg03_rejects_symlink_below_root PROPERTIES
            SKIP_REGULAR_EXPRESSION "SKIPPED:")
    endif()
    if(NOT WIN32)
        secure_frontend_add_cases(secure_frontend_paths_tests
            cfg02_rejects_shared_writable_root cfg02_root_may_traverse_symlink
            cfg02_engine_executable_must_be_private_regular_file)
        secure_frontend_add_cases(secure_frontend_paths_tests
            cfg03_rejects_symlinked_intermediate_directory cfg03_rejects_symlinked_final_file
            cfg03_fallback_walk_matches_openat2 cfg03_rejects_mount_crossing)
        set_tests_properties(secure_frontend_paths_tests.cfg03_rejects_mount_crossing PROPERTIES
            SKIP_REGULAR_EXPRESSION "SKIPPED:")
    endif()

    secure_frontend_add_test_executable(secure_frontend_secrets_tests tests/secrets_test.cpp secure_frontend_secrets)
    secure_frontend_add_cases(secure_frontend_secrets_tests
        base64url_known_vectors token_generate_is_43_base64url_chars token_generate_differs_across_calls
        secret_bytes_wiped_on_destroy_and_move secret_bytes_rejects_over_capacity
        auth03_compare_touches_fixed_window auth03_prefix_and_suffix_variants_rejected)

    secure_frontend_add_test_executable(secure_frontend_token_store_tests tests/token_store_test.cpp
        secure_frontend_token_store)
    if(NOT WIN32)
        secure_frontend_add_cases(secure_frontend_token_store_tests
            token_store_creates_0600_file_in_0700_dir token_store_rotate_is_atomic token_store_refuses_symlinked_target
            token_store_round_trips_through_reader)
    endif()
    target_link_libraries(secure_frontend_token_store_tests PRIVATE secure_frontend_token_reader)
    if(WIN32)
        secure_frontend_add_cases(secure_frontend_token_store_tests
            token_store_windows_round_trips_through_dpapi token_store_windows_file_has_private_dacl
            token_reader_windows_accepts_plaintext_under_private_dacl
            LABELS windows-runtime)
    endif()

    secure_frontend_add_test_executable(secure_frontend_config_tests tests/config_test.cpp secure_frontend_config)
    secure_frontend_add_cases(secure_frontend_config_tests
        defaults_to_loopback requires_key_for_loopback requires_explicit_opt_in_for_remote_host
        requires_key_after_remote_opt_in accepts_remote_host_with_opt_in_and_key
        requires_separate_opt_in_for_wildcard_host rejects_invalid_ports rejects_invalid_hosts_and_blank_remote_keys
        net03_wildcard_spellings_need_wildcard_opt_in net03_remote_opt_in_alone_rejects_wildcard
        net01_loopback_spellings_classified_from_bytes net02_hostname_rejected_before_bind
        net01_localhost_maps_to_ipv4_loopback)

    secure_frontend_add_test_executable(secure_frontend_secret_source_tests tests/secret_source_test.cpp secure_frontend_config)
    secure_frontend_add_cases(secure_frontend_secret_source_tests
        accepts_environment_variable_name_without_retaining_a_secret accepts_protected_file_path_metadata
        rejects_unsafe_environment_variable_names rejects_blank_or_control_containing_file_paths
        rejects_paths_that_escape_or_trigger_platform_special_handling)

    # Built and run on every platform (SP1 K4). Protected-file cases need real
    # Windows ACL semantics: windows-runtime there, run by the windows-msys2-clang
    # job and excluded under wine.
    secure_frontend_add_test_executable(secure_frontend_token_reader_tests tests/token_reader_test.cpp
        secure_frontend_token_reader)
    secure_frontend_add_cases(secure_frontend_token_reader_tests
        reads_the_named_environment_variable rejects_control_characters_in_environment_token
        auth02_short_operator_token_rejected)
    secure_frontend_add_cases(secure_frontend_token_reader_tests
        reads_an_owner_only_regular_file_below_the_root rejects_control_characters_in_file_token
        auth02_token_file_with_trailing_lf_accepted auth02_token_file_with_trailing_crlf_accepted
        auth02_token_file_with_two_newlines_rejected auth02_token_file_with_bom_rejected
        auth02_token_file_over_4k_rejected auth02_notepad_edits_rejected_with_reason
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(NOT WIN32)
        secure_frontend_add_cases(secure_frontend_token_reader_tests
            rejects_a_group_or_world_accessible_file rejects_a_symlink_that_escapes_the_root rejects_a_non_regular_file
            cfg03_rejects_hardlinked_token_file cfg05_env_token_absent_from_proc_environ)
    endif()

    secure_frontend_add_test_executable(secure_frontend_engine_stdio_process_tests tests/engine_stdio_process_test.cpp
        secure_frontend_engine_stdio_process)
    set(_stdio_cases test_round_trip test_invalid_record write_line_fails_once_deadline_passed read_line_rejects_oversize_on_all_platforms
        read_line_waits_for_a_record_split_across_writes)
    if(WIN32)
        list(APPEND _stdio_cases job_object_terminates_grandchild)
    else()
        list(APPEND _stdio_cases child_inherits_only_stdio_descriptors child_receives_exact_argv_and_env
            terminate_reaps_killed_child)
    endif()
    secure_frontend_add_cases(secure_frontend_engine_stdio_process_tests ${_stdio_cases} TIMEOUT 300)

    # SP2 F1: test-only stand-in for `strata --serve`. Never installed. SP1's own
    # fake (tests/fake_engine_main.cpp, secure_frontend_fake_engine) is separate.
    # SP3 Task 14: the fake reads stdin on a thread; the toolchain needs the
    # thread library linked (find_package adds it portably: -pthread on Linux,
    # winpthread for the mingw cross).
    find_package(Threads REQUIRED)
    add_executable(strata-supervision-fake-engine tests/supervision_fake_engine_main.cpp)
    target_link_libraries(strata-supervision-fake-engine PRIVATE Threads::Threads)
    target_include_directories(strata-supervision-fake-engine PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_features(strata-supervision-fake-engine PRIVATE cxx_std_20)
    secure_frontend_set_warnings(strata-supervision-fake-engine)
    if(WIN32)
        target_link_libraries(strata-supervision-fake-engine PRIVATE shell32 advapi32)
    endif()

    # SP5 M1 Task 11: test-only stand-in for `strata-vision` (the vision encoder child).
    # Never installed. Records its argv, answers READY, serves ENC/QUIT (see the file).
    add_executable(strata-fake-vision-child tests/fake_vision_child_main.cpp)
    target_compile_features(strata-fake-vision-child PRIVATE cxx_std_20)
    secure_frontend_set_warnings(strata-fake-vision-child)

    # Paths every SP2 test needs (fixture directories come from SP1's
    # make_scratch_directory below ${SECURE_FRONTEND_TEST_TMP}).
    function(secure_frontend_test_paths target)
        target_compile_definitions(${target} PRIVATE
            "STRATA_FAKE_ENGINE_PATH=\"$<TARGET_FILE:strata-supervision-fake-engine>\""
            "STRATA_FAKE_VISION_CHILD_PATH=\"$<TARGET_FILE:strata-fake-vision-child>\""
            "STRATA_SECURE_SERVER_PATH=\"$<TARGET_FILE:strata-secure-server>\"")
        add_dependencies(${target} strata-supervision-fake-engine strata-fake-vision-child strata-secure-server)
        if(TARGET strata_egress_tripwire)  # SP3 Task 19: Linux-only tripwire targets, when defined
            target_compile_definitions(${target} PRIVATE
                STRATA_EGRESS_TRIPWIRE_PATH="$<TARGET_FILE:strata_egress_tripwire>"
                STRATA_EGRESS_PROBE_PATH="$<TARGET_FILE:strata-egress-probe-helper>")
            add_dependencies(${target} strata_egress_tripwire strata-egress-probe-helper)
        endif()
        if(WIN32)
            target_link_libraries(${target} PRIVATE advapi32)  # grant_current_user()
        endif()
    endfunction()

    # SP3 Task 19 (spec §6.2): the LD_PRELOAD egress tripwire and its probe helper.
    # Test-only, Linux-only, and defined above the first secure_frontend_test_paths
    # call so if(TARGET ...) is true for every test binary that follows.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_library(strata_egress_tripwire SHARED tests/support/egress_tripwire.cpp)
        target_link_libraries(strata_egress_tripwire PRIVATE ${CMAKE_DL_LIBS})
        target_compile_features(strata_egress_tripwire PRIVATE cxx_std_20)
        secure_frontend_set_warnings(strata_egress_tripwire)
        add_executable(strata-egress-probe-helper tests/egress_probe_helper.cpp)
        target_compile_features(strata-egress-probe-helper PRIVATE cxx_std_20)
        secure_frontend_set_warnings(strata-egress-probe-helper)
    endif()

    # SP1 Task 2 already builds and registers secure_frontend_engine_stdio_process_tests.
    secure_frontend_test_paths(secure_frontend_engine_stdio_process_tests)

    secure_frontend_add_test_executable(secure_frontend_fake_engine_tests tests/fake_engine_test.cpp
        secure_frontend_engine_process secure_frontend_engine_stdio_process)
    secure_frontend_test_paths(secure_frontend_fake_engine_tests)
    # Crash exit codes are Windows runtime semantics: MSYS2 only.
    secure_frontend_add_cases(secure_frontend_fake_engine_tests fake_engine_modes_selftest fake_engine_dump_is_parseable
        fake_engine_stream_modes_selftest
        TIMEOUT 120 LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})

    # F3: start/stop the real server with the fake engine; process-tree helpers.
    add_library(secure_frontend_test_support STATIC tests/support/server_harness.cpp)
    target_include_directories(secure_frontend_test_support PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_features(secure_frontend_test_support PUBLIC cxx_std_20)
    target_link_libraries(secure_frontend_test_support PUBLIC secure_frontend_tokenizer_pack)
    # SP3 Task 9 (pre-flight P36): §7.2 bodies (api_errors) and the --config file renderer (config_json.hpp).
    target_link_libraries(secure_frontend_test_support PUBLIC secure_frontend_api_core secure_frontend_typed_config)
    # SP5 M1 Task 12: the managed-vision harness branch installs an fx model in-process
    # (publish_staged), so the store/manifest libraries join the support closure.
    target_link_libraries(secure_frontend_test_support PUBLIC secure_frontend_acquire secure_frontend_model_store
        secure_frontend_manifest_core)
    if(WIN32)
        target_link_libraries(secure_frontend_test_support PUBLIC ws2_32 advapi32)
    endif()
    secure_frontend_set_warnings(secure_frontend_test_support)
    secure_frontend_test_paths(secure_frontend_test_support)

    secure_frontend_add_test_executable(secure_frontend_server_tests tests/server_test.cpp secure_frontend_test_support)
    secure_frontend_test_paths(secure_frontend_server_tests)
    target_link_libraries(secure_frontend_server_tests PRIVATE secure_frontend_engine_stdio_process)
    # Later tasks append case names to these three set() lines only. Every
    # server-level test is windows-runtime on Windows: it relies on console
    # groups, Jobs, tokens and process exit codes.
    set(SECURE_FRONTEND_SERVER_CASES harness_server_lifecycle_selftest proc01_server_passes_literal_argv proc04_ready_is_eager_and_health_starting_is_503 proc04_chat_during_restart_is_generic_503 proc04_abort_in_generation_is_generic_503 proc04_health_leaves_ready_after_idle_engine_death state_dir_must_be_owner_only state_dir_stale_engine_tmp_is_cleared ext01_extension_fields_spawn_nothing ext02_extension_env_never_reaches_child ext02_rejected_before_spawn engine_cuda_cache_follows_roots_cache)
    set(SECURE_FRONTEND_SERVER_LINUX_CASES proc05_frontend_sigkill_kills_engine proc05_frontend_sigterm_stops_all_descendants proc05_frontend_sigint_stops_all_descendants proc05_frontend_has_only_engine_children proc05_sigterm_during_generation_exits_cleanly proc05_double_sigterm_is_idempotent proc05_sigterm_with_idle_client_exits_cleanly proc06_nnp_startup_hint_names_nvidia_uvm_fix)
    set(SECURE_FRONTEND_SERVER_WINDOWS_CASES proc05_windows_ctrl_break_stops_all_descendants proc05_windows_ctrl_break_with_idle_client_exits_cleanly proc05_windows_terminate_frontend_kills_job state_dir_must_be_owner_only_windows)
    if(WIN32)
        list(APPEND SECURE_FRONTEND_SERVER_CASES ${SECURE_FRONTEND_SERVER_WINDOWS_CASES})
    else()
        list(APPEND SECURE_FRONTEND_SERVER_CASES ${SECURE_FRONTEND_SERVER_LINUX_CASES})
    endif()
    secure_frontend_add_cases(secure_frontend_server_tests ${SECURE_FRONTEND_SERVER_CASES}
        TIMEOUT 120 LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(WIN32)
        target_link_libraries(secure_frontend_server_tests PRIVATE iphlpapi)  # SP3 Task 20: SocketScan reads the iphlpapi tables
    endif()

    # SP3 §9.5: test-only probe for the offline GPU kit. Never installed.
    add_executable(strata-api-probe tests/api_probe_main.cpp)
    target_link_libraries(strata-api-probe PRIVATE secure_frontend_api_client secure_frontend_json secure_frontend_utf8_stream secure_frontend_sha256)
    target_compile_features(strata-api-probe PRIVATE cxx_std_20)
    secure_frontend_set_warnings(strata-api-probe)

    secure_frontend_add_test_executable(secure_frontend_api_client_tests tests/api_client_test.cpp
        secure_frontend_api_client secure_frontend_test_support secure_frontend_engine_process)
    secure_frontend_test_paths(secure_frontend_api_client_tests)
    target_compile_definitions(secure_frontend_api_client_tests PRIVATE
        STRATA_API_PROBE_PATH="$<TARGET_FILE:strata-api-probe>")
    add_dependencies(secure_frontend_api_client_tests strata-api-probe)
    if(WIN32)
        target_link_libraries(secure_frontend_api_client_tests PRIVATE ws2_32)
    endif()
    # Real loopback sockets: windows-runtime on Windows.
    set(SECURE_FRONTEND_API_CLIENT_CASES client_reads_chunked_stream_and_requires_done_and_terminal_chunk client_rejects_event_over_cap
        client_accepts_only_loopback_address run_refuses_non_loopback_server_json probe_modes_pass_against_fake_engine)
    secure_frontend_add_cases(secure_frontend_api_client_tests ${SECURE_FRONTEND_API_CLIENT_CASES} TIMEOUT 120 LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})

    secure_frontend_add_test_executable(secure_frontend_api_server_tests tests/api_server_test.cpp
        secure_frontend_test_support secure_frontend_api_core secure_frontend_socket_io secure_frontend_api_client)
    secure_frontend_test_paths(secure_frontend_api_server_tests)
    set(SECURE_FRONTEND_API_SERVER_CASES
        dos01_body_over_limit_is_413_before_reading dos01_content_length_over_request_limit_is_413_before_auth
        dos01_unauthenticated_gets_401_before_body_is_read dos01_expect_continue_after_auth_only
        dos01_slow_header_is_408_at_header_deadline dos01_slow_body_is_408_at_request_deadline
        dos01_incomplete_body_then_close_frees_worker err_unauthenticated_is_401_on_every_path_and_method
        security_headers_on_every_response
        web01_bad_host_rejected_on_every_route web01_ipv6_bound_host_rules web02_bound_authority_and_localhost_alias_succeed web02_host_alias_from_config_succeeds
        web03_untrusted_origin_no_cors_header web04_default_emits_no_cors_header_anywhere web05_only_exact_configured_origin_allowed web06_preflight_matrix
        web06_cross_origin_post_without_trust_rejected auth01_every_route_rejects_missing_malformed_wrong_token cfg01_wildcard_bind_requires_host_aliases
        dos01_eviction_over_tcp_admits_new_client dos01_slowloris_cannot_starve_a_real_client dos01_slow_body_clients_cannot_starve_a_real_client
        net01_workers_add_no_listener net01_ipv6_loopback_listener_only
        max_tokens_above_limit_is_clamped max_tokens_clamped_to_context_room prompt_alone_over_context_is_400
        fit_max_tokens_false_returns_400_like_the_pin
        enc_round_trip_reaches_the_prompt image_rejections_name_image_url_before_any_write
        idle_unload_respawns_before_the_next_request
        queue_and_answer_room_limits_are_enforced
        aliases_answer_like_the_primary_model
        absent_max_tokens_uses_auto sampling_passthrough_reaches_gen dos01_context_rule_is_400_without_gen
        chat_response_has_openai_shape dos02_excess_connections_get_503_retry_after dos02_queue_full_is_503
        dos02_queue_timeout_is_503 dos02_queue_is_fifo dos02_health_answers_while_generation_places_full
        dos02_serial_mode_one_worker
        dos02_queued_client_disconnect_leaves_queue dos02_non_stream_disconnect_cancels
        dos02_resources_return_to_idle shutdown_errors_never_report_fatal
        dos01_service_healthy_after_each_attack
        ext01_upstream_control_routes_are_404_after_auth ext02_http_headers_cannot_enable_extensions
        log_line_format_and_rate_limit err_no_token_prompt_or_path_in_any_body_or_log)
    if(WIN32)
        # SP3 Task 22: Winsock parity cases (the same code paths run on Linux by hand; see the test file note).
        secure_frontend_add_cases(secure_frontend_api_server_tests win_refusal_is_read_not_reset
            win_eviction_wakes_worker_within_one_slice win_disconnect_detected_by_peek
            LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    endif()
    # Ruling R-J: these cases start the real server over sockets; wine excludes them, MSYS2 is authoritative.
    secure_frontend_add_cases(secure_frontend_api_server_tests ${SECURE_FRONTEND_API_SERVER_CASES}
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    set_tests_properties(secure_frontend_api_server_tests.web01_ipv6_bound_host_rules PROPERTIES SKIP_RETURN_CODE 77)
    set_tests_properties(secure_frontend_api_server_tests.net01_ipv6_loopback_listener_only PROPERTIES SKIP_RETURN_CODE 77)
    if(WIN32)
        target_link_libraries(secure_frontend_api_server_tests PRIVATE iphlpapi)
    endif()
    # SP3 M2 end-to-end cases (real sockets, ServerProcess): windows-runtime on Windows (R-J).
    target_link_libraries(secure_frontend_api_server_tests PRIVATE secure_frontend_json)
    set(SECURE_FRONTEND_API_SERVER_M2_CASES
        utf8_non_stream_max_tokens_cut_mid_character_returns_length generation_timeout_returns_text_with_length
        stream_matches_non_stream_text dos02_queue_full_with_streams_is_503_before_headers ext01_extension_fields_rejected_on_stream_path
        dos02_slow_reader_never_backpressures_engine finish_stop_length_and_generated_bytes_cap utf8_timeout_cut_mid_character_returns_length
        dos02_stream_disconnect_sends_stop_and_frees_engine dos02_slow_stream_reader_hits_write_stall stream_cut_has_no_terminal_chunk
        stream_cancel_during_prefill_frees_engine log_stream_outcomes_use_fixed_codes stream_keepalive_comment_during_prefill
        err_mid_stream_is_error_event_then_done crash_mid_stream_is_engine_unavailable_event nonfinite_is_engine_error_and_engine_stays_ready
        engine_error_carries_should_retry_false dos02_shutdown_during_stream_ends_with_error_event)
    secure_frontend_add_cases(secure_frontend_api_server_tests ${SECURE_FRONTEND_API_SERVER_M2_CASES}
        TIMEOUT 120 LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})

    secure_frontend_add_test_executable(secure_frontend_deadline_tests tests/deadline_test.cpp secure_frontend_engine_stdio_process)
    secure_frontend_test_paths(secure_frontend_deadline_tests)
    # Portable and unlabeled: it also runs under wine.
    secure_frontend_add_cases(secure_frontend_deadline_tests deadline_zero_timeout_is_immediate_everywhere TIMEOUT 120)

    secure_frontend_add_test_executable(secure_frontend_engine_child_tests tests/engine_child_test.cpp
        secure_frontend_engine_stdio_process secure_frontend_test_support)
    secure_frontend_test_paths(secure_frontend_engine_child_tests)
    target_link_libraries(secure_frontend_engine_child_tests PRIVATE secure_frontend_engine_process)
    # SP2 R4: the SP4 seam cases drive the internal launch headers (src/posix_child_launch.hpp, src/win_child_launch.hpp).
    target_include_directories(secure_frontend_engine_child_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    set(SECURE_FRONTEND_CHILD_CASES proc04_exit_status_is_classified proc06_child_ids_and_cwd)
    set(SECURE_FRONTEND_CHILD_LINUX_CASES proc05_group_killed_after_leader_reaped proc02_child_signal_state_is_default proc02_canary_descriptors_absent
        proc03_other_uid_cannot_open_engine_fd proc03_same_uid_reopen_is_accepted_risk proc06_child_has_no_new_privs
        sp4_seam_keep_fds_lift_and_hook_order sp4_seam_hook_failure_is_distinct_from_execve_failure)
    set(SECURE_FRONTEND_CHILD_WINDOWS_CASES proc02_canary_handles_absent proc02_stdin_pipe_dacl_is_owner_only proc03_windows_pipe_second_open_fails proc01_windows_argv_round_trip
        sp4_seam_launch_in_job_handle_and_crt_block sp4_seam_launch_in_job_rejects_non_inheritable_handle)
    if(WIN32)
        list(APPEND SECURE_FRONTEND_CHILD_CASES ${SECURE_FRONTEND_CHILD_WINDOWS_CASES})
    else()
        list(APPEND SECURE_FRONTEND_CHILD_CASES ${SECURE_FRONTEND_CHILD_LINUX_CASES})
    endif()
    secure_frontend_add_cases(secure_frontend_engine_child_tests ${SECURE_FRONTEND_CHILD_CASES}
        TIMEOUT 120 LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(NOT WIN32)
        set_tests_properties(secure_frontend_engine_child_tests.proc03_other_uid_cannot_open_engine_fd PROPERTIES SKIP_RETURN_CODE 77)
    endif()
    # SP2 G3: a test-only copy of the fake whose embedded manifest demands
    # elevation. Its case (proc06_elevation_required_is_spawn_failed) is in the
    # binary's case list only, never registered with CTest: a validation-kit
    # step for a NON-elevated prompt on the owner's offline Windows box.
    if(WIN32)
        enable_language(RC)
        add_executable(strata-supervision-fake-engine-elevated tests/supervision_fake_engine_main.cpp tests/fake_engine_elevated.rc)
        target_link_libraries(strata-supervision-fake-engine-elevated PRIVATE Threads::Threads)
        target_include_directories(strata-supervision-fake-engine-elevated PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_compile_features(strata-supervision-fake-engine-elevated PRIVATE cxx_std_20)
        target_link_libraries(strata-supervision-fake-engine-elevated PRIVATE shell32 advapi32)
        if(MSVC)
            # The .rc embeds the requireAdministrator manifest; without /MANIFEST:NO the
            # linker generates a second one and the informational windows-msvc job
            # fails with a duplicate-manifest link error.
            target_link_options(strata-supervision-fake-engine-elevated PRIVATE /MANIFEST:NO)
        endif()
        secure_frontend_set_warnings(strata-supervision-fake-engine-elevated)
        add_dependencies(secure_frontend_engine_child_tests strata-supervision-fake-engine-elevated)
        target_compile_definitions(secure_frontend_engine_child_tests PRIVATE
            "STRATA_FAKE_ENGINE_ELEVATED_PATH=\"$<TARGET_FILE:strata-supervision-fake-engine-elevated>\"")
    endif()

    secure_frontend_add_test_executable(secure_frontend_engine_supervisor_tests tests/engine_supervisor_test.cpp
        secure_frontend_engine_supervisor secure_frontend_parity secure_frontend_test_support)
    secure_frontend_test_paths(secure_frontend_engine_supervisor_tests)
    # UNIT: no surviving process (in-process fakes, or a spawn that fails
    # before any child runs); also smoke-run under wine. PROCESS: real
    # fake-engine children. LINUX / WINDOWS: platform-only process cases. Later
    # tasks append case names to these four set() lines only.
    set(SECURE_FRONTEND_SUPERVISOR_UNIT_CASES supervisor_health_literals_per_state proc04_restart_backoff_then_circuit_open proc04_healthy_window_resets_failure_count proc04_missing_engine_opens_circuit_without_spinning proc04_client_err_lines_open_circuit_until_restart supervisor_retires_ended_generation_on_its_own_thread proc04_monitor_fallback_without_pidfd proc04_backoff_survives_stale_wake proc04_fatal_line_before_ready_kills_as_fatal_line proc04_unreaped_child_opens_circuit supervisor_unreaped_at_shutdown_reports_engine_left proc06_nnp_hint_when_exit_status_lags supervisor_exception_opens_circuit supervisor_shutdown_sends_eof_first_then_kills supervisor_lease_outliving_shutdown_is_safe supervisor_wait_wakes_on_lease_release supervisor_wait_wakes_on_shutdown proc06_refuses_privileged_start engine_environment_uses_cache_root_when_set sp3_d2_kill_reason_follows_stop_cause sp3_d2_client_stop_drain_failure_restarts_uncounted sp3_d2_timeout_stop_drain_failure_still_counts sp3_d2_client_stop_counts_when_engine_ended_itself sp3_d2_uncounted_end_resets_count_after_healthy_window sp3_d2_uncounted_streak_is_bounded sp3_d2_done_resets_uncounted_streak sp6_env_strata_family_renders_unchanged sp6_env_forced_values_override_and_add sp6_env_forced_values_reject_never_list sp6_env_forcible_names_are_the_ruled_set sp6_env_hook_derives_values_from_environment sp6_env_hook_suppresses_only_optional_rows sp6_env_refused_family_is_spawn_failure idle_unload_tears_down_then_respawns_on_next_request idle_unload_never_fires_during_a_generation lazy_load_defers_the_first_spawn glm_child_env_is_exactly_the_named_typed_set forced_defaults_stay_forced_unless_the_table_moves_them dflash_never_reaches_the_child)
    set(SECURE_FRONTEND_SUPERVISOR_PROCESS_CASES proc04_recovers_after_transient_crash proc04_monitor_detects_idle_crash proc04_fatal_prefix_kills_engine proc04_ready_timeout_kills_and_counts proc04_drain_failure_kills_and_restarts proc04_no_leak_across_restarts proc02_child_env_is_exact_allowlist supervisor_serving_api_is_thread_safe proc04_slow_stdin_write_bounded_by_request_deadline sp6_env_derived_value_reaches_child fake_maya_dialect_round_trips_only_under_the_maya_dialect vision_child_launches_with_pinned_args_when_enabled vision_child_respects_resource_limits vision_encode_round_trip_at_the_pin vision_encode_failures_take_the_pinned_paths)
    set(SECURE_FRONTEND_SUPERVISOR_LINUX_CASES proc05_setsid_grandchild_is_reaped proc05_setsid_grandchild_is_reaped_at_shutdown supervisor_start_refuses_without_wake shutdown_signal_preserves_errno proc05_cgroup_kill_when_delegated)
    set(SECURE_FRONTEND_SUPERVISOR_WINDOWS_CASES proc04_windows_abort_does_not_stall proc04_windows_crash_does_not_stall proc04_windows_write_timeout_kills_engine)
    if(WIN32)
        list(APPEND SECURE_FRONTEND_SUPERVISOR_PROCESS_CASES ${SECURE_FRONTEND_SUPERVISOR_WINDOWS_CASES})
    else()
        list(APPEND SECURE_FRONTEND_SUPERVISOR_PROCESS_CASES ${SECURE_FRONTEND_SUPERVISOR_LINUX_CASES})
    endif()
    secure_frontend_add_cases(secure_frontend_engine_supervisor_tests ${SECURE_FRONTEND_SUPERVISOR_UNIT_CASES} TIMEOUT 120)
    # Process cases are windows-runtime on Windows (Jobs, exit codes, pipes).
    secure_frontend_add_cases(secure_frontend_engine_supervisor_tests ${SECURE_FRONTEND_SUPERVISOR_PROCESS_CASES}
        TIMEOUT 120 LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(WIN32)
        # Tokenizing and writing a ~240 KB GEN line on a slow runner; the case itself ends in seconds.
        set_tests_properties(secure_frontend_engine_supervisor_tests.proc04_windows_write_timeout_kills_engine PROPERTIES TIMEOUT 300)
    endif()
    if(NOT WIN32)
        set_tests_properties(secure_frontend_engine_supervisor_tests.proc05_cgroup_kill_when_delegated PROPERTIES SKIP_RETURN_CODE 77)
    endif()

    secure_frontend_add_test_executable(secure_frontend_http_policy_tests tests/http_policy_test.cpp secure_frontend_http_policy
        secure_frontend_api_core secure_frontend_config secure_frontend_http_request_handler)
    secure_frontend_add_cases(secure_frontend_http_policy_tests
        web01_host_matrix web02_host_name_case_is_folded web03_origin_matrix web06_preflight_rules_unit cors_and_alias_grammar)

    secure_frontend_add_test_executable(secure_frontend_http_parser_tests tests/http_parser_test.cpp
        secure_frontend_api_core secure_frontend_http_request_handler)
    secure_frontend_add_cases(secure_frontend_http_parser_tests
        err_every_code_renders_fixed_body err_param_is_key_only
        imf_fixdate_is_bounded_for_out_of_range_clocks
        wire_response_has_security_headers_and_date
        dos01_request_line_over_limit_is_414 dos01_header_block_over_limit_is_431 dos01_too_many_headers_is_431
        dos01_transfer_encoding_variants_are_411 dos01_content_length_variants head_request_line_and_header_syntax
        wire_head_has_no_content_length route_result_seam_returns_complete_response
        dos01_status_matrix_415_417_505 content_type_variants_accepted auth_and_route_order_follows_spec
        dos01_json_depth_5_is_400 dos01_json_limits dos01_content_array_is_unsupported_parameter stream_flag_type_and_options_rules
        sampling_neutral_values_are_no_ops sampling_bounds_rejected sampling_integer_forms_accepted)
    target_link_libraries(secure_frontend_http_parser_tests PRIVATE
        secure_frontend_api_router secure_frontend_secrets secure_frontend_http_policy secure_frontend_chat_schema)

    secure_frontend_add_test_executable(secure_frontend_http_request_handler_tests tests/http_request_handler_test.cpp
        secure_frontend_http_request_handler)
    secure_frontend_add_cases(secure_frontend_http_request_handler_tests
        accepts_authorized_request passes_the_bounded_raw_body_to_an_authorized_dispatcher
        rejects_malformed_and_ambiguous_messages requires_one_well_formed_bearer_token
        fails_closed_before_calling_validator_for_untrusted_origin emits_cors_only_for_policy_approved_origin
        handles_policy_approved_preflight_without_exposing_an_endpoint constant_time_helper_matches_only_equal_tokens
        auth03_router_uses_verifier)
    target_link_libraries(secure_frontend_http_request_handler_tests PRIVATE
        secure_frontend_api_router secure_frontend_http_policy secure_frontend_secrets)

    secure_frontend_add_test_executable(secure_frontend_http_socket_server_tests tests/http_socket_server_test.cpp
        secure_frontend_http_socket_server)
    secure_frontend_add_cases(secure_frontend_http_socket_server_tests
        serves_a_loopback_request_without_outbound_connections socket_server_survives_client_early_close
        socket_server_rejects_slow_request_past_deadline socket_server_send_times_out_on_stalled_reader
        socket_server_rejects_oversize_request_over_tcp socket_server_accept_waits_without_timeout
        socket_server_ipv6_bind_is_v6only socket_server_response_is_complete
        socket_server_survives_reset_before_accept socket_server_responds_after_client_half_close
        parser_honors_configured_max_request_bytes socket_server_shutdown_listener_wakes_accept
        socket_server_shutdown_listener_wakes_idle_client
        socket_server_rejects_oversize_header_with_431 head_terminator_split_across_reads
        expect_continue_skipped_when_body_already_sent expect_continue_sent_after_authorization
        stream_handler_dispatch_writes_head_chunks_and_terminal_chunk no_response_status_closes_without_writing
        listener_and_accepted_sockets_are_not_inherited
        send_retries_on_eintr accept_backs_off_on_transient_failure send_some_slices_to_max_send_chunk
        send_all_bounded_stops_at_stall_on_a_stalled_reader send_all_bounded_meets_deadline_and_completes
        send_all_bounded_stall_restarts_on_progress send_all_bounded_stop_flag_cuts_an_inflight_write_within_the_drain_budget
        socket_io_poll_probe_and_recv set_no_inherit_marks_the_socket
        TIMEOUT 300)
    secure_frontend_add_cases(secure_frontend_http_socket_server_tests stream_socket_peek_and_nonblocking_send
        TIMEOUT 120 LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    target_link_libraries(secure_frontend_http_socket_server_tests PRIVATE secure_frontend_socket_io
        secure_frontend_api_router secure_frontend_secrets secure_frontend_http_policy secure_frontend_sse)
    secure_frontend_test_paths(secure_frontend_http_socket_server_tests)
    set_tests_properties(secure_frontend_http_socket_server_tests.socket_server_ipv6_bind_is_v6only PROPERTIES SKIP_RETURN_CODE 77)
    if(WIN32)
        secure_frontend_add_cases(secure_frontend_http_socket_server_tests win_send_chunks_respect_write_stall
            LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    endif()

    secure_frontend_add_test_executable(secure_frontend_concurrency_tests tests/concurrency_test.cpp
        secure_frontend_connection_pool secure_frontend_generation_gate secure_frontend_request_log)
    secure_frontend_test_paths(secure_frontend_concurrency_tests)
    # Portable and unlabeled: these also run under wine.
    set(SECURE_FRONTEND_CONCURRENCY_CASES dos01_oldest_header_phase_connection_is_evicted dos01_remote_address_cap
        dos01_linger_list_overflow_closes_oldest dos01_linger_closes_on_peer_eof refusal_response_is_fixed_and_small
        gate_first_request_gets_the_slot gate_queue_full_is_busy gate_zero_queue_admits_one_at_a_time gate_fifo_order gate_timeout_returns_timeout
        request_log_format_and_token_bucket request_log_names_streamed_chats
        gate_cancelled_waiter_leaves_queue gate_fast_fails_when_engine_not_ready gate_shutdown_refuses_waiters)
    secure_frontend_add_cases(secure_frontend_concurrency_tests ${SECURE_FRONTEND_CONCURRENCY_CASES} TIMEOUT 120)

    secure_frontend_add_test_executable(secure_frontend_api_router_tests tests/api_router_test.cpp secure_frontend_api_router)
    secure_frontend_add_cases(secure_frontend_api_router_tests
        health_samples_status_before_state_once_each health_includes_engine_state_when_provided
        health_is_503_with_engine_state_when_unavailable dispatches_exact_health_route
        dispatches_models_with_json_escaping rejects_non_exact_routes
        fails_closed_when_provider_throws_or_returns_invalid_model health_carries_recovery_only_with_failed
        auth01_every_route_rejects_missing_malformed_wrong_token models_list_keeps_utf8_model_id)
    target_link_libraries(secure_frontend_api_router_tests PRIVATE
        secure_frontend_secrets secure_frontend_api_router secure_frontend_http_policy)

    secure_frontend_add_test_executable(secure_frontend_engine_process_tests tests/engine_process_test.cpp
        secure_frontend_engine_process)
    secure_frontend_add_cases(secure_frontend_engine_process_tests
        starts_without_a_shell_and_uses_only_allowlisted_environment rejects_empty_executable
        rejects_malformed_allowlist_entry rejects_embedded_nul_in_exec_boundary termination_cleans_up_a_process_group)
    secure_frontend_add_cases(secure_frontend_engine_process_tests proc02_engine_process_env_checks_windows_names
        TIMEOUT 120 LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    secure_frontend_test_paths(secure_frontend_engine_process_tests)

    secure_frontend_add_test_executable(secure_frontend_engine_protocol_client_tests tests/engine_protocol_client_test.cpp
        secure_frontend_engine_protocol_client)
    secure_frontend_add_cases(secure_frontend_engine_protocol_client_tests
        runs_the_solo_protocol gen_line_unchanged_without_embeddings_geni_with_them stop_and_quit_are_explicit write_deadlines_reach_the_transport refuses_stop_when_not_advertised
        rejects_malformed_and_unexpected_engine_output bounds_and_engine_errors_fail_closed
        prefill_progress_is_bounded_in_both_profiles
        resume_and_reused_progress_is_consumed_in_the_strata_profile
        gen_carries_bounded_sampling_keys
        sampling_defaults_reach_gen_request
        generation_total_deadline_is_enforced
        gen_line_fits_max_prompt_tokens derived_line_cap_is_clamped_to_protocol_max stop_cause_and_completed_generations
        next_event_yields_tokens_progress_and_done next_event_timeout_keeps_generation_active
        next_event_finish_forms_and_nonfinite_stays_idle
        maya_flavor_consumes_note_and_progress strata_flavor_still_fails_closed_on_note maya_pp_grammar_is_bounded)

    secure_frontend_add_test_executable(secure_frontend_model_inventory_tests tests/model_inventory_test.cpp
        secure_frontend_model_inventory)
    secure_frontend_add_cases(secure_frontend_model_inventory_tests
        validates_portable_model_ids validates_portable_artifact_paths)
    set(_inventory_root_cases inventories_only_local_gguf_artifacts rejects_duplicate_ids)
    if(WIN32)
        list(APPEND _inventory_root_cases cfg03_inventory_rejects_junction_entry)
    else()
        list(APPEND _inventory_root_cases cfg03_inventory_rejects_symlink_entry inventory_symlink_error_names_entry
            inventory_duplicate_detection_is_case_insensitive inventory_ignores_non_portable_non_model_names
            inventory_rejects_non_portable_directory)
    endif()
    secure_frontend_add_cases(secure_frontend_model_inventory_tests ${_inventory_root_cases}
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # SP4 §4.9 delta a; pre-flight F-5: a scratch inventory root, labelled like the cases above.
    secure_frontend_add_cases(secure_frontend_model_inventory_tests dl04_staging_ignored_by_inventory_scan
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})

    secure_frontend_add_test_executable(secure_frontend_engine_arguments_tests tests/engine_arguments_test.cpp
        secure_frontend_engine_arguments)
    secure_frontend_add_cases(secure_frontend_engine_arguments_tests
        engine_receives_model_path_from_inventory engine_native_path_is_utf8_for_non_ascii_root
        engine_args_reject_owned_and_network_flags
        strata_profile_passes_pack_and_weight_flags_through rejects_invalid_relative_artifact_path
        engine_args_render_typed_gpu_and_deny_gpu_passthrough
        glm_launch_argv_matches_mayas_launcher_form glm_context_and_parallel_bounds_enforced
        glm_rejects_every_engine_argument
        reasoning_config_reaches_engine_launch_and_env
        mtp_false_drops_the_mtp_arg
        vram_reserve_mib_becomes_the_pinned_flag
        gpu_and_elastic_rows_reach_the_engine_argv
        expert_profile_flags_reach_launch
        parallel_reaches_the_engine_within_one_child
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # Pure parsing, no canonical root: runs under wine too.
    secure_frontend_add_cases(secure_frontend_engine_arguments_tests gpu_list_rejects_malformed_values)
    # SP4 Task 24b (spec §2.3, §4.9 c): the managed launch over a scratch models store.
    target_link_libraries(secure_frontend_engine_arguments_tests PRIVATE secure_frontend_launch secure_frontend_strata_cli)
    secure_frontend_add_cases(secure_frontend_engine_arguments_tests launch_composed_from_manifest_qwen vision_compose_rules
        managed_launch_argv_is_utf8_for_non_ascii_models_root launch_refuses_model_not_installed
        engine_args_reject_weight_flags_for_managed_model managed_launch_renders_typed_gpu_list
        managed_glm_rows_refused_for_qwen_manifest LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # Pure in-memory (F-63): wine runs it too.
    secure_frontend_add_cases(secure_frontend_engine_arguments_tests launch_refuses_engine_too_old)

    secure_frontend_add_test_executable(secure_frontend_chat_schema_tests tests/chat_schema_test.cpp secure_frontend_chat_schema)
    secure_frontend_add_cases(secure_frontend_chat_schema_tests
        parses_minimal_text_request image_url_parts_accepted_only_for_vision_models
        image_part_caps_and_shape_are_checked_before_decode
        rejects_unsupported_and_unsafe_features rejects_duplicate_and_malformed_json
        renders_escaped_minimal_response
        renders_openai_completion_shape)

    # SP5 M1 Task 12: the image_url payload gate — data URL, strict base64, byte caps and
    # the four pass-through formats' dimensions, checked before ANY write (0600 staging).
    secure_frontend_add_test_executable(secure_frontend_image_payload_tests tests/image_payload_test.cpp
        secure_frontend_image_payload)
    secure_frontend_add_cases(secure_frontend_image_payload_tests
        image_payload_stages_valid_images_with_the_pin_key
        image_payload_rejects_bad_shape_before_any_write
        image_payload_caps_bytes_and_sides)

    # SP3 Task 18: static egress tripwire (spec §6.2) over the server binary itself.
    secure_frontend_add_test_executable(secure_frontend_egress_tests tests/egress_test.cpp secure_frontend_test_support)
    secure_frontend_test_paths(secure_frontend_egress_tests)
    set(SECURE_FRONTEND_EGRESS_CASES egress_server_imports_no_resolver_or_http_client
        egress_static_tripwire_fails_on_binary_without_dynamic_section)
    secure_frontend_add_cases(secure_frontend_egress_tests ${SECURE_FRONTEND_EGRESS_CASES} TIMEOUT 120)
    # SP3 Task 19: runtime tripwires. On Windows the interposer cases are not registered (no interposer);
    # the server-starting cases carry the windows-runtime label (ruling R-J).
    target_link_libraries(secure_frontend_egress_tests PRIVATE secure_frontend_socket_io)
    if(WIN32)
        secure_frontend_add_cases(secure_frontend_egress_tests egress_command_like_values_trigger_nothing
            LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
        secure_frontend_add_cases(secure_frontend_egress_tests egress_table_scan_during_lifecycle
            LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
        target_link_libraries(secure_frontend_egress_tests PRIVATE iphlpapi)
    else()
        secure_frontend_add_cases(secure_frontend_egress_tests egress_interposer_self_test
            egress_interposer_records_nothing_during_lifecycle egress_table_scan_during_lifecycle
            egress_command_like_values_trigger_nothing LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    endif()

    secure_frontend_add_test_executable(secure_frontend_json_tests tests/json_test.cpp secure_frontend_json)
    secure_frontend_add_cases(secure_frontend_json_tests
        json_accepts_strict_document json_rejects_duplicate_keys json_rejects_depth_over_limit
        json_rejects_non_integer_numbers json_rejects_bom_trailing_data_and_comments
        json_enforces_size_entry_and_string_limits json_string_escaper_round_trips json_decimals_only_when_enabled)

    secure_frontend_add_test_executable(secure_frontend_parity_table_tests tests/parity_table_test.cpp
        secure_frontend_parity)
    secure_frontend_add_cases(secure_frontend_parity_table_tests
        every_upstream_key_has_exactly_one_disposition every_env_knob_is_dispositioned
        typed_rows_name_a_destination every_maya_key_has_exactly_one_disposition
        every_maya_env_knob_is_dispositioned dflash_is_rejected_on_licence
        updater_and_installer_rows_are_rejected)

    secure_frontend_add_test_executable(secure_frontend_typed_config_tests tests/typed_config_test.cpp
        secure_frontend_typed_config secure_frontend_engine_supervisor)
    secure_frontend_add_cases(secure_frontend_typed_config_tests
        typed_config_accepts_minimal_file_and_applies_defaults cfg01_unknown_key_rejected cfg01_duplicate_key_rejected
        cfg01_type_confusion_rejected cfg01_missing_required_rejected cfg01_out_of_range_rejected
        cfg01_chat_ranges_match_enforced_caps typed_config_cross_field_rules typed_config_errors_never_contain_values
        engine_lib_dirs_must_be_absolute_directories
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    secure_frontend_add_cases(secure_frontend_typed_config_tests cfg02_logs_and_cache_roots_are_created_private
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # SP4 §4.9 c, d: engine.model_id is name or name:tag; roots.tokenizer_pack is optional.
    secure_frontend_add_cases(secure_frontend_typed_config_tests typed_config_model_reference_accepts_name_tag
        describe_reports_unset_expert_keys LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    secure_frontend_add_cases(secure_frontend_typed_config_tests each_rejected_upstream_key_errors_at_load_naming_it
        sampling_defaults_cover_the_pinned_validator
        reasoning_rows_match_the_pinned_validator
        glm_keys_parse_with_mayas_kinds_and_defaults
        glm_keys_rejected_on_strata_profile_by_name
        thinking_budget_default_is_mayas_32768
        glm_environment_projection_moves_the_split_default
        glm_max_context_typed_and_glm53_args_refused
        glm_vision_flags_reach_both_children
        lifecycle_rows_match_the_pin
        vram_family_rows_match_the_pin
        timeout_shape_rows_match_the_pin
        timeout_shape_rows_at_each_edge
        session_rows_match_the_pin
        slot_save_path_is_a_bounded_private_path
        codex_and_tool_call_rows_are_dispositioned
        session_rows_at_each_edge
        replicas_parallel_row_at_the_pin
        multi_child_replicas_reject_with_the_ruling
        vision_rows_match_the_pin
        bounds_are_the_pins_at_each_edge)
    # SP4 Task 24b (spec §4.9 c/d; F-8): managed-model config errors, also through strata-secure-server --check.
    target_link_libraries(secure_frontend_typed_config_tests PRIVATE secure_frontend_launch secure_frontend_strata_cli)
    add_dependencies(secure_frontend_typed_config_tests strata-secure-server)
    secure_frontend_add_cases(secure_frontend_typed_config_tests cfg01_engine_profile_rejected_for_managed_model
        cfg01_tokenizer_pack_root_rejected_for_managed_model cfg01_model_reference_rejected_for_managed_model
        ARGS $<TARGET_FILE:strata-secure-server> LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(NOT WIN32)
        # chmod-based: the config folder's mode decides the roots.secret default.
        secure_frontend_add_cases(secure_frontend_typed_config_tests
            cfg02_env_token_ignores_config_folder_permissions cfg02_file_token_default_secret_root_reports_one_issue)
    endif()
    # CFG-06: the second case reads the token through the production reader first.
    target_link_libraries(secure_frontend_typed_config_tests PRIVATE secure_frontend_secrets secure_frontend_token_reader)
    secure_frontend_add_cases(secure_frontend_typed_config_tests cfg06_config_has_no_secret_typed_member)
    secure_frontend_add_cases(secure_frontend_typed_config_tests cfg06_validated_config_bytes_do_not_contain_token
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # D3: the README key table equals render_config_schema_markdown().
    secure_frontend_add_cases(secure_frontend_typed_config_tests readme_config_table_matches_schema
        ARGS ${CMAKE_CURRENT_SOURCE_DIR}/README.md)
    # SP4 §4.9 delta e: the pull.* keys (scratch roots, DACL-private on Windows).
    secure_frontend_add_cases(secure_frontend_typed_config_tests cfg01_pull_keys_table_driven
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # SP3 SP1-addendum A1 (spec §5.1): unlabelled, so the wine smoke runs them (pre-flight T4).
    secure_frontend_add_cases(secure_frontend_typed_config_tests cfg01_sp3_rows_type_and_range
        cfg01_header_deadline_le_request_deadline cfg01_response_deadline_ge_write_stall
        cfg01_wildcard_bind_requires_host_aliases cfg01_host_alias_grammar_and_count
        web05_cors_origin_config_rejects_wildcard_null_path_duplicate_and_17_entries
        cfg01_sp3_concurrency_rows_and_defaults cfg01_queue_plus_two_le_workers cfg01_serial_requires_zero_queue
        cfg01_remote_cap_le_workers cfg01_sp1_config_with_one_worker_still_valid
        cfg01_derived_defaults_follow_worker_count cfg01_explicit_values_are_not_adjusted)
    if(WIN32)
        secure_frontend_add_cases(secure_frontend_typed_config_tests cfg01_config_with_everyone_write_ace_rejected
            LABELS windows-runtime)
    else()
        secure_frontend_add_cases(secure_frontend_typed_config_tests cfg01_group_writable_config_rejected)
    endif()

    secure_frontend_add_test_executable(secure_frontend_tokenizer_pack_tests tests/tokenizer_pack_test.cpp
        secure_frontend_tokenizer_pack)
    set(_tokenizer_cases loads_validates_and_decodes_offline_pack rejects_ambiguous_or_incompatible_pack_assets
        rejects_malformed_json_and_special_literals_for_decode encoding_fails_closed_for_special_invalid_and_missing_tokens
        token_byte_decoder_returns_raw_token_bytes)
    if(WIN32)
        list(APPEND _tokenizer_cases cfg03_tokenizer_file_swapped_to_junction_rejected)
    else()
        list(APPEND _tokenizer_cases rejects_symlinked_assets cfg03_tokenizer_file_swapped_to_symlink_rejected)
    endif()
    secure_frontend_add_cases(secure_frontend_tokenizer_pack_tests ${_tokenizer_cases}
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})

    secure_frontend_add_test_executable(secure_frontend_qwen_prompt_renderer_tests tests/qwen_prompt_renderer_test.cpp
        secure_frontend_qwen_prompt_renderer)
    secure_frontend_add_cases(secure_frontend_qwen_prompt_renderer_tests
        renders_fixed_qwen_chatml_prompt accepts_systemless_conversation rejects_unsafe_or_unsupported_conversations)

    secure_frontend_add_test_executable(secure_frontend_glm_profile_tests tests/glm_profile_test.cpp
        secure_frontend_chat_generation_plan)
    secure_frontend_add_cases(secure_frontend_glm_profile_tests
        renders_exact_fixed_profile rejects_boundary_injection_and_invalid_order creates_plan_only_with_control_tokens)

    secure_frontend_add_test_executable(secure_frontend_chat_generation_plan_tests tests/chat_generation_plan_test.cpp
        secure_frontend_chat_generation_plan)
    secure_frontend_add_cases(secure_frontend_chat_generation_plan_tests
        composes_schema_prompt_and_tokenizer vision_marker_runs_join_the_prompt_ids defaults_output_limit_and_rejects_unsafe_inputs
        rejects_missing_or_non_control_framing_tokens does_not_parse_arbitrary_special_literals
        sampling_defaults_merge_under_request_overrides)

    secure_frontend_add_test_executable(secure_frontend_chat_execution_tests tests/chat_execution_test.cpp
        secure_frontend_chat_execution)
    secure_frontend_add_cases(secure_frontend_chat_execution_tests
        executes_a_bounded_non_streaming_completion rejects_context_and_output_limits_before_generation
        fails_closed_on_invalid_engine_output executes_glm53_only_when_explicitly_selected
        glm_profile_generation_completes_over_maya_dialect maya_dialect_cancellation_round_trips
        chat_recovers_after_generation_timeout chat_gen_write_bounded_by_generation_deadline chat_marks_engine_failed_when_drain_fails
        chat_rejects_nonfinite_done_and_stays_ready health_reflects_protocol_state
        health_is_failed_after_engine_closed_mid_generation health_is_failed_when_engine_closes_before_ready
        chat_applies_engine_context_rule_with_eight_token_margin chat_uses_adopted_ready_without_waiting
        resolve_max_tokens_follows_decisions_1_and_2
        resolve_max_tokens_fit_false_refuses_like_the_pin
        min_and_max_tokens_bounds_clamp_at_resolve engine_silence_s_sets_the_stall_watchdog
        repeat_stop_tokens_ends_a_runaway_reply
        run_generation_reports_finish_usage_and_context run_generation_cancel_sends_stop_and_drains
        run_generation_timeout_stops_and_reports_timed_out run_generation_drain_failure_abandons
        run_generation_shutdown_uses_short_drain run_generation_maps_engine_errors
        drive_generation_bytes_cap_cuts_on_code_point drive_generation_drops_tail_on_length_and_replaces_on_stop
        drive_generation_cancel_sends_stop_and_drains chat_max_tokens_cut_mid_character_returns_length)

    secure_frontend_add_test_executable(secure_frontend_subsystem_limits_tests tests/subsystem_limits_test.cpp
        secure_frontend_subsystem_limits)
    secure_frontend_add_cases(secure_frontend_subsystem_limits_tests
        ready_timeout_defaults_to_900_seconds subsystem_limits_follow_config supervisor_policy_follows_config
        supervisor_flavor_is_the_maya_dialect_for_glm53
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})

    add_executable(secure_frontend_fake_engine tests/fake_engine_main.cpp)
    target_compile_features(secure_frontend_fake_engine PRIVATE cxx_std_20)
    secure_frontend_set_warnings(secure_frontend_fake_engine)
    set(SECURE_FRONTEND_SERVER_ARGS ARGS $<TARGET_FILE:strata-secure-server> $<TARGET_FILE:secure_frontend_fake_engine>
        $<TARGET_FILE:strata>)  # SP5 M1 Task 13: ARGS[2] is the `strata` CLI (strata serve cases)

    secure_frontend_add_test_executable(secure_frontend_server_cli_tests tests/server_cli_test.cpp
        secure_frontend_typed_config)
    add_dependencies(secure_frontend_server_cli_tests strata-secure-server secure_frontend_fake_engine strata)
    secure_frontend_add_cases(secure_frontend_server_cli_tests
        cli_config_file_and_flags_share_validator cli_flag_overrides_file_and_is_reported cli_check_prints_no_token
        cli_check_unreadable_token_is_not_reported_valid
        cli_unknown_option_does_not_echo_value
        auth04_empty_token_rejected_on_loopback auth04_no_switch_disables_auth serve_requires_state_root
        ${SECURE_FRONTEND_SERVER_ARGS} LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    secure_frontend_add_cases(secure_frontend_server_cli_tests cli_check_has_no_side_effects
        ${SECURE_FRONTEND_SERVER_ARGS} LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    # SP5 M1 Task 13: `strata serve` (foreground) — the CLI binary boots the same supervised path.
    secure_frontend_add_cases(secure_frontend_server_cli_tests
        serve_prints_ready_then_serves serve_runs_foreground_and_shuts_clean_on_sigterm
        ${SECURE_FRONTEND_SERVER_ARGS} LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    target_link_libraries(secure_frontend_server_cli_tests PRIVATE secure_frontend_token_reader secure_frontend_server_cli
        secure_frontend_acquire)
    # Unit case (parse + validate in process, no child): unlabeled, so it also runs under wine.
    secure_frontend_add_cases(secure_frontend_server_cli_tests cli_sp2_flags_map_to_schema_keys TIMEOUT 120)
    # SP4 §4.9 d: pure argv parsing, so wine runs it too.
    secure_frontend_add_cases(secure_frontend_server_cli_tests cli_expert_flag_parsing)

    # SP7 M1 Task 1: the hardened service unit (exact text) and the `current`
    # seam. The internal header lives in src/, like the SP2 launch seams.
    secure_frontend_add_test_executable(secure_frontend_service_ops_tests tests/service_ops_test.cpp
        secure_frontend_service_ops secure_frontend_test_support)
    target_include_directories(secure_frontend_service_ops_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    set(SECURE_FRONTEND_SERVICE_OPS_CASES render_systemd_unit_exact_golden render_systemd_unit_rejects_whitespace_paths
        render_systemd_unit_rejects_relative_or_empty render_schtasks_create_exact_golden
        render_schtasks_create_rejects_unsafe_paths)
    secure_frontend_add_cases(secure_frontend_service_ops_tests ${SECURE_FRONTEND_SERVICE_OPS_CASES})

    # SP7 M1 Task 3: the D-7 doctor checks, all driven by fake ProbeBundles.
    secure_frontend_add_test_executable(secure_frontend_doctor_tests tests/doctor_checks_test.cpp
        secure_frontend_doctor secure_frontend_typed_config secure_frontend_test_support)
    target_include_directories(secure_frontend_doctor_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    secure_frontend_add_cases(secure_frontend_doctor_tests
        doctor_check_config_names_rejected_keys doctor_check_config_valid_passes doctor_check_token_modes
        doctor_check_roots_report_named_failures doctor_check_port_busy_fails_with_fix
        doctor_check_gpu_and_driver doctor_check_cuda_runtime doctor_check_memlock
        doctor_deep_digests_and_run_order doctor_human_fix_never_carries_install_commands)

    # SP7 M1 Task 4: the D-6 uninstall plan; the probe case runs a canned HTTP
    # listener on loopback (no real server, no engine).
    secure_frontend_add_test_executable(secure_frontend_uninstall_tests tests/uninstall_test.cpp
        secure_frontend_uninstall secure_frontend_typed_config secure_frontend_test_support)
    target_include_directories(secure_frontend_uninstall_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    secure_frontend_add_cases(secure_frontend_uninstall_tests
        uninstall_plan_no_listener_orders_removals uninstall_plan_listener_with_unit_stops_via_manager
        uninstall_plan_listener_without_unit_refuses_with_ctrlc_hint uninstall_plan_listener_with_unit_but_no_manager_refuses
        uninstall_plan_purge_needs_the_typed_word uninstall_plan_refuses_paths_outside_allowed_roots
        uninstall_plan_missing_optional_paths_are_skipped uninstall_plan_refuses_when_install_metadata_mismatches
        uninstall_health_probe_answers_on_a_listener_and_not_without_one)

    # SP7 M1 Task 5: the new CLI verbs as real child processes against temp roots.
    secure_frontend_add_test_executable(secure_frontend_cli_verbs_tests tests/cli_verbs_test.cpp
        secure_frontend_test_support)
    secure_frontend_add_cases(secure_frontend_cli_verbs_tests
        cli_usage_lists_the_new_verbs cli_uninstall_refuses_while_a_server_answers
        ARGS $<TARGET_FILE:strata> TIMEOUT 120)
    if(NOT WIN32)
        # The systemd-shim cases are POSIX-only; the Windows side is registered
        # in the WIN32 block below (Task 6).
        secure_frontend_add_cases(secure_frontend_cli_verbs_tests
            cli_service_enable_status_disable_roundtrip cli_service_enable_without_user_manager
            cli_uninstall_plain_removes_and_keeps cli_uninstall_purge_without_the_word_refuses
            cli_uninstall_purge_with_typed_word_removes_models
            ARGS $<TARGET_FILE:strata> TIMEOUT 120)
    endif()
    if(WIN32)
        # Task 6: the Task Scheduler CLI roundtrip, windows-runtime labelled —
        # cross-compiled by the cross gate, run only on the owner's Windows box.
        secure_frontend_add_cases(secure_frontend_cli_verbs_tests
            cli_service_enable_status_disable_taskscheduler
            ARGS $<TARGET_FILE:strata> LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    endif()
    if(NOT WIN32)
        # Symlink layouts are POSIX-only here; the Windows pointer form
        # (current.txt) belongs to M2's update, which writes through it.
        secure_frontend_add_cases(secure_frontend_service_ops_tests
            resolve_current_target_follows_current_pointer resolve_current_target_plain_install_uses_self
            service_enable_writes_unit_then_enables service_enable_missing_user_manager_writes_nothing
            service_enable_reports_failed_enable service_disable_removes_only_our_unit
            service_disable_refuses_foreign_unit service_status_one_line_each service_status_without_user_manager
            service_enable_e2e_path_shim)
    endif()
    if(WIN32)
        # The Task Scheduler plan branch (Task 6): registered in Windows test
        # builds; the cross gate compiles them, the owner's box runs them.
        secure_frontend_add_cases(secure_frontend_service_ops_tests
            service_enable_writes_task_then_creates service_enable_without_task_scheduler_writes_nothing
            service_disable_refuses_foreign_task_file service_disable_removes_task_and_our_file
            service_status_task_one_line_each)
    endif()
    secure_frontend_add_cases(secure_frontend_server_cli_tests
        init_writes_config_and_token_then_server_starts init_refuses_to_overwrite_without_force
        init_force_refuses_a_non_regular_config_target init_failure_creates_nothing
        ${SECURE_FRONTEND_SERVER_ARGS} LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)

    secure_frontend_add_test_executable(secure_frontend_server_e2e_tests tests/server_e2e_test.cpp
        secure_frontend_typed_config)
    add_dependencies(secure_frontend_server_e2e_tests strata-secure-server secure_frontend_fake_engine)
    if(WIN32)
        target_link_libraries(secure_frontend_server_e2e_tests PRIVATE iphlpapi ws2_32)
    endif()
    secure_frontend_add_cases(secure_frontend_server_e2e_tests
        cfg01_invalid_config_fails_before_listener_and_child net02_remote_addresses_need_opt_in
        net02_error_is_non_secret_and_exits_before_bind ready_timeout_is_configurable
        cfg05_token_absent_from_child_argv_env_and_outputs
        auth01_socket_rejects_missing_and_wrong_token_on_every_route auth02_valid_token_succeeds_and_is_not_echoed
        serve_reports_why_the_token_and_tokenizer_pack_are_unusable
        ${SECURE_FRONTEND_SERVER_ARGS} LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    # GetExtendedTcpTable is not faithful under wine.
    secure_frontend_add_cases(secure_frontend_server_e2e_tests net01_default_listener_is_loopback_only
        ${SECURE_FRONTEND_SERVER_ARGS} LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    if(NOT WIN32)
        secure_frontend_add_cases(secure_frontend_server_e2e_tests serve_reports_symlinked_model_entry
            ${SECURE_FRONTEND_SERVER_ARGS} TIMEOUT 120)
        secure_frontend_add_cases(secure_frontend_server_e2e_tests cfg03_engine_receives_canonical_models_root
            ${SECURE_FRONTEND_SERVER_ARGS} TIMEOUT 120)
        secure_frontend_add_cases(secure_frontend_server_e2e_tests server_process_is_not_dumpable
            ${SECURE_FRONTEND_SERVER_ARGS} TIMEOUT 120)
    endif()

    # --- SP4 tests ---
    secure_frontend_add_test_executable(secure_frontend_sha256_tests tests/sha256_test.cpp secure_frontend_sha256)
    secure_frontend_add_cases(secure_frontend_sha256_tests fips_180_4_short_vectors fips_180_4_million_a
        LABELS release-also)
    secure_frontend_add_cases(secure_frontend_sha256_tests long_message_one_gibibyte TIMEOUT 900)
    secure_frontend_add_cases(secure_frontend_sha256_tests chunk_boundaries_do_not_change_digest
        length_field_encodes_bits_big_endian hex_helpers_are_strict)
    if(SECURE_FRONTEND_TEST_HOOKS)
        secure_frontend_add_cases(secure_frontend_sha256_tests length_counter_past_2_32_bytes)
    endif()

    secure_frontend_add_test_executable(secure_frontend_acquire_tests tests/acquire_test.cpp secure_frontend_acquire_core)
    secure_frontend_add_cases(secure_frontend_acquire_tests exit_classes_match_spec_table
        reason_table_is_complete_and_ordered error_text_states_resumable
        version_dir_name_unique_for_same_version_label staging_plan_classifies_partials
        abandoned_keys_match_same_model_only update_diff_lists_changed_files_and_license)
    target_sources(secure_frontend_acquire_tests PRIVATE tests/acquire_store_test.cpp tests/acquire_store_windows_test.cpp)
    target_link_libraries(secure_frontend_acquire_tests PRIVATE secure_frontend_acquire)
    secure_frontend_add_cases(secure_frontend_acquire_tests concurrent_pull_same_manifest_second_is_models_busy
        part_file_create_append_resume_truncate rename_within_never_replaces rename_fallback_never_replaces
        remove_tree_removes_links_without_following hash_into_rejects_hard_links_and_counts_bytes
        hash_into_stops_when_interrupted
        store_environment_seams_report_space_and_fs_kind overlong_joined_paths_fail_closed_without_throwing
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(WIN32)
        secure_frontend_add_cases(secure_frontend_acquire_tests store_primitives_windows store_adopts_only_private_files_windows
            LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    endif()
    # SP4 Task 19 (spec §4.4-§4.8): verify, publish, retire, orphan adoption, rm.
    target_sources(secure_frontend_acquire_tests PRIVATE tests/acquire_publish_test.cpp)
    secure_frontend_add_cases(secure_frontend_acquire_tests dl04_publish_uses_noreplace_and_never_overwrites
        publish_falls_back_when_noreplace_unsupported dl04_orphan_adopted_after_rehash_by_digest
        replace_loaded_model_retires_old_version layout_check_requires_pack_files_and_valid_tokenizer
        staged_tree_must_be_exactly_the_manifest publish_requires_staging_key_of_manifest
        overlong_staging_tree_is_publish_failed retire_removes_read_only_published_version
        downgrade_adopts_retired_version_keeping_one_live rm_refuses_held_version_and_removes_read_only_tree
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # F-42: pure in-memory case, so wine runs it too.
    secure_frontend_add_cases(secure_frontend_acquire_tests install_decisions_follow_sequence_rules)
    if(SECURE_FRONTEND_TEST_HOOKS)
        secure_frontend_add_cases(secure_frontend_acquire_tests dl04_crash_between_publish_and_index_is_not_loaded
            LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    endif()
    if(WIN32)
        secure_frontend_add_cases(secure_frontend_acquire_tests replace_loaded_model_retires_old_version_windows
            rm_open_version_stays_retired_windows LABELS windows-runtime)
    else()
        secure_frontend_add_cases(secure_frontend_acquire_tests rm_reports_unreachable_version_as_failure
            rm_failed_delete_stays_retired)
    endif()
    # SP4 Task 22 (spec §1.3, §3.7, §4.6, §4.7, §6.1): run_pull; these write a models store.
    target_sources(secure_frontend_acquire_tests PRIVATE tests/acquire_pull_test.cpp)
    secure_frontend_add_cases(secure_frontend_acquire_tests dl02_correct_digest_publishes_atomically dl02_byte_limit_enforced_while_streaming
        dl02_resume_with_range_completes_and_verifies resume_offset_ignores_preallocation dl02_published_files_are_private
        dl02_preflight_refuses_without_space dl03_untrusted_manifest_digest_rejected dl03_downgrade_rejected dl03_sequence_conflict_rejected
        dl04_interrupt_during_download_never_indexed dl04_interrupt_during_verification dl04_stale_staging_from_other_manifest_discarded
        abandoned_partials_kept_with_yes abandoned_staging_reported_and_offered_for_deletion all_sources_failed_exits_3_and_keeps_part
        enospc_mid_stream_keeps_part_and_exits_6 update_reuses_unchanged_files license_change_requires_interactive_yes
        update_reuse_copy_interrupted_mid_file_exits_8 pull_verify_interrupted_exits_8
        pull_without_bundle_refuses_sourceless_files confirmation_answers_parsed_strictly already_installed_needs_no_network
        pull_budgets_map_to_exit_classes discard_partial_runs_only_after_confirmation
        unreadable_installed_license_requires_interactive_yes
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # SP4 Task 23 (spec §1.5, §4.5, §4.8, §6.2): the strata CLI's local verbs.
    target_sources(secure_frontend_acquire_tests PRIVATE tests/acquire_cli_test.cpp)
    target_link_libraries(secure_frontend_acquire_tests PRIVATE secure_frontend_strata_cli)
    # Neither writes a models store: wine runs them; program update is release evidence too.
    secure_frontend_add_cases(secure_frontend_acquire_tests program_update_exits_12_without_network LABELS release-also)
    secure_frontend_add_cases(secure_frontend_acquire_tests cli_requires_config_and_known_verb)
    secure_frontend_add_cases(secure_frontend_acquire_tests list_and_show_report_installed_models
        list_all_reports_retired_orphaned_and_staging rm_refuses_loaded_model rm_retired_deletes_unheld_versions
        rm_partials_deletes_other_staging LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # SP5 M1 Task 14 (D-4): strata version and strata key show|rotate.
    secure_frontend_add_cases(secure_frontend_acquire_tests version_names_frontend_and_engine_versions
        key_show_requires_local_token_and_never_logs LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(SECURE_FRONTEND_TEST_HOOKS)
        secure_frontend_add_cases(secure_frontend_acquire_tests dl03_third_party_cannot_shadow_catalog
            pull_test_cacert_reaches_argv_in_hook_builds list_outdated_uses_catalog_sequence
            publish_failure_after_step_2_resumes_without_download
            LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    endif()
    if(WIN32)
        secure_frontend_add_cases(secure_frontend_acquire_tests dl02_published_files_have_private_dacl_windows LABELS windows-runtime)
    endif()
    # SP4 Task 27 (spec §1.3, §6.1, §8.3, D6): the network verbs through CliServices seams.
    target_sources(secure_frontend_acquire_tests PRIVATE tests/acquire_network_cli_test.cpp)
    secure_frontend_add_cases(secure_frontend_acquire_tests pull_cli_prints_summary_and_installs run_installed_model_needs_no_network
        run_refuses_glm53_without_engine LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(SECURE_FRONTEND_TEST_HOOKS)
        secure_frontend_add_cases(secure_frontend_acquire_tests run_missing_model_prompts_and_decline_exits_2
            run_missing_model_non_interactive_exits_2 LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
        secure_frontend_add_cases(secure_frontend_acquire_tests update_models_pulls_outdated_catalog_models
            ARGS ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/payload/fixture-qwen-t1 LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
        add_dependencies(secure_frontend_acquire_tests strata secure_frontend_fake_curl)
        if(WIN32)
            secure_frontend_add_cases(secure_frontend_acquire_tests dl04_interrupt_during_download_never_indexed_windows
                ARGS $<TARGET_FILE:strata> $<TARGET_FILE:secure_frontend_fake_curl> LABELS windows-runtime TIMEOUT 120)
        else()
            # Fix round 1: §8.3/§8.2 signals end to end through a strata child (TIMEOUT: each waits <= 15 s).
            secure_frontend_add_cases(secure_frontend_acquire_tests dl04_sigint_during_download_exits_8
                dl04_sigterm_during_download_exits_8 interrupt_at_confirmation_prompt_exits_8
                ARGS $<TARGET_FILE:strata> $<TARGET_FILE:secure_frontend_fake_curl> TIMEOUT 120)
        endif()
    endif()
    secure_frontend_add_test_executable(secure_frontend_bundle_tests tests/bundle_test.cpp secure_frontend_acquire_core)
    secure_frontend_add_cases(secure_frontend_bundle_tests sha256sums_render_sorted_bytewise sha256sums_parse_is_strict
        sums_agreement_rules missing_list_names_sourceless_files)
    # SP4 Task 20 (spec §5): bundle open/verify/import/export; these write a models store or a bundle.
    target_sources(secure_frontend_bundle_tests PRIVATE tests/bundle_io_test.cpp)
    target_link_libraries(secure_frontend_bundle_tests PRIVATE secure_frontend_acquire)
    secure_frontend_add_cases(secure_frontend_bundle_tests dl02_import_bundle_publishes_same_as_pull
        dl03_bundle_digest_mismatch_publishes_nothing bundle_rejects_traversal_path bundle_rejects_unlisted_file_in_files_dir
        bundle_sha256sums_must_match_manifest bundle_rejects_hardlinked_file export_refuses_bundle_forbidden_license
        export_refuses_fat32_target_for_large_file export_rehashes_and_rejects_bit_rot verify_writes_nothing
        import_from_read_only_bundle_directory bundle_incomplete_and_marker_rules export_onto_shared_writable_target
        bundle_directory_must_not_be_a_volume_root
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # Task 13 carry: a bundle exactly as tools/secure/make_bundle.py writes it.
    secure_frontend_add_cases(secure_frontend_bundle_tests make_bundle_tool_output_opens_verifies_and_imports
        ARGS ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/bundle/make-bundle-iq2_xs
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # Refused before anything is written (no store, no target directory), so wine runs it too.
    secure_frontend_add_cases(secure_frontend_bundle_tests export_refuses_when_one_file_license_forbids_bundle)
    # SP4 Task 22 (spec §2.7, §5.3): pull --bundle; these write a bundle.
    target_sources(secure_frontend_bundle_tests PRIVATE tests/bundle_pull_test.cpp)
    secure_frontend_add_cases(secure_frontend_bundle_tests pull_bundle_resumes_after_interrupt pull_bundle_incomplete_without_pack_sources
        pull_bundle_resume_rehashes_files_from_earlier_run LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # SP4 Task 23 (spec §5): strata import / verify / export; these write a models store.
    target_sources(secure_frontend_bundle_tests PRIVATE tests/bundle_cli_test.cpp)
    target_link_libraries(secure_frontend_bundle_tests PRIVATE secure_frontend_strata_cli)
    secure_frontend_add_cases(secure_frontend_bundle_tests import_works_without_downloader cli_verify_export_import_round_trip
        failed_export_says_to_remove_target import_blocked_by_orphan_says_how_to_clear_it
        import_license_change_needs_interactive_yes import_with_unreadable_installed_version_needs_interactive_yes
        import_over_corrupt_orphan_reports_target_exists
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(WIN32)
        secure_frontend_add_cases(secure_frontend_bundle_tests bundle_rejects_junction_entry_windows LABELS windows-runtime)
    else()
        secure_frontend_add_cases(secure_frontend_bundle_tests bundle_rejects_symlink_entry
            bundle_walk_fails_closed_on_overlong_or_odd_names)
        secure_frontend_add_cases(secure_frontend_bundle_tests bundle_at_mount_root_is_read_but_never_written)
        set_tests_properties(secure_frontend_bundle_tests.bundle_at_mount_root_is_read_but_never_written PROPERTIES
            SKIP_REGULAR_EXPRESSION "SKIPPED:")
    endif()
    secure_frontend_add_test_executable(secure_frontend_model_index_tests tests/model_index_test.cpp secure_frontend_model_store)
    secure_frontend_add_cases(secure_frontend_model_index_tests index_render_is_deterministic
        install_retires_previous_version reinstall_same_version_does_not_retire
        downgrade_to_retired_version_leaves_it_live_only)
    # SP4 §4.9 delta b: DACL-private scratch roots.
    secure_frontend_add_cases(secure_frontend_model_index_tests scan_tolerates_repeated_shard_names_across_versions
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # SP4 §4.5: index.json on disk. Writing goes through the models store (ruling B).
    target_link_libraries(secure_frontend_model_index_tests PRIVATE secure_frontend_acquire)
    secure_frontend_add_cases(secure_frontend_model_index_tests index_round_trip_through_disk
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    secure_frontend_add_cases(secure_frontend_model_index_tests index_inconsistent_manifest_fails_closed
        index_rejects_unknown_keys_and_bad_dirs index_rejects_bad_versions_and_retired_dirs)
    # SP4 Task 23 / F-58: shared lookup and engine gate (pure); Task 15 carry: skipped-entry count.
    secure_frontend_add_cases(secure_frontend_model_index_tests find_installed_matches_name_and_tag
        engine_gate_honours_profile_family_and_version)
    if(NOT WIN32)
        secure_frontend_add_cases(secure_frontend_model_index_tests scan_counts_skipped_entries)
    endif()

    secure_frontend_add_test_executable(secure_frontend_manifest_tests tests/manifest_test.cpp secure_frontend_model_store)
    secure_frontend_add_cases(secure_frontend_manifest_tests source_url_grammar_matrix dns_names_and_wildcards proxy_grammar)
    secure_frontend_add_cases(secure_frontend_manifest_tests valid_qwen_manifest_accepted manifest_field_rules_matrix
        reserved_manifest_names_rejected model_name_index_json_rejected part_suffix_path_rejected stored_path_length_fits_p1
        file_and_directory_prefix_collision_rejected shard_set_must_be_complete_in_one_directory
        launch_keys_follow_profile manifest_accepts_mmproj_role_and_rejects_duplicates wildcard_redirect_hosts_validated total_size_above_budget_is_total_budget_exceeded
        engine_version_parsed_with_fourth_component)
    secure_frontend_add_cases(secure_frontend_manifest_tests raw_profile_rejected_in_release_build LABELS release-only)
    if(SECURE_FRONTEND_TEST_HOOKS)
        secure_frontend_add_cases(secure_frontend_manifest_tests raw_profile_accepted_with_test_hooks
            typed_digest_must_match_catalog_bytes_too)
    endif()
    secure_frontend_add_cases(secure_frontend_manifest_tests base_manifest_parses dl03_invalid_manifest_matrix
        dl03_http_url_rejected manifest_identity_is_sha256_of_exact_bytes trust_rules_catalog_digest_or_typed_digest)
    secure_frontend_add_cases(secure_frontend_manifest_tests dl05_catalog_pins_match_committed_list
        ARGS ${CMAKE_CURRENT_SOURCE_DIR}/catalog/CATALOG.sha256 ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/catalog/CATALOG.sha256
        LABELS release-also)
    secure_frontend_add_cases(secure_frontend_manifest_tests engine_version_read_from_upstream_version_file
        ARGS ${SECURE_FRONTEND_ENGINE_VERSION_TEXT} LABELS release-also)
    secure_frontend_add_test_executable(secure_frontend_fetch_tests tests/fetch_test.cpp secure_frontend_acquire_core)
    secure_frontend_add_cases(secure_frontend_fetch_tests dl03_location_with_glob_characters_rejected
        location_resolution_and_host_normalization location_query_characters
        address_policy_denies_special_ranges address_policy_any_denied_answer_rejects_hop ipv6_only_answer_fails_closed
        allow_private_addresses_pins_first_ipv4 resolve_argument_brackets_ipv6
        transfer_argv_exact_order config_line_is_single_quoted_url probe_argv_is_version_only
        probe_output_parsing_and_floor curl_exit_codes_map_to_reasons
        informational_header_blocks_skipped header_block_limits_enforced split_feed_reports_exact_body_offset
        status_table_decisions
        retry_backoff_follows_schedule non_transient_moves_to_next_source
        exhausted_class_follows_last_source_reason run_budget_remaining_seconds
        staging_cwd_not_treated_as_key landlock_rights_per_abi confinement_plan_detects_readable_roots
        confinement_label_texts crt_fd_block_layout)
    # SP4 §10.1: the fake downloader is a test executable; it never opens a socket.
    add_executable(secure_frontend_fake_curl tests/fake_curl_main.cpp)
    target_include_directories(secure_frontend_fake_curl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests
        ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_features(secure_frontend_fake_curl PRIVATE cxx_std_20)
    secure_frontend_set_warnings(secure_frontend_fake_curl)
    if(WIN32)
        target_link_libraries(secure_frontend_fake_curl PRIVATE advapi32)
    endif()
    add_dependencies(secure_frontend_fetch_tests secure_frontend_fake_curl)
    secure_frontend_add_cases(secure_frontend_fetch_tests fake_curl_scenario_parses_and_renders
        fake_curl_argv_grammar_matches_builder)
    if(WIN32)
        if(SECURE_FRONTEND_TEST_HOOKS)
            secure_frontend_add_cases(secure_frontend_fetch_tests fake_curl_records_on_crt_entry_4_windows
                ARGS $<TARGET_FILE:secure_frontend_fake_curl> LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
        endif()
    else()
        # Record-channel cases are registered only with test hooks (plan Global Constraints).
        if(SECURE_FRONTEND_TEST_HOOKS)
            secure_frontend_add_cases(secure_frontend_fetch_tests fake_curl_replays_scenario_and_records
                fake_curl_rejects_argv_outside_grammar ARGS $<TARGET_FILE:secure_frontend_fake_curl>)
        endif()
        secure_frontend_add_cases(secure_frontend_fetch_tests fake_curl_answers_probe
            ARGS $<TARGET_FILE:secure_frontend_fake_curl>)
    endif()
    # SP4 Task 21 (spec §3.3-§3.7): fetch_file over ScriptedTransport; these write a models store.
    target_sources(secure_frontend_fetch_tests PRIVATE tests/fetch_file_test.cpp)
    target_link_libraries(secure_frontend_fetch_tests PRIVATE secure_frontend_acquire)
    secure_frontend_add_cases(secure_frontend_fetch_tests dl03_truncated_body_rejected dl03_oversize_body_rejected_mid_stream
        dl03_redirect_to_http_rejected dl03_redirect_off_allowlist_rejected dl03_redirect_limit redirect_query_only_in_config_line
        dl03_private_address_rejected dl03_mixed_public_private_answer_rejected dl03_range_ignored_restarts_from_zero
        dl03_content_range_mismatch_rejected dl03_content_encoding_gzip_fails_digest dl03_stalled_source_times_out
        time_budget_exceeded_is_resumable tls_untrusted_moves_to_next_source digest_mismatch_after_resume_refetches_once
        free_space_rechecked_while_writing ipv6_only_hop_is_address_not_allowed
        range_ignored_twice_is_range_mismatch_then_restarts proxy_hop_skips_address_policy
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(SECURE_FRONTEND_TEST_HOOKS)
        secure_frontend_add_cases(secure_frontend_fetch_tests test_cacert_reaches_argv_in_hook_builds
            LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    endif()
    # SP4 Task 22: a wrong digest during an update leaves the installed version active.
    target_sources(secure_frontend_fetch_tests PRIVATE tests/fetch_pull_test.cpp)
    secure_frontend_add_cases(secure_frontend_fetch_tests dl03_wrong_digest_rejected_prior_version_intact
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    # SP4 Tasks 25/26 (spec §3.1-§3.3, §10.3): the confined downloader on Linux and Windows.
    target_link_libraries(secure_frontend_fetch_tests PRIVATE secure_frontend_downloader)
    if(WIN32)
        # Task 26 (spec §3.2 Windows column). Ruling I11: two unconditional cases, the two
        # record-reading cases hooks-only. All windows-runtime: MSYS2 CI is authoritative.
        target_sources(secure_frontend_fetch_tests PRIVATE tests/fetch_spawn_windows_test.cpp)
        secure_frontend_add_cases(secure_frontend_fetch_tests downloader_transfer_through_job_windows
            dl03_default_windows_curl_path_accepted_windows ARGS $<TARGET_FILE:secure_frontend_fake_curl>
            LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
        # Fix round 1: SP1 normalisation/root-form rules on the downloader path (wine-runnable).
        secure_frontend_add_cases(secure_frontend_fetch_tests dl03_downloader_path_normalised_windows
            dl03_downloader_unc_path_rejected_windows ARGS $<TARGET_FILE:secure_frontend_fake_curl>)
        if(SECURE_FRONTEND_TEST_HOOKS)
            secure_frontend_add_cases(secure_frontend_fetch_tests dl03_downloader_runs_at_low_integrity_windows
                priv04_downloader_env_is_systemroot_only_windows ARGS $<TARGET_FILE:secure_frontend_fake_curl>
                LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
        endif()
    else()
        target_sources(secure_frontend_fetch_tests PRIVATE tests/fetch_spawn_test.cpp)
        secure_frontend_add_cases(secure_frontend_fetch_tests downloader_spawn_report_classified)
        # Record-channel and hook-switch cases (plan Global Constraints).
        if(SECURE_FRONTEND_TEST_HOOKS)
            secure_frontend_add_cases(secure_frontend_fetch_tests priv04_downloader_argv_exact priv04_downloader_env_is_empty
                redirect_url_absent_from_downloader_argv dl03_downloader_untrusted_path_rejected downloader_below_floor_exits_9
                dl03_downloader_cannot_write_files dl03_downloader_cannot_read_home pre_exec_failure_fails_closed_exit_9
                probe_interrupted_exits_8
                ruleset_failure_fails_closed_exit_9 record_fd_does_not_clobber_report_pipe
                confinement_reduced_is_announced_without_landlock
                ARGS $<TARGET_FILE:secure_frontend_fake_curl>)
            # Ruling R7: skipped only on a kernel without Landlock; a rejected ruleset is a failure.
            set_tests_properties(secure_frontend_fetch_tests.dl03_downloader_cannot_write_files
                secure_frontend_fetch_tests.dl03_downloader_cannot_read_home
                secure_frontend_fetch_tests.ruleset_failure_fails_closed_exit_9
                PROPERTIES SKIP_REGULAR_EXPRESSION "SKIPPED: Landlock is unavailable")
        endif()
    endif()
    # SP4 Task 28 (spec §7, §10.3 DL-01/PRIV-01..04, §10.5): privacy lifecycle and release-only proofs.
    secure_frontend_add_test_executable(secure_frontend_privacy_tests tests/privacy_test.cpp secure_frontend_strata_cli)
    add_dependencies(secure_frontend_privacy_tests strata strata-secure-server secure_frontend_fake_engine secure_frontend_fake_curl
        strata-supervision-fake-engine)
    if(WIN32)
        target_link_libraries(secure_frontend_privacy_tests PRIVATE iphlpapi ws2_32)
    endif()
    set(_sf_server_args ARGS $<TARGET_FILE:strata-secure-server> $<TARGET_FILE:secure_frontend_fake_engine>)
    secure_frontend_add_cases(secure_frontend_privacy_tests priv03_api_payloads_resembling_pull_trigger_nothing ${_sf_server_args}
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    secure_frontend_add_cases(secure_frontend_privacy_tests doctor_proxy_hint_is_presence_only ARGS $<TARGET_FILE:strata>
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    secure_frontend_add_cases(secure_frontend_privacy_tests doctor_warns_on_strata_env_knob ARGS $<TARGET_FILE:strata>
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    secure_frontend_add_cases(secure_frontend_privacy_tests priv04_secure_server_does_not_link_acquisition
        ARGS ${CMAKE_CURRENT_BINARY_DIR}/strata-secure-server.link-set.txt ${CMAKE_CURRENT_BINARY_DIR}/strata.link-set.txt
        LABELS release-also)
    secure_frontend_add_cases(secure_frontend_privacy_tests release_binary_lacks_hook_marker
        ARGS $<TARGET_FILE:strata> $<TARGET_FILE:strata-secure-server> LABELS release-only)
    if(UNIX)
        # Linux LD_PRELOAD socket audit (logs, and with SF_CONNECT_AUDIT_BLOCK refuses, non-loopback use).
        add_library(secure_frontend_connect_audit SHARED tests/connect_audit_shim.cpp)
        set_target_properties(secure_frontend_connect_audit PROPERTIES PREFIX "")
        target_compile_features(secure_frontend_connect_audit PRIVATE cxx_std_20)
        target_link_libraries(secure_frontend_connect_audit PRIVATE dl)
        secure_frontend_set_warnings(secure_frontend_connect_audit)
        add_executable(secure_frontend_fd_census tests/fd_census_main.cpp)
        secure_frontend_set_warnings(secure_frontend_fd_census)
        add_executable(secure_frontend_resolve_probe tests/resolve_probe_main.cpp)
        secure_frontend_set_warnings(secure_frontend_resolve_probe)
        target_link_libraries(secure_frontend_resolve_probe PRIVATE dl)
        add_dependencies(secure_frontend_privacy_tests secure_frontend_connect_audit secure_frontend_resolve_probe)
        secure_frontend_add_cases(secure_frontend_privacy_tests dl01_server_makes_no_outbound_connection
            ARGS $<TARGET_FILE:strata-secure-server> $<TARGET_FILE:secure_frontend_fake_engine>
                 $<TARGET_FILE:secure_frontend_connect_audit> $<TARGET_FILE:secure_frontend_resolve_probe>
            LABELS release-also TIMEOUT 120)
        secure_frontend_add_cases(secure_frontend_privacy_tests priv01_lifecycle_and_crash_restart_make_no_network_use
            ARGS $<TARGET_FILE:strata-secure-server> $<TARGET_FILE:strata-supervision-fake-engine>
                 $<TARGET_FILE:secure_frontend_connect_audit>
            TIMEOUT 120)
        target_sources(secure_frontend_fetch_tests PRIVATE tests/fetch_release_test.cpp)
        add_dependencies(secure_frontend_fetch_tests secure_frontend_fd_census strata)
        secure_frontend_add_cases(secure_frontend_fetch_tests release_spawn_has_no_fd4
            ARGS $<TARGET_FILE:strata> $<TARGET_FILE:secure_frontend_fd_census> LABELS release-only)
    else()
        secure_frontend_add_cases(secure_frontend_privacy_tests dl01_server_makes_no_outbound_connection_windows ${_sf_server_args}
            LABELS windows-runtime release-also TIMEOUT 120)
    endif()
    if(SECURE_FRONTEND_TEST_HOOKS)
        # Record-channel cases (plan Global Constraints): hooks builds only.
        secure_frontend_add_cases(secure_frontend_privacy_tests dl01_serve_and_infer_never_spawn_downloader ${_sf_server_args}
            LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
        foreach(_case IN ITEMS dl01_positive_control_pull_spawn_is_recorded priv01_local_verbs_never_spawn_downloader
                priv02_pull_output_and_logs_contain_no_url_query priv02_errors_contain_no_proxy_or_address)
            secure_frontend_add_cases(secure_frontend_privacy_tests ${_case}
                ARGS $<TARGET_FILE:strata> $<TARGET_FILE:secure_frontend_fake_curl> LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
        endforeach()
        # Ruling R6: on Linux the probe's strata child also runs under the connect-audit shim.
        if(UNIX)
            secure_frontend_add_cases(secure_frontend_privacy_tests priv01_positive_control_doctor_downloader_probe_is_recorded
                ARGS $<TARGET_FILE:strata> $<TARGET_FILE:secure_frontend_fake_curl> $<TARGET_FILE:secure_frontend_connect_audit>
                TIMEOUT 120)
        else()
            secure_frontend_add_cases(secure_frontend_privacy_tests priv01_positive_control_doctor_downloader_probe_is_recorded
                ARGS $<TARGET_FILE:strata> $<TARGET_FILE:secure_frontend_fake_curl> LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
        endif()
        secure_frontend_add_cases(secure_frontend_privacy_tests hooks_build_announces_marker
            ARGS $<TARGET_FILE:strata> $<TARGET_FILE:strata-secure-server>)
    endif()
    # SP4 Task 27 (spec §3.2, §7.3, §10.3): confinement through the strata CLI and acquire.log.
    target_sources(secure_frontend_fetch_tests PRIVATE tests/fetch_cli_test.cpp)
    target_link_libraries(secure_frontend_fetch_tests PRIVATE secure_frontend_strata_cli)
    secure_frontend_add_cases(secure_frontend_fetch_tests confinement_reduced_written_to_log_record LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(NOT WIN32)
        secure_frontend_add_cases(secure_frontend_fetch_tests doctor_downloader_probes_on_fresh_store
            ARGS $<TARGET_FILE:secure_frontend_fake_curl>)
        if(SECURE_FRONTEND_TEST_HOOKS)
            secure_frontend_add_cases(secure_frontend_fetch_tests confinement_reduced_when_root_beneath_allowed_dir
                ARGS $<TARGET_FILE:secure_frontend_fake_curl>)
        endif()
    endif()

    add_test(NAME strata_secure_server_help COMMAND strata-secure-server --help)
    # G4: past --help the server refuses an elevated token, and the Windows CI
    # runners (and wine) are elevated. On Windows the CLI checks below run it
    # through the shared non-elevated launch (tests/support/non_elevated_launch.hpp)
    # and are windows-runtime (wine cannot produce a non-elevated token); on
    # Linux they run the server directly and stay unlabeled.
    set(SECURE_FRONTEND_SERVER_CLI_LAUNCH strata-secure-server)
    if(WIN32)
        secure_frontend_add_test_executable(secure_frontend_non_elevated_run tests/non_elevated_run_main.cpp shell32)
        target_include_directories(secure_frontend_non_elevated_run PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        add_dependencies(secure_frontend_non_elevated_run strata-secure-server)
        set(SECURE_FRONTEND_SERVER_CLI_LAUNCH secure_frontend_non_elevated_run $<TARGET_FILE:strata-secure-server>)
    endif()
    # SP5 M2 Task 7 (D-8, C-5): the GLM launch is composed from the model directory and the
    # typed table — engine.args with glm53 is refused by name (SP1 pass-through retired).
    add_test(NAME strata_secure_server_glm_rejects_engine_args
        COMMAND ${SECURE_FRONTEND_SERVER_CLI_LAUNCH} --expert --profile glm53 --models-root models --tokenizer-pack tok
                --engine engine --model-id glm-local --engine-arg --max-context --engine-arg 32768 --token-env STRATA_UNUSED_TOKEN)
    set_tests_properties(strata_secure_server_glm_rejects_engine_args PROPERTIES
        PASS_REGULAR_EXPRESSION "engine.args: engine.profile glm53 takes no engine arguments"
        FAIL_REGULAR_EXPRESSION "32768")
    # Review Focus 4: a malformed --gpu is a startup error with a fixed message (never the value).
    add_test(NAME strata_secure_server_rejects_malformed_gpu
        COMMAND ${SECURE_FRONTEND_SERVER_CLI_LAUNCH} --models-root models --tokenizer-pack tok --engine engine
                --model-id m --token-env STRATA_UNUSED_TOKEN --gpu 0,0)
    set_tests_properties(strata_secure_server_rejects_malformed_gpu PROPERTIES
        PASS_REGULAR_EXPRESSION "engine.gpu: must be a comma-separated list of distinct device indices"
        FAIL_REGULAR_EXPRESSION "0,0")
    if(WIN32)
        set_tests_properties(strata_secure_server_glm_rejects_engine_args strata_secure_server_rejects_malformed_gpu
            PROPERTIES LABELS windows-runtime)
    endif()
endif()

# PRIV-04 supplement (SP4 §7.1): the transitive link closures of strata-secure-server and
# (its positive control) strata, read by privacy.priv04_secure_server_does_not_link_acquisition.
# Kept last so every target_link_libraries above is already recorded. Generator
# expressions ($<LINK_ONLY:x>, $<$<PLATFORM_ID:Windows>:x>, ...) are handled
# conservatively: every name inside one that is a target is followed, whatever the condition.
function(secure_frontend_link_closure target out_var)
    set(_seen "")
    set(_queue ${target})
    while(_queue)
        list(POP_FRONT _queue _item)
        if(NOT TARGET ${_item} OR _item IN_LIST _seen)
            continue()
        endif()
        list(APPEND _seen ${_item})
        get_target_property(_direct ${_item} LINK_LIBRARIES)
        get_target_property(_interface ${_item} INTERFACE_LINK_LIBRARIES)
        foreach(_lib IN LISTS _direct _interface)
            if(NOT _lib OR _lib MATCHES "-NOTFOUND$")
                continue()
            endif()
            if(_lib MATCHES "[<>]")
                # A generator expression, or a piece of one split at a ';' inside it. Keep
                # "ns::name" whole; every other separator splits the text into words.
                string(REPLACE "::" "@@" _words "${_lib}")
                string(REGEX MATCHALL "[A-Za-z0-9_.+@-]+" _words "${_words}")
                foreach(_word IN LISTS _words)
                    string(REPLACE "@@" "::" _word "${_word}")
                    list(APPEND _queue ${_word})
                endforeach()
            else()
                list(APPEND _queue ${_lib})
            endif()
        endforeach()
    endwhile()
    set(${out_var} ${_seen} PARENT_SCOPE)
endfunction()
foreach(_sf_link_target IN ITEMS strata-secure-server strata)
    secure_frontend_link_closure(${_sf_link_target} _sf_link_set)
    list(JOIN _sf_link_set "\n" _sf_link_text)
    # file(WRITE) writes text mode on a native Windows host (CRLF on MSYS2); pin LF on every host.
    file(CONFIGURE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${_sf_link_target}.link-set.txt"
        CONTENT "@_sf_link_text@\n" @ONLY NEWLINE_STYLE UNIX)
endforeach()
