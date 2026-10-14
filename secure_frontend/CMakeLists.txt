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

function(secure_frontend_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
        if(SECURE_FRONTEND_WERROR)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        if(SECURE_FRONTEND_WERROR)
            target_compile_options(${target} PRIVATE -Werror)
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
    src/engine_stdio_process.cpp
)

add_library(secure_frontend_http_socket_server
    src/http_socket_server.cpp
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

add_library(secure_frontend_typed_config src/frontend_config.cpp src/config_file.cpp)
target_compile_features(secure_frontend_typed_config PUBLIC cxx_std_20)
target_include_directories(secure_frontend_typed_config PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_typed_config PUBLIC secure_frontend_config secure_frontend_json
    secure_frontend_model_inventory secure_frontend_engine_arguments)
target_link_libraries(secure_frontend_typed_config PUBLIC secure_frontend_paths)

add_library(secure_frontend_server_cli src/server_cli.cpp)
target_compile_features(secure_frontend_server_cli PUBLIC cxx_std_20)
target_include_directories(secure_frontend_server_cli PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_server_cli PUBLIC secure_frontend_typed_config)

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

add_library(secure_frontend_subsystem_limits src/subsystem_limits.cpp)
target_compile_features(secure_frontend_subsystem_limits PUBLIC cxx_std_20)
target_include_directories(secure_frontend_subsystem_limits PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_subsystem_limits PUBLIC secure_frontend_typed_config
    secure_frontend_http_socket_server secure_frontend_chat_execution secure_frontend_chat_schema)

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

target_compile_features(secure_frontend_http_request_handler PUBLIC cxx_std_20)
target_include_directories(secure_frontend_http_request_handler
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_http_request_handler PUBLIC secure_frontend_http_policy)

target_compile_features(secure_frontend_http_socket_server PUBLIC cxx_std_20)
target_include_directories(secure_frontend_http_socket_server
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_http_socket_server PUBLIC secure_frontend_http_request_handler secure_frontend_config)

target_compile_features(secure_frontend_api_router PUBLIC cxx_std_20)
target_include_directories(secure_frontend_api_router
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(secure_frontend_api_router PUBLIC secure_frontend_http_request_handler)

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
target_compile_features(secure_frontend_json PUBLIC cxx_std_20)
target_include_directories(secure_frontend_json PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(secure_frontend_chat_schema PUBLIC secure_frontend_json)
target_link_libraries(secure_frontend_tokenizer_pack PUBLIC secure_frontend_json)
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
target_link_libraries(strata-secure-server PRIVATE secure_frontend_subsystem_limits)
target_compile_features(strata-secure-server PRIVATE cxx_std_20)

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

if(WIN32)
    target_link_libraries(secure_frontend_config PUBLIC ws2_32)
    target_link_libraries(secure_frontend_http_socket_server PUBLIC ws2_32)
    target_link_libraries(secure_frontend_token_reader PUBLIC advapi32)
    target_link_libraries(secure_frontend_paths PUBLIC advapi32)
endif()

foreach(_target IN ITEMS
        secure_frontend_paths secure_frontend_config secure_frontend_token_reader secure_frontend_http_policy
        secure_frontend_http_request_handler secure_frontend_api_router secure_frontend_engine_process
        secure_frontend_engine_protocol_client secure_frontend_engine_stdio_process
        secure_frontend_http_socket_server secure_frontend_model_inventory secure_frontend_engine_arguments
        secure_frontend_json secure_frontend_typed_config secure_frontend_server_cli secure_frontend_chat_schema
        secure_frontend_tokenizer_pack secure_frontend_qwen_prompt_renderer secure_frontend_glm_prompt_renderer
        secure_frontend_chat_generation_plan secure_frontend_chat_execution secure_frontend_subsystem_limits
        secure-frontend-smoke strata-secure-smoke-server strata-secure-server)
    secure_frontend_set_warnings(${_target})
endforeach()

if(STRATA_BUILD_SECURE_FRONTEND_TESTS)
    enable_testing()

    secure_frontend_add_test_executable(secure_frontend_paths_tests tests/paths_test.cpp secure_frontend_paths)
    secure_frontend_add_cases(secure_frontend_paths_tests
        relative_path_accepts_portable_forms cfg02_rejects_traversal_and_absolute cfg02_rejects_nul_and_control_bytes
        cfg04_rejects_reserved_and_device_names cfg04_rejects_trailing_dot_space_and_8dot3 cfg04_rejects_ads_and_drive_forms)
    secure_frontend_add_cases(secure_frontend_paths_tests
        cfg02_rejects_relative_root cfg02_sibling_prefix_root_rejected cfg04_rejects_unc_device_and_extended_roots
        cfg04_final_path_on_network_share_is_actionable)
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

    if(UNIX)
        # POSIX-only until SP1 Task 18 un-gates it for the windows-msys2-clang job.
        secure_frontend_add_test_executable(secure_frontend_token_reader_tests tests/token_reader_test.cpp
            secure_frontend_token_reader)
        secure_frontend_add_cases(secure_frontend_token_reader_tests
            reads_an_owner_only_regular_file_below_the_root reads_the_named_environment_variable
            rejects_control_characters_in_resolved_tokens rejects_a_group_or_world_accessible_file
            rejects_a_symlink_that_escapes_the_root rejects_a_non_regular_file
            cfg03_rejects_hardlinked_token_file)
    endif()

    secure_frontend_add_test_executable(secure_frontend_engine_stdio_process_tests tests/engine_stdio_process_test.cpp
        secure_frontend_engine_stdio_process)
    set(_stdio_cases test_round_trip test_invalid_record read_line_rejects_oversize_on_all_platforms
        read_line_waits_for_a_record_split_across_writes)
    if(WIN32)
        list(APPEND _stdio_cases job_object_terminates_grandchild)
    else()
        list(APPEND _stdio_cases child_inherits_only_stdio_descriptors child_receives_exact_argv_and_env
            terminate_reaps_killed_child)
    endif()
    secure_frontend_add_cases(secure_frontend_engine_stdio_process_tests ${_stdio_cases} TIMEOUT 300)

    secure_frontend_add_test_executable(secure_frontend_http_policy_tests tests/http_policy_test.cpp secure_frontend_http_policy)
    secure_frontend_add_cases(secure_frontend_http_policy_tests
        accepts_exact_host_without_browser_origin rejects_ambiguous_or_untrusted_host requires_an_exact_same_origin
        rejects_duplicate_or_malformed_origin permits_only_configured_cors_origin_when_enabled)

    secure_frontend_add_test_executable(secure_frontend_http_request_handler_tests tests/http_request_handler_test.cpp
        secure_frontend_http_request_handler)
    secure_frontend_add_cases(secure_frontend_http_request_handler_tests
        accepts_authorized_request passes_the_bounded_raw_body_to_an_authorized_dispatcher
        rejects_malformed_and_ambiguous_messages requires_one_well_formed_bearer_token
        fails_closed_before_calling_validator_for_untrusted_origin emits_cors_only_for_policy_approved_origin
        handles_policy_approved_preflight_without_exposing_an_endpoint constant_time_helper_matches_only_equal_tokens)

    secure_frontend_add_test_executable(secure_frontend_http_socket_server_tests tests/http_socket_server_test.cpp
        secure_frontend_http_socket_server)
    secure_frontend_add_cases(secure_frontend_http_socket_server_tests
        serves_a_loopback_request_without_outbound_connections socket_server_survives_client_early_close
        socket_server_rejects_slow_request_past_deadline socket_server_send_times_out_on_stalled_reader
        socket_server_rejects_oversize_request_over_tcp socket_server_accept_waits_without_timeout
        socket_server_ipv6_bind_is_v6only socket_server_response_is_complete
        socket_server_survives_reset_before_accept socket_server_responds_after_client_half_close
        parser_honors_configured_max_request_bytes
        TIMEOUT 300)

    secure_frontend_add_test_executable(secure_frontend_api_router_tests tests/api_router_test.cpp secure_frontend_api_router)
    secure_frontend_add_cases(secure_frontend_api_router_tests
        health_samples_status_before_state_once_each health_includes_engine_state_when_provided
        health_is_503_with_engine_state_when_unavailable dispatches_exact_health_route
        dispatches_models_with_json_escaping rejects_non_exact_routes
        fails_closed_when_provider_throws_or_returns_invalid_model)

    secure_frontend_add_test_executable(secure_frontend_engine_process_tests tests/engine_process_test.cpp
        secure_frontend_engine_process)
    secure_frontend_add_cases(secure_frontend_engine_process_tests
        starts_without_a_shell_and_uses_only_allowlisted_environment rejects_empty_executable
        rejects_malformed_allowlist_entry rejects_embedded_nul_in_exec_boundary termination_cleans_up_a_process_group)

    secure_frontend_add_test_executable(secure_frontend_engine_protocol_client_tests tests/engine_protocol_client_test.cpp
        secure_frontend_engine_protocol_client)
    secure_frontend_add_cases(secure_frontend_engine_protocol_client_tests
        runs_the_solo_protocol stop_and_quit_are_explicit refuses_stop_when_not_advertised
        rejects_malformed_and_unexpected_engine_output bounds_and_engine_errors_fail_closed
        prefill_progress_is_glm_only_and_strictly_bounded generation_total_deadline_is_enforced
        gen_line_fits_max_prompt_tokens derived_line_cap_is_clamped_to_protocol_max)

    secure_frontend_add_test_executable(secure_frontend_model_inventory_tests tests/model_inventory_test.cpp
        secure_frontend_model_inventory)
    secure_frontend_add_cases(secure_frontend_model_inventory_tests
        validates_portable_model_ids validates_portable_artifact_paths inventories_only_local_gguf_artifacts
        rejects_duplicate_ids_and_symlinks)

    secure_frontend_add_test_executable(secure_frontend_engine_arguments_tests tests/engine_arguments_test.cpp
        secure_frontend_engine_arguments)
    secure_frontend_add_cases(secure_frontend_engine_arguments_tests
        engine_receives_model_path_from_inventory engine_args_reject_owned_and_network_flags
        strata_profile_passes_pack_and_weight_flags_through rejects_invalid_relative_artifact_path
        glm_profile_passes_arguments_through_without_native
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})

    secure_frontend_add_test_executable(secure_frontend_chat_schema_tests tests/chat_schema_test.cpp secure_frontend_chat_schema)
    secure_frontend_add_cases(secure_frontend_chat_schema_tests
        parses_minimal_text_request rejects_unsupported_and_unsafe_features rejects_duplicate_and_malformed_json
        renders_escaped_minimal_response)

    secure_frontend_add_test_executable(secure_frontend_json_tests tests/json_test.cpp secure_frontend_json)
    secure_frontend_add_cases(secure_frontend_json_tests
        json_accepts_strict_document json_rejects_duplicate_keys json_rejects_depth_over_limit
        json_rejects_non_integer_numbers json_rejects_bom_trailing_data_and_comments
        json_enforces_size_entry_and_string_limits json_string_escaper_round_trips)

    secure_frontend_add_test_executable(secure_frontend_typed_config_tests tests/typed_config_test.cpp
        secure_frontend_typed_config)
    secure_frontend_add_cases(secure_frontend_typed_config_tests
        typed_config_accepts_minimal_file_and_applies_defaults cfg01_unknown_key_rejected cfg01_duplicate_key_rejected
        cfg01_type_confusion_rejected cfg01_missing_required_rejected cfg01_out_of_range_rejected
        typed_config_cross_field_rules typed_config_errors_never_contain_values
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})
    if(NOT WIN32)
        # chmod-based: the config folder's mode decides the roots.secret default.
        secure_frontend_add_cases(secure_frontend_typed_config_tests
            cfg02_env_token_ignores_config_folder_permissions cfg02_file_token_default_secret_root_reports_one_issue)
    endif()

    secure_frontend_add_test_executable(secure_frontend_tokenizer_pack_tests tests/tokenizer_pack_test.cpp
        secure_frontend_tokenizer_pack)
    set(_tokenizer_cases loads_validates_and_decodes_offline_pack rejects_ambiguous_or_incompatible_pack_assets
        rejects_malformed_json_and_special_literals_for_decode encoding_fails_closed_for_special_invalid_and_missing_tokens)
    if(NOT WIN32)
        list(APPEND _tokenizer_cases rejects_symlinked_assets)
    endif()
    secure_frontend_add_cases(secure_frontend_tokenizer_pack_tests ${_tokenizer_cases})

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
        composes_schema_prompt_and_tokenizer defaults_output_limit_and_rejects_unsafe_inputs
        rejects_missing_or_non_control_framing_tokens does_not_parse_arbitrary_special_literals)

    secure_frontend_add_test_executable(secure_frontend_chat_execution_tests tests/chat_execution_test.cpp
        secure_frontend_chat_execution)
    secure_frontend_add_cases(secure_frontend_chat_execution_tests
        executes_a_bounded_non_streaming_completion rejects_context_and_output_limits_before_generation
        fails_closed_on_invalid_engine_output executes_glm53_only_when_explicitly_selected
        chat_recovers_after_generation_timeout chat_marks_engine_failed_when_drain_fails
        chat_rejects_nonfinite_done_and_stays_ready health_reflects_protocol_state
        health_is_failed_after_engine_closed_mid_generation health_is_failed_when_engine_closes_before_ready
        chat_applies_engine_context_rule_with_eight_token_margin)

    secure_frontend_add_test_executable(secure_frontend_subsystem_limits_tests tests/subsystem_limits_test.cpp
        secure_frontend_subsystem_limits)
    secure_frontend_add_cases(secure_frontend_subsystem_limits_tests
        ready_timeout_defaults_to_900_seconds subsystem_limits_follow_config
        LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME})

    add_executable(secure_frontend_fake_engine tests/fake_engine_main.cpp)
    target_compile_features(secure_frontend_fake_engine PRIVATE cxx_std_20)
    secure_frontend_set_warnings(secure_frontend_fake_engine)
    set(SECURE_FRONTEND_SERVER_ARGS ARGS $<TARGET_FILE:strata-secure-server> $<TARGET_FILE:secure_frontend_fake_engine>)

    secure_frontend_add_test_executable(secure_frontend_server_cli_tests tests/server_cli_test.cpp
        secure_frontend_typed_config)
    add_dependencies(secure_frontend_server_cli_tests strata-secure-server secure_frontend_fake_engine)
    secure_frontend_add_cases(secure_frontend_server_cli_tests
        cli_config_file_and_flags_share_validator cli_flag_overrides_file_and_is_reported cli_check_prints_no_token
        cli_unknown_option_does_not_echo_value
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
        ${SECURE_FRONTEND_SERVER_ARGS} LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    # GetExtendedTcpTable is not faithful under wine.
    secure_frontend_add_cases(secure_frontend_server_e2e_tests net01_default_listener_is_loopback_only
        ${SECURE_FRONTEND_SERVER_ARGS} LABELS ${SECURE_FRONTEND_WINDOWS_RUNTIME} TIMEOUT 120)
    if(NOT WIN32)
        secure_frontend_add_cases(secure_frontend_server_e2e_tests cfg03_engine_receives_canonical_models_root
            ${SECURE_FRONTEND_SERVER_ARGS} TIMEOUT 120)
    endif()

    add_test(NAME strata_secure_server_help COMMAND strata-secure-server --help)
    # The GLM runner takes positional arguments: glm53 without any --engine-arg is a usage error.
    add_test(NAME strata_secure_server_glm_requires_engine_arg
        COMMAND strata-secure-server --profile glm53 --models-root models --tokenizer-pack tok
                --engine engine --model-id glm-local --token-env STRATA_UNUSED_TOKEN)
    set_tests_properties(strata_secure_server_glm_requires_engine_arg PROPERTIES
        PASS_REGULAR_EXPRESSION "glm53 requires at least one --engine-arg")
endif()
