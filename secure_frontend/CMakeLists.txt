cmake_minimum_required(VERSION 3.20)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    project(secure_frontend VERSION 0.1.0 LANGUAGES CXX)
    include(CTest)
    option(STRATA_BUILD_SECURE_FRONTEND_TESTS "Build the portable frontend tests" ${BUILD_TESTING})
endif()

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
)

add_library(secure_frontend_model_inventory
    src/model_inventory.cpp
)

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
    secure_frontend_chat_generation_plan secure_frontend_chat_execution)
target_compile_features(strata-secure-server PRIVATE cxx_std_20)

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

if(WIN32)
    target_link_libraries(secure_frontend_config PUBLIC ws2_32)
    target_link_libraries(secure_frontend_http_socket_server PUBLIC ws2_32)
    target_link_libraries(secure_frontend_token_reader PUBLIC advapi32)
endif()

if(MSVC)
    target_compile_options(secure_frontend_config PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_token_reader PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_http_policy PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_http_request_handler PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_api_router PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_engine_process PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_engine_protocol_client PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_engine_stdio_process PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_http_socket_server PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_model_inventory PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_chat_schema PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_tokenizer_pack PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_qwen_prompt_renderer PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_glm_prompt_renderer PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_chat_generation_plan PRIVATE /W4 /WX)
    target_compile_options(secure_frontend_chat_execution PRIVATE /W4 /WX)
    target_compile_options(secure-frontend-smoke PRIVATE /W4 /WX)
    target_compile_options(strata-secure-smoke-server PRIVATE /W4 /WX)
    target_compile_options(strata-secure-server PRIVATE /W4 /WX)
else()
    target_compile_options(secure_frontend_config PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_token_reader PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_http_policy PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_http_request_handler PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_api_router PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_engine_process PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_engine_protocol_client PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_engine_stdio_process PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_http_socket_server PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_model_inventory PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_chat_schema PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_tokenizer_pack PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_qwen_prompt_renderer PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_glm_prompt_renderer PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_chat_generation_plan PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure_frontend_chat_execution PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(secure-frontend-smoke PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(strata-secure-smoke-server PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(strata-secure-server PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

if(STRATA_BUILD_SECURE_FRONTEND_TESTS)
    enable_testing()
    add_executable(secure_frontend_config_tests tests/config_test.cpp)
    target_link_libraries(secure_frontend_config_tests PRIVATE secure_frontend_config)
    target_compile_features(secure_frontend_config_tests PRIVATE cxx_std_20)

    add_executable(secure_frontend_secret_source_tests tests/secret_source_test.cpp)
    target_link_libraries(secure_frontend_secret_source_tests PRIVATE secure_frontend_config)
    target_compile_features(secure_frontend_secret_source_tests PRIVATE cxx_std_20)

    if(UNIX)
        # Protected-file behavior is runtime-tested on Linux/POSIX only. The
        # Windows implementation is fail-closed, but needs MSVC/Windows runtime
        # coverage before a release claim.
        add_executable(secure_frontend_token_reader_tests tests/token_reader_test.cpp)
        target_link_libraries(secure_frontend_token_reader_tests PRIVATE secure_frontend_token_reader)
        target_compile_features(secure_frontend_token_reader_tests PRIVATE cxx_std_20)
        add_executable(secure_frontend_engine_stdio_process_tests tests/engine_stdio_process_test.cpp)
        target_link_libraries(secure_frontend_engine_stdio_process_tests PRIVATE secure_frontend_engine_stdio_process)
        target_compile_features(secure_frontend_engine_stdio_process_tests PRIVATE cxx_std_20)
    endif()

    if(MSVC)
        target_compile_options(secure_frontend_config_tests PRIVATE /W4 /WX)
        target_compile_options(secure_frontend_secret_source_tests PRIVATE /W4 /WX)
        if(UNIX)
            target_compile_options(secure_frontend_token_reader_tests PRIVATE /W4 /WX)
            target_compile_options(secure_frontend_engine_stdio_process_tests PRIVATE /W4 /WX)
        endif()
    else()
        target_compile_options(secure_frontend_config_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
        target_compile_options(secure_frontend_secret_source_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
        if(UNIX)
            target_compile_options(secure_frontend_token_reader_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
            target_compile_options(secure_frontend_engine_stdio_process_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
        endif()
    endif()

    add_test(NAME secure_frontend_config_tests COMMAND secure_frontend_config_tests)
    add_test(NAME secure_frontend_secret_source_tests COMMAND secure_frontend_secret_source_tests)
    if(UNIX)
        add_test(NAME secure_frontend_token_reader_tests COMMAND secure_frontend_token_reader_tests)
        add_test(NAME secure_frontend_engine_stdio_process_tests COMMAND secure_frontend_engine_stdio_process_tests)
    endif()

    add_executable(secure_frontend_http_policy_tests tests/http_policy_test.cpp)
    target_link_libraries(secure_frontend_http_policy_tests PRIVATE secure_frontend_http_policy)
    target_compile_features(secure_frontend_http_policy_tests PRIVATE cxx_std_20)

    if(MSVC)
        target_compile_options(secure_frontend_http_policy_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_http_policy_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()

    add_test(NAME secure_frontend_http_policy_tests COMMAND secure_frontend_http_policy_tests)

    add_executable(secure_frontend_http_request_handler_tests tests/http_request_handler_test.cpp)
    target_link_libraries(secure_frontend_http_request_handler_tests PRIVATE secure_frontend_http_request_handler)
    target_compile_features(secure_frontend_http_request_handler_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(secure_frontend_http_request_handler_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_http_request_handler_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME secure_frontend_http_request_handler_tests COMMAND secure_frontend_http_request_handler_tests)

    if(UNIX)
        add_executable(secure_frontend_http_socket_server_tests tests/http_socket_server_test.cpp)
        target_link_libraries(secure_frontend_http_socket_server_tests PRIVATE secure_frontend_http_socket_server)
        target_compile_features(secure_frontend_http_socket_server_tests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(secure_frontend_http_socket_server_tests PRIVATE /W4 /WX)
        else()
            target_compile_options(secure_frontend_http_socket_server_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
        endif()
        add_test(NAME secure_frontend_http_socket_server_tests COMMAND secure_frontend_http_socket_server_tests)
    endif()

    add_executable(secure_frontend_api_router_tests tests/api_router_test.cpp)
    target_link_libraries(secure_frontend_api_router_tests PRIVATE secure_frontend_api_router)
    target_compile_features(secure_frontend_api_router_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(secure_frontend_api_router_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_api_router_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME secure_frontend_api_router_tests COMMAND secure_frontend_api_router_tests)

    add_executable(secure_frontend_engine_process_tests tests/engine_process_test.cpp)
    target_link_libraries(secure_frontend_engine_process_tests PRIVATE secure_frontend_engine_process)
    target_compile_features(secure_frontend_engine_process_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(secure_frontend_engine_process_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_engine_process_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME secure_frontend_engine_process_tests COMMAND secure_frontend_engine_process_tests)

    add_executable(secure_frontend_engine_protocol_client_tests tests/engine_protocol_client_test.cpp)
    target_link_libraries(secure_frontend_engine_protocol_client_tests PRIVATE secure_frontend_engine_protocol_client)
    target_compile_features(secure_frontend_engine_protocol_client_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(secure_frontend_engine_protocol_client_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_engine_protocol_client_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME secure_frontend_engine_protocol_client_tests COMMAND secure_frontend_engine_protocol_client_tests)

    add_executable(secure_frontend_model_inventory_tests tests/model_inventory_test.cpp)
    target_link_libraries(secure_frontend_model_inventory_tests PRIVATE secure_frontend_model_inventory)
    target_compile_features(secure_frontend_model_inventory_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(secure_frontend_model_inventory_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_model_inventory_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME secure_frontend_model_inventory_tests COMMAND secure_frontend_model_inventory_tests)

    add_executable(secure_frontend_chat_schema_tests tests/chat_schema_test.cpp)
    target_link_libraries(secure_frontend_chat_schema_tests PRIVATE secure_frontend_chat_schema)
    target_compile_features(secure_frontend_chat_schema_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(secure_frontend_chat_schema_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_chat_schema_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME secure_frontend_chat_schema_tests COMMAND secure_frontend_chat_schema_tests)

    add_executable(secure_frontend_tokenizer_pack_tests tests/tokenizer_pack_test.cpp)
    target_link_libraries(secure_frontend_tokenizer_pack_tests PRIVATE secure_frontend_tokenizer_pack)
    target_compile_features(secure_frontend_tokenizer_pack_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(secure_frontend_tokenizer_pack_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_tokenizer_pack_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME secure_frontend_tokenizer_pack_tests COMMAND secure_frontend_tokenizer_pack_tests)

    add_executable(secure_frontend_qwen_prompt_renderer_tests tests/qwen_prompt_renderer_test.cpp)
    target_link_libraries(secure_frontend_qwen_prompt_renderer_tests PRIVATE secure_frontend_qwen_prompt_renderer)
    target_compile_features(secure_frontend_qwen_prompt_renderer_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(secure_frontend_qwen_prompt_renderer_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_qwen_prompt_renderer_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME secure_frontend_qwen_prompt_renderer_tests COMMAND secure_frontend_qwen_prompt_renderer_tests)

    add_executable(secure_frontend_glm_profile_tests tests/glm_profile_test.cpp)
    target_link_libraries(secure_frontend_glm_profile_tests PRIVATE secure_frontend_chat_generation_plan)
    target_compile_features(secure_frontend_glm_profile_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(secure_frontend_glm_profile_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_glm_profile_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME secure_frontend_glm_profile_tests COMMAND secure_frontend_glm_profile_tests)

    add_executable(secure_frontend_chat_generation_plan_tests tests/chat_generation_plan_test.cpp)
    target_link_libraries(secure_frontend_chat_generation_plan_tests PRIVATE secure_frontend_chat_generation_plan)
    target_compile_features(secure_frontend_chat_generation_plan_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(secure_frontend_chat_generation_plan_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_chat_generation_plan_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME secure_frontend_chat_generation_plan_tests COMMAND secure_frontend_chat_generation_plan_tests)

    add_executable(secure_frontend_chat_execution_tests tests/chat_execution_test.cpp)
    target_link_libraries(secure_frontend_chat_execution_tests PRIVATE secure_frontend_chat_execution)
    target_compile_features(secure_frontend_chat_execution_tests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(secure_frontend_chat_execution_tests PRIVATE /W4 /WX)
    else()
        target_compile_options(secure_frontend_chat_execution_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME secure_frontend_chat_execution_tests COMMAND secure_frontend_chat_execution_tests)
    add_test(NAME strata_secure_server_help COMMAND strata-secure-server --help)
endif()
