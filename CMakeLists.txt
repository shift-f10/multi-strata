# Secure Strata root build: our secure_frontend/ plus upstream Strata's engine
# from the pinned, unmodified git submodule upstream/ (docs/AGENT_HANDOFF.md,
# "Repository layout"). Upstream's own CMakeLists.txt is used as-is.
cmake_minimum_required(VERSION 3.24)
project(secure_strata LANGUAGES CXX)

# Upstream forces CMAKE_BUILD_TYPE=Release into the cache when it is empty,
# which would leak to the whole build; choose the default here first.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
endif()

# Upstream calls enable_testing() only in its own directories; the root ctest
# sees any test only when the root enables testing.
include(CTest)

option(SECURE_STRATA_BUILD_ENGINE "Configure upstream's engine from upstream/" ON)
option(STRATA_BUILD_SECURE_FRONTEND_TESTS "Build the portable frontend tests" ${BUILD_TESTING})
# Declared here, before upstream's option(STRATA_WERROR OFF) exists, so the
# frontend keeps -Werror whatever STRATA_WERROR is.
option(SECURE_FRONTEND_WERROR "Treat warnings as errors in the secure frontend" ON)

# Upstream's defaults that would need a GPU SDK or the network; -D overrides.
set(STRATA_ENABLE_CUDA OFF CACHE BOOL "Build the CUDA targets")
set(STRATA_ENABLE_HIP OFF CACHE BOOL "Build the HIP targets")
set(STRATA_NATIVE_EXPERTS OFF CACHE BOOL "Native (IQ) experts through ggml-cpu (fetches llama.cpp)")

# The frontend first: see SECURE_FRONTEND_WERROR above.
add_subdirectory(secure_frontend)

if(SECURE_STRATA_BUILD_ENGINE)
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/upstream/CMakeLists.txt")
    message(FATAL_ERROR "upstream/ is empty: run `git submodule update --init`")
  endif()
  add_subdirectory(upstream)
endif()
