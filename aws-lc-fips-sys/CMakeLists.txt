#[[
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0 OR ISC
]]

cmake_minimum_required(VERSION 3.0)

project(AWS_LC_RUST NONE)
enable_language(C)

if (BUILD_SHARED_LIBS AND FIPS)
    # FIPS_SHARED does not support unique function or data sections, but we can't set this from Rust
    # as cmake crate will postfix the C/CXX flags after out disablement nullifying them.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-function-sections -fno-data-sections")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-function-sections -fno-data-sections")
endif ()

add_subdirectory(aws-lc aws-lc EXCLUDE_FROM_ALL)

add_definitions(-DAWS_LC_RUST_INCLUDE_SSL)
add_library(rust_wrapper rust_wrapper.c)
target_include_directories(rust_wrapper PRIVATE include)
target_link_libraries(rust_wrapper PUBLIC crypto ssl)

if (BORINGSSL_PREFIX)
    set_target_properties(rust_wrapper crypto ssl PROPERTIES PREFIX "lib${BORINGSSL_PREFIX}")
endif ()
