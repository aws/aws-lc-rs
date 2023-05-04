#[[
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0 OR ISC
]]

cmake_minimum_required(VERSION 3.0)

project(AWS_LC_RUST NONE)
enable_language(C)

add_subdirectory(aws-lc aws-lc EXCLUDE_FROM_ALL)

add_definitions(-DAWS_LC_RUST_INCLUDE_SSL)
add_library(rust_wrapper STATIC rust_wrapper.c)
target_include_directories(rust_wrapper PRIVATE include)
target_link_libraries(rust_wrapper PUBLIC crypto ssl)

set(FINAL_ARTIFACTS_DIRECTORY ${CMAKE_BINARY_DIR}/artifacts)

# Places the compiled library files at the root of the binary directory so we can have a consistent
# location to find the artifacts cross-platform.
set_target_properties(rust_wrapper crypto ssl
        PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${FINAL_ARTIFACTS_DIRECTORY}
        LIBRARY_OUTPUT_DIRECTORY ${FINAL_ARTIFACTS_DIRECTORY})

# Based on https://stackoverflow.com/a/7750816 as some generators, like MSVC, will try to prefix the output directory
# which is not needed in our case.
foreach (OUT_NAME ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${OUT_NAME} OUT_NAME)
    set_target_properties(rust_wrapper crypto ssl
            PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY_${OUT_NAME} ${FINAL_ARTIFACTS_DIRECTORY}
            LIBRARY_OUTPUT_DIRECTORY_${OUT_NAME} ${FINAL_ARTIFACTS_DIRECTORY})
endforeach ()

if (BORINGSSL_PREFIX)
    if (MSVC)
        set(TARGET_PREFIX "${BORINGSSL_PREFIX}")
    else()
        set(TARGET_PREFIX "lib${BORINGSSL_PREFIX}")
    endif()
    set_target_properties(rust_wrapper crypto ssl PROPERTIES PREFIX ${TARGET_PREFIX})
endif ()
