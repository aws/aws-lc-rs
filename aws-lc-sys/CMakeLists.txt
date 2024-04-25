# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

cmake_minimum_required(VERSION 3.0)

project(AWS_LC_RUST NONE)
enable_language(C)

function(set_my_target_properties ...)
    set_target_properties(rust_wrapper crypto PROPERTIES ${ARGV})
    if (BUILD_LIBSSL)
        set_target_properties(ssl PROPERTIES ${ARGV})
    endif()
endfunction()

if(BUILD_SHARED_LIBS)
    add_definitions(-DBORINGSSL_SHARED_LIBRARY)
endif()

add_subdirectory(aws-lc aws-lc EXCLUDE_FROM_ALL)

if (BUILD_LIBSSL)
    add_definitions(-DAWS_LC_RUST_INCLUDE_SSL)
endif()

add_library(rust_wrapper rust_wrapper.c)
target_include_directories(rust_wrapper PRIVATE include)
target_link_libraries(rust_wrapper PUBLIC crypto)
if (BUILD_LIBSSL)
    target_link_libraries(rust_wrapper PUBLIC ssl)
endif()

set(FINAL_ARTIFACTS_DIRECTORY ${CMAKE_BINARY_DIR}/artifacts)

# Places the compiled library files at the root of the binary directory so we can have a consistent
# location to find the artifacts cross-platform.
set_my_target_properties(
        ARCHIVE_OUTPUT_DIRECTORY ${FINAL_ARTIFACTS_DIRECTORY}
        RUNTIME_OUTPUT_DIRECTORY ${FINAL_ARTIFACTS_DIRECTORY}
        LIBRARY_OUTPUT_DIRECTORY ${FINAL_ARTIFACTS_DIRECTORY})

# Based on https://stackoverflow.com/a/7750816 as some generators, like MSVC, will try to prefix the output directory
# which is not needed in our case.
foreach (OUT_NAME ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${OUT_NAME} OUT_NAME)
    set_my_target_properties(
            ARCHIVE_OUTPUT_DIRECTORY_${OUT_NAME} ${FINAL_ARTIFACTS_DIRECTORY}
            RUNTIME_OUTPUT_DIRECTORY_${OUT_NAME} ${FINAL_ARTIFACTS_DIRECTORY}
            LIBRARY_OUTPUT_DIRECTORY_${OUT_NAME} ${FINAL_ARTIFACTS_DIRECTORY})
endforeach ()

if (BORINGSSL_PREFIX)
    if (MSVC)
        set(TARGET_PREFIX "${BORINGSSL_PREFIX}")
        set_my_target_properties(IMPORT_PREFIX ${TARGET_PREFIX})
    else()
        set(TARGET_PREFIX "lib${BORINGSSL_PREFIX}")
    endif()
    set_my_target_properties(PREFIX ${TARGET_PREFIX})

    # This BORINGSSL_PREFIX has an "_" appended, so we must remove it
    string(REGEX REPLACE "_$" "" BORINGSSL_PREFIX_MACRO ${BORINGSSL_PREFIX})
    add_definitions(-DBORINGSSL_PREFIX=${BORINGSSL_PREFIX_MACRO})
endif ()
