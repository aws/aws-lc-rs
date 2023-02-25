cmake_minimum_required(VERSION 3.0)

project(AWS_LC_RUST NONE)
enable_language(C)

add_subdirectory(aws-lc aws-lc EXCLUDE_FROM_ALL)

add_definitions(-DAWS_LC_RUST_INCLUDE_SSL)
add_library(rust_wrapper STATIC rust_wrapper.c)
target_include_directories(rust_wrapper PRIVATE include)
target_link_libraries(rust_wrapper PUBLIC crypto ssl)

if (BORINGSSL_PREFIX)
    set_target_properties(rust_wrapper crypto ssl PROPERTIES PREFIX "lib${BORINGSSL_PREFIX}")
endif ()
