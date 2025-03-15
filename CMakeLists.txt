cmake_minimum_required(VERSION 3.16)
project(srtla_send VERSION 1.0.0)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/Modules")

find_package(spdlog REQUIRED)

add_library(common_obj OBJECT
    src/common.c
    src/common.h)

add_executable(srtla_send
    src/sender.cpp
    src/sender.h)

target_include_directories(srtla_send PRIVATE
    "deps/argparse/include")
target_link_libraries(srtla_send PRIVATE
    common_obj
    spdlog::spdlog
    -Wl,-rpath,/usr/local/lib
)
target_compile_features(srtla_send PRIVATE cxx_std_17)
#target_compile_options(srtla_send PRIVATE -Wall -Wextra)
target_compile_definitions(srtla_send PUBLIC VERSION="${CMAKE_PROJECT_VERSION}")

set(CMAKE_BUILD_TYPE RelWithDebInfo)
install(TARGETS srtla_send RUNTIME DESTINATION bin)
