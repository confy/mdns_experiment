cmake_minimum_required(VERSION 3.16)

project(mdns_experiment)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
    mdns
    GIT_REPOSITORY https://github.com/mjansson/mdns.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(mdns)

add_executable(mdns_server mdns_server.cpp)
target_include_directories(mdns_server PUBLIC ${mdns_SOURCE_DIR})
target_link_libraries(mdns_server PRIVATE mdns::mdns)
