cmake_minimum_required(VERSION 3.12)
project(SimpleMdnsExample VERSION 1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

add_subdirectory(mdns_cpp)

add_executable(mdns_client mdns_client.cpp)

target_include_directories(mdns_client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mdns_cpp/include)
target_include_directories(mdns_client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mdns_cpp/src)
target_link_libraries(mdns_client PRIVATE mdns_cpp Threads::Threads)

# Add platform-specific libraries for the client
if(WIN32)
    target_link_libraries(mdns_client PRIVATE ws2_32)
endif()
