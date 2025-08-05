cmake_minimum_required(VERSION 3.12)
project(SimpleMdnsExample VERSION 1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

# Use FetchContent to download the single-header mdns.h
include(FetchContent)
FetchContent_Declare(
    mdns
    GIT_REPOSITORY https://github.com/mjansson/mdns.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(mdns)

# Add the mDNS server executable
add_executable(mdns_server mdns_server.cpp)
target_include_directories(mdns_server PUBLIC ${mdns_SOURCE_DIR})
target_link_libraries(mdns_server PRIVATE Threads::Threads)

# Add platform-specific libraries for the server
if(WIN32)
    target_link_libraries(mdns_server PRIVATE ws2_32 iphlpapi)
elseif(UNIX)
    target_link_libraries(mdns_server PRIVATE m)
endif()

# Add the mDNS client executable
add_executable(mdns_client mdns_client.cpp)
target_include_directories(mdns_client PUBLIC ${mdns_SOURCE_DIR})
target_link_libraries(mdns_client PRIVATE Threads::Threads)

# Add platform-specific libraries for the client
if(WIN32)
    target_link_libraries(mdns_client PRIVATE ws2_32)
endif()