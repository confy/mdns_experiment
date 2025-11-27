#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <cstring>
#include <map>
#include <set>
#include <ifaddrs.h>
#include "mdns_cpp/src/mdns.h"
#include "mdns_cpp/mdns.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // For inet_ntoa
#include <unistd.h>    // For close



int main() {
    std::string service_to_find = "_lumo-lidar._tcp.local.";
    int discovery_timeout_ms = 10000; // Discover for 10 seconds

    std::unique_ptr<mdns_cpp::mDNS> mdns_client = std::make_unique<mdns_cpp::mDNS>();
    mdns_cpp::mDNS::ServiceQueries queries = { {service_to_find, MDNS_RECORDTYPE_PTR} };
    auto discovered_services = mdns_client->executeQuery(queries);

    std::cout << "\n--- Discovered Services ---" << std::endl;
    bool found = false;
    for (const auto& [name, info] : discovered_services) {
        if (info.has_ptr && info.has_srv && info.has_a) {
            found = true;
            std::cout << "  Instance: " << info.instance_name << std::endl;
            std::cout << "  Host: " << info.host_name << std::endl;
            if (!info.addresses.empty()) {
                std::cout << "  Addresses:" << std::endl;
                for (const auto& addr : info.addresses) {
                    std::cout << "    - " << addr << std::endl;
                }
            }
            std::cout << "  Port: " << info.port << std::endl;
            if (!info.txt_records.empty()) {
                std::cout << "  TXT Records:" << std::endl;
                for (const auto& txt : info.txt_records) {
                    std::cout << "    - " << txt.first << " = " << txt.second << std::endl;
                }
            }
            std::cout << "--------------------------" << std::endl;
        }
    }
    if (!found) {
        std::cout << "No complete services of type '" << service_to_find << "' found." << std::endl;
    }
    return 0;
}