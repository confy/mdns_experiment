#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <cstring>
#include <map>
#include <ifaddrs.h>
#include "mdns.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // For inet_ntoa
#include <unistd.h>    // For close

// Struct to hold all info for a service instance
struct ServiceInfo {
    std::string instance_name; // e.g. lumo-abx000420._lumo-lidar._tcp.local.
    std::string host_name;     // e.g. lumo-abx000420.local.
    std::string address;       // IP address
    int port = 0;
    std::vector<std::pair<std::string, std::string>> txt_records;
    bool has_ptr = false, has_srv = false, has_a = false, has_txt = false;
};

// Map from instance name to ServiceInfo
static std::map<std::string, ServiceInfo> services;
static std::mutex services_mutex;
static std::atomic<bool> discovery_running(false);

// Helper: Setup IPv4 socket for mDNS queries
int open_mdns_query_socket() {
    struct sockaddr_in service_addr;
    memset(&service_addr, 0, sizeof(service_addr));
    service_addr.sin_family = AF_INET;
    service_addr.sin_addr.s_addr = INADDR_ANY;
    service_addr.sin_port = htons(0); // ephemeral port
    return mdns_socket_open_ipv4(&service_addr);
}

// Callback for mDNS responses
static int query_callback(int sock, const struct sockaddr* from, size_t addrlen,
                         mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype,
                         uint16_t rclass, uint32_t ttl, const void* data, size_t size,
                         size_t name_offset, size_t name_length, size_t record_offset,
                         size_t record_length, void* user_data) {
    char name_buffer[256];
    mdns_string_t name = mdns_string_extract(data, size, &name_offset, name_buffer, sizeof(name_buffer));
    std::lock_guard<std::mutex> lock(services_mutex);
    if (rtype == MDNS_RECORDTYPE_PTR) {
        char ptr_buffer[256];
        mdns_string_t ptr = mdns_record_parse_ptr(data, size, record_offset, record_length, ptr_buffer, sizeof(ptr_buffer));
        std::string instance(ptr.str, ptr.length);
        services[instance].instance_name = instance;
        services[instance].has_ptr = true;
        std::cout << "Found PTR: " << instance << std::endl;
    } else if (rtype == MDNS_RECORDTYPE_SRV) {
        char srv_buffer[256];
        mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length, srv_buffer, sizeof(srv_buffer));
        std::string instance(name.str, name.length);
        std::string host(srv.name.str, srv.name.length);
        services[instance].host_name = host;
        services[instance].port = srv.port;
        services[instance].has_srv = true;
        std::cout << "SRV: " << host << ", port: " << srv.port << std::endl;
    } else if (rtype == MDNS_RECORDTYPE_A) {
        struct sockaddr_in addr;
        mdns_record_parse_a(data, size, record_offset, record_length, &addr);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        std::string instance(name.str, name.length);
        services[instance].address = ip;
        services[instance].has_a = true;
        std::cout << "A: " << ip << std::endl;
    } else if (rtype == MDNS_RECORDTYPE_TXT) {
        mdns_record_txt_t txt_records[8];
        size_t txt_count = mdns_record_parse_txt(data, size, record_offset, record_length, txt_records, 8);
        std::string instance(name.str, name.length);
        for (size_t i = 0; i < txt_count; ++i) {
            std::string key(txt_records[i].key.str, txt_records[i].key.length);
            std::string value(txt_records[i].value.str, txt_records[i].value.length);
            services[instance].txt_records.emplace_back(key, value);
            std::cout << "TXT: " << key << " = " << value << std::endl;
        }
        services[instance].has_txt = true;
    }
    return 0;
}

void discovery_loop(const std::string& service_type, int timeout_ms) {
    int sock = open_mdns_query_socket();
    if (sock < 0) {
        std::cerr << "Failed to open mDNS socket." << std::endl;
        return;
    }

    std::cout << "Starting mDNS discovery for service type: " << service_type << std::endl;

    uint8_t buffer[1024];
    int query_id = mdns_query_send(sock, MDNS_RECORDTYPE_PTR, service_type.c_str(), service_type.length(), buffer, sizeof(buffer), 0);
    if (query_id < 0) {
        std::cerr << "Failed to send mDNS query." << std::endl;
        mdns_socket_close(sock);
        return;
    }

    std::cout << "Waiting for mDNS responses..." << std::endl;
    auto start = std::chrono::steady_clock::now();
    while (discovery_running) {
        mdns_query_recv(sock, buffer, sizeof(buffer), query_callback, nullptr, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeout_ms) {
            break;
        }
    }

    mdns_socket_close(sock);
    std::cout << "mDNS discovery finished." << std::endl;
}

int main() {
    std::string service_to_find = "_lumo-lidar._tcp.local.";
    int discovery_timeout_ms = 10000; // Discover for 10 seconds

    discovery_running = true;
    std::thread client_thread(discovery_loop, service_to_find, discovery_timeout_ms);
    client_thread.join();
    discovery_running = false;

    std::cout << "\n--- Discovered Services ---" << std::endl;
    std::lock_guard<std::mutex> lock(services_mutex);
    bool found = false;
    for (const auto& [name, info] : services) {
        if (info.has_ptr && info.has_srv && info.has_a) {
            found = true;
            std::cout << "  Instance: " << info.instance_name << std::endl;
            std::cout << "  Host: " << info.host_name << std::endl;
            std::cout << "  Address: " << info.address << std::endl;
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