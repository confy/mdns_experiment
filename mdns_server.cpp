#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <cstring> // For memset, memcpy
#include <ifaddrs.h>
#include <arpa/inet.h>
#include "mdns.h"  // The single-file mDNS library

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h> // For close
#endif

#define SERVICE_NAME "MyCppService"
#define SERVICE_TYPE "_http._tcp.local."
#define SERVICE_PORT 8000

// Helper function to get local IPv4 addresses
static int get_ipv4_addresses(std::vector<struct in_addr>& addresses) {
// ( ... existing get_ipv4_addresses function ... )
#ifdef _WIN32
    // Windows specific: Use GetAdaptersAddresses
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (pAddresses == NULL) {
        std::cerr << "Memory allocation failed for GetAdaptersAddresses." << std::endl;
        return 0;
    }

    DWORD dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (pAddresses == NULL) {
            std::cerr << "Memory allocation failed for GetAdaptersAddresses (retry)." << std::endl;
            return 0;
        }
        dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    }

    if (dwRetVal == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES pAdapter = pAddresses; pAdapter != NULL; pAdapter = pAdapter->Next) {
            for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress; pUnicast != NULL; pUnicast = pUnicast->Next) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in* sa_in = (struct sockaddr_in*)pUnicast->Address.lpSockaddr;
                    addresses.push_back(sa_in->sin_addr);
                }
            }
        }
    } else {
        std::cerr << "Call to GetAdaptersAddresses failed with error: " << dwRetVal << std::endl;
    }
    free(pAddresses);
#else
    // Linux/macOS specific: Use getifaddrs
    struct ifaddrs* ifaddr, * ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 0;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
            if (sa->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) { // Exclude loopback
                addresses.push_back(sa->sin_addr);
            }
        }
    }
    freeifaddrs(ifaddr);
#endif
    return addresses.size();
}

// Callback to respond to mDNS queries
static int mdns_query_callback(int sock, const struct sockaddr* from, size_t addrlen,
    mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl,
    const void* data, size_t size, size_t name_offset, size_t name_length,
    size_t record_offset, size_t record_length, void* user_data) {
    char name_buffer[256];
    mdns_string_t name = mdns_string_extract(data, size, &name_offset, name_buffer, sizeof(name_buffer));
    std::string query_name(name.str, name.length);
    
    // Check if the query is for our service type
    if (rtype == MDNS_RECORDTYPE_PTR && query_name == SERVICE_TYPE) {
        std::cout << "Received mDNS PTR query for " << query_name << ", responding..." << std::endl;
        mdns_record_t* records = (mdns_record_t*)user_data;
        uint8_t response_buffer[1024];
        
        // Use the function name `mdns_send`, which is a common alternative.
        mdns_send(sock, from, addrlen, response_buffer, sizeof(response_buffer),
                  records, 4, nullptr, 0);
    }
    return 0;
}

int main() {
    struct sockaddr_in service_addr;
    memset(&service_addr, 0, sizeof(service_addr));
    service_addr.sin_family = AF_INET;
    service_addr.sin_addr.s_addr = INADDR_ANY;
    service_addr.sin_port = htons(MDNS_PORT);
    int sock = mdns_socket_open_ipv4(&service_addr);
    if (sock < 0) {
        std::cerr << "Failed to open mDNS socket." << std::endl;
        return 1;
    }
    std::cout << "Announcing service..." << std::endl;
    // Announce PTR record
    mdns_record_t ptr_record;
    memset(&ptr_record, 0, sizeof(ptr_record));
    std::string service_type = SERVICE_TYPE;
    std::string instance_name = SERVICE_NAME "." SERVICE_TYPE;
    ptr_record.name.str = service_type.c_str();
    ptr_record.name.length = service_type.length();
    ptr_record.type = MDNS_RECORDTYPE_PTR;
    ptr_record.data.ptr.name.str = instance_name.c_str();
    ptr_record.data.ptr.name.length = instance_name.length();

    // Announce SRV record
    mdns_record_t srv_record;
    memset(&srv_record, 0, sizeof(srv_record));
    srv_record.name.str = instance_name.c_str();
    srv_record.name.length = instance_name.length();
    srv_record.type = MDNS_RECORDTYPE_SRV;
    srv_record.data.srv.priority = 0;
    srv_record.data.srv.weight = 0;
    srv_record.data.srv.port = SERVICE_PORT;

    // Use actual hostname for SRV/A records
    char actual_hostname[256] = {};
    gethostname(actual_hostname, sizeof(actual_hostname));
    std::string host_name = std::string(actual_hostname) + ".local.";
    srv_record.data.srv.name.str = host_name.c_str();
    srv_record.data.srv.name.length = host_name.length();

    // Announce TXT record
    mdns_record_t txt_record;
    memset(&txt_record, 0, sizeof(txt_record));
    txt_record.name.str = instance_name.c_str();
    txt_record.name.length = instance_name.length();
    txt_record.type = MDNS_RECORDTYPE_TXT;
    txt_record.data.txt.key.str = "path";
    txt_record.data.txt.key.length = 4;
    txt_record.data.txt.value.str = "/";
    txt_record.data.txt.value.length = 1;

    // Announce A record
    mdns_record_t a_record;
    memset(&a_record, 0, sizeof(a_record));
    a_record.name.str = host_name.c_str();
    a_record.name.length = host_name.length();
    a_record.type = MDNS_RECORDTYPE_A;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    std::vector<struct in_addr> addresses;
    get_ipv4_addresses(addresses);
    if (!addresses.empty()) {
        addr.sin_addr = addresses[0];
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    a_record.data.a.addr = addr;

    uint8_t buffer[1024];
    // Announce all records together
    mdns_record_t records[4] = { ptr_record, srv_record, txt_record, a_record };
    mdns_announce_multicast(sock, buffer, sizeof(buffer), ptr_record, records + 1, 3, nullptr, 0);

    std::cout << "Listening for queries..." << std::endl;
    auto start = std::chrono::steady_clock::now();
    int timeout_ms = 10000;
    std::cout << "Announcing service with hostname: " << host_name << std::endl;
    std::cout << "Service instance: " << instance_name << std::endl;
    std::cout << "PTR: " << service_type << " -> " << instance_name << std::endl;
    std::cout << "SRV: " << instance_name << " port " << SERVICE_PORT << " host " << host_name << std::endl;
    std::cout << "TXT: path=/" << std::endl;
    get_ipv4_addresses(addresses);
    std::cout << "A: " << host_name << " IPs: ";
    for (const auto& addr : addresses) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));
        std::cout << ip << " ";
    }
    std::cout << std::endl;

    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() < timeout_ms) {
        std::cout << "Waiting for mDNS queries..." << std::endl;
        // Pass the records array as the user_data pointer.
        // The callback will then use this pointer to access the records.
        mdns_socket_listen(sock, buffer, sizeof(buffer), mdns_query_callback, records);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    mdns_socket_close(sock);
    std::cout << "Service stopped." << std::endl;
    return 0;
}