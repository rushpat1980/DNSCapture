#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <windivert.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include "DNSProxy.h"

// TBD: replace this with proper logging later. 
#define VERBOSE_LOG 0

// DNS Header structure
#pragma pack(push, 1)
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

// DNS Question structure
struct DNSQuestion {
    uint16_t qtype;
    uint16_t qclass;
};


void DNSProxy::PacketCaptureThread() {
    std::string filter = "udp.DstPort == 53 && !loopback";
    divertHandle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);

    if (divertHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open WinDivert handle" << std::endl;
        return;
    }

    std::vector<uint8_t> packetBuffer(MAX_PACKET_SIZE);

    while (!stopProcessing) {
        UINT packetLen = packetBuffer.size();
        WINDIVERT_ADDRESS addr;

        if (!WinDivertRecv(divertHandle, packetBuffer.data(), packetLen, &packetLen, &addr)) {
            continue;
        }

        uint32_t localIP, localPort;

        // Reentrancy check: If from the Proxy process skip processing.
        if (GetRequestLocalAddr(reinterpret_cast<const char*>(packetBuffer.data()), packetLen, localIP, localPort)) {
            if (IsDNSRequestIssuedByCurrentProcess(localIP, localPort)) {
                std::cout << "[PCThread] Reentrance Detected. Skipping packet from DNSProxy from socket " << localIP << "::" << localPort << std::endl;
                uint32_t sendLen = 0;
                auto ret = WinDivertSend(divertHandle, packetBuffer.data(), packetBuffer.size(), &sendLen, &addr);
                if (!ret) {
                    std::cerr << "[PCThread] Packet re-injection failed in WinDivertSend: " << GetLastError() << std::endl;
                }
                else {
                    std::cout << "[PCThread] Packet re-injection suceeded. " << std::endl;
                }
                continue;
            }
        }

        // Create a copy of the packet and enqueue it
        std::vector<uint8_t> packetCopy(packetBuffer.begin(), packetBuffer.begin() + packetLen);
        requestQueue.enqueue(packetCopy, addr);
    }

    WinDivertClose(divertHandle);
}

// Get the next packet from the queue and process it.
// Assuming some processing here that could be changed.
// For now this thread gets the query response from 8.8.8.8 and tries to resolve 
// the original response using the received response.
void DNSProxy::PacketProcessingThread() {
    while (!stopProcessing) {
        // Dequeue a packet
        auto [packetData, addr] = requestQueue.dequeue();

        DNSPacket originalPacket, responsePacket;
        // Initialize headers before use
        memset(&responsePacket.ipHeader, 0, sizeof(WINDIVERT_IPHDR));
        memset(&responsePacket.udpHeader, 0, sizeof(WINDIVERT_UDPHDR));

        if (!ParseDNSPacket(reinterpret_cast<const char*>(packetData.data()), packetData.size(), originalPacket)) {
            continue;
        }

        if (ResolveDNSQuery(originalPacket, responsePacket)) {
            std::cout << "[PPThread] ResolveDNS(from 8.8.8.8) successful" << std::endl;
            ReconstructDNSResponse(originalPacket, responsePacket);
            std::cout << "[PPThread] Reconstruct DNSResponse finished" << std::endl;

            // Calculate IP and UDP header lengths
            UINT ipHdrLen = sizeof(WINDIVERT_IPHDR);
            UINT udpHdrLen = sizeof(WINDIVERT_UDPHDR);
            UINT payloadLen = responsePacket.payload.size();

            // Update IP total length
            UINT totalLen = ipHdrLen + udpHdrLen + payloadLen;
            responsePacket.ipHeader.Length = htons(totalLen);

            // Update UDP header length
            responsePacket.udpHeader.Length = htons(udpHdrLen + payloadLen);

            responsePacket.ipHeader.Version = 4; // IPv4 
            responsePacket.ipHeader.HdrLength = 5; // 5 * 4 = 20 bytes 
            responsePacket.ipHeader.TOS = 0; 
            responsePacket.ipHeader.Length = htons(ipHdrLen + udpHdrLen + payloadLen); 
            responsePacket.ipHeader.Id = htons(54321); // Example ID 
            responsePacket.ipHeader.FragOff0 = 0;
            responsePacket.ipHeader.TTL = 64; // Typical value 
            responsePacket.ipHeader.Protocol = IPPROTO_UDP; 
            responsePacket.ipHeader.Checksum = 0; // Will be filled in by checksum calculation

#if VERBOSE_LOG
            // Print detailed IP header fields
            std::cout << "IP Header:" << std::endl;
            std::cout << "  Version: " << (responsePacket.ipHeader.Version << 4) << std::endl;
            std::cout << "  HeaderLength: " << responsePacket.ipHeader.HdrLength << std::endl;
            std::cout << "  TOS: " << responsePacket.ipHeader.TOS << std::endl;
            std::cout << "  Length: " << ntohs(responsePacket.ipHeader.Length) << std::endl;
            std::cout << "  ID: " << ntohs(responsePacket.ipHeader.Id) << std::endl;
            std::cout << "  Flags: " << responsePacket.ipHeader.FragOff0 << std::endl;
            std::cout << "  TTL: " << (int)responsePacket.ipHeader.TTL << std::endl;
            std::cout << "  Protocol: " << (int)responsePacket.ipHeader.Protocol << std::endl;
            std::cout << "  Checksum: " << ntohs(responsePacket.ipHeader.Checksum) << std::endl;

            char srcIpStr[INET_ADDRSTRLEN]; char dstIpStr[INET_ADDRSTRLEN]; 
            inet_ntop(AF_INET, &responsePacket.ipHeader.SrcAddr, srcIpStr, INET_ADDRSTRLEN); 
            inet_ntop(AF_INET, &responsePacket.ipHeader.DstAddr, dstIpStr, INET_ADDRSTRLEN); 
            std::cout << " SrcAddr: " << srcIpStr << std::endl; 
            std::cout << " DstAddr: " << dstIpStr << std::endl;

            // Print detailed UDP header fields
            std::cout << "UDP Header:" << std::endl;
            std::cout << "  SrcPort: " << ntohs(responsePacket.udpHeader.SrcPort) << std::endl;
            std::cout << "  DstPort: " << ntohs(responsePacket.udpHeader.DstPort) << std::endl;
            std::cout << "  Length: " << ntohs(responsePacket.udpHeader.Length) << std::endl;
            std::cout << "  Checksum: " << ntohs(responsePacket.udpHeader.Checksum) << std::endl;
#endif
            // Construct packet
            std::vector<BYTE> packetBuffer(totalLen);  // Adjust buffer size to total length
            BYTE* ptr = packetBuffer.data();

            // Copy IP header
            memcpy(ptr, &responsePacket.ipHeader, ipHdrLen);
            ptr += ipHdrLen;

            // Copy UDP header
            memcpy(ptr, &responsePacket.udpHeader, udpHdrLen);
            ptr += udpHdrLen;

            // Copy payload
            memcpy(ptr, responsePacket.payload.data(), payloadLen);

            // Prepare address
            WINDIVERT_ADDRESS sendAddr = addr;
            sendAddr.Outbound = 0;  // Ensure outbound is set to 0
#if VERBOSE_LOG
            // Print packet details
            std::cout << "[PPThread] Sending packet:" << std::endl;
            std::cout << "  Total Length: " << totalLen << std::endl;
            std::cout << "  IP Length: " << ntohs(responsePacket.ipHeader.Length) << std::endl;
            std::cout << "  UDP Length: " << ntohs(responsePacket.udpHeader.Length) << std::endl;
            std::cout << "  IP SrcAddr: " << (responsePacket.ipHeader.SrcAddr & 0xFF) << "."
                << ((responsePacket.ipHeader.SrcAddr >> 8) & 0xFF) << "."
                << ((responsePacket.ipHeader.SrcAddr >> 16) & 0xFF) << "."
                << ((responsePacket.ipHeader.SrcAddr >> 24) & 0xFF) << std::endl;
            std::cout << "  IP DstAddr: " << (responsePacket.ipHeader.DstAddr & 0xFF) << "."
                << ((responsePacket.ipHeader.DstAddr >> 8) & 0xFF) << "."
                << ((responsePacket.ipHeader.DstAddr >> 16) & 0xFF) << "."
                << ((responsePacket.ipHeader.DstAddr >> 24) & 0xFF) << std::endl;
            std::cout << "  Payload Size: " << payloadLen << std::endl;

            // Print raw packet data for verification
            std::cout << "Raw Packet Data:" << std::endl;
            for (size_t i = 0; i < totalLen; ++i) {
                std::printf("%02X ", packetBuffer[i]);
            }
            std::cout << std::endl;
#endif

            // Calculate and apply checksums for the packet
            if (!WinDivertHelperCalcChecksums(packetBuffer.data(), totalLen, &sendAddr, 0)) {
                std::cerr << "[PPThread] Checksum calculation failed. Verify the packet structure and ensure the headers are correctly formatted." << std::endl;
                return;
            }

            // Send the packet
            UINT sendLen = totalLen;
            auto ret = WinDivertSend(divertHandle, packetBuffer.data(), sendLen, &sendLen, &sendAddr);
            if (!ret) {
                DWORD error = GetLastError();
                // Additional diagnostics
                char errorBuffer[256];
                FormatMessageA(
                    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL,
                    error,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    errorBuffer,
                    sizeof(errorBuffer),
                    NULL
                );
                std::cerr << "[PPThread] Error in WinDivertSend. Err = " << error << " Error message: " << errorBuffer << std::endl;
            }
            else {
                std::cout << "[PPThread] WinDivertSend finished" << std::endl;
            }
        }
        else {
            // Drop the packet if we could not resolve the DNS query using our DNS server.
            std::cout << "[PPThread] Reconstruct DNSResponse failed..." << std::endl;
        }
    }
}

bool DNSProxy::IsDNSRequestIssuedByCurrentProcess(const uint32_t& localIP, const uint32_t& localPort) {
    // Fetch UDP table
    ULONG udpTableSize = 0;
    uint32_t udpSocketCount = 0;
    std::string localDNSIP;
    {
        sockaddr_in localAddr = {};
        localAddr.sin_addr.s_addr = localIP;
        localAddr.sin_port = localPort;

        char localIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &localAddr.sin_addr, localIp, sizeof(localIp));
        std::cout << "[PCThread] DNS request(OUTBOUND) received from local socket " << localIp << "::" << localPort << std::endl;
    }

    std::cout << "[PCThread] Reentrancy Check..." << std::endl;
    
    GetExtendedUdpTable(nullptr, &udpTableSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<char> udpTableBuffer(udpTableSize);
    if (GetExtendedUdpTable(udpTableBuffer.data(), &udpTableSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        PMIB_UDPTABLE_OWNER_PID udpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(udpTableBuffer.data());
        for (DWORD i = 0; i < udpTable->dwNumEntries; ++i) {
            if (udpTable->table[i].dwOwningPid == GetCurrentProcessId()) {
                udpSocketCount++;
                if (ntohs(udpTable->table[i].dwLocalPort) == localPort) {
                    std::cout << i << "[PCThread] Port matched..." << std::endl;

                    sockaddr_in localAddr = {};
                    localAddr.sin_addr.s_addr = udpTable->table[i].dwLocalAddr;
                    localAddr.sin_port = udpTable->table[i].dwLocalPort;

                    char localIp[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &localAddr.sin_addr, localIp, sizeof(localIp));

                    if (IsProxyIPAddress(localIp)) {
                        std::cout << i << "[PCThread] Port and IP matched...skipping packet " << std::endl;
                        return true;
                    }
                }
            }
        }
    }

    std::cout << "[PCThread] No reentrancy Detected. Total UDP Sockets checked for the Proxy process = [" << udpSocketCount << "]" << std::endl;
    return false;
}

bool DNSProxy::IsProxyIPAddress(const std::string& ipAddr) {
    if (localIPAddrForProxy == ipAddr) {
        return true;
    }
    return false;
}


bool DNSProxy::GetRequestLocalAddr(const char* packet, const size_t& packetLen, uint32_t& localIP, uint32_t& localPort) {
    WINDIVERT_IPHDR* ipHeader = nullptr;
    WINDIVERT_UDPHDR* udpHeader = nullptr;

    if (!WinDivertHelperParsePacket(packet, packetLen,
        &ipHeader, nullptr, nullptr, nullptr,
        nullptr, nullptr, &udpHeader,
        nullptr, nullptr, nullptr, nullptr)) {
        return false;
    }

    if (!ipHeader || !udpHeader) {
        std::cerr << "WinDivertHelperParsePacket Failed to get local addr. err = " << GetLastError() << std::endl;
        return false;
    }

    localIP = ipHeader->SrcAddr;
    localPort = ntohs(udpHeader->SrcPort);
    return true;
}

bool DNSProxy::ParseDNSPacket(const char* packet, size_t packetLen, DNSPacket& parsedPacket) {
    WINDIVERT_IPHDR* ipHeader = nullptr;
    WINDIVERT_UDPHDR* udpHeader = nullptr;
    uint8_t* dnsPayload = nullptr;
    UINT dnsPayloadLen = 0;

#if VERBOSE_LOG
    std::cout << "Raw DNS packet data:" << std::endl;
    for (size_t i = 0; i < packetLen; ++i) {
        std::printf("%02X ", static_cast<unsigned char>(packet[i]));
    }
    std::cout << std::endl;
#endif

    if (!WinDivertHelperParsePacket(packet, packetLen,
        &ipHeader, nullptr, nullptr, nullptr,
        nullptr, nullptr, &udpHeader,
        (PVOID*)&dnsPayload, &dnsPayloadLen, nullptr, nullptr)) {
        return false;
    }

    if (!ipHeader || !udpHeader || !dnsPayload) {
        return false;
    }

    parsedPacket.ipHeader = *ipHeader;
    parsedPacket.udpHeader = *udpHeader;
    parsedPacket.payload = std::vector<uint8_t>(
        dnsPayload,
        dnsPayload + dnsPayloadLen
        );

#if VERBOSE_LOG
    {
        auto* header = reinterpret_cast<DNSHeader*>(parsedPacket.payload.data());
        std::cout << "(MUST MATCH)Parsed DNS Header:" << std::endl;
        std::cout << " ID: " << ntohs(header->id) << std::endl;
        std::cout << " Flags: " << ntohs(header->flags) << std::endl;
        std::cout << " Questions: " << ntohs(header->qdcount) << std::endl;
        std::cout << " Answer RRs: " << ntohs(header->ancount) << std::endl;
        std::cout << " Authority RRs: " << ntohs(header->nscount) << std::endl;
        std::cout << " Additional RRs: " << ntohs(header->arcount) << std::endl;
    }
#endif

    // Convert IP addresses to human-readable form
    char srcIp[INET_ADDRSTRLEN], dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ipHeader->SrcAddr, srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ipHeader->DstAddr, dstIp, INET_ADDRSTRLEN);

    // Print IP addresses and ports
    std::cout << "[PPThread] Processing DNS request " << srcIp
        << "::" << ntohs(udpHeader->SrcPort) << " ==>> " << dstIp
        << "::" << ntohs(udpHeader->DstPort) << std::endl;

    return true;
}

// Issue to DNS request to 8.8.8.8 and get the response back.
bool DNSProxy::ResolveDNSQuery(DNSPacket& query, DNSPacket& response) {
    WSADATA wsaData; 
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl; return false;
    }
    
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    if (sock == INVALID_SOCKET) { 
        std::cerr << "Socket creation failed" << std::endl; WSACleanup(); 
        return false; 
    }

    // Convert IP addresses to human-readable form
    char srcIp1[INET_ADDRSTRLEN], dstIp1[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &query.ipHeader.SrcAddr, srcIp1, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &query.ipHeader.DstAddr, dstIp1, INET_ADDRSTRLEN);

    uint8_t* dnsPayload = query.payload.data();
    size_t dnsPayloadLen = query.payload.size();

    auto header = reinterpret_cast<DNSHeader*>(dnsPayload);

#if VERBOSE_LOG
    std::cout << "IP Header: " << srcIp1 << "::" << ntohs(query.udpHeader.SrcPort) << " = >> "
        << dstIp1 << "::" << ntohs(query.udpHeader.DstPort) << std::endl;
    std::cout << "DNS Payload Length: " << dnsPayloadLen << std::endl;

    std::cout << "Parsed DNS Header:" << std::endl;
    std::cout << " ID: " << ntohs(header->id) << std::endl;
    std::cout << " Flags: " << ntohs(header->flags) << std::endl;
    std::cout << " Questions: " << ntohs(header->qdcount) << std::endl;
    std::cout << " Answer RRs: " << ntohs(header->ancount) << std::endl;
    std::cout << " Authority RRs: " << ntohs(header->nscount) << std::endl;
    std::cout << " Additional RRs: " << ntohs(header->arcount) << std::endl;

    std::cout << "#####query header: id= " << ntohs(header->id)
        << " flag= " << ntohs(header->flags)
        << " qdcount= " << ntohs(header->qdcount)
        << std::endl;

    // Extract and print the DNS question section
    size_t offset = sizeof(DNSHeader);
    for (int i = 0; i < ntohs(header->qdcount); ++i) {
        std::string domainName;
        while (dnsPayload[offset] != 0) {
            int len = dnsPayload[offset];
            domainName.append((char*)&dnsPayload[offset + 1], len);
            domainName.append(".");
            offset += len + 1;
        }
        offset += 1;  // Skip the null byte

        uint16_t qtype = ntohs(*reinterpret_cast<uint16_t*>(&dnsPayload[offset]));
        offset += 2;
        uint16_t qclass = ntohs(*reinterpret_cast<uint16_t*>(&dnsPayload[offset]));
        offset += 2;

        std::cout << "DNS Question:" << std::endl;
        std::cout << " Domain Name: " << domainName << std::endl;
        std::cout << " QTYPE: " << qtype << std::endl;
        std::cout << " QCLASS: " << qclass << std::endl;
    }
#endif
    sockaddr_in dnsServer = {};
    dnsServer.sin_family = AF_INET;
    dnsServer.sin_port = htons(53);
    inet_pton(AF_INET, DNS_SERVER, &dnsServer.sin_addr);

    // Bind the socket to a local address and port (optional step)
    struct sockaddr_in bindAddr;
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(0); 
    // Use a `specific local IP address` that we can use to validate in the WinDivertRecv.
    inet_pton(AF_INET, localIPAddrForProxy.c_str(), &bindAddr.sin_addr.s_addr);

    if (bind(sock, (struct sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed" << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Get the local address and port after binding
    struct sockaddr_in localAddr;
    int addrLen = sizeof(localAddr);
    if (getsockname(sock, (struct sockaddr*)&localAddr, &addrLen) == SOCKET_ERROR) {
        std::cerr << "[PPThread] getsockname failed" << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Convert the local IP address from binary to string format using inet_ntop
    char ipStr[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &localAddr.sin_addr, ipStr, sizeof(ipStr)) == nullptr) {
        std::cerr << "inet_ntop failed" << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "[PPThread] Resolving DNS query (from 8.8.8.8) using local socket " << ipStr << "::" <<
        ntohs(localAddr.sin_port) << std::endl;

#if VERBOSE_LOG
    std::cout << "#####DNS Query length = " << query.payload.size() << std::endl;
#endif
    int sendResult = sendto(sock,
        reinterpret_cast<const char*>(query.payload.data()),
        query.payload.size(),
        0,
        reinterpret_cast<sockaddr*>(&dnsServer),
        sizeof(dnsServer)
    );
    
    if (sendResult == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    std::vector<uint8_t> responseBuffer(MAX_PACKET_SIZE);
    int recvLen = recvfrom(sock,
        reinterpret_cast<char*>(responseBuffer.data()),
        responseBuffer.size(),
        0,
        nullptr,
        nullptr
    );

    PrintDNSResponse(responseBuffer, recvLen);

    closesocket(sock);
#if VERBOSE_LOG
    std::cout << "######DNS response length = " << recvLen << std::endl;
#endif

    if (recvLen <= 0) {
        return false;
    }

    response.payload = std::vector<uint8_t>(
        responseBuffer.begin(),
        responseBuffer.begin() + recvLen
        );

    PrintResolvedIPs(response.payload);

    return true;
}

bool DNSProxy::ReconstructDNSResponse(const DNSPacket& originalQuery, DNSPacket& resolvedResponse) {
    // Swap source and destination details
    resolvedResponse.ipHeader.SrcAddr = originalQuery.ipHeader.DstAddr;
    resolvedResponse.ipHeader.DstAddr = originalQuery.ipHeader.SrcAddr;

    resolvedResponse.udpHeader.SrcPort = htons(53);
    resolvedResponse.udpHeader.DstPort = originalQuery.udpHeader.SrcPort;

    return true;
}

void DNSProxy::PrintResolvedIPs(std::vector<uint8_t>& dnsResponse) {
#if VERBOSE_LOG
    // DNS response header is 12 bytes
    if (dnsResponse.size() < sizeof(DNSHeader)) {
        return;
    }

    auto h = reinterpret_cast<DNSHeader*>(dnsResponse.data());
    auto ans = ntohs(h->ancount);
    // Check number of answer records
    uint16_t answerCount = (dnsResponse[6] << 8) | dnsResponse[7];

    size_t offset = sizeof(DNSHeader); // Start after DNS header

    // Skip question section
    while (offset < dnsResponse.size() && dnsResponse[offset] != 0) {
        offset += dnsResponse[offset] + 1;
    }
    offset++; // Skip null terminator
    offset += 4; // Skip question type and class

    // Process answer records
    for (int i = 0; i < answerCount; i++) {
        // Skip name (could be compressed)
        if (offset >= dnsResponse.size()) break;

        // Check for compression pointer
        if (dnsResponse[offset] == 0xC0) {
            offset += 2; // Skip compression pointer
        }
        else {
            // Skip domain name
            while (offset < dnsResponse.size() && dnsResponse[offset] != 0) {
                offset += dnsResponse[offset] + 1;
            }
            offset++; // Skip null terminator
        }

        // Ensure enough bytes for record type, class, TTL, and data length
        if (offset + 10 > dnsResponse.size()) break;

        // Record Type (2 bytes)
        uint16_t recordType = (dnsResponse[offset] << 8) | dnsResponse[offset + 1];
        offset += 2;

        // Class (2 bytes)
        uint16_t recordClass = (dnsResponse[offset] << 8) | dnsResponse[offset + 1];
        offset += 2;

        // TTL (4 bytes)
        offset += 4;

        // Resource Data Length
        uint16_t dataLength = (dnsResponse[offset] << 8) | dnsResponse[offset + 1];
        offset += 2;

        // Process A record (IPv4)
        if (recordType == 1 && dataLength == 4) {
            if (offset + 4 > dnsResponse.size()) break;

            char ipStr[INET_ADDRSTRLEN];
            snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u",
                dnsResponse[offset],
                dnsResponse[offset + 1],
                dnsResponse[offset + 2],
                dnsResponse[offset + 3]
            );

            std::cout << "Resolved IP: " << ipStr << std::endl;
        }

        offset += dataLength;
    }
#endif
}

void DNSProxy::PrintDNSResponse(const std::vector<uint8_t>& buffer, size_t size) {
#if VERBOSE_LOG
    if (size < sizeof(DNSHeader)) {
        return;
    }

    const DNSHeader* header = reinterpret_cast<const DNSHeader*>(buffer.data());
    std::cout << "DNS Header:" << std::endl;
    std::cout << " ID: " << ntohs(header->id) << std::endl;
    std::cout << " Flags: " << ntohs(header->flags) << std::endl;
    std::cout << " Questions: " << ntohs(header->qdcount) << std::endl;
    std::cout << " Answer RRs: " << ntohs(header->ancount) << std::endl;
    std::cout << " Authority RRs: " << ntohs(header->nscount) << std::endl;
    std::cout << " Additional RRs: " << ntohs(header->arcount) << std::endl;
    size_t offset = sizeof(DNSHeader);
    if (offset >= size) return;

    // Skip the query section 
    while (buffer[offset] != 0) {
        offset++;
    }

    offset += 5; // null byte + qtype + qclass 
    std::cout << "DNS Answer Section:" << std::endl;
    for (int i = 0; i < ntohs(header->ancount); ++i) {
        if (offset + 10 > size) return;
        uint16_t type = ntohs(*reinterpret_cast<const uint16_t*>(&buffer[offset + 2]));
        uint16_t dataLen = ntohs(*reinterpret_cast<const uint16_t*>(&buffer[offset + 8]));
        if (type == 1 && dataLen == 4) {
            // A record 
            const uint8_t* ip = &buffer[offset + 10];
            std::cout << " IP Address: " << (int)ip[0] << "." << (int)ip[1] << "." << (int)ip[2] << "." << (int)ip[3] << std::endl;
        }
        offset += 10 + dataLen;
    }
#endif

}
