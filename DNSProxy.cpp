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
                //std::cout << "[PCThread] Checksum[2] = " << WinDivertHelperCalcChecksums(packetBuffer.data(), packetBuffer.size(), &addr, 0)
                //    << std::endl;
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
        if (!ParseDNSPacket(reinterpret_cast<const char*>(packetData.data()), packetData.size(), originalPacket)) {
            continue;
        }

        if (ResolveDNSQuery(originalPacket, responsePacket)) {
            std::cout << "[PPThread] ResolveDNS(from 8.8.8.8) successful" << std::endl;

            ReconstructDNSResponse(originalPacket, responsePacket);

            std::cout << "[PPThread] Reconstruct DNSResponse finished" << std::endl;

            // Prepare a complete packet buffer

            // Calculate IP and UDP header lengths
            UINT ipHdrLen = sizeof(WINDIVERT_IPHDR);
            UINT udpHdrLen = sizeof(WINDIVERT_UDPHDR);
            UINT payloadLen = responsePacket.payload.size();

            // Update IP total length
            UINT totalLen = ipHdrLen + udpHdrLen + payloadLen;
            responsePacket.ipHeader.Length = htons(totalLen);

            // Update UDP header length
            responsePacket.udpHeader.Length = htons(udpHdrLen + payloadLen);

            // Construct packet
            std::vector<BYTE> packetBuffer(MAX_PACKET_SIZE);
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

            // ----------------------------------------------------------------------------------------------------------
            // ****BUG****: TBD- PACKET formatting is not correct****...Debug print to troubleshoot fields in DNS response.
            // 1. Clearly DNS response that we are creating is much smaller.
            // 2. Understand other fields in the response and fill them in correctly.
            // ----------------------------------------------------------------------------------------------------------
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

            // BUG: These checksums are incorrect. Fix the checksums in order to build a valid response.
            std::cout << " Checksum1 = " << WinDivertHelperCalcChecksums(packetBuffer.data(), totalLen, &sendAddr,
                WINDIVERT_HELPER_NO_IP_CHECKSUM
            ) << " Checksum2 = " << WinDivertHelperCalcChecksums(packetBuffer.data(), totalLen, &sendAddr,
                WINDIVERT_HELPER_NO_ICMP_CHECKSUM
            ) << " Checksum3 = " << WinDivertHelperCalcChecksums(packetBuffer.data(), totalLen, &sendAddr,
                WINDIVERT_HELPER_NO_TCP_CHECKSUM
            ) << " Checksum4 = " << WinDivertHelperCalcChecksums(packetBuffer.data(), totalLen, &sendAddr,
                WINDIVERT_HELPER_NO_UDP_CHECKSUM
            ) << std::endl;

            //std::cout << "Checksum01 = " << WinDivertHelperCalcChecksums(originalPacket.payload.data(), totalLen, &sendAddr,
            //    WINDIVERT_HELPER_NO_IP_CHECKSUM
            //) << "Checksum02 = " << WinDivertHelperCalcChecksums(originalPacket.payload.data(), totalLen, &sendAddr,
            //    WINDIVERT_HELPER_NO_ICMP_CHECKSUM
            //) << "Checksum03 = " << WinDivertHelperCalcChecksums(originalPacket.payload.data(), totalLen, &sendAddr,
            //    WINDIVERT_HELPER_NO_TCP_CHECKSUM
            //) << "Checksum04 = " << WinDivertHelperCalcChecksums(originalPacket.payload.data(), totalLen, &sendAddr,
            //    WINDIVERT_HELPER_NO_UDP_CHECKSUM
            //)
            //    << std::endl;

            // Send the packet
            UINT sendLen = totalLen;
            auto ret = WinDivertSend(divertHandle, packetBuffer.data(), sendLen, &sendLen, &sendAddr);
            if (!ret) {
                DWORD error = GetLastError();
                std::cerr << "[PPThread] Error in WinDivertSend: " << error << std::endl;
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
                std::cerr << "[PPThread] Error in WinDivertSend. Err = " << error << " Error message : " << errorBuffer << std::endl;
            }
            else {
                std::cout << "[PPThread] WinDivertSend finished" << std::endl;
            }
        }
        else {
            std::cout << "[PPThread] Reconstruct DNSResponse failed..." << std::endl;
            // drop the packet if we could not resolve the DNS query using our DNS server.
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
    UINT* dnsPayload = nullptr;
    UINT dnsPayloadLen = 0;

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
bool DNSProxy::ResolveDNSQuery(const DNSPacket& query, DNSPacket& response) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return false;
    }

    sockaddr_in dnsServer = {};
    dnsServer.sin_family = AF_INET;
    dnsServer.sin_port = htons(53);

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

    inet_pton(AF_INET, DNS_SERVER, &dnsServer.sin_addr);
    struct sockaddr_in localAddr;
    int addrLen = sizeof(localAddr);

    // Get the local address and port after binding
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

    closesocket(sock);

    if (recvLen <= 0) {
        return false;
    }

    response.payload = std::vector<uint8_t>(
        responseBuffer.begin(),
        responseBuffer.begin() + recvLen
        );

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
