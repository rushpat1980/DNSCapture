#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>

std::vector<std::string> GetLocalIPAddresses() {
    std::vector<std::string> ipAddresses;

    // Allocate a buffer for IP adapter addresses
    ULONG bufferLength = 0;
    GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &bufferLength);

    std::vector<BYTE> buffer(bufferLength);
    PIP_ADAPTER_ADDRESSES pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    // Get the adapter addresses
    if (GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &bufferLength) == NO_ERROR) {
        for (auto pCurrAddresses = pAddresses; pCurrAddresses != NULL; pCurrAddresses = pCurrAddresses->Next) {
            // Skip adapters that are not operational
            if (pCurrAddresses->OperStatus != IfOperStatusUp)
                continue;

            for (auto pUnicast = pCurrAddresses->FirstUnicastAddress; pUnicast != NULL; pUnicast = pUnicast->Next) {
                SOCKADDR_IN* sockAddr = reinterpret_cast<SOCKADDR_IN*>(pUnicast->Address.lpSockaddr);

                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(sockAddr->sin_addr), ipstr, INET_ADDRSTRLEN);

                // Skip loopback and link-local addresses
                if (strcmp(ipstr, "127.0.0.1") != 0 && strncmp(ipstr, "169.254.", 8) != 0) {
                    ipAddresses.push_back(ipstr);
                }
            }
        }
    }

    return ipAddresses;
}