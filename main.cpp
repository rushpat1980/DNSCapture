#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <windivert.h>
#include <Ws2tcpip.h> 
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include "DNSProxy.h"

// TBD: move these include include lib section.
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Psapi.lib")
/*
Rushi's TBD: 
- Use C++ exception handling instead of returning true/false.
- Write unit tests to cover modular functios.
- Write integration test to cover entire DNS redirection scenario with and without process recursive skip mechanism.
- Integrate this code with windows service or convert it to a service.
- If needed this entire bundle(process binary, windivert.dll, windivert64.sys, etc) should be packaged into an installer.
- Add a check to ensure the process runs as administrator(wont be needed if it runs as a service).
- Performance validation: On a regular client this shall work find. However performance testing is required for DNS heavy situation. Undestand the use case.
- Long run testing: long run testing to ensure no memory leaks, high CPU usage(unlikely), crashes, etc. 
- Better logging, post installation folder structure.
- Extend the DNSProxy to IPv6. For now focus on IPv4.
- Ensure code formatting is consistent.
- Code refacoring, cleanup unwanted comments, fix typos, etc.
*/

int main() {
    try {
        DNSProxy proxy;

        // Start packet processing in a separate thread
        proxy.Start();

        // Replace this with Service shutdown processing code to shutdown DNSProxy.
        std::cout << "DNSProxy running. Waiting for service shutdown..." << std::endl;

        // Placeholder for actual service shutdown logic
        std::cin.get();

        // Shutdown the proxy
        proxy.Shutdown();
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}