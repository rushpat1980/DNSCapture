#include <iostream>
#include <winsock2.h>
#include <windivert.h>
#include <windows.h>
#include <Ws2tcpip.h>
#include <queue>
#include <iphlpapi.h>
#include <vector>
#include <memory>
#include <atomic>

std::vector<std::string> GetLocalIPAddresses();

class DNSProxy {
private:
    static constexpr size_t MAX_PACKET_SIZE = 4096;
    static constexpr const char* DNS_SERVER = "8.8.8.8";
    static constexpr size_t QUEUE_MAX_SIZE = 1000;  // Limit queue size to prevent memory overflow

    // Thread-safe queue for DNS requests
    class DNSRequestQueue {
    private:
        std::queue<std::pair<std::vector<uint8_t>, WINDIVERT_ADDRESS>> requestQueue;
        std::mutex queueMutex;
        std::condition_variable notEmptyCV;
        std::condition_variable notFullCV;
        size_t maxSize;

    public:
        DNSRequestQueue(size_t max_size = QUEUE_MAX_SIZE) : maxSize(max_size) {}

        void enqueue(const std::vector<uint8_t>& packet, const WINDIVERT_ADDRESS& addr) {
            std::unique_lock<std::mutex> lock(queueMutex);

            // Wait if queue is full
            notFullCV.wait(lock, [this]() { return requestQueue.size() < maxSize; });

            requestQueue.push({ packet, addr });

            // Notify that queue is not empty
            lock.unlock();
            notEmptyCV.notify_one();
        }

        std::pair<std::vector<uint8_t>, WINDIVERT_ADDRESS> dequeue() {
            std::unique_lock<std::mutex> lock(queueMutex);

            // Wait until queue is not empty
            notEmptyCV.wait(lock, [this]() { return !requestQueue.empty(); });

            auto request = requestQueue.front();
            requestQueue.pop();

            // Notify that queue is not full
            lock.unlock();
            notFullCV.notify_one();

            return request;
        }
    };

    std::mutex socketMutex;
    std::thread packetProcessingThread, packetCaptureThread, responseCaptureThread;
    std::atomic<bool> stopProcessing{ false };

    std::condition_variable shutdownCV;
    std::mutex shutdownMutex;
    WSADATA wsaData;
    HANDLE divertHandle;
    std::string localIPAddrForProxy;

    DNSRequestQueue requestQueue;

    struct DNSPacket {
        WINDIVERT_IPHDR ipHeader;
        WINDIVERT_UDPHDR udpHeader;
        std::vector<uint8_t> payload;
    };

    bool GetRequestLocalAddr(const char* packet, const size_t& packetLen, uint32_t& localIP, uint32_t& localPort);
    bool ParseDNSResponsePacket(const char* packet, size_t packetLen, DNSPacket& parsedPacket);
    bool ParseDNSPacket(const char* packet, size_t packetLen, DNSPacket& parsedPacket);
    bool ResolveDNSQuery(const DNSPacket& query, DNSPacket& response);
    bool ReconstructDNSResponse(const DNSPacket& originalQuery, DNSPacket& resolvedResponse);

public:
    DNSProxy() {
        // Initialize Winsock: Note: this shall ideally be done only once for a program.
        // Move this to a common place if socket is used at multiple places in the program in future.
        // For each call to WSAStartup, make sure WSACleanup is called too.
        (void)WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    ~DNSProxy() {
        Shutdown();
        WSACleanup();
    }

    void PacketCaptureThread();
    // Get the next packet from the queue and process it.
    void PacketProcessingThread();
    bool IsDNSRequestIssuedByCurrentProcess(const uint32_t& localIP, const uint32_t& localPort);
    bool IsProxyIPAddress(const std::string& ipAddr);

    void Start() {
        // Why should DNS Proxy use a fixed local IP for its purpose?
        // Since its not possible to track the calling process at network layer, there are multiple way to avoid recursive entrace.
        // We are opting #2 for the prototyping phase.
        // 1. Create another thread that does WinDivertRecv at the socket, keep track of ip tuple and process info. 
        //    Use this info while processing the packet at the network layer to find the initiating process. 
        //    Avoid processing the packet if its coming from this proxy process.
        // 2. A rather simplistic approch is to use a fixed local IP while socket binding when proxy process does network activity.
        //    Preserve the IP:port of the packet thats in flight. On WinDivertRecv skip the processing if the saved local binding matches. 
        //    Second approach does lot of assumptions and may not always work. But this is good enough for initial prototyping rather   
        //    that looking for a perfect solution.
        // 3. A perfect solution is to use WFP filter driver which is foolproof, performance effective but requires kernel code. This is our final 
        //    approach if above two methods dont work.
        // 
        auto localIPs = GetLocalIPAddresses();
        localIPAddrForProxy = localIPs[0];
        std::cout << "DNS Proxy uses local ip = " << localIPAddrForProxy << std::endl;

        // Start packet capture thread
        packetCaptureThread = std::thread(&DNSProxy::PacketCaptureThread, this);
        
        // Start packet processing thread
        packetProcessingThread = std::thread(&DNSProxy::PacketProcessingThread, this);
    }

    void Shutdown() {
        // Signal the processing thread to stop
        stopProcessing = true;
        shutdownCV.notify_all();

        // Wait for threads to finish
        if (packetCaptureThread.joinable()) {
            packetCaptureThread.join();
        }

        if (packetProcessingThread.joinable()) {
            packetProcessingThread.join();
        }
    }
};
