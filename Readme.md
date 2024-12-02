# DNSProxy

DNSProxy is a lightweight DNS interception and proxying tool built using WinDivert. It captures DNS traffic, serves responses locally, and forwards queries to upstream DNS servers as needed. It also ensures no interference with traffic originating from the DNS proxy process itself.

---

## Features

- **DNS Traffic Capture:** Intercepts DNS packets (UDP port 53) using WinDivert.
- **Local DNS Proxy:** Redirects DNS queries to a local process for custom processing.
- **Upstream Routing:** Modifies DNS packets dynamically to forward to upstream DNS servers.
- **Traffic Exclusion:** Prevents recursive interception of DNS requests from the proxy itself.
- **Security:** Supports binary path validation and optional signature checking to identify the proxy process.

---

## Installation

### Prerequisites

1. **WinDivert Library:** Download and place `WinDivert.dll`, `WinDivert.lib`, and `WinDivert.h` in your project directories.
2. **Visual Studio:** Use Visual Studio for building the project. Ensure the correct compiler and runtime environment are set up.

### Steps(TBD)

1. Clone the repository:
   ```bash
   git clone https://github.com/rushikeshpatil12/DNSProxy.git
   ```

2. Open the project in Visual Studio.

3. Build the solution in **Release** mode.

4. Run the `DNSProxy.exe` executable with **administrative privileges**.

## Usage

### How It Works

1. **Capture:** DNSProxy captures DNS traffic using the WinDivert library by applying a filter for UDP port 53.
2. **Process:** Captured packets are forwarded to a local DNS proxy process for handling.
3. **Redirect:** Responses are modified and redirected to upstream DNS servers if required.

### Example Execution

Run the application as an administrator:

```bash
DNSProxy.exe
```

## Configuration

1. **Adjust Proxy Logic:** Modify the `ProcessPacket` function in the code to define custom logic for handling DNS queries and routing to upstream servers.
2. **Exclude Proxy Traffic:** Use binary path validation (`FWP_CONDITION_ALE_APP_ID`) in WinDivert or WFP filters to ensure no recursive interception of the proxy process's traffic.

## Implementation Highlights

### Key Design Considerations

- **Efficient Packet Processing:** Uses smart pointers (`std::unique_ptr`) for automatic memory management.
- **Traffic Exclusion:** Prevents recursive DNS interception using binary path validation.
- **Upstream DNS Routing:** Dynamically determines and modifies packets for routing to upstream servers.

### WinDivert Filter

Example of a filter for DNS traffic:

```cpp
HANDLE handle = WinDivertOpen("udp.DstPort == 53 || udp.SrcPort == 53", WINDIVERT_LAYER_NETWORK, 0, 0);
```

### Packet Processing

Core packet processing happens in the `ProcessPacket` function:

```cpp
void ProcessPacket(UINT8* packet, UINT packetLen, WINDIVERT_ADDRESS& addr) {
    // Parse and inspect packet contents (e.g., DNS header).
    // Modify destination IP/port if necessary.
    // Forward modified packet back using WinDivertSend.
}
```

## Security Considerations

1. **PID Spoofing:** Use binary path validation instead of PID-based process matching.
2. **Signature Validation:** Optionally validate the binary signature of the proxy process for added security.

## Future Enhancements

1. Add support for DNS over TCP (relatively uncommon but used for reliability and encryption).
2. Optimize for high-throughput traffic scenarios by integrating kernel-level WFP filters.
3. Support encrypted DNS protocols like DoH (DNS over HTTPS).

## License
Released under CC0 1.0 Universal Public Domain Dedication. Unrestricted rights for commercial and non-commercial use, modification, and distribution.
