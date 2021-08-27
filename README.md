# A C++ header-only ICMP/ICMPv6 Ping library

This is cross-platform library, which allows performing system-like ping requests from C++ applications without need of use system "ping" command.
As library is socket-based, on most operating systems, it will require administrator privilages (root) to run.

## How to use

icmplib delivers function Ping declared as:
```
PingResult Ping(const icmplib::AddressIP &target, unsigned timeout = 60, uint16_t sequence = 1, uint8_t ttl = 255);
```
where:
* target - Network address (may be created from std::string)
* timeout - Timeout in seconds
* sequence - Sequence number to be sent
* ttl - Time-to-live to be set for packet

PingResult structure is declared as:
```
struct PingResult {
    enum class ResponseType {
        Success,
        Unreachable,
        TimeExceeded,
        Timeout,
        Unsupported,
        Failure
    } response;
    double interval;
    icmplib::AddressIP address;
    uint8_t code;
    uint8_t ttl;
};
```
where:
* interval - Time in miliseconds between sending request and receiving response
* address - Address of responding host
* code - ICMP Code parameter
* ttl - Received IPv4 header TTL parameter 
* response - Type of received response

```
ResponseType            | Meaning
--------------------------------------------------------------------------------------------------------
Success                 | ICMP Echo Response successfully received
Unreachable             | ICMP Destination Ureachable message received (eg. target host does not exist)
TimeExceeded            | ICMP Time Exceeded message received (eg. TTL meet zero value on some host)
Timeout                 | No message recived in given time (see "timeout" parameter)
Unsupported             | Received unsupported ICMP packet
Failure                 | Failed to send ICMP Echo Request to given target host
```

## Examples

In order to make internet connection test simply use:
```
#include "icmplib.h"

...

bool isConnected()
{
    return icmplib::Ping("8.8.8.8", 5).response == icmplib::PingResponseType::Success; // Test Google DNS address
}
```

Simple traceroute implementation:
```
#include "icmplib.h"
#include <vector>
...

std::vector<std::string> traceroute(const std::string &address)
{
    std::vector<std::string> result;
    for (uint8_t ttl = 1; ttl != 0; ttl++) {
        auto ping = icmplib::Ping(address, 5, 1, ttl);
        switch (ping.response) {
        case icmplib::PingResult::ResponseType::TimeExceeded:
            result.push_back(ping.address.ToString());
            break;
        case icmplib::PingResult::ResponseType::Success:
            result.push_back(ping.address.ToString());
            return result;
        default:
            return result;
        }
    }
    return result;
}
```

## Known issues

On Windows 10 ICMP messages other than Echo Response seem to be blocked and, while being received, are not passed to application via socket, timeout is detected instead