# A C++ header-only ICMP Ping library

This is cross-platform library, which allows performing system-like IPv4 ping requests from C++ applications without need of use system "ping" command.
As library is socket based, on most operating systems, it will require administrator privilages (root) to run.

## How to use

icmplib delivers function Ping declared as:
```
PingResult Ping(const std::string &ipv4, unsigned timeout = 60, uint8_t ttl = 255);
```
where:
* ipv4 - IPv4 network address
* timeout - Timeout in seconds
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
    std::string ipv4;
    uint8_t code;
    uint8_t ttl;
};
```
where:
* interval - Time in miliseconds between sending request and receiving response
* ipv4 - IPv4 address of responding host
* code - ICMP Code parameter
* ttl - Received IPv4 header TTL parameter 
* response - Type of received response

```
ResponseType            | Meaning
----------------------------------------------------------------------------------------------------
Success                 | ICMP Echo Response successfully received
Unreachable             | ICMP Destination Ureachable message received (ie. host does not exist)
TimeExceeded            | ICMP Time Exceeded message received (ie. TTL meet zero value on some host)
Timeout                 | No message recived in passed time (see "timeout" parameter)
Unsupported             | Received unsupported ICMP packet
Failure                 | Failed to send ICMP Echo Request to given host
```

## Examples

In order to make internet connection test simply use:
```
#include "icmplib.h"

...

bool isConnected()
{
    return icmplib::Ping("8.8.8.8", 5).response == icmplib::PingResponseType::Success; // Test Google DNS server address
}
```

Simple traceroute implementation:
```
#include "icmplib.h"
#include <vector>
...

std::vector<std::string> traceroute(const std::string &ipv4)
{
    std::vector<std::string> result;
    for (uint8_t ttl = 1; ttl != 0; ttl++) {
        auto ping = icmplib::Ping(ipv4, 5, ttl);
        switch (ping.response) {
        case icmplib::PingResult::ResponseType::TimeExceeded:
            result.push_back(ping.ipv4);
            break;
        case icmplib::PingResult::ResponseType::Success:
            result.push_back(ping.ipv4);
            return result;
        default:
            return result;
        }
    }
    return result;
}
```

## To be done

Work need to be done:
* Code needs refactor to be more SOLID-like
* Auto hostname translation to IP address
* IPv6 support

## Known issues

On Windows 10 ICMP Destination Unreachable messages seems to be blocked and, while being received, are not passed to application via socket