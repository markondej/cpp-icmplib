#include <iostream>
#include "icmplib.h"

int main(int argc, char *argv[])
{
    int ret = 0;
    std::string address = "8.8.8.8";
    if (argc > 1) { address = argv[1]; }
    std::cout << "Pinging " << address << " with " << ICMPLIB_PING_DATA_SIZE << " bytes of data:" << std::endl;
    auto result = icmplib::Ping(address);
    switch (result.response) {
    case icmplib::PingResponseType::Failure:
        std::cout << "Network error." << std::endl;
        ret = 1;
        break;
    case icmplib::PingResponseType::Timeout:
        std::cout << "Request timed out." << std::endl;
        break;
    default:
        std::cout << "Reply from " << result.ipv4 << ": ";
        switch (result.response) {
        case icmplib::PingResponseType::Success:
            std::cout << "time=" << result.interval << " TTL=" << static_cast<unsigned>(result.ttl);
            break;
        case icmplib::PingResponseType::Unreachable:
            std::cout << "Destination unreachable.";
            break;
        case icmplib::PingResponseType::TimeExceeded:
            std::cout << "Time exceeded.";
            break;
        }
        std::cout << std::endl;
    }
    return ret;
}