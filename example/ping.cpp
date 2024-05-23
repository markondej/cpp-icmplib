#include <iostream>
#include "icmplib.h"

int main(int argc, char *argv[])
{
    std::string address = "8.8.8.8", resolved;
    if (argc > 1) { address = argv[1]; }
    try {
        if (!icmplib::IPAddress::IsCorrect(address, icmplib::IPAddress::Type::Unknown)) {
            resolved = address; address = icmplib::IPAddress(address);
        }
    } catch (...) {
        std::cout << "Ping request could not find host " << address << ". Please check the name and try again." << std::endl;
        return 1;
    }

    int ret = EXIT_SUCCESS;
    std::cout << "Pinging " << (resolved.empty() ? address : resolved + " [" + address + "]")
              << " with " << ICMPLIB_PING_DATA_SIZE << " bytes of data:" << std::endl;
    auto result = icmplib::Ping(address, ICMPLIB_TIMEOUT_1S);
    switch (result.response) {
    case icmplib::PingResponseType::Failure:
        std::cout << "Network error." << std::endl;
        ret = EXIT_FAILURE;
        break;
    case icmplib::PingResponseType::Timeout:
        std::cout << "Request timed out." << std::endl;
        break;
    default:
        std::cout << "Reply from " << static_cast<std::string>(result.address) << ": ";
        switch (result.response) {
        case icmplib::PingResponseType::Success:
            std::cout << "time=" << result.delay;
            if (result.address.GetType() != icmplib::IPAddress::Type::IPv6) {
                std::cout << " TTL=" << static_cast<unsigned>(result.ttl);
            }
            break;
        case icmplib::PingResponseType::Unreachable:
            std::cout << "Destination unreachable.";
            break;
        case icmplib::PingResponseType::TimeExceeded:
            std::cout << "Time exceeded.";
            break;
        default:
            std::cout << "Response not supported.";
        }
        std::cout << std::endl;
    }
    return ret;
}
