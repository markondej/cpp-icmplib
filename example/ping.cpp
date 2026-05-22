#include <iostream>
#include "icmplib.h"

int main(int argc, char *argv[])
{
    std::string address = "8.8.8.8", resolved;
    uint16_t packet_size = ICMPLIB_PING_DATA_SIZE;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-l" && i + 1 < argc) {
            try {
                int size = std::stoi(argv[++i]);
                if (size < 0 || size > ICMPLIB_MAX_PING_DATA_SIZE) {
                    std::cerr << "Packet size must be between 0 and " << ICMPLIB_MAX_PING_DATA_SIZE << "." << std::endl;
                    return EXIT_FAILURE;
                }
                packet_size = static_cast<uint16_t>(size);
            } catch (...) {
                std::cerr << "Invalid packet size value." << std::endl;
                return EXIT_FAILURE;
            }
        } else {
            address = arg;
        }
    }

    try {
        if (!icmplib::IPAddress::IsCorrect(address, icmplib::IPAddress::Type::Unknown)) {
            resolved = address; address = icmplib::IPAddress(address);
        }
    } catch (...) {
        std::cerr << "Ping request could not find host " << address << ". Please check the name and try again." << std::endl;
        return EXIT_FAILURE;
    }

    int ret = EXIT_SUCCESS;
    std::cout << "Pinging " << (resolved.empty() ? address : resolved + " [" + address + "]")
              << " with " << packet_size << " bytes of data:" << std::endl;
    auto result = icmplib::Ping(address, ICMPLIB_TIMEOUT_1S, 1, 255, packet_size);
    switch (result.response) {
    case icmplib::PingResponseType::Failure:
        std::cerr << "Network error." << std::endl;
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
