#include <iostream>
#include "icmplib.h"

int main()
{
    std::string address = "8.8.8.8";
    std::cout << "Pinging " << address << " with " << ICMPLIB_PING_DATA_SIZE << " bytes of data:" << std::endl;
    try {
        auto result = icmplib::Ping(address, 5, 5);
        if (result.response != icmplib::Echo::Result::ResponseType::Timeout) {
            std::cout << "Reply from " << result.host << ": ";
            switch (result.response) {
            case icmplib::Echo::Result::ResponseType::Success:
                std::cout << "time=" << result.interval << " TTL=" << static_cast<unsigned>(result.ttl);
                break;
            case icmplib::Echo::Result::ResponseType::Unreachable:
                std::cout << "Destination unreachable.";
                break;
            }
        } else {
            std::cout << "Request timed out.";
        }
        std::cout << std::endl;
    } catch (std::exception &e) {
        std::cout << "Network error." << std::endl;
        return 1;
    }
    return 0;
}