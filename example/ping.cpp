#include <iostream>
#include "icmplib.h"

int main()
{
	std::string address = "8.8.8.8";
    std::cout << "Ping " << address << " ... ";
    try {
		auto result = icmplib::Ping("8.8.8.8");
        std::cout << result.interval << "ms" << std::endl;
    } catch (std::exception &e) {
        std::cout << "failure" << std::endl;
        return 1;
    }
    return 0;
}