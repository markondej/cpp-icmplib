#ifndef ICMPLIB_PING_DATA_SIZE
#define ICMPLIB_PING_DATA_SIZE 64
#endif

#ifndef ICMPLIB_PING_DATA_SIZE
#define ICMPLIB_PING_DATA_SIZE 64
#endif

#include <exception>
#include <chrono>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#define ICMPLIB_IPV4_HEADER_SIZE 20

#if (defined _WIN32 && defined _MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#endif

namespace icmplib {
    class WinSock {
    public:
        WinSock(const WinSock &) = delete;
        WinSock(WinSock &&) = delete;
        virtual ~WinSock() {
            WSACleanup();
        }
        WinSock &operator=(const WinSock &) = delete;
        static WinSock &Initialize() {
            static WinSock instance;
            return instance;
        }
    private:
        WinSock() {
            WSADATA wsaData;
            int error = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (error != NO_ERROR) {
                throw std::runtime_error("Cannot initialize WinSock!");
            }
            if ((LOBYTE(wsaData.wVersion) != 2) || (HIBYTE(wsaData.wVersion) != 2)) {
                WSACleanup();
                throw std::runtime_error("Cannot initialize WinSock!");
            }
        }
    };

    class Echo {
    public:
        Echo() = delete;
        Echo(const Echo &) = delete;
        Echo(Echo &&) = delete;
        Echo &operator=(const Echo &) = delete;
        static unsigned Execute(const std::string &ipv4, unsigned ttl = 255) {
            WinSock::Initialize();

            SOCKADDR_IN address;
            std::memset(&address, 0, sizeof(SOCKADDR_IN));
            address.sin_family = AF_INET;
            address.sin_port = htons(53);
            if (InetPtonA(AF_INET, ipv4.c_str(), &address.sin_addr) != TRUE) {
                throw std::runtime_error("Wrong IP address passed!");
            }

            SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (sock == INVALID_SOCKET) {
                throw std::runtime_error("Cannot initialize socket!");
            }

            if (setsockopt(sock, IPPROTO_IP, IP_TTL, reinterpret_cast<char *>(&ttl), sizeof(ttl)) == SOCKET_ERROR) {
                closesocket(sock);
                throw std::runtime_error("Cannot set socket options!");
            }

            ICMPEchoMessage request;
            std::memset(&request, 0, sizeof(ICMPEchoMessage));
            request.header.id = rand() % USHRT_MAX;
            request.header.type = 8;
            SetChecksum(request);
            int bytes = sendto(sock, reinterpret_cast<char *>(&request), sizeof(ICMPEchoMessage), 0, reinterpret_cast<SOCKADDR *>(&address), sizeof(SOCKADDR_IN));
            if (bytes == SOCKET_ERROR) {
                closesocket(sock);
                throw std::runtime_error("Error while sending data!");
            }

            auto start = std::chrono::high_resolution_clock::now();

            int length = sizeof(SOCKADDR_IN);
            std::memset(&address, 0, sizeof(SOCKADDR_IN));
            char buffer[sizeof(ICMPEchoMessage) + ICMPLIB_IPV4_HEADER_SIZE];
            bytes = recvfrom(sock, buffer, sizeof(ICMPEchoMessage) + ICMPLIB_IPV4_HEADER_SIZE, 0, reinterpret_cast<SOCKADDR *>(&address), &length);
            if (bytes == SOCKET_ERROR) {
                closesocket(sock);
                throw std::runtime_error("Error while receiving data!");
            }
            auto end = std::chrono::high_resolution_clock::now();

            ICMPEchoMessage response;
            std::memcpy(&response, &buffer[ICMPLIB_IPV4_HEADER_SIZE], bytes - ICMPLIB_IPV4_HEADER_SIZE > sizeof(ICMPEchoMessage) ? sizeof(ICMPEchoMessage) : bytes - ICMPLIB_IPV4_HEADER_SIZE);
            uint16_t checksum = response.header.checksum;
            response.header.checksum = 0;
            if ((checksum != SetChecksum(response)) || (request.header.id != response.header.id)) {
                closesocket(sock);
                throw std::runtime_error("Wrong host response!");
            }
            closesocket(sock);

            return static_cast<unsigned>(std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
        }
    private:
        struct ICMPEchoHeader {
            uint8_t type;
            uint8_t code;
            uint16_t checksum;
            uint16_t id;
            uint16_t seq;
        };

        struct ICMPEchoMessage {
            ICMPEchoHeader header;
            uint8_t data[ICMPLIB_PING_DATA_SIZE];
        };

        static uint16_t SetChecksum(ICMPEchoMessage &message) {
            uint16_t *element = reinterpret_cast<uint16_t *>(&message);
            uint32_t sum = 0, length = sizeof(ICMPEchoMessage);
            for (; length > 1; length -= 2) {
                sum += *element++;
            }
            if (length > 0) {
                sum += *reinterpret_cast<uint8_t *>(element);
            }
            sum = (sum >> 16) + (sum & 0xFFFF);
            sum += (sum >> 16);
            message.header.checksum = static_cast<uint16_t>(~sum);
            return message.header.checksum;
        };
    };

    unsigned Ping(const std::string &ipv4, unsigned ttl = 255) {
        return Echo::Execute(ipv4, ttl);
    }
}