#ifndef ICMPLIB_PING_DATA_SIZE
#define ICMPLIB_PING_DATA_SIZE 64
#endif

#include <exception>
#include <chrono>
#include <string>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <climits>
#endif

#define ICMPLIB_IPV4_HEADER_SIZE 20
#ifdef _WIN32
#define ICMPLIB_SOCKET SOCKET
#define ICMPLIB_SOCKADDR SOCKADDR
#define ICMPLIB_SOCKADDR_IN SOCKADDR_IN
#define ICMPLIB_SOCKETADDR_LENGTH int
#define ICMPLIB_SOCKET_ERROR SOCKET_ERROR
#define ICMPLIB_INETPTON InetPtonA
#define ICMPLIB_CLOSESOCKET closesocket
#else
#define ICMPLIB_SOCKET int
#define ICMPLIB_SOCKADDR sockaddr
#define ICMPLIB_SOCKADDR_IN sockaddr_in
#define ICMPLIB_SOCKETADDR_LENGTH socklen_t
#define ICMPLIB_SOCKET_ERROR -1
#define ICMPLIB_INETPTON inet_pton
#define ICMPLIB_CLOSESOCKET close
#endif

#if (defined _WIN32 && defined _MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#endif

namespace icmplib {
#ifdef _WIN32
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
#endif
    class Echo {
    public:
        Echo() = delete;
        Echo(const Echo &) = delete;
        Echo(Echo &&) = delete;
        Echo &operator=(const Echo &) = delete;
        static unsigned Execute(const std::string &ipv4, unsigned ttl = 255) {
#ifdef _WIN32
			WinSock::Initialize();
#endif	

            ICMPLIB_SOCKADDR_IN address;
            std::memset(&address, 0, sizeof(ICMPLIB_SOCKADDR_IN));
            address.sin_family = AF_INET;
            address.sin_port = htons(53);

            if (ICMPLIB_INETPTON(AF_INET, ipv4.c_str(), &address.sin_addr) <= 0) {
                throw std::runtime_error("Wrong IP address passed!");
            }

            ICMPLIB_SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#ifdef _WIN32
            if (sock == INVALID_SOCKET) {
#else
            if (sock <= 0) {
#endif	
                throw std::runtime_error("Cannot initialize socket!");
            }

            if (setsockopt(sock, IPPROTO_IP, IP_TTL, reinterpret_cast<char *>(&ttl), sizeof(ttl)) == ICMPLIB_SOCKET_ERROR) {
				ICMPLIB_CLOSESOCKET(sock);
                throw std::runtime_error("Cannot set socket options!");
            }

            ICMPEchoMessage request;
            std::memset(&request, 0, sizeof(ICMPEchoMessage));
            request.header.id = rand() % USHRT_MAX;
            request.header.type = 8;
            SetChecksum(request);
            int bytes = sendto(sock, reinterpret_cast<char *>(&request), sizeof(ICMPEchoMessage), 0, reinterpret_cast<ICMPLIB_SOCKADDR *>(&address), static_cast<ICMPLIB_SOCKETADDR_LENGTH>(sizeof(ICMPLIB_SOCKADDR_IN)));
            if (bytes == ICMPLIB_SOCKET_ERROR) {
				ICMPLIB_CLOSESOCKET(sock);
                throw std::runtime_error("Error while sending data!");
            }

            auto start = std::chrono::high_resolution_clock::now();

            ICMPLIB_SOCKETADDR_LENGTH length = sizeof(ICMPLIB_SOCKADDR_IN);
            std::memset(&address, 0, sizeof(ICMPLIB_SOCKADDR_IN));
            char buffer[sizeof(ICMPEchoMessage) + ICMPLIB_IPV4_HEADER_SIZE];
            bytes = recvfrom(sock, buffer, sizeof(ICMPEchoMessage) + ICMPLIB_IPV4_HEADER_SIZE, 0, reinterpret_cast<ICMPLIB_SOCKADDR *>(&address), &length);
            if (bytes == ICMPLIB_SOCKET_ERROR) {
				ICMPLIB_CLOSESOCKET(sock);
                throw std::runtime_error("Error while receiving data!");
            }
            auto end = std::chrono::high_resolution_clock::now();

            ICMPEchoMessage response;
            std::memcpy(&response, &buffer[ICMPLIB_IPV4_HEADER_SIZE], static_cast<long unsigned>(bytes) - ICMPLIB_IPV4_HEADER_SIZE > sizeof(ICMPEchoMessage) ? sizeof(ICMPEchoMessage) : bytes - ICMPLIB_IPV4_HEADER_SIZE);
            uint16_t checksum = response.header.checksum;
            response.header.checksum = 0;
            if ((checksum != SetChecksum(response)) || (request.header.id != response.header.id)) {
				ICMPLIB_CLOSESOCKET(sock);
                throw std::runtime_error("Wrong host response!");
            }
			ICMPLIB_CLOSESOCKET(sock);

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