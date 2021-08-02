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
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <climits>
#endif

#define ICMPLIB_ICMP_ECHO_REQUEST 8
#define ICMPLIB_ICMP_ECHO_RESPONSE 0
#define ICMPLIB_ICMP_DESTINATION_UNREACHABLE 3

#define ICMPLIB_IPV4_HEADER_SIZE 20
#define ICMPLIB_RECV_BUFFER_SIZE 1024

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
		struct ICMPEchoResult {
			enum class ResponseType {
				Success,
				Unreachable
			} response;
			double interval;
			std::string host;
			unsigned ttl;
		};
        Echo() = delete;
        Echo(const Echo &) = delete;
        Echo(Echo &&) = delete;
        Echo &operator=(const Echo &) = delete;
        static ICMPEchoResult Execute(const std::string &ipv4, unsigned ttl = 255) {
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
            request.id = rand() % USHRT_MAX;
            request.type = ICMPLIB_ICMP_ECHO_REQUEST;
            SetChecksum(request, sizeof(ICMPEchoMessage));
            int bytes = sendto(sock, reinterpret_cast<char *>(&request), sizeof(ICMPEchoMessage), 0, reinterpret_cast<ICMPLIB_SOCKADDR *>(&address), static_cast<ICMPLIB_SOCKETADDR_LENGTH>(sizeof(ICMPLIB_SOCKADDR_IN)));
            if (bytes == ICMPLIB_SOCKET_ERROR) {
				ICMPLIB_CLOSESOCKET(sock);
                throw std::runtime_error("Error while sending data!");
            }

            auto start = std::chrono::high_resolution_clock::now();

            ICMPLIB_SOCKETADDR_LENGTH length = sizeof(ICMPLIB_SOCKADDR_IN);
            std::memset(&address, 0, sizeof(ICMPLIB_SOCKADDR_IN));
            char buffer[ICMPLIB_RECV_BUFFER_SIZE];
            bytes = recvfrom(sock, buffer, ICMPLIB_RECV_BUFFER_SIZE, 0, reinterpret_cast<ICMPLIB_SOCKADDR *>(&address), &length);
            if (bytes == ICMPLIB_SOCKET_ERROR) {
				ICMPLIB_CLOSESOCKET(sock);
                throw std::runtime_error("Error while receiving data!");
            }
			
            auto end = std::chrono::high_resolution_clock::now();
			ICMPEchoResult result;
			result.interval = static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) / 100000.0d;

            ICMPHeader header;
			std::memset(&header, 0, sizeof(ICMPHeader));
			ICMPEchoMessage response;
			std::memset(&response, 0, sizeof(ICMPEchoMessage));
			std::memcpy(&header, &buffer[ICMPLIB_IPV4_HEADER_SIZE], static_cast<long unsigned>(bytes) - ICMPLIB_IPV4_HEADER_SIZE > sizeof(ICMPHeader) ? sizeof(ICMPHeader) : static_cast<long unsigned>(bytes) - ICMPLIB_IPV4_HEADER_SIZE);			
			uint16_t checksum = header.checksum;
			switch (header.type) {
				case ICMPLIB_ICMP_ECHO_RESPONSE:
					std::memcpy(&response, &buffer[ICMPLIB_IPV4_HEADER_SIZE], static_cast<long unsigned>(bytes) - ICMPLIB_IPV4_HEADER_SIZE > sizeof(ICMPEchoMessage) ? sizeof(ICMPEchoMessage) : static_cast<long unsigned>(bytes) - ICMPLIB_IPV4_HEADER_SIZE);			
					response.checksum = 0;
					if ((checksum != SetChecksum(response, sizeof(ICMPEchoMessage))) || (request.id != response.id)) {
						ICMPLIB_CLOSESOCKET(sock);
						throw std::runtime_error("Wrong host response!");
					}
					result.response = ICMPEchoResult::ResponseType::Success;
				case ICMPLIB_ICMP_DESTINATION_UNREACHABLE:
					header.checksum = 0;
					if (checksum != SetChecksum(header, sizeof(ICMPHeader))) {
						ICMPLIB_CLOSESOCKET(sock);
						throw std::runtime_error("Wrong host response!");
					}				
					result.response = ICMPEchoResult::ResponseType::Unreachable;
				default:
					ICMPLIB_CLOSESOCKET(sock);
					throw std::runtime_error("Unsupported response type!");
			}
			ICMPLIB_CLOSESOCKET(sock);

            return result;
        }
    private:
        struct ICMPHeader {
            uint8_t type;
            uint8_t code;
            uint16_t checksum;
        };

        struct ICMPEchoMessage : ICMPHeader {
            uint16_t id;
            uint16_t seq;
            uint8_t data[ICMPLIB_PING_DATA_SIZE];
        };

        static uint16_t SetChecksum(ICMPHeader &packet, unsigned long length) {
            uint16_t *element = reinterpret_cast<uint16_t *>(&packet);
            uint32_t sum = 0;
            for (; length > 1; length -= 2) {
                sum += *element++;
            }
            if (length > 0) {
                sum += *reinterpret_cast<uint8_t *>(element);
            }
            sum = (sum >> 16) + (sum & 0xFFFF);
            sum += (sum >> 16);
            packet.checksum = static_cast<uint16_t>(~sum);
            return packet.checksum;
        };		
    };

    Echo::ICMPEchoResult Ping(const std::string &ipv4, unsigned ttl = 255) {
        return Echo::Execute(ipv4, ttl);
    }
}