#ifndef ICMPLIB_PING_DATA_SIZE
#define ICMPLIB_PING_DATA_SIZE 64
#endif

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <chrono>
#include <string>
#include <thread>
#include <algorithm>
#include <regex>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <climits>
#endif

#define ICMPLIB_ICMP_ECHO_RESPONSE 0
#define ICMPLIB_ICMP_DESTINATION_UNREACHABLE 3
#define ICMPLIB_ICMP_ECHO_REQUEST 8
#define ICMPLIB_ICMP_TIME_EXCEEDED 11

#define ICMPLIB_IPV4_ADDRESS_SIZE 16
#define ICMPLIB_IPV4_HEADER_SIZE 20
#define ICMPLIB_IPV4_TTL_OFFSET 8
#define ICMPLIB_RECV_BUFFER_SIZE 1024
#define ICMPLIB_ORIGINAL_DATA_SIZE ICMPLIB_IPV4_HEADER_SIZE + 8

#ifdef _WIN32
#define ICMPLIB_SOCKET SOCKET
#define ICMPLIB_SOCKADDR SOCKADDR
#define ICMPLIB_SOCKADDR_IN SOCKADDR_IN
#define ICMPLIB_SOCKETADDR_LENGTH int
#define ICMPLIB_SOCKET_ERROR SOCKET_ERROR
#define ICMPLIB_INETPTON InetPtonA
#define ICMPLIB_INETNTOP InetNtopA
#define ICMPLIB_CLOSESOCKET closesocket
#else
#define ICMPLIB_SOCKET int
#define ICMPLIB_SOCKADDR sockaddr
#define ICMPLIB_SOCKADDR_IN sockaddr_in
#define ICMPLIB_SOCKETADDR_LENGTH socklen_t
#define ICMPLIB_SOCKET_ERROR -1
#define ICMPLIB_INETPTON inet_pton
#define ICMPLIB_INETNTOP inet_ntop
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
    class ICMPEcho {
    public:
        struct Result {
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
        ICMPEcho() = delete;
        ICMPEcho(const ICMPEcho &) = delete;
        ICMPEcho(ICMPEcho &&) = delete;
        ICMPEcho &operator=(const ICMPEcho &) = delete;
        static Result Execute(const std::string &target, unsigned timeout = 60, uint8_t ttl = 255) {
#ifdef _WIN32
            WinSock::Initialize();
#endif
            Result result = { Result::ResponseType::Timeout, static_cast<double>(timeout), std::string(), 0, 0 };
            try {
                Address address(target);
                Socket sock(ttl);

                Request request;
                request.Transmit(sock.GetSocket(), address);
                auto start = std::chrono::high_resolution_clock::now();

                while (true) {
                    Response response;
                    bool recv = response.Recv(sock.GetSocket(), address);
                    auto end = std::chrono::high_resolution_clock::now();
                    if (!recv) {
                        if (static_cast<unsigned>(std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()) > timeout) {
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::microseconds(1));
                        continue;
                    }

                    result.response = GetResponseType(request, response);
                    if (result.response == Result::ResponseType::Timeout) {
                        continue;
                    }

                    result.interval = static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) / 1000.0;
                    result.ipv4 = address.ToString();
                    result.code = response.GetHeader().code;
                    result.ttl = response.GetTTL();
                }
            } catch (...) {
                return { Result::ResponseType::Failure, 0, std::string(), 0, 0 };
            }
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

        struct ICMPRevertedMessage : ICMPHeader {
            uint32_t unused;
            uint8_t data[ICMPLIB_ORIGINAL_DATA_SIZE];
        };

        class Socket {
        public:
            Socket(uint8_t ttl) {
                sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#ifdef _WIN32
                if (sock == INVALID_SOCKET) {
#else
                if (*sock <= 0) {
#endif	
                    throw std::runtime_error("Cannot initialize socket!");
                }

                if (setsockopt(sock, IPPROTO_IP, IP_TTL, reinterpret_cast<char *>(&ttl), sizeof(uint8_t)) == ICMPLIB_SOCKET_ERROR) {
                    ICMPLIB_CLOSESOCKET(sock);
                    throw std::runtime_error("Cannot set socket options!");
                }

#ifdef _WIN32
                unsigned long mode = 1;
                if (ioctlsocket(sock, FIONBIO, &mode) != NO_ERROR) {
#else
                int flags = fcntl(sock, F_GETFL, 0);
                if ((flags == -1) || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
#endif
                    ICMPLIB_CLOSESOCKET(sock);
                    throw std::runtime_error("Cannot set socket options!");
                }
                }
            virtual ~Socket() {
                ICMPLIB_CLOSESOCKET(sock);
            }
            inline const ICMPLIB_SOCKET &GetSocket() {
                return sock;
            }
        private:
            ICMPLIB_SOCKET sock;
        };

        class Address : public ICMPLIB_SOCKADDR_IN {
        public:
            Address() = delete;
            Address(const std::string &address) {
                std::string ipv4 = address;
                if (!std::regex_match(address, std::regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"))) {
                    ipv4 = Resolve(address);
                }
                std::memset(this, 0, sizeof(ICMPLIB_SOCKADDR_IN));
                this->sin_family = AF_INET;
                this->sin_port = htons(53);

                if (ICMPLIB_INETPTON(AF_INET, ipv4.c_str(), &this->sin_addr) <= 0) {
                    throw std::runtime_error("Incorrect IPv4 address provided!");
                }
            }
            std::string ToString() const {
                std::string ipv4;
                char buffer[ICMPLIB_IPV4_ADDRESS_SIZE + 1];
                if (ICMPLIB_INETNTOP(AF_INET, &this->sin_addr, buffer, ICMPLIB_IPV4_ADDRESS_SIZE + 1) != NULL) {
                    ipv4 = buffer;
                }
                return ipv4;
            }
            std::string Resolve(const std::string &hostname) {
                hostent *he = gethostbyname(hostname.c_str());
                return std::string(inet_ntoa(*reinterpret_cast<IN_ADDR *>(he->h_addr_list[0])));
            }
        };

        class Request : public ICMPEchoMessage {
        public:
            Request() {
                std::memset(this, 0, sizeof(ICMPEchoMessage));
                this->id = rand() % USHRT_MAX;
                this->type = ICMPLIB_ICMP_ECHO_REQUEST;
                SetChecksum<ICMPEchoMessage>(this);
            };
            void Transmit(ICMPLIB_SOCKET sock, ICMPLIB_SOCKADDR_IN &address) {
                int bytes = sendto(sock, reinterpret_cast<char *>(this), sizeof(ICMPEchoMessage), 0, reinterpret_cast<ICMPLIB_SOCKADDR *>(&address), static_cast<ICMPLIB_SOCKETADDR_LENGTH>(sizeof(ICMPLIB_SOCKADDR_IN)));
                if (bytes == ICMPLIB_SOCKET_ERROR) {
                    throw std::runtime_error("Failed to send request!");
                }
            };
        };

        class Response {
        public:
            Response() : header(nullptr), length(0) {
                std::memset(&buffer, 0, sizeof(uint8_t) * ICMPLIB_RECV_BUFFER_SIZE);
            };
            virtual ~Response() {
                if (header != nullptr) {
                    delete header;
                }
            };
            bool Recv(ICMPLIB_SOCKET sock, ICMPLIB_SOCKADDR_IN &address) {
                ICMPLIB_SOCKETADDR_LENGTH length = sizeof(ICMPLIB_SOCKADDR_IN);
                std::memset(&address, 0, sizeof(ICMPLIB_SOCKADDR_IN));
                int bytes = recvfrom(sock, reinterpret_cast<char *>(buffer), ICMPLIB_RECV_BUFFER_SIZE, 0, reinterpret_cast<ICMPLIB_SOCKADDR *>(&address), &length);
                if (bytes <= 0) {
                    return false;
                }
                length = static_cast<unsigned>(bytes);
                return true;
            };
            template <class T>
            const T Generate() const {
                if (sizeof(T) < length) {
                    throw std::runtime_error("Incorrect ICMP packet size!");
                }
                T packet;
                std::memset(&packet, 0, sizeof(T));
                std::memcpy(&packet, &buffer[ICMPLIB_IPV4_HEADER_SIZE], static_cast<long unsigned>(length) - ICMPLIB_IPV4_HEADER_SIZE > sizeof(T) ? sizeof(T) : static_cast<long unsigned>(length) - ICMPLIB_IPV4_HEADER_SIZE);
                return packet;
            };
            const ICMPHeader &GetHeader() {
                if (header == nullptr) {
                    header = new ICMPHeader;
                    *header = Generate<ICMPHeader>();
                }
                return *header;
            }
            inline const uint8_t GetTTL() {
                return buffer[ICMPLIB_IPV4_TTL_OFFSET];
            };
            inline const unsigned GetSize() {
                return length - ICMPLIB_IPV4_HEADER_SIZE;
            };
        private:
            uint8_t buffer[ICMPLIB_RECV_BUFFER_SIZE];
            ICMPHeader *header;
            unsigned length;
        };

        static Result::ResponseType GetResponseType(const Request &request, Response &response) {
            Result::ResponseType result = Result::ResponseType::Timeout;

            ICMPEchoMessage echo;
            ICMPRevertedMessage reverted;
            switch (response.GetHeader().type) {
            case ICMPLIB_ICMP_ECHO_RESPONSE:
                result = Result::ResponseType::Success;
                echo = response.Generate<ICMPEchoMessage>();
                echo.checksum = 0;
                if ((response.GetHeader().checksum != SetChecksum<ICMPEchoMessage>(&echo)) || (request.id != echo.id)) {
                    result = Result::ResponseType::Unsupported;
                }
                break;
            case ICMPLIB_ICMP_DESTINATION_UNREACHABLE:
                result = Result::ResponseType::Unreachable;
            case ICMPLIB_ICMP_TIME_EXCEEDED:
                if (result == Result::ResponseType::Timeout) {
                    result = Result::ResponseType::TimeExceeded;
                }
                reverted = response.Generate<ICMPRevertedMessage>();
                reverted.checksum = 0;
                if (response.GetHeader().checksum != SetChecksum<ICMPRevertedMessage>(&reverted)) {
                    result = Result::ResponseType::Unsupported;
                }
                break;
            case ICMPLIB_ICMP_ECHO_REQUEST:
                break;
            default:
                result = Result::ResponseType::Unsupported;
            }

            return result;
        };

        template <class T>
        static uint16_t SetChecksum(T *packet) {
            uint16_t *element = reinterpret_cast<uint16_t *>(packet);
            unsigned long size = sizeof(T);
            uint32_t sum = 0;
            for (; size > 1; size -= 2) {
                sum += *element++;
            }
            if (size > 0) {
                sum += *reinterpret_cast<uint8_t *>(element);
            }
            sum = (sum >> 16) + (sum & 0xFFFF);
            sum += (sum >> 16);
            packet->checksum = static_cast<uint16_t>(~sum);
            return packet->checksum;
        };
    };

    using PingResult = ICMPEcho::Result;
    using PingResponseType = ICMPEcho::Result::ResponseType;

    PingResult Ping(const std::string &target, unsigned timeout = 60, uint8_t ttl = 255) {
        return ICMPEcho::Execute(target, timeout, ttl);
    }
}