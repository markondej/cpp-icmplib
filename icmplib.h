#ifndef ICMPLIB_PING_DATA_SIZE
#define ICMPLIB_PING_DATA_SIZE 64
#endif

#ifndef ICMPLIB_RECV_BUFFER_SIZE
#define ICMPLIB_RECV_BUFFER_SIZE 1024
#endif

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <chrono>
#include <string>
#include <thread>
#include <regex>
#ifdef _WIN32
#define _WIN32_WINNT 0x0601
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <cstring>
#include <climits>
#endif

#define ICMPLIB_ICMP_ECHO_RESPONSE 0
#define ICMPLIB_ICMP_DESTINATION_UNREACHABLE 3
#define ICMPLIB_ICMP_ECHO_REQUEST 8
#define ICMPLIB_ICMP_TIME_EXCEEDED 11

#define ICMPLIB_INET4_ADDRESSSTRLEN 17
#define ICMPLIB_INET4_HEADER_SIZE 20
#define ICMPLIB_INET4_TTL_OFFSET 8
#define ICMPLIB_ORIGINAL_DATA_SIZE ICMPLIB_INET4_HEADER_SIZE + 8

#define ICMPLIB_NOP_DELAY 10

#ifdef _WIN32
#define ICMPLIB_SOCKET SOCKET
#define ICMPLIB_SOCKET_ERROR SOCKET_ERROR
#define ICMPLIB_CLOSESOCKET closesocket
#else
#define ICMPLIB_SOCKET int
#define ICMPLIB_SOCKET_ERROR -1
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
    class AddressIPv4 : public sockaddr_in {
    public:
        AddressIPv4() {
            std::memset(this, 0, sizeof(sockaddr_in));
            sin_family = AF_INET;
        }
        AddressIPv4(const std::string &address) : AddressIPv4() {
            std::string ipv4 = address;
            if (!IsCorrect(address)) {
                ipv4 = Resolve(address);
            }
            if (inet_pton(AF_INET, ipv4.c_str(), &sin_addr) <= 0) {
                throw std::runtime_error("Incorrect IPv4 address provided!");
            }
        }
        std::string Resolve(const std::string &address) const {
#ifdef _WIN32
            WinSock::Initialize();
#endif
            AddressIPv4 addr;

            addrinfo hints;
            std::memset(&hints, 0, sizeof(addrinfo));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            addrinfo *result = NULL;
            if (getaddrinfo(address.c_str(), NULL, &hints, &result) == 0) {
                for (addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
                    switch (ptr->ai_family) {
                    case AF_INET:
                        try {
                            std::memcpy(reinterpret_cast<sockaddr_in *>(&addr), ptr->ai_addr, sizeof(sockaddr_in));
                            freeaddrinfo(result);
                            return addr.ToString();
                        }
                        catch (...) {
                            break;
                        }
                    default:
                        break;
                    }
                }
                freeaddrinfo(result);
            }
            throw std::runtime_error("Cannot resolve address: " + address);
        }
        std::string ToString() const {
            char buffer[ICMPLIB_INET4_ADDRESSSTRLEN];
            if (inet_ntop(AF_INET, &sin_addr, buffer, ICMPLIB_INET4_ADDRESSSTRLEN) != NULL) {
                return std::string(buffer);
            }
            throw std::runtime_error("Cannot convert IPv4 address structure");
        }
        static inline bool IsCorrect(const std::string &address) {
            return std::regex_match(address, std::regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"));
        }
    };

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
            Result result = { Result::ResponseType::Timeout, static_cast<double>(timeout), std::string(), 0, 0 };
            try {
#ifdef _WIN32
                WinSock::Initialize();
#endif
                AddressIPv4 address(target);
                Socket sock(ttl);

                Request request;
                request.Send(sock.GetSocket(), address);
                auto start = std::chrono::high_resolution_clock::now();

                while (true) {
                    Response response;
                    bool recv = response.Recv(sock.GetSocket(), address);
                    auto end = std::chrono::high_resolution_clock::now();
                    if (!recv) {
                        if (static_cast<unsigned>(std::chrono::duration_cast<std::chrono::seconds>(end - start).count()) > timeout) {
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::microseconds(ICMPLIB_NOP_DELAY));
                        continue;
                    }

                    result.response = GetResponseType(request, response);
                    if (result.response != Result::ResponseType::Timeout) {
                        result.interval = static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) / 1000.0;
                        result.ipv4 = address.ToString();
                        result.code = response.GetICMPHeader().code;
                        result.ttl = response.GetTTL();
                        break;
                    }
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
                if (sock <= 0) {
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

        class Request : public ICMPEchoMessage {
        public:
            Request() {
                std::memset(this, 0, sizeof(ICMPEchoMessage));
                id = rand() % USHRT_MAX;
                type = ICMPLIB_ICMP_ECHO_REQUEST;
                SetChecksum<ICMPEchoMessage>(this);
            };
            void Send(ICMPLIB_SOCKET sock, sockaddr_in &address) {
                int bytes = sendto(sock, reinterpret_cast<char *>(this), sizeof(ICMPEchoMessage), 0, reinterpret_cast<sockaddr *>(&address), static_cast<socklen_t>(sizeof(sockaddr)));
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
            bool Recv(ICMPLIB_SOCKET sock, sockaddr_in &address) {
                socklen_t length = sizeof(sockaddr_in);
                std::memset(&address, 0, sizeof(sockaddr_in));
                int bytes = recvfrom(sock, reinterpret_cast<char *>(buffer), ICMPLIB_RECV_BUFFER_SIZE, 0, reinterpret_cast<sockaddr *>(&address), &length);
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
                std::memcpy(&packet, &buffer[ICMPLIB_INET4_HEADER_SIZE], static_cast<long unsigned>(length) - ICMPLIB_INET4_HEADER_SIZE > sizeof(T) ? sizeof(T) : static_cast<long unsigned>(length) - ICMPLIB_INET4_HEADER_SIZE);
                return packet;
            };
            const ICMPHeader &GetICMPHeader() {
                if (header == nullptr) {
                    header = new ICMPHeader;
                    *header = Generate<ICMPHeader>();
                }
                return *header;
            }
            inline const uint8_t GetTTL() {
                return buffer[ICMPLIB_INET4_TTL_OFFSET];
            };
            inline const unsigned GetSize() {
                return length - ICMPLIB_INET4_HEADER_SIZE;
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
            switch (response.GetICMPHeader().type) {
            case ICMPLIB_ICMP_ECHO_RESPONSE:
                result = Result::ResponseType::Success;
                echo = response.Generate<ICMPEchoMessage>();
                echo.checksum = 0;
                if ((response.GetICMPHeader().checksum != SetChecksum<ICMPEchoMessage>(&echo)) || (request.id != echo.id)) {
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
                if (response.GetICMPHeader().checksum != SetChecksum<ICMPRevertedMessage>(&reverted)) {
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
