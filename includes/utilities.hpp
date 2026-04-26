#pragma once

#include <string>
#include <format>
#include <vector>
#include <sstream>
#include <functional>

#ifdef _WIN32
    #include <ws2tcpip.h>
    #include <winsock.h>
    #pragma comment (lib, "ws2_32.lib")
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <cstring>
    #include <netdb.h>

    #define closesocket(s) close(s)
#endif

static socklen_t sockaddr_size = 16; 

namespace ep {
    template<typename return_type, typename... arguments_type>
    class callback {
        std::function<return_type(arguments_type...)> dest;
        public:
            void install(auto idest) { dest = idest; };
            template<typename... arguments> auto call(arguments&&... args) const { return dest(args...); };
    };

    class utils {
        public:
            static uint32_t hostname_to_ip(std::string host) {
                struct addrinfo hints, *res = 0;
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;

                if (getaddrinfo(host.c_str(), 0, &hints, &res) != 0) return 0;
                
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
                auto ip = static_cast<uint32_t>(ipv4->sin_addr.s_addr);
                freeaddrinfo(res);
                return ip;
            };

            static auto dip_to_strip(unsigned int decimal_ip) { 
                return std::format("{}.{}.{}.{}", (unsigned char)(decimal_ip & 0x000000ff), (unsigned char)((decimal_ip & 0x0000ff00) >> 8), (unsigned char)((decimal_ip & 0x00ff0000) >> 16), (unsigned char)((decimal_ip & 0xff000000) >> 24));
            };

            static auto strip_to_dip(const std::string string_ip) {
                std::vector<std::string> parts;
                std::stringstream ss(string_ip);
                unsigned int result = 0;
                std::string part;
                
                while (std::getline(ss, part, '.')) parts.push_back(part);
                for (int i = 0; i < 4; i++) result |= std::stoi(parts[i]) << (8 * i);
                
                return result;
            };
    };
};