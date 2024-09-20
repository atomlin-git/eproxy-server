#pragma once

#include <string>
#include <format>
#include <vector>
#include <sstream>

static socklen_t sockaddr_size = 16; 

template<typename return_type>
class callback {
    void* dest;
    public:
        template <class T> void install(T idest) { dest = idest; };
        template<typename... arguments>
            auto call(arguments&&... args) {
                using type = return_type(*)(arguments...);
                return reinterpret_cast<type>(dest)(args...); 
            };
};

class utils {
    public:
        static std::string dip_to_strip(unsigned int decimal_ip) { 
            return std::format("{}.{}.{}.{}", (unsigned char)(decimal_ip & 0x000000ff), (unsigned char)((decimal_ip & 0x0000ff00) >> 8), (unsigned char)((decimal_ip & 0x00ff0000) >> 16), (unsigned char)((decimal_ip & 0xff000000) >> 24));
        };

        static unsigned int strip_to_dip(const std::string string_ip) {
            std::vector<std::string> parts;
            std::stringstream ss(string_ip);
            unsigned int result = 0;
            std::string part;
            
            while (std::getline(ss, part, '.')) parts.push_back(part);
            for (int i = 0; i < 4; i++) result |= std::stoi(parts[i]) << (8 * i);
            
            return result;
        };
};