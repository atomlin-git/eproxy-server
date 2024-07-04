#pragma once

#include <sstream>
#include <string>
#include <format>

class utils
{
    public:
        utils() { };
        ~utils() { };

        std::string dip_to_strip(unsigned int decimal_ip) { 
            return std::format("{}.{}.{}.{}", (unsigned char)(decimal_ip & 0x000000ff), (unsigned char)((decimal_ip & 0x0000ff00) >> 8), (unsigned char)((decimal_ip & 0x00ff0000) >> 16), (unsigned char)((decimal_ip & 0xff000000) >> 24));
        };

        unsigned int strip_to_dip(std::string string_ip) {
            std::istringstream stream_ip ( string_ip );
            unsigned int parts[4] = { 0 };
            
            for (int i = 0; i < 4; i++) 
            {
                stream_ip >> parts[i];
                if (stream_ip.fail()) return 0;
            }

            return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
        };


};