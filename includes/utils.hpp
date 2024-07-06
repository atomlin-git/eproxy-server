#pragma once

#include <string>
#include <format>
#include <functional>
#include <iostream>
#include <typeinfo>

template<typename return_type>
class callback
{
    void* dest;

    public:
        template <class T>
            bool install(T idest) {
                dest = idest;
                return true;
            }; 

        template<typename... arguments>
            auto call(arguments&&... args) {
                using type = return_type(*)(arguments...);
                return reinterpret_cast<type>(dest)(args...); 
            };
};

class utils
{
    public:
        utils() { };
        ~utils() { };

        std::string dip_to_strip(unsigned int decimal_ip) { 
            return std::format("{}.{}.{}.{}", (unsigned char)(decimal_ip & 0x000000ff), (unsigned char)((decimal_ip & 0x0000ff00) >> 8), (unsigned char)((decimal_ip & 0x00ff0000) >> 16), (unsigned char)((decimal_ip & 0xff000000) >> 24));
        };
};