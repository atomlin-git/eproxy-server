#include "headers.hpp"

proxy server = { 1337 };

callback udp_callback;

int main()
{
    udp_callback.install([](std::string source_ip, std::string dest_ip, unsigned short source_port, unsigned short dest_port, unsigned char* data, unsigned int length) -> bool {
        printf("[%s -> %s | %d -> %d] length: %d\n\n", source_ip.c_str(), dest_ip.c_str(), source_port, dest_port, length);
        return false;
    });
    server.callback_enable(proxys::callback_udp, &udp_callback);
    
    server.set_auth_data("admin", "neadmin");
    while(1) Sleep(25);
}