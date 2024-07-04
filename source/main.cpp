#include "headers.hpp"

proxy server = { 1337 };

int main()
{
    server.set_auth_data("admin", "neadmin");
    while(1) Sleep(25);
}