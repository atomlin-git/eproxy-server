#include "headers.hpp"

proxy proxy_server = { 1337 };

int main() {
    proxy_server.set_auth_data("admin", "neadmin");
    while(1) std::this_thread::sleep_for(std::chrono::milliseconds(45));
};