#include "headers.hpp"

#ifndef EPS_LIBRARY
    proxy proxy_server = { 1337 };
    
    int main() {
        while(1) std::this_thread::sleep_for(std::chrono::milliseconds(45));
    };
#endif
