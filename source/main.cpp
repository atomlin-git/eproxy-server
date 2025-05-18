#include <chrono>
#include "proxy.hpp"

ep::server proxy = { 1337 };

int main() {
    while(1) std::this_thread::sleep_for(std::chrono::milliseconds(45));
};