###### Simple and easy oneheader socks5 proxy server, which supports TCP and UDP commands; <br>

###### Callbacks use example:

```cpp
// announce callback:
callback udp_callback;

// install detour function:
udp_callback.install([](std::string source_ip, std::string dest_ip, unsigned short source_port, unsigned short dest_port, unsigned char* data, unsigned int length) -> bool {
    printf("[%s -> %s | %d -> %d] length: %d\n\n", source_ip.c_str(), dest_ip.c_str(), source_port, dest_port, length);
    return false;
});

// enable callback treatment:
server.callback_enable(proxys::callback_udp, &udp_callback);
```

###### To-Do List:

 — crossplatform; <br>
 — bind command support; <br>
 — big refactory; <br>
 — support ipv6; <br>
 — support domain name on udp packets; <br>
