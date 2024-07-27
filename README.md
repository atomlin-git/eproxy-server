###### Simple and easy socks5 proxy server, which supports TCP and UDP commands; <br>

###### Callbacks use example:

```cpp
// announce callbacks:
callback<bool> udp_callback;
callback<bool> tcp_callback;

// install detour functions:
udp_callback.install([](client* person, unsigned short& source_ip, unsigned short& dest_ip, unsigned short& source_port, unsigned short& dest_port, proxys::data* buf) -> bool {
    printf("[%s -> %s | %d -> %d] length: %d\n\n", utils::dip_to_strip(source_ip).c_str(), utils::dip_to_strip(dest_ip).c_str(), source_port, dest_port, buf->length);
    return true;
});

udp_callback.install([](client* person, std::string source_ip, std::string dest_ip, proxys::data* buf) -> bool {
    printf("[%s -> %s] length: %d\n\n", source_ip.c_str(), dest_ip.c_str(), buf->length);
    return true;
});

// enable callbacks treatment:
server.callback_enable(proxys::callback_udp, &udp_callback);
server.callback_enable(proxys::callback_tcp, &tcp_callback);
```

###### To-Do List:

 — crossplatform; <br>
 — bind command support; <br>
 — support ipv6; <br>
