###### Simple and easy socks5 proxy server, which supports TCP and UDP commands; <br>

###### Callbacks use example:

```cpp
// announce callback:
callback<bool> udp_callback;

// install detour function:
udp_callback.install([](client* person, unsigned short& source_ip, unsigned short& dest_ip, unsigned short& source_port, unsigned short& dest_port, proxys::data* buf) -> bool {
    printf("[%s -> %s | %d -> %d] length: %d\n\n", utils::dip_to_strip(source_ip).c_str(), utils::dip_to_strip(dest_ip).c_str(), source_port, dest_port, buf->length);
    return false;
});

// enable callback treatment:
server.callback_enable(proxys::callback_udp, &udp_callback);
```

###### To-Do List:

 — crossplatform; <br>
 — bind command support; <br>
 — support ipv6; <br>
