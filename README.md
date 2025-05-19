###### simple cross-platform socks5 proxy server, which supports TCP and UDP commands, and can work how library <br>

###### callbacks use example:

```cpp
// announce callbacks:
ep::callback<udp_callback_t> udp_callback;
ep::callback<tcp_callback_t> tcp_callback;

// install detour functions:
udp_callback.install([&](ep::client* person, unsigned int& source_ip, unsigned int& dest_ip, unsigned short& source_port, unsigned short& dest_port, ep::buffer* buf) -> bool {
    printf("[%s -> %s | %d -> %d] length: %d\n", ep::utils::dip_to_strip(source_ip).c_str(), ep::utils::dip_to_strip(dest_ip).c_str(), source_port, dest_port, buf->length);
    return true;
});

tcp_callback.install([&](ep::client* person, std::string source_ip, std::string dest_ip, ep::buffer* buf) -> bool {
    printf("[%s -> %s] length: %d\n", source_ip.c_str(), dest_ip.c_str(), buf->length);
    return true;
});

// enable callbacks treatment:
proxy.callback_enable(ep::callback_t::udp, &udp_callback);
proxy.callback_enable(ep::callback_t::tcp, &tcp_callback);
```
<hr>

###### todo list:
> *add more comments (or write small doc) to internal functional* <br>
