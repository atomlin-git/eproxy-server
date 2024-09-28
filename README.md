###### simple cross-platform socks5 proxy server, which supports TCP and UDP commands, and can work how library <br>

###### callbacks use example:

```cpp
// announce callbacks:
callback<udp_callback_t> udp_callback;

// install detour functions:
udp_callback.install([&](client* person, unsigned int& source_ip, unsigned int& dest_ip, unsigned short& source_port, unsigned short& dest_port, proxys::data* buf) -> bool {
    printf("[%s -> %s | %d -> %d] length: %d\n\n", utils::dip_to_strip(source_ip).c_str(), utils::dip_to_strip(dest_ip).c_str(), source_port, dest_port, buf->length);
    return true;
});

// enable callbacks treatment:
server.callback_enable(proxys::callback_udp, &udp_callback);
```
###### due to the peculiarities of the TCP/IP protocol, the dest IP and port cannot be changed on the go, because of this, the TCP callback has a different structure: ```(client* person, std::string source_ip, std::string dest_ip, proxys::data* buf)```

<hr>

###### known issues:
> *small memory leak when the connection to the proxied object does not break* <br>

<hr>

###### todo list:
> *bind command support* <br>
> *support ipv6* <br>
> *backward compatibility with socsk4* <br>
