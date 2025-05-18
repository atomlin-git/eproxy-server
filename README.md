###### simple cross-platform socks5 proxy server, which supports TCP and UDP commands, and can work how library <br>

###### callbacks use example:

```cpp
// announce callbacks:
ep::callback<udp_callback_t> udp_callback;

// install detour functions:
udp_callback.install([&](ep::client* person, unsigned int& source_ip, unsigned int& dest_ip, unsigned short& source_port, unsigned short& dest_port, ep::buffer* buf) -> bool {
    printf("[%s -> %s | %d -> %d] length: %d\n\n", ep::utils::dip_to_strip(source_ip).c_str(), ep::utils::dip_to_strip(dest_ip).c_str(), source_port, dest_port, buf->length);
    return true;
});

// enable callbacks treatment:
proxy.callback_enable(ep::callback_t::udp, &udp_callback);
```
###### due to the peculiarities of the TCP/IP protocol, the dest IP and port cannot be changed on the go, because of this, the TCP callback has a different structure: ```(client* person, std::string source_ip, std::string dest_ip, proxys::data* buf)```
###### one-header solution available in "one-header" branch

<hr>

###### known issues:
> *small memory leak when the connection to the proxied object does not break* <br>

<hr>

###### todo list:
> *bind command support* <br>
> *support ipv6* <br>
> *backward compatibility with socsk4* <br>
> *add more comments (or write small doc) to internal functional* <br>
