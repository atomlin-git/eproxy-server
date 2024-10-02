#pragma once

#ifdef _WIN32
    #include <ws2tcpip.h>
    #include <winsock.h>
    #pragma comment (lib, "ws2_32.lib")
#elif __linux__
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <cstring>
    #include <netdb.h>

    #define closesocket(s) close(s)
#endif

#include <thread>
#include <string>
#include <unordered_map>

#include "utilities.hpp"

namespace proxys {
    enum callbacks {
        callback_udp = 1,
        callback_tcp = 2,
    };

    enum states {
        state_handshake = 0,
        state_connection_request = 1,
        state_authorization_rfc1929 = 2,
        state_tcp_proxyfy = 10,
        state_udp_proxyfy = 11,
    };

    struct data {
        unsigned int length = 0;
        unsigned char* data;
        struct sockaddr_in addr = { };
    };

    // proxy structures
    #pragma pack(push, 1)
        struct handshake {
            unsigned char protocol_version;
            unsigned char method_count;
            unsigned char auth_methods[];
        };

        struct request {
            unsigned char protocol_version;
            unsigned char command;
            unsigned char rsv;
            unsigned char address_type;
            unsigned char data[];
        };
    #pragma pack(pop)
};

class client {
    public:
        client(sockaddr_in addr, int socket_) : tcp_data(addr, socket_) {};
        ~client() {
            if (tcp_data.second != -1) closesocket(tcp_data.second);
            if (personal_proxy_data.first != -1) closesocket(personal_proxy_data.first);
        };

        std::shared_ptr <proxys::data> read() {
            if (tcp_data.second == -1) return 0;
            unsigned char buffer[4096] = { 0 };

            int length = recv(tcp_data.second, (char*)buffer, 4096, 0);
            if (length <= 0) return 0;

            std::shared_ptr <proxys::data> buf = std::make_shared<proxys::data>();
            buf->data = buffer;
            buf->length = length;
            buf->addr = {};

            return buf;
        };

        std::shared_ptr <proxys::data> read_personal() {
            if (personal_proxy_data.first == -1) return 0;

            unsigned char buffer[4096] = { 0 };
            struct sockaddr_in client  = { 0 };
            int length = -1;

            switch(client_state) {
                case proxys::state_tcp_proxyfy: length = recv(personal_proxy_data.first, (char*)buffer, 4096, 0); break;
                case proxys::state_udp_proxyfy: length = recvfrom(personal_proxy_data.first, (char*)buffer, 4096, 0, (sockaddr*)&client, &sockaddr_size); break;
            };      
            if (length <= 0) return 0;

            std::shared_ptr <proxys::data> buf = std::make_shared<proxys::data>();
            buf->data = buffer;
            buf->length = length;
            buf->addr = client;

            return buf;
        };

        int send_data(unsigned char* data, unsigned int length) {
            if (!data || tcp_data.second == -1) return false;
            return send(tcp_data.second, (char*)data, length, 0);
        };

        int send_personal(unsigned char* data, unsigned int length, unsigned int address, unsigned short port) {
            if (!data || personal_proxy_data.first == -1) return false;
            if (client_state == proxys::state_tcp_proxyfy) return send(personal_proxy_data.first, (char*)data, length, 0);

            struct sockaddr_in send = { 0 };
            send.sin_family = AF_INET;
            send.sin_port = htons(port);
            send.sin_addr.s_addr = address;

            return sendto(personal_proxy_data.first, (char*)data, length, 0, (sockaddr*)&send, sockaddr_size);
        };

        bool init_personal(unsigned char proto) {
            if((personal_proxy_data.first = socket(AF_INET, (proto == IPPROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM, proto)) == -1) return false;

            struct sockaddr_in addr = { 0 };
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = (proto == IPPROTO_UDP) ? INADDR_ANY : dst_data.first;
            addr.sin_port = htons((proto == IPPROTO_UDP) ? 0 : htons(dst_data.second));
            
            if (proto == 0) {
                if (connect(personal_proxy_data.first, (sockaddr*)&addr, sockaddr_size) == -1) return false;
                personal_proxy_data.second = htons(dst_data.second);
            } else {
                if (bind(personal_proxy_data.first, (sockaddr*)&addr, sockaddr_size) == -1) return false;
                if (getsockname(personal_proxy_data.first, (struct sockaddr*)&addr, &sockaddr_size) == -1) return false;
                personal_proxy_data.second = htons(addr.sin_port);
            };

            return true;
        };

        void set_dst_port(unsigned short port) { dst_data.second = port; };
        void set_dst_addr(unsigned int addr) { dst_data.first = addr; };

        void set_udp_forwarder(int udp_forwarder_port_) { udp_forwarder_port = udp_forwarder_port_; };
        void update_state(proxys::states state) { client_state = state; };

        unsigned short get_udp_forwarder() { return udp_forwarder_port; };
        proxys::states get_state() { return client_state; };

        auto get_proxy_data() { return personal_proxy_data; };
        auto get_dst_data() { return dst_data; };
        auto get_tcp_data() { return tcp_data; };
    private:
        unsigned short udp_forwarder_port = 0;
        proxys::states client_state = proxys::state_handshake;

        std::pair <unsigned int, unsigned short> dst_data = { 0, 0 }; // addr, port
        std::pair <int, unsigned short> personal_proxy_data = { -1, 0 }; // socket, socket port
        std::pair <sockaddr_in, int> tcp_data; // tcp socket addr, tcp socket
};

#define udp_callback_t bool, client*, unsigned int&, unsigned int&, unsigned short&, unsigned short&, proxys::data*
#define tcp_callback_t bool, client*, std::string, std::string, proxys::data*

class proxy : virtual utils
{
    public:
        proxy(unsigned short port)  {
            #ifdef _WIN32
                WSADATA wsaData = { 0 };
                WSAStartup(MAKEWORD(2, 2), &wsaData);
            #endif

            if ((socket_ = socket(AF_INET, SOCK_STREAM, 0)) == -1) return;

            struct sockaddr_in sockaddr = { 0 };
            sockaddr.sin_family = AF_INET;
            sockaddr.sin_addr.s_addr = INADDR_ANY;
            sockaddr.sin_port = htons(port);

            if (bind(socket_, (struct sockaddr*)&sockaddr, sockaddr_size) == -1) return;
            if (listen(socket_, SOMAXCONN) == -1) return;

            std::thread([&]{accept_clients();}).detach();
        };

        ~proxy() {
            closesocket(socket_);
            #ifdef _WIN32
                WSACleanup();
            #endif
        };

        bool set_auth_data(std::string login, std::string password) {
            if(login.empty() || password.empty()) return false;
            auth_data = { login, password };
            return true;
        };

        bool callback_enable(proxys::callbacks type, std::any ptr) {
            if(callback_list[type].has_value()) return false;
            callback_list[type] = ptr;
            return true;
        };
    private:
        void accept_clients() {
            struct sockaddr_in client_addr = { 0 };
            while (socket_ != -1) {
                int clientsocket = accept(socket_, (struct sockaddr*)&client_addr, &sockaddr_size);
                if (clientsocket < 0) return;

                if (!local_ipv4) {
                    struct sockaddr_in local_addr = { 0 };
                    if (getsockname(clientsocket, (struct sockaddr*)&local_addr, &sockaddr_size) != -1) local_ipv4 = local_addr.sin_addr.s_addr;
                };

                std::shared_ptr<client> person = std::make_shared<client>(client_addr, clientsocket);
                std::thread([this, person] {network_tcp(person);}).detach();
                clients.insert({ &*person, 1 });
            };
        };

        bool network_tcp(const std::shared_ptr<client>& person) { // the main TCP stream in which we accept packets for connection
            if(!person) return false;
            std::shared_ptr<proxys::data> buf = 0;
            while (buf = person->read()) { 
                if(!this->proxyfy(person, buf)) break;
            };

            return person_destroy(person);
        };

        bool personal_network(const std::shared_ptr<client>& person) { // the TCP or UDP stream in which we receive packets for forwarding
            if (!person) return false;

            unsigned char packet_buffer[65536] = { 0x00, 0x00, 0x00, 0x01 };
            unsigned int person_binary_address = person->get_tcp_data().first.sin_addr.s_addr;

            proxys::states state = person->get_state();
            std::shared_ptr<proxys::data> buf = 0;

            while (buf = person->read_personal()) {
                if (state == proxys::state_tcp_proxyfy) { // request from client to server
                    if(callback_list[proxys::callback_tcp].has_value()) {
                        try {
                            if(const auto& callback_ptr = std::any_cast<callback<tcp_callback_t>*>(callback_list[proxys::callback_tcp])) {
                                if(!callback_ptr->call(&*person, this->dip_to_strip(person_binary_address), this->dip_to_strip(person->get_dst_data().first), &*buf)) continue;
                            };
                        } catch (...) {};
                    };
                    
                    if(person->send_data(buf->data, buf->length) <= 0) return person_destroy(person);
                    continue;
                };

                unsigned int src_addr = buf->addr.sin_addr.s_addr;
                unsigned short src_port = htons(buf->addr.sin_port);

                unsigned int dst_addr = *(unsigned int*)&buf->data[4];
                unsigned short dst_port = htons(*(unsigned short*)&buf->data[8]);

                if(buf->addr.sin_addr.s_addr == person_binary_address) { // request from client to server (udp)
                    if(buf->length <= 10) continue;
                    if(callback_list[proxys::callback_udp].has_value()) {
                        try {
                            if(const auto& callback_ptr = std::any_cast<callback<udp_callback_t>*>(callback_list[proxys::callback_udp])) {
                                if(!callback_ptr->call(&*person, src_addr, dst_addr, src_port, dst_port, &*buf)) continue;
                            };
                        } catch (...) {};
                    };

                    person->set_udp_forwarder(htons(buf->addr.sin_port));
                    person->send_personal(buf->data + 10, buf->length - 10, dst_addr, dst_port);
                    continue;
                };
                
                //request server to client (udp)

                unsigned short forwarder = person->get_udp_forwarder();
                if(callback_list[proxys::callback_udp].has_value()) {
                    try {
                        if(const auto& callback_ptr = std::any_cast<callback<udp_callback_t>*>(callback_list[proxys::callback_udp])) {
                            if(!callback_ptr->call(&*person, src_addr, person_binary_address, src_port, forwarder, &*buf)) continue;
                        };
                    } catch (...) {};
                };

                *(unsigned int*)&packet_buffer[4] = src_addr;
                *(unsigned short*)&packet_buffer[8] = htons(src_port);

                memcpy(&packet_buffer[10], buf->data, buf->length);
                person->send_personal(packet_buffer, buf->length + 10, person_binary_address, forwarder);
            };

            return person_destroy(person);
        };

        bool proxyfy(const std::shared_ptr<client>& person, std::shared_ptr<proxys::data> buf) {
            if (!person || !buf) return false;
            switch (person->get_state()) {
                case proxys::state_handshake: {
                    if (buf->length < 3) return false;
                    proxys::handshake* handshake = (proxys::handshake*)(buf->data);
                    if(handshake->protocol_version != 0x05) return false;

                    unsigned char packet[2] = { 0x05, 0xFF };
                    for (unsigned char i = 0; i < handshake->method_count; i++) {
                        switch(handshake->auth_methods[i]) {
                            case 0x00: {
                                if (auth_data.first.empty() || auth_data.second.empty()) {
                                    packet[1] = 0x00;
                                    person->update_state(proxys::state_connection_request);
                                    return person->send_data(packet, 2);
                                };

                                break;
                            };
                            case 0x02: {
                                if (!auth_data.first.empty() && !auth_data.second.empty()) {
                                    packet[1] = 0x02;
                                    person->update_state(proxys::state_authorization_rfc1929);
                                    return person->send_data(packet, 2);
                                };

                                break;
                            };
                        };
                    };

                    return person->send_data(packet, 2);
                };

                case proxys::state_authorization_rfc1929: {
                    if (buf->data[0] != 0x01) return false;
                    if (buf->length != (3 + auth_data.first.size() + auth_data.second.size())) return false;
                    if (buf->data[1] != auth_data.first.size() || buf->data[buf->data[1] + 2] != auth_data.second.size()) return false;

                    unsigned char packet[2] = { 0x01, 0x00 };
                    std::string incoming_username = { (char*)&buf->data[2], buf->data[1] };
                    std::string incoming_password = { (char*)&buf->data[buf->data[1] + 3], buf->data[buf->data[1] + 2] };

                    if((auth_data.first != incoming_username) || (auth_data.second != incoming_password)) return false;

                    person->update_state(proxys::state_connection_request);
                    return person->send_data(packet, 2);
                };

                case proxys::state_connection_request: {
                    if (buf->length < 10) return false;

                    proxys::request* request = (proxys::request*)(buf->data);
                    if(request->protocol_version != 0x05) return false;
                    if(request->command != 0x03 && request->command != 0x01) return false;
                    if(request->rsv != 0x00) return false;

                    switch(request->address_type) {
                        case 0x01: { // ipv4
                            person->set_dst_addr(*(unsigned int*)&request->data[0]);
                            break;
                        };

                        case 0x03: { // domain name
                            if(request->data[0] > buf->length) return false;
                            char hostname[256] = { 0 };
                            memcpy(hostname, &request->data[1], request->data[0]);

                            struct addrinfo hints, *res = 0;
                            memset(&hints, 0, sizeof(hints));
                            hints.ai_family = AF_INET;
                            hints.ai_socktype = SOCK_STREAM;

                            if (getaddrinfo(hostname, NULL, &hints, &res) != 0) return false;
                            
                            struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
                            person->set_dst_addr((unsigned int)ipv4->sin_addr.s_addr);
                            freeaddrinfo(res);
                            break;
                        };

                        default: return false; // ipv6 and other unk parameters
                    };

                    person->set_dst_port(*(unsigned short*)&buf->data[buf->length - 2]);

                    bool is_udp = request->command == 0x03;
                    if (!person->init_personal(is_udp ? IPPROTO_UDP : 0)) {
                        unsigned char error[10] = { 0x05, 0x01 };
                        person->send_data(error, 10);
                        return false;
                    };

                    person->update_state((proxys::states)(is_udp + 10));
                    std::thread([this, person] {personal_network(person); }).detach();

                    unsigned char packet[10] = { 0x05, 0x00, 0x00, 0x01 };
                    *(unsigned int*)&packet[4] = local_ipv4;
                    *(unsigned short*)&packet[8] = htons(person->get_proxy_data().second);
                    
                    return person->send_data(packet, 10);
                };

                case proxys::state_tcp_proxyfy: { // from client to server
                    if(callback_list[proxys::callback_tcp].has_value()) {
                        try {
                            if(const auto& callback_ptr = std::any_cast<callback<tcp_callback_t>*>(callback_list[proxys::callback_tcp])) {
                                if(!callback_ptr->call(&*person, dip_to_strip(person->get_dst_data().first), dip_to_strip(person->get_tcp_data().first.sin_addr.s_addr), &*buf)) return true;
                            };
                        } catch (...) {};
                    };

                    if(person->send_personal(buf->data, buf->length, person->get_dst_data().first, person->get_dst_data().second) <= 0) return person_destroy(person);
                    break;
                };

                default: return false;
            };

            return true;
        };

        bool person_destroy(const std::shared_ptr<client>& person) {
            if(!person) return false;
            clients[&*person] = 0;
            person->~client();
            return true;
        };

        auto get_clients() {
            std::vector<client*> t;

            for(const auto& [ c, s ] : clients) {
                if(!c || s == 0) continue;
                t.emplace_back(c);
            };

            return t;
        };

        long long socket_ = -1;
        unsigned int local_ipv4 = 0;

        std::pair<std::string, std::string> auth_data;
        std::unordered_map<client*, unsigned int> clients;
        std::unordered_map<proxys::callbacks, std::any> callback_list;
};