#pragma once

#include <ws2tcpip.h>
#include <winsock.h>
#pragma comment (lib, "ws2_32.lib")

#include <unordered_map>
#include <thread>
#include <string>
#include <vector>

static int sockaddr_size = 16; 

namespace proxys
{
    enum callbacks
    {
        callback_udp = 1,
        callback_tcp = 2,
    };

    enum states
    {
        state_handshake = 0,
        state_connection_request = 1,
        state_authorization_rfc1929 = 2,
        state_tcp_proxyfy = 3,
    };

    struct data
    {
        unsigned int length;
        unsigned char* data;
        struct sockaddr_in addr;
    };

    // proxy structures
    #pragma pack(push, 1)
        struct handshake
        {
            unsigned char protocol_version;
            unsigned char method_count;
            unsigned char auth_methods[];
        };

        struct request
        {
            unsigned char protocol_version;
            unsigned char command;
            unsigned char rsv;
            unsigned char address_type;
            unsigned char data[];
        };
    #pragma pack(pop)
};

class client
{
    public:
        client(sockaddr_in addr, int sock) {
            tcp_data = { addr, sock };
            personal_proxy_data = { -1, 0 };

            udp_forwarder_port = 0;
            client_state = proxys::state_handshake;
        };
        ~client() {
            if (tcp_data.second != -1) closesocket(tcp_data.second);
            if (personal_proxy_data.first != -1) closesocket(personal_proxy_data.first);
        };

        std::shared_ptr <proxys::data> read()
        {
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

        std::shared_ptr <proxys::data> read_personal()
        {
            if (personal_proxy_data.first == -1) return 0;

            unsigned char buffer[4096] = { 0 };
            struct sockaddr_in client = { 0 };
            int length = -1;

            switch(client_state)
            {
                case proxys::state_tcp_proxyfy:
                {
                    length = recv(personal_proxy_data.first, (char*)buffer, 4096, 0);
                    break;
                }

                case proxys::state_connection_request:
                {
                    length = recvfrom(personal_proxy_data.first, (char*)buffer, 4096, 0, (sockaddr*)&client, &sockaddr_size);    
                    break;
                }
            };      
            if (length <= 0) return 0;

            std::shared_ptr <proxys::data> buf = std::make_shared<proxys::data>();
            buf->data = buffer;
            buf->length = length;
            buf->addr = client;

            return buf;
        };

        int send_data(unsigned char* data, unsigned int length)
        {
            if (!data || tcp_data.second == -1) return false;
            return send(tcp_data.second, (char*)data, length, 0);
        };

        int send_personal(unsigned char* data, unsigned int length, unsigned int address, unsigned short port)
        {
            if (!data || personal_proxy_data.first == -1) return false;
            if (client_state == proxys::state_tcp_proxyfy) return send(personal_proxy_data.first, (char*)data, length, 0);

            struct sockaddr_in send = { 0 };
            send.sin_family = AF_INET;
            send.sin_port = htons(port);
            send.sin_addr.S_un.S_addr = address;

            return sendto(personal_proxy_data.first, (char*)data, length, 0, (sockaddr*)&send, sockaddr_size);
        };

        bool init_personal(unsigned char proto)
        {
            if (personal_proxy_data.first != -1) return false;
            personal_proxy_data.first = socket(AF_INET, (proto == IPPROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM, proto);
            if (personal_proxy_data.first == -1) return false;

            struct sockaddr_in addr = { 0 };
            addr.sin_family = AF_INET;
            addr.sin_addr.S_un.S_addr = (proto == IPPROTO_UDP) ? INADDR_ANY : dst_data.first;
            addr.sin_port = htons((proto == IPPROTO_UDP) ? 0 : htons(dst_data.second));
            
            if (proto == 0)
            {
                unsigned long timeout = 10000;
                if (setsockopt(personal_proxy_data.first, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, 4) == -1) return false;
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

        std::pair <unsigned int, unsigned short> get_dst_data() { return dst_data; };
        std::pair <int, unsigned short> get_proxy_data() { return personal_proxy_data; };
        std::pair <sockaddr_in, int> get_tcp_data() { return tcp_data; };
    private:
        unsigned short udp_forwarder_port;
        proxys::states client_state;

        std::pair <unsigned int, unsigned short> dst_data; // addr, port
        std::pair <int, unsigned short> personal_proxy_data; // socket, socket port
        std::pair <sockaddr_in, int> tcp_data; // tcp socket addr, tcp socket
};

class proxy : public utils
{
    public:
        proxy(unsigned short port) 
        {
            WSADATA wsaData = { 0 };
            WSAStartup(MAKEWORD(2, 2), &wsaData);

            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock == -1) return;

            struct sockaddr_in sockaddr = { 0 };
            sockaddr.sin_family = AF_INET;
            sockaddr.sin_addr.S_un.S_addr = INADDR_ANY;
            sockaddr.sin_port = htons(port);

            if (bind(sock, (struct sockaddr*)&sockaddr, sockaddr_size) == -1) return;
            if (listen(sock, SOMAXCONN) == -1) return;

            local_ipv4 = -1;
            std::thread([this]{accept_clients();}).detach();
        };

        ~proxy() {
            closesocket(sock); 
            clients.clear();
            WSACleanup();
        };

        bool set_auth_data(std::string login, std::string password)
        {
            if(login.empty() || password.empty()) return false;
            auth_data = { login, password };
            return true;
        };

        bool callback_enable(proxys::callbacks type, callback<bool>* ptr)
        {
            if(!ptr) return false;
            if(callback_list[type]) return false; // already exists
            callback_list[type] = ptr;
            return true;
        };
        
    private:
        void accept_clients()
        {
            struct sockaddr_in client_addr = { 0 };
            while (sock != -1)
            {
                int clientsock = accept(sock, (struct sockaddr*)&client_addr, &sockaddr_size);
                if (clientsock < 0) return;

                if (local_ipv4 <= 0)
                {
                    struct sockaddr_in local_addr = { 0 };
                    if (getsockname(clientsock, (struct sockaddr*)&local_addr, &sockaddr_size) != -1)
                        local_ipv4 = local_addr.sin_addr.S_un.S_addr;
                }

                std::shared_ptr<client> person = std::make_shared<client>( client_addr, clientsock );
                clients.emplace_back(person);
                std::thread([this, person] {network_tcp(person); }).detach();
            };
        };

        bool network_tcp(std::shared_ptr<client> person)
        {
            if(!person) return false;
            std::shared_ptr<proxys::data> buf = 0;
            while (buf = person->read()) this->proxyfy(person, buf);

            return person_destroy(person);
        };

        bool personal_network(std::shared_ptr<client> person)
        {
            if (!person) return false;
            unsigned char packet_buffer[65536] = { 0x00, 0x00, 0x00, 0x01 };
            unsigned int person_binary_address = person->get_tcp_data().first.sin_addr.S_un.S_addr;

            proxys::states state = person->get_state();
            std::shared_ptr<proxys::data> buf = 0;

            while (buf = person->read_personal())
            {
                if (state == proxys::state_tcp_proxyfy)
                {
                    if (auto callb = callback_list[proxys::callback_tcp])
                    {
                        if(!callb->call(dip_to_strip(person_binary_address), dip_to_strip(person->get_dst_data().first), 0, person->get_dst_data().second, buf->data, buf->length))
                        {
                            return false;
                        }
                    };

                    if(person->send_data(buf->data, buf->length) <= 0) return person_destroy(person);
                    continue;
                }

                if (buf->addr.sin_addr.S_un.S_addr == person_binary_address) // request from client to server (udp)
                {
                    if (buf->length <= 10) continue;
                    if (auto callb = callback_list[proxys::callback_udp])
                    {
                        if(!callb->call(dip_to_strip(buf->addr.sin_addr.S_un.S_addr), dip_to_strip(*(unsigned int*)&buf->data[4]), htons(buf->addr.sin_port), htons(*(unsigned short*)&buf->data[8]), buf->data, buf->length))
                        {
                            return false;
                        }
                    };

                    person->set_udp_forwarder(htons(buf->addr.sin_port));
                    person->send_personal(buf->data + 10, buf->length - 10, *(unsigned int*)&buf->data[4], htons(*(unsigned short*)&buf->data[8]));
                    continue;
                }
                
                if(auto callb = callback_list[proxys::callback_udp])
                {
                    if(!callb->call(dip_to_strip(buf->addr.sin_addr.S_un.S_addr), dip_to_strip(person_binary_address), htons(buf->addr.sin_port), person->get_forwarder(), buf->data, buf->length))
                    {
                        return false;
                    }
                };

                //request server to client (udp)

                *(unsigned int*)&packet_buffer[4] = buf->addr.sin_addr.S_un.S_addr;
                *(unsigned short*)&packet_buffer[8] = buf->addr.sin_port;

                memcpy(&packet_buffer[10], buf->data, buf->length);
                person->send_personal(packet_buffer, buf->length + 10, person_binary_address, person->get_udp_forwarder());
            };

            return person_destroy(person);
        };

        bool proxyfy(std::shared_ptr<client> person, std::shared_ptr<proxys::data> buf)
        {
            if (!person || !buf) return false;
            proxys::states state = person->get_state();

            switch (state)
            {
                case proxys::state_handshake:
                {
                    if (buf->length < 3) return person_destroy(person);
                    proxys::handshake* handshake = (proxys::handshake*)(buf->data);
                    if(handshake->protocol_version != 0x05) return person_destroy(person);

                    unsigned char packet[2] = { 0x05, 0xFF };
                    for (unsigned char i = 0; i < handshake->method_count; i++)
                    {
                        switch(handshake->auth_methods[i])
                        {
                            case 0x00:
                            {
                                if (auth_data.first.empty() || auth_data.second.empty())
                                {
                                    packet[1] = 0x00;
                                    person->update_state(proxys::state_connection_request);
                                    return person->send_data(packet, 2);
                                }

                                break;
                            };
                            case 0x02:
                            {
                                if (!auth_data.first.empty() && !auth_data.second.empty())
                                {
                                    packet[1] = 0x02;
                                    person->update_state(proxys::state_authorization_rfc1929);
                                    return person->send_data(packet, 2);
                                }

                                break;
                            };
                        }
                    };

                    return person->send_data(packet, 2);
                };

                case proxys::state_authorization_rfc1929:
                {
                    if (buf->data[0] != 0x01) return person_destroy(person);
                    if (buf->length != (3 + auth_data.first.size() + auth_data.second.size())) return person_destroy(person);
                    if (buf->data[1] != auth_data.first.size() || buf->data[buf->data[1] + 2] != auth_data.second.size()) return person_destroy(person);

                    unsigned char packet[2] = { 0x01, 0x00 };
                    std::string incoming_username = { (char*)&buf->data[2], buf->data[1] };
                    std::string incoming_password = { (char*)&buf->data[buf->data[1] + 3], buf->data[buf->data[1] + 2] };

                    if((auth_data.first != incoming_username) || (auth_data.second != incoming_password)) return person_destroy(person);

                    person->update_state(proxys::state_connection_request);
                    return person->send_data(packet, 2);
                };

                case proxys::state_connection_request:
                {
                    if (buf->length < 10) return person_destroy(person);

                    proxys::request* request = (proxys::request*)(buf->data);
                    if(request->protocol_version != 0x05) return person_destroy(person);
                    if(request->command != 0x03 && request->command != 0x01) return person_destroy(person);
                    if(request->rsv != 0x00) return person_destroy(person);

                    switch(request->address_type)
                    {
                        case 0x01: // ipv4
                        {
                            person->set_dst_addr(*(unsigned int*)&request->data[0]);
                            break;
                        };

                        case 0x03: // domain name
                        {
                            char hostname[256] = { 0 };
                            memcpy(hostname, &request->data[1], request->data[0]);

                            struct addrinfo hints, *res = 0;
                            memset(&hints, 0, sizeof(hints));
                            hints.ai_family = AF_INET;
                            hints.ai_socktype = SOCK_STREAM;

                            if (getaddrinfo(hostname, NULL, &hints, &res) != 0) return person_destroy(person);

                            struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
                            person->set_dst_addr((unsigned int)ipv4->sin_addr.S_un.S_addr);
                            freeaddrinfo(res);
                            break;
                        };

                        default: return person_destroy(person); // ipv6 and other unk parameters
                    };

                    person->set_dst_port(*(unsigned short*)&buf->data[buf->length - 2]);

                    bool is_udp = request->command == 0x03;
                    if (!person->init_personal(is_udp ? IPPROTO_UDP : 0))
                    {
                        unsigned char error[10] = { 0x05, 0x01 };
                        person->send_data(error, 10);
                        return person_destroy(person);
                    };

                    if (!is_udp) person->update_state(proxys::state_tcp_proxyfy);

                    std::thread([this, person] {personal_network(person); }).detach();

                    unsigned char packet[10] = { 0x05, 0x00, 0x00, 0x01 };
                    *(unsigned int*)&packet[4] = local_ipv4;
                    *(unsigned short*)&packet[8] = htons(person->get_proxy_data().second);
                    
                    return person->send_data(packet, 10);
                };

                case proxys::state_tcp_proxyfy:
                {
                    if(auto callb = callback_list[proxys::callback_tcp])
                    {
                        if(!callb->call(dip_to_strip(person->get_dst_data().first), dip_to_strip(person->get_tcp_data().first.sin_addr.S_un.S_addr), person->get_dst_data().second, 0, buf->data, buf->length))
                        {
                            return false;
                        }
                    };

                    if(person->send_personal(buf->data, buf->length, person->get_dst_data().first, person->get_dst_data().second) <= 0) return person_destroy(person);
                    break;
                };

                default: return person_destroy(person);
            };

            return true;
        };

        bool person_destroy(std::shared_ptr<client> person) {
            if(!person) return false; 
            if(!clients.size()) return false;
            std::erase_if(clients, [](const std::shared_ptr<client>& ptr) { return ptr; });
            person.reset();
            return true;
        };

        int sock;
        int local_ipv4;

        std::pair<std::string, std::string> auth_data;
        std::vector<std::shared_ptr<client>> clients;
        std::unordered_map<proxys::callbacks, callback<bool>*> callback_list;
};