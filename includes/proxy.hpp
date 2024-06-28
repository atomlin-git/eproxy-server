#pragma once

#include <ws2tcpip.h>
#include <winsock.h>
#pragma comment (lib, "ws2_32.lib")

#include <thread>
#include <string>
#include <vector>

namespace proxys
{
    enum pstates
    {
        state_inited = 0,
        state_authorization_passed = 1,
        state_authorization_rfc1929 = 2,
        state_tcp_proxyfy = 3,
    };

    struct data
    {
        unsigned int length;
        unsigned char* data;
        struct sockaddr_in addr;
    };
};

class client
{
    public:
        client(sockaddr_in addr, int sock) {
            tcp_data.first = addr;
            tcp_data.second = sock;

            client_state = proxys::state_inited;

            personal_proxy_data.first = -1;
            personal_proxy_data.second = 0;
        };
        ~client() {
            if (tcp_data.second != -1) closesocket(tcp_data.second);
            if (personal_proxy_data.first != -1) closesocket(personal_proxy_data.first);
        };

        std::shared_ptr <proxys::data> read()
        {
            if (tcp_data.second == -1) return 0;
            unsigned char buffer[524288] = { 0 };

            int length = recv(tcp_data.second, (char*)buffer, 524288, 0);
            if (!length || length == -1) return 0;

            std::shared_ptr <proxys::data> buf = std::make_shared<proxys::data>();
            buf->data = new unsigned char[length];
            memcpy(buf->data, buffer, length);
            buf->length = length;

            return buf;
        };

        std::shared_ptr <proxys::data> read_personal()
        {
            if (personal_proxy_data.first == -1) return 0;

            unsigned char buffer[524288] = { 0 };
            struct sockaddr_in client = { 0 };
            int clientlength = sizeof(client);

            int length = recvfrom(personal_proxy_data.first, (char*)buffer, 524288, 0, (sockaddr*)&client, &clientlength);
            if (!length || length == -1) return 0;

            std::shared_ptr <proxys::data> buf = std::make_shared<proxys::data>();
            buf->data = new unsigned char[length];
            memcpy(buf->data, buffer, length);
            buf->length = length;
            buf->addr = client;

            return buf;
        };

        bool send_data(unsigned char* data, unsigned int length)
        {
            if (!data) return false;
            if (send(tcp_data.second, (char*)data, length, 0) == -1) return false;
            return true;
        };

        bool send_personal(unsigned char* data, unsigned int length, unsigned int address, unsigned short port)
        {
            if (!data || personal_proxy_data.first == -1) return false;
            struct sockaddr_in send = { 0 };
            send.sin_family = AF_INET;
            send.sin_port = htons(port);
            send.sin_addr.S_un.S_addr = address;
            return sendto(personal_proxy_data.first, (char*)data, length, 0, (sockaddr*)&send, sizeof(sockaddr_in));
        };

        bool init_personal(unsigned short port, unsigned char proto)
        {
            if (personal_proxy_data.first != -1) return false;
            personal_proxy_data.first = socket(AF_INET, (proto == IPPROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM, proto);
            if (personal_proxy_data.first == -1) return false;

            struct sockaddr_in addr = { 0 };
            addr.sin_family = AF_INET;
            addr.sin_addr.S_un.S_addr = (proto == IPPROTO_UDP) ? INADDR_ANY : dst_data.first;
            addr.sin_port = htons((proto == IPPROTO_UDP) ? port : htons(dst_data.second));
            
            if (proto == 0)
            {
                unsigned long timeout = 1000;
                if (setsockopt(personal_proxy_data.first, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) == -1) return false;
                if (connect(personal_proxy_data.first, (sockaddr*)&addr, sizeof(sockaddr)) == -1) return false;
            } else bind(personal_proxy_data.first, (sockaddr*)&addr, sizeof(addr));

            personal_proxy_data.second = (proto == IPPROTO_UDP) ? port : htons(dst_data.second);
            return true;
        };

        void set_dst_port(unsigned short port) { dst_data.second = port; };
        void set_dst_addr(unsigned int addr) { dst_data.first = addr; };

        void set_forwarder(int f) { forwarder = f; };
        void update_state(proxys::pstates st) { client_state = st; };

        unsigned short get_forwarder() { return forwarder; };
        proxys::pstates get_state() { return client_state; };

        std::pair <unsigned int, unsigned short> get_dst_data() { return dst_data; };
        std::pair <int, unsigned short> get_proxy_data() { return personal_proxy_data; };
        std::pair <sockaddr_in, int> get_tcp_data() { return tcp_data; };
    private:
        unsigned short forwarder;
        proxys::pstates client_state;

        std::pair <unsigned int, unsigned short> dst_data; // addr, port
        std::pair <int, unsigned short> personal_proxy_data; // socket, socket port
        std::pair <sockaddr_in, int> tcp_data; // tcp socket addr, tcp socket
};

class proxy
{
    public:
        proxy(unsigned short port) {
            if(!port) return;

            WSADATA wsaData = { 0 };
            WSAStartup(MAKEWORD(2, 2), &wsaData);

            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (!sock) return;

            struct sockaddr_in sockaddr = { 0 };
            sockaddr.sin_family = AF_INET;
            sockaddr.sin_addr.s_addr = INADDR_ANY;
            sockaddr.sin_port = htons(port);

            if (bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1) return;
            if (listen(sock, SOMAXCONN) == -1) return;

            local_ipv4 = -1;
            std::thread([this] {accepts(); }).detach();
        };

        bool set_auth_data(std::string login, std::string password)
        {
            if(login.empty() || password.empty()) return false;
            auth_data.first = login;
            auth_data.second = password;
            return true;
        };

        ~proxy() { closesocket(sock); WSACleanup(); clients.clear(); };
    private:
        void accepts()
        {
            int addrlen = sizeof(sockaddr);
            while (sock != -1)
            {
                sockaddr_in client_addr = { 0 };

                int clientsock = accept(sock, (struct sockaddr*)&client_addr, &addrlen);
                if (clientsock == -1) continue;

                if (local_ipv4 <= 0)
                {
                    struct sockaddr_in saddr = { 0 };
                    int s = sizeof(saddr);
                    getsockname(clientsock, reinterpret_cast<struct sockaddr*>(&saddr), &s);
                    local_ipv4 = saddr.sin_addr.s_addr;
                }

                std::shared_ptr<client> person = std::make_shared<client>( client_addr, clientsock );
                clients.emplace_back(person);
                std::thread([this, person] {network_tcp(person); }).detach();
            }
        };

        bool network_tcp(std::shared_ptr<client> person)
        {
            if(!person) return false;
            std::shared_ptr<proxys::data> buf = 0;
            while (buf = person->read())
                std::thread([this, person, &buf] {proxyfy(person, buf); }).detach();

            return person_destroy(person);
        };

        bool personal_network(std::shared_ptr<client> person)
        {
            if (!person) return false;
            unsigned char packet[10] = { 0x00, 0x00, 0x00, 0x01 };
            unsigned char packet_buffer[65536] = { 0 };
            unsigned int person_binary_address = person->get_tcp_data().first.sin_addr.S_un.S_addr;

            proxys::pstates state = person->get_state();
            std::shared_ptr<proxys::data> buf = 0;

            while (buf = person->read_personal())
            {
                if (state == proxys::state_tcp_proxyfy)
                {
                    person->send_data(buf->data, buf->length);
                    continue;
                }

                if (buf->addr.sin_addr.S_un.S_addr == person_binary_address) // request from client to server (udp)
                {
                    if (buf->length <= 10) continue;
                    person->set_forwarder(htons(buf->addr.sin_port));
                    person->send_personal(buf->data + 10, buf->length - 10, *(unsigned int*)&buf->data[4], htons(*(unsigned short*)&buf->data[8]));
                    continue;
                }
                
                //request server to client (udp)

                *(unsigned int*)&packet[4] = buf->addr.sin_addr.S_un.S_addr;
                *(unsigned short*)&packet[8] = buf->addr.sin_port;

                memcpy(packet_buffer, packet, 10);
                memcpy(&packet_buffer[10], buf->data, buf->length);
                person->send_personal(packet_buffer, buf->length + 10, person_binary_address, person->get_forwarder());
            };

            return person_destroy(person);
        };

        bool proxyfy(std::shared_ptr<client> person, std::shared_ptr<proxys::data> buf)
        {
            if (!person || !buf) return false;
            proxys::pstates state = person->get_state();

            switch (state)
            {
                case proxys::state_inited:
                {
                    if (buf->length < 3) return person_destroy(person);
                    if (buf->data[0] != 0x05) return person_destroy(person);
                    unsigned char packet[2] = { 0x05, 0xFF };

                    for (unsigned char i = 2; i < (buf->data[1] + 2); i++)
                    {
                        switch(buf->data[i])
                        {
                            case 0x02:
                            {
                                if (!auth_data.first.empty() && !auth_data.second.empty())
                                {
                                    packet[1] = 0x02;
                                    person->update_state(proxys::state_authorization_rfc1929);
                                    person->send_data(packet, 2);
                                    return true;
                                };
                            };
                            case 0x00:
                            {
                                if (auth_data.first.empty() || auth_data.second.empty())
                                {
                                    packet[1] = 0x00;
                                    person->update_state(proxys::state_authorization_passed);
                                    person->send_data(packet, 2);
                                    return true;
                                };
                            };
                        };
                    };

                    person->send_data(packet, 2);
                    break;
                };

                case proxys::state_authorization_rfc1929:
                {
                    if (buf->length != (3 + auth_data.first.size() + auth_data.second.size())) return person_destroy(person);
                    if (buf->data[0] != 0x01) return person_destroy(person);

                    unsigned char packet[2] = { 0x01 };
                    unsigned char recved_username[64] = { 0 };
                    unsigned char recved_password[64] = { 0 };

                    memcpy(recved_username, &buf->data[2], buf->data[1]);
                    memcpy(recved_password, &buf->data[buf->data[1] + 3], buf->data[buf->data[1] + 2]);

                    if (strcmp(auth_data.first.c_str(), (char*)recved_username)) return person_destroy(person);
                    if (strcmp(auth_data.second.c_str(), (char*)recved_password)) return person_destroy(person);

                    packet[1] = 0x00;
                    person->update_state(proxys::state_authorization_passed);
                    person->send_data(packet, 2);
                    break;
                };

                case proxys::state_authorization_passed:
                {
                    if (buf->length < 10) return person_destroy(person);
                    if (buf->data[0] != 0x05) return person_destroy(person);
                    if (buf->data[1] != 0x03 && buf->data[1] != 0x01)
                    {
                        unsigned char error[10] = { 0x05, 0x07 };
                        person->send_data(error, 10);
                        return person_destroy(person);
                    };

                    if (buf->data[3] == 0x03)
                    {
                        char hostname[256] = { 0 };
                        memcpy(&hostname[0], &buf->data[5], buf->data[4]);

                        struct addrinfo hints, *res;
                        memset(&hints, 0, sizeof(hints));
                        hints.ai_family = AF_INET;
                        hints.ai_socktype = SOCK_STREAM;

                        if (getaddrinfo(hostname, NULL, &hints, &res) != 0) return person_destroy(person);

                        struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
                        person->set_dst_addr((unsigned int)ipv4->sin_addr.S_un.S_addr);
                        freeaddrinfo(res);
                    }
                    else person->set_dst_addr(*(unsigned int*)&buf->data[4]);
                    person->set_dst_port(*(unsigned short*)&buf->data[buf->length - 2]);

                    std::srand(std::time(nullptr));
                    bool is_udp = buf->data[1] == 0x03;

                    if (!person->init_personal(std::rand() % 65535, is_udp ? IPPROTO_UDP : 0))
                    {
                        unsigned char error[10] = { 0x05, 0x01 };
                        person->send_data(error, 10);
                        return person_destroy(person);
                    };

                    if (!is_udp) 
                        person->update_state(proxys::state_tcp_proxyfy);

                    unsigned char packet[10] = { 0x05, 0x00, 0x00, 0x01 };
                    *(unsigned int*)&packet[4] = local_ipv4;
                    *(unsigned short*)&packet[8] = htons(person->get_proxy_data().second);
                    person->send_data(packet, 10);

                    std::thread([this, person] {personal_network(person); }).detach();
                    break;
                };

                case proxys::state_tcp_proxyfy:
                {
                    person->send_personal(buf->data, buf->length, person->get_dst_data().first, person->get_dst_data().second);
                    break;
                };

                default: return person_destroy(person);
            }

            return true;
        };

        bool person_destroy(std::shared_ptr<client> person) {
            if(!person) return false; 
            if(!clients.size()) return false;
            clients.erase(std::remove(clients.begin(), clients.end(), person), clients.end());
            return true;
        };

        int sock;
        int local_ipv4;

        std::pair<std::string, std::string> auth_data;
        std::vector<std::shared_ptr<client>> clients;
};