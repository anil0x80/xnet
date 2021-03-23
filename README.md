# xnet
Simple and lightweight asynchronous TCP communication library, with AES&RSA encryption support from Crypto++ library.

Xnet is coded specifically for Winsock, so it does not have any platform support other than Windows.

Xnet is meant to be simple-to-use. You can check the examples for client & server.

# How does it work?
Xnet internally decrypts incoming packets and encrypts outgoing packets automatically for you. 

All you have to do is register packet handlers for specific packet-ids that you define.

Xnet expects you to provide "packet handler" functions and will call the specific handler corresponding to packet id if a packet is received.

Both client & server libraries support multi-threading for the most performance.

# Encryption
For each session, a random 128-bit AES key&iv is generated. This key is encrypted using the server's public RSA key.

The server decrypts the key using its private RSA key, if successful, communication is established.

If you want to use this, make sure to generate a fresh RSA key pair. 

# Packets
Each packet consists of a packet header and actual data. The header holds the size of data and the packet id.

Since the incoming data length might vary, the packet header and contents are separately encrypted. Receiving end first decrypts packet header(fixed size), and then packet contents are decrypted(size might vary).

For protection, the server will drop the connection if an unknown packet id is received. Also, there is support for specifying maximum packet sizes per packet id, so the server will stop decrypting&reading packet contents if its size exceeds maximum packet size. This will prevent DOS attacks.

packet_manager class is responsible for receiving & sending packets.

# TODO
UDP support.

# EXAMPLE SERVER
```cpp
#include "../xnet_example/shared.h"
#include <iostream>
#include <thread>

#include "../../xnet/xnet/server/xnet_server.h"

std::unique_ptr<xnet::server> tcp_server;

void on_new_chat_message(uintptr_t client, uint8_t* p_data, uint32_t size)
{
	std::cout << "[" << std::to_string(client) << "]: " << (const char*)p_data << std::endl;
}

void on_new_client(uintptr_t client, uint32_t ip, std::string dns)
{
	std::cout << "New client: " << std::to_string(client) << std::endl;
	tcp_server->send_to_client(client,"Hello!", 7, packet_chat_message);
}

void on_dropped(uintptr_t client)
{
	std::cout << "Dropped client: " << std::to_string(client) << std::endl;
}

int main()
{
	tcp_server = xnet::server::initialize("127.0.0.1", 3333, xnet::protocol::tcp);
	tcp_server->register_client_drop_handler(&on_dropped);
	tcp_server->register_new_client_handler(&on_new_client);
	tcp_server->register_packet_handler(&on_new_chat_message, packet_chat_message);

	if(tcp_server->start())
	{
		while(tcp_server->is_running())
			std::this_thread::sleep_for(std::chrono::seconds(1));
	}
	else
	{
		std::cout << "Failed connection, last error: " << (uint32_t)tcp_server->get_last_error() << " : " << tcp_server->get_last_os_error() << std::endl;
	}
	
	return 0;
}
```

# EXAMPLE CLIENT
```cpp
#include "shared.h"
#include <iostream>
#include <thread>

#include "../../xnet/xnet/client/xnet_client.h"

std::unique_ptr<xnet::client> tcp_client;

void on_chat_message_received(uint8_t* data, uint32_t size)
{
	std::cout << "[SERVER]: " << (const char*)data << std::endl;
	tcp_client->send_packet("Hello to server!", 17, packet_chat_message);
}

int main()
{
	tcp_client = xnet::client::initialize("127.0.0.1", 3333, xnet::protocol::tcp);
	tcp_client->register_packet_handler(&on_chat_message_received, packet_chat_message);
	if (tcp_client->connect())
	{
		while (tcp_client->is_connected())
			std::this_thread::sleep_for(std::chrono::seconds(1));
	}
	else
	{
		std::cout << "Failed connection, last error: " << (uint32_t)tcp_client->get_last_error() << " : "<<  tcp_client->get_last_os_error() << std::endl;
	}

	return 0;
}
```

# EXAMPLE PACKET ID'S
```cpp
#pragma once
#include <cstdint>

enum packet_id : uint32_t
{
	packet_chat_message,
};
```


