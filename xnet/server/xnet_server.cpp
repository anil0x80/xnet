#include PRECOMPILED_HEADER
#include "xnet_server.h"


#include "../shared/packet_manager.h"
#include "../shared/private_definitions.h"
#include "../shared/utils.h"

/* represents a client connected to server */
class server_client
{
public:
	bool has_aes_key() const;
	void send_packet(const void* p_data, uint32_t size, uint32_t packet_id);

	packet_manager_in pm_in;
	packet_manager_out pm_out;
	packet_manager_out pm_out_unencrypted; // packets added to this manager will be encrypted and sent when session key is received.
	CryptoPP::SecByteBlock aes_key{}; // aes key that is unique per session.
	CryptoPP::SecByteBlock aes_iv{};  // aes iv that is unique per session.
	uint32_t should_drop{};
	uint32_t dealt_with_unencrypted_packets{};
	uint32_t ack_sent{};
};

bool server_client::has_aes_key() const
{
	return !aes_key.empty();
}

void server_client::send_packet(const void* p_data, uint32_t size, uint32_t packet_id)
{
	if (has_aes_key())
	{
		pm_out.append(size, packet_id, (char*)p_data, &aes_key, &aes_iv);
		return;
	}

	/* no aes key, add this packet to unencrypted queue, so we can send it later when we get the aes key */
	pm_out_unencrypted.append(size, packet_id, (char*)p_data, nullptr, nullptr);
}

class server_internal final : public xnet::server
{
public:
	server_internal(std::string ip, unsigned short port, xnet::protocol protocol);
	server_internal(const server_internal&) = delete;
	server_internal& operator=(const server_internal&) = delete;
	server_internal(server_internal&&) = delete;
	server_internal& operator=(server_internal&&) = delete;
	~server_internal() override;
	
	void register_packet_handler(xnet::server_packet_handler function) override;
	void register_client_drop_handler(xnet::server_client_drop_handler function) override;
	void register_new_client_handler(xnet::server_new_client_handler function) override;
	bool send_to_client(uintptr_t client, const void* p_data, uint32_t size, uint32_t packet_id) override;
	bool drop_client(uintptr_t client) override;
	void set_used_packet_ids_and_max_sizes(std::map<uint32_t, uint32_t> packets) override;
	bool start() override;
	bool is_running() override;
	
	void run();
	void process_packets();

	server_client* get_server_client(SOCKET s);
	void set_last_error(xnet::error_code code);
	
private:
	void close_connection(size_t idx);

public:
	xnet::error_code get_last_error() override;
	int get_last_os_error() override;
	
private:
	/* networking*/
	std::string ip_;
	unsigned short port_;
	xnet::protocol protocol_;
	std::vector<WSAPOLLFD> master_fd_;
	std::vector<WSAPOLLFD> use_fd_;
	std::unordered_map<SOCKET, std::unique_ptr<server_client>> client_list_;
	std::map<uint32_t, uint32_t> packet_maximums_; // packet_id -> maximum size
	
	/* callbacks */
	xnet::server_packet_handler packet_handler_{};
	xnet::server_client_drop_handler client_drop_handler_{};
	xnet::server_new_client_handler new_client_handler_{};
	
	/* crypto */
	CryptoPP::RSA::PrivateKey rsa_private_key_;
	
	/* debug */
	std::atomic<xnet::error_code> last_error_{ xnet::error_code::error_success };

	/* multi threading */
	std::thread networking_thread_{};
	std::thread packet_processor_thread_{};
	std::atomic<bool> is_running_{ false };
	bool is_shutdown_{ false };
	std::shared_mutex client_list_mutex_;
	std::mutex packet_maximums_mutex_;
};

void server_internal::run()
{
	while(!is_shutdown_)
	{
		/* since WSAPoll will change revents of each fd, we need to use a copy */
		use_fd_ = master_fd_;

		/* 1 ms delay if there is no events, to not hog the cpu, note that this wont BLOCK */
		if (WSAPoll(use_fd_.data(), (uint32_t)use_fd_.size(), 1) > 0) // at least one socket meets event requirements, which sent back to us on revents
		{
			auto& listening_socket = use_fd_[0]; // first element is the listening socket
			if (listening_socket.revents & POLLRDNORM)
			{
				/* incoming connection */
				sockaddr_in client_address{};
				int client_address_size = sizeof(client_address);
				const auto client_socket = accept(listening_socket.fd, (sockaddr*)&client_address, &client_address_size);

				/* get dns resolved */
				char host[NI_MAXHOST]{};
				char service[NI_MAXSERV]{};
				getnameinfo((sockaddr*)&client_address, client_address_size, host, NI_MAXHOST, service, NI_MAXSERV, 0);

				/* set socket properties */
				DWORD flags = 1;
				setsockopt(client_socket, SOL_SOCKET, TCP_NODELAY, (char*)&flags, sizeof(flags));
				unsigned long non_blocking = 1;
				ioctlsocket(client_socket, FIONBIO, &non_blocking);

				/* invoke the app callback */
				{
					/* hold lock here, to protect the app, as it probably is processing packets */
					std::unique_lock<std::shared_mutex> lock{ client_list_mutex_ };
					if (new_client_handler_)
					{
						if (!new_client_handler_(client_socket, client_address.sin_addr.S_un.S_addr, host))
						{
							/* app did not accept this client, drop him */
							shutdown(client_socket, SD_SEND);
							closesocket(client_socket);
							continue;
						}
					}

					/* add client socket to master set, so we can check for incoming packets later */
					client_list_[client_socket] = std::make_unique<server_client>();
				}

				
				master_fd_.push_back({client_socket, POLLRDNORM | POLLWRNORM , 0});
			}

			/* loop from end to beginning, check if any data are ready to be read */
			for (auto i = use_fd_.size() - 1; i >= 1; i--)
			{
				auto& current_fd = use_fd_[i];
				const auto current_socket = current_fd.fd;
				auto* current_client = get_server_client(current_socket);

				if (!current_client) // should not happen
				{
					close_connection(i);
					continue;
				}

				auto* aes_key = current_client->has_aes_key() ? &current_client->aes_key : nullptr;
				auto* aes_iv = current_client->has_aes_key() ? &current_client->aes_iv : nullptr;

				if (current_client->should_drop) // app requested a drop
				{
					close_connection(i);
					continue;
				}

				/* error occurred on this fd */
				if (current_fd.revents & POLLERR || current_fd.revents & POLLHUP || current_fd.revents & POLLNVAL)
				{
					close_connection(i);
					continue;
				}

				/* read logic */
				if (current_fd.revents & POLLRDNORM) // if normal data can be read without blocking
				{
					auto bytes_received = 0;
					auto& pm = current_client->pm_in;

					if (pm.current_state == packet_manager_in::will_process_packet_header)
					{
						/* read packet header */
						bytes_received = recv(current_socket, (char*)&pm.current_packet.header + pm.current_extraction_offset,
							(int)(sizeof(packet_manager_in::packet::packet_header) - pm.current_extraction_offset), 0);
					}
					else
					{
						/* read packet contents */
						bytes_received = recv(current_socket, (char*)pm.current_packet.contents.get() +
							pm.current_extraction_offset, (int)(pm.current_packet.header.content_size - pm.current_extraction_offset), 0);
					}

					if (bytes_received == 0)
					{
						/* client disconnected, note %99.99 of time POLLHUP or POLLERR occurs, not this. */
						close_connection(i);
						continue;
					}

					if (bytes_received == SOCKET_ERROR)
					{
						if (WSAGetLastError() != WSAEWOULDBLOCK)
						{
							/* any other error than would block is reason for kick */
							close_connection(i);
							continue;
						}
					}

					if (bytes_received > 0)
					{
						/* increment extraction offset by bytes received */
						pm.current_extraction_offset += bytes_received;

						/* check if we fully read the packet header */
						if (pm.current_state == packet_manager_in::will_process_packet_header &&
							pm.current_extraction_offset == sizeof packet_manager_in::packet::packet_header)
						{
							/* decrypt header if we have the keys */
							if (aes_key && aes_iv)
								utils::decrypt_aes((byte*)&pm.current_packet.header, sizeof packet_manager_in::packet::packet_header,
									aes_key, aes_iv);

							/* if client has no aes key, the first packet must be packet_id_aes_data with size of packet_aes_data*/
							if (!current_client->has_aes_key())
							{
								if (pm.current_packet.header.id != xnet::packet_id_aes_data)
								{
									/* first packet we expect is the aes data, if smt else is received, drop the client */
									close_connection(i);
									continue;
								}
								
								if (pm.current_packet.header.content_size != sizeof xnet::packet_aes_data)
								{
									close_connection(i);
									continue;
								}
							}
							else
							{
								std::unique_lock<std::mutex> lock{ packet_maximums_mutex_ };
								if (!packet_maximums_.empty())
								{
									if(!packet_maximums_.contains(pm.current_packet.header.id))
									{
										/* unknown packet id */
										close_connection(i);
										continue;
									}
									
									if (pm.current_packet.header.content_size > packet_maximums_[pm.current_packet.header.id])
									{
										/* invalid packet size */
										close_connection(i);
										continue;
									}
								}
							}

							/* read packet contents next */
							pm.current_packet.contents = std::make_unique<uint8_t[]>(pm.current_packet.header.content_size);
							pm.current_extraction_offset = 0;
							pm.current_state = packet_manager_in::will_process_packet_contents;
						}
						else if (pm.current_extraction_offset == pm.current_packet.header.content_size)
						{
							/* decrypt the packet contents and move it into queue */
							if (aes_key && aes_iv)
								utils::decrypt_aes((byte*)pm.current_packet.contents.get(), pm.current_packet.header.content_size,
									aes_key, aes_iv);
							pm.on_parse_complete(); // we acquire a lock here
						}
					}

				}

				/* write logic */
				if (current_fd.revents & POLLWRNORM) // can write normal data without blocking
				{
					/* first deal with the packets that were added to queue while we didn't have the client session key */
					auto& pm = current_client->pm_out;
					auto& pm_unencrypted = current_client->pm_out_unencrypted;
					if (!current_client->dealt_with_unencrypted_packets && current_client->has_aes_key() && current_client->ack_sent)
					{
						std::lock_guard<std::mutex> lock{ pm_unencrypted.mutex_queue };
						while(pm_unencrypted.has_pending_packets())
						{
							/* since we have the key and sent the ack, now encrypt these packets if there are any */
							auto* packet = pm_unencrypted.retrieve();
							pm.append_unencrypted_packet(std::move(*packet), &current_client->aes_key, &current_client->aes_iv);
							pm_unencrypted.pop();
						}

						current_client->dealt_with_unencrypted_packets = true;
					}
					
					std::lock_guard<std::mutex> lock{ pm.mutex_queue };
					while (pm.has_pending_packets())
					{
						auto* packet = pm.retrieve();
						const auto bytes_sent = send(current_socket, (char*)packet->buffer.get() + pm.buffer_offset,
							(int)(packet->size - pm.buffer_offset), 0);

						if (bytes_sent > 0)
						{
							pm.buffer_offset += bytes_sent;
						}

						if (pm.buffer_offset == packet->size)
						{
							/* successfully wrote the full packet */
							pm.buffer_offset = 0;
							pm.pop();
						}
						else
						{
							/* do not try to send data again, as it would probably block */
							break;
						}
					}
				}
			}
		}

		/* do not burn cpu */
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}

	is_running_ = false;
}

void server_internal::process_packets()
{
	while (!is_shutdown_)
	{
		{
			std::shared_lock<std::shared_mutex> mutex{ client_list_mutex_ };
			for (auto& entry : client_list_)
			{
				auto* client = entry.second.get();
				if (client)
				{
					/* we are looping through the queue, new packets might be added to id at same time, we need to acquire the lock */
					auto& pm = client->pm_in;
					std::lock_guard<std::mutex> lock_queue{ pm.mutex_queue };
					while (pm.has_pending_packets() && !client->should_drop)
					{
						auto* packet = pm.retrieve();

						if (!client->has_aes_key() && packet->header.id == xnet::packet_id_aes_data)
						{
							/* aes data is received, decrypt it with private rsa key */
							auto* aes_data = (xnet::packet_aes_data*)packet->contents.get();

							/* set client key */
							client->aes_key.resize(CryptoPP::AES::DEFAULT_KEYLENGTH);
							client->aes_iv.resize(CryptoPP::AES::DEFAULT_KEYLENGTH);
							utils::decrypt_rsa(rsa_private_key_, (byte*)aes_data->key, 128, client->aes_key.BytePtr(), client->aes_key.SizeInBytes());
							utils::decrypt_rsa(rsa_private_key_, (byte*)aes_data->iv, 128, client->aes_iv.BytePtr(), client->aes_iv.SizeInBytes());

							/* here, it is guaranteed that we won't receive a new packet without sending the aes ack,
							 * as the client is coded that way..
							 */

							/* send ack */
							client->send_packet(xnet::dummy_packet, sizeof xnet::dummy_packet, xnet::packet_id_aes_ack);
							pm.pop();
							client->ack_sent = 1;
							continue;
						}

						/* call client handler */
						if(!packet_handler_(entry.first, packet->header.id, packet->contents.get(), packet->header.content_size))
						{
							/* app requested a drop */
							client->should_drop = 1;
						}

						/* delete the packet, frees the memory */
						pm.pop();
					}
				}
			}
		}
		
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

server_client* server_internal::get_server_client(SOCKET s)
{
	return client_list_[s].get();
}

void server_internal::set_last_error(xnet::error_code code)
{
	last_error_ = code;
}

void server_internal::close_connection(size_t idx)
{
	const auto socket = use_fd_[idx].fd;

	master_fd_.erase(master_fd_.begin() + idx);
	use_fd_.erase(use_fd_.begin() + idx);
	{
		std::unique_lock<std::shared_mutex> lock{ client_list_mutex_ };
		client_list_.erase(socket);

		shutdown(socket, SD_SEND);
		closesocket(socket);

		/* call the callback */
		if (client_drop_handler_)
		{
			client_drop_handler_(socket);
		}
	}
}

xnet::error_code server_internal::get_last_error()
{
	return last_error_;
}

int server_internal::get_last_os_error()
{
	return WSAGetLastError();
}

bool server_internal::send_to_client(uintptr_t client, const void* p_data, uint32_t size, uint32_t packet_id)
{
	/* we do not hold and locks, as this function will be called from process packets, while holding the same lock. */
	//std::shared_lock<std::shared_mutex> mutex{ client_list_mutex_ };
	auto* server_client = get_server_client(client);
	if (server_client)
	{
		server_client->send_packet(p_data, size, packet_id);
		return true;
	}
	
	set_last_error(xnet::error_code::error_no_client);
	return false;
}

/* you might still receive a packet from a client that you marked as should_drop,
 * because networking thread might be processing the packets while you give this info.
 * so you should not %100 trust the socket value passed to your handler would be valid.
 */
bool server_internal::drop_client(uintptr_t client)
{
	std::shared_lock<std::shared_mutex> mutex{ client_list_mutex_ };
	auto* server_client = get_server_client(client);
	if (server_client)
	{
		server_client->should_drop = 1;
		return true;
	}

	set_last_error(xnet::error_code::error_no_client);
	return false;
}

void server_internal::set_used_packet_ids_and_max_sizes(std::map<uint32_t, uint32_t> packets)
{
	/* we need to protect this, even if the possibility of crash is %0.0000000001 */
	std::unique_lock<std::mutex> lock{ packet_maximums_mutex_ };
	packet_maximums_ = std::move(packets);
}

server_internal::~server_internal()
{
	is_shutdown_ = true;

	/* make sure threads are valid before attempting to join them */
	if (networking_thread_.joinable())
	{
		networking_thread_.join();
	}
		
	if (packet_processor_thread_.joinable())
	{
		packet_processor_thread_.join();
	}
		
	/* close all connections */
	for (auto& fd : master_fd_)
	{
		closesocket(fd.fd);
	}
	
	WSACleanup();
}

bool server_internal::start()
{
	if (last_error_ != xnet::error_code::error_success)
	{
		/* something went wrong on early initialization phase */
		return false;
	}
		
	const auto listening = socket(AF_INET, SOCK_STREAM, 0);
	if (listening == INVALID_SOCKET)
	{
		set_last_error(xnet::error_code::error_socket_creation);
		return false;
	}

	BOOL reuse_address = true;
	if (setsockopt(listening, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse_address, sizeof BOOL) != 0)
	{
		closesocket(listening);
		set_last_error(xnet::error_code::error_generic);
		return false;
	}
	
	sockaddr_in hint = {};
	hint.sin_family = AF_INET;
	hint.sin_port = htons(port_);
	inet_pton(AF_INET, ip_.c_str(), &hint.sin_addr.s_addr);

	if (bind(listening, (sockaddr*)&hint, sizeof(hint)) == SOCKET_ERROR)
	{
		closesocket(listening);
		set_last_error(xnet::error_code::error_generic);
		return false;
	}

	if (listen(listening, SOMAXCONN) == SOCKET_ERROR)
	{
		closesocket(listening);
		set_last_error(xnet::error_code::error_generic);
		return false;
	}

	/* add listening socket to master set */
	master_fd_.push_back({listening, POLLRDNORM , 0});
	is_running_ = true;

	/* create threads */
	networking_thread_ = std::thread([p = this] {p->run(); });
	packet_processor_thread_ = std::thread([p = this] {p->process_packets(); });
	
	return true;
}

bool server_internal::is_running()
{
	return is_running_;
}

std::unique_ptr<xnet::server> xnet::server::initialize(std::string ip, unsigned short port, protocol proto)
{
	return std::make_unique<server_internal>(std::move(ip), port, proto);
}

server_internal::server_internal(std::string ip, unsigned short port, xnet::protocol protocol) : ip_(std::move(ip)), port_(port),
                                                                                                 protocol_(protocol)
{
	/* start wsa, do crypto things */
	/* initialize things */
	WSADATA ws_data{};
	const auto version = MAKEWORD(2, 2);

	if (WSAStartup(version, &ws_data) != 0)
	{
		set_last_error(xnet::error_code::error_initialization);
		return;
	}

	if (protocol_ == xnet::protocol::udp)
	{
		set_last_error(xnet::error_code::error_unsupported_protocol);
		return;
	}

	if (!utils::get_rsa_key_from_hex_string(rsa_private_key_, xnet::rsa_private_key, sizeof xnet::rsa_private_key))
	{
		set_last_error(xnet::error_code::error_crypto);
	}

}

void server_internal::register_packet_handler(xnet::server_packet_handler function)
{
	packet_handler_ = function;
}

void server_internal::register_client_drop_handler(xnet::server_client_drop_handler function)
{
	client_drop_handler_ = function;
}

void server_internal::register_new_client_handler(xnet::server_new_client_handler function)
{
	new_client_handler_ = function;
}

