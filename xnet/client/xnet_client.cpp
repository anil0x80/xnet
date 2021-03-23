#include PRECOMPILED_HEADER
#include "xnet_client.h"
#include "../shared/packet_manager.h"
#include "../shared/private_definitions.h"
#include "../shared/utils.h"

class client_internal final : public xnet::client
{
public:
	/* initialize client with ip and port */
	client_internal(std::string ip, uint16_t port, xnet::protocol proto);
	client_internal(const client_internal&) = delete;
	client_internal& operator=(const client_internal&) = delete;
	client_internal(client_internal&&) = delete;
	client_internal& operator=(client_internal&&) = delete;
	~client_internal() override;

	bool connect() override;

	void register_packet_handler(xnet::client_packet_handler function, uint32_t packet_id) override;

	void remove_packet_handler(uint32_t packet_id) override;

	void send_packet(const void* p_data, uint32_t size, uint32_t packet_id) override;

	xnet::error_code get_last_error() override;

	int get_last_os_error() override;

	bool is_connected() override;

	void set_last_error(xnet::error_code code);
	void run();
	void process_packets();

	std::optional<xnet::client_packet>  retrieve_packet() override;
private:
	/* networking variables */
	xnet::protocol protocol_;
	std::string ip_;
	uint16_t port_;
	WSAPOLLFD fd_{};
	packet_manager_in pm_in_;
	packet_manager_out pm_out_;
	std::atomic<bool> is_connected_{false};

	/* crypto variables */
	CryptoPP::SecByteBlock aes_key_;
	CryptoPP::SecByteBlock aes_iv_;
	CryptoPP::RSA::PublicKey rsa_public_key_;

	/* packet callbacks */
	std::unordered_map<uint32_t, xnet::client_packet_handler> packet_handlers_{};

	/* other */
	std::atomic<xnet::error_code> last_error_{ xnet::error_code::error_success };
	bool is_shutdown_{ false };
	std::thread networking_thread_{};
	std::thread packet_processor_thread_{};
};

std::unique_ptr<xnet::client> xnet::client::initialize(std::string endpoint_ip, uint16_t endpoint_port, protocol proto)
{
	return std::make_unique<client_internal>(endpoint_ip, endpoint_port, proto);
}

client_internal::client_internal(std::string ip, uint16_t port, xnet::protocol proto) : protocol_(proto), ip_(std::move(ip)),
	port_(port), aes_key_(utils::get_random_aes_key()), aes_iv_(utils::get_random_aes_iv())
{
	/* initialize things */
	WSADATA ws_data{};
	const auto version = MAKEWORD(2, 2);

	if (WSAStartup(version, &ws_data) != 0)
	{
		last_error_ = xnet::error_code::error_initialization;
		return;
	}

	if (!utils::get_rsa_key_from_hex_string(rsa_public_key_, xnet::rsa_public_key, sizeof xnet::rsa_public_key))
	{
		last_error_ = xnet::error_code::error_crypto;
	}
}

client_internal::~client_internal()
{
	is_connected_ = false;
	is_shutdown_ = true;

	/* wait for helper threads to end */
	if (networking_thread_.joinable())
	{
		networking_thread_.join();
	}

	if (packet_processor_thread_.joinable())
	{
		packet_processor_thread_.join();
	}

	/* use graceful disconnect if possible */
	shutdown(fd_.fd, SD_SEND);
	closesocket(fd_.fd);

	WSACleanup();
}

/* connect and do the aes handshake, set last error */
bool client_internal::connect()
{
	if (last_error_ != xnet::error_code::error_success)
	{
		/* an error occurred during initialization phase, we should not connect */
		return false;
	}

	if (protocol_ == xnet::protocol::udp)
	{
		/* not supported, yet. */
		last_error_ = xnet::error_code::error_unsupported_protocol;
		return false;
	}
		
	/* create the socket */
	fd_.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd_.fd == INVALID_SOCKET)
	{
		last_error_ = xnet::error_code::error_socket_creation;
		return false;
	}

	/* bind socket to local ip, connect ex fails without this */
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = 0;
	auto ret_bind = bind(fd_.fd, (SOCKADDR*)&addr, sizeof(addr));
	if (ret_bind == SOCKET_ERROR)
	{
		closesocket(fd_.fd);
		last_error_ = xnet::error_code::error_generic;
		return false;
	}

	/* set socket properties */
	DWORD flags = 1;
	if(setsockopt(fd_.fd, SOL_SOCKET, TCP_NODELAY, (char*)&flags, sizeof(flags)) != 0)
	{
		closesocket(fd_.fd);
		last_error_ = xnet::error_code::error_generic;
		return false;
	}
	
	unsigned long non_blocking = 1;
	if (ioctlsocket(fd_.fd, FIONBIO, &non_blocking) != 0)
	{
		closesocket(fd_.fd);
		last_error_ = xnet::error_code::error_generic;
		return false;
	}

	fd_.events = POLLRDNORM | POLLWRNORM;
	fd_.revents = 0;

	sockaddr_in hint{};
	hint.sin_family = AF_INET;
	hint.sin_port = htons(port_);
	inet_pton(AF_INET, ip_.c_str(), &hint.sin_addr);

	DWORD numBytes = 0;
	GUID guid = WSAID_CONNECTEX;
	LPFN_CONNECTEX ConnectExPtr = nullptr;
	const auto success = ::WSAIoctl(fd_.fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
		(void*)&guid, sizeof(guid), (void*)&ConnectExPtr, sizeof(ConnectExPtr),
		&numBytes, nullptr, nullptr);
	if (success != 0)
	{
		closesocket(fd_.fd);
		last_error_ = xnet::error_code::error_generic;
		return false;
	}

	/* connect to server */
	OVERLAPPED overlapped{};
	const auto result = ConnectExPtr(fd_.fd, (sockaddr*)&hint, sizeof(hint), nullptr,
		0, nullptr, &overlapped);
	const auto last_error = WSAGetLastError();
	if (!result && last_error != WSA_IO_PENDING)
	{
		closesocket(fd_.fd);
		last_error_ = xnet::error_code::error_generic;
		return false;
	}

	if (last_error == WSA_IO_PENDING)
	{
		DWORD flags_2;
		DWORD transferred;
		WSAGetOverlappedResult(fd_.fd, &overlapped, &transferred, TRUE, &flags_2);
	}

	if (WSAGetLastError() != 0)
	{
		/* an error occurred on connection */
		closesocket(fd_.fd);
		last_error_ = xnet::error_code::error_connection;
		return false;
	}

	/* set flag */
	is_connected_ = true;
	
	/* start receiving packets */
	networking_thread_ = std::thread([p = this] {p->run(); });

	/* we need to send the session key and wait for ack here */
	xnet::packet_aes_data data{};
	utils::encrypt_rsa(rsa_public_key_, aes_key_.BytePtr(), aes_key_.size(), (byte*)data.key, sizeof data.key);
	utils::encrypt_rsa(rsa_public_key_, aes_iv_.BytePtr(), aes_iv_.size(), (byte*)data.iv, sizeof data.iv);
	
	pm_out_.append(sizeof xnet::packet_aes_data, xnet::packet_id_aes_data, (char*)&data, nullptr, nullptr);

	/* if we do not get the response in 10 seconds, connection should die */
	const auto wait_end = clock() + CLOCKS_PER_SEC * 10;
	while(true)
	{
		if (wait_end <= clock())
		{
			/* timeout, server did not send the ack */
			closesocket(fd_.fd);
			last_error_ = xnet::error_code::error_no_ack;
			is_connected_ = false;
			return false;
		}

		{
			std::lock_guard<std::mutex> lock{ pm_in_.mutex_queue };

			if (pm_in_.has_pending_packets())
			{
				auto* packet = pm_in_.retrieve();
				if (packet && packet->header.id == xnet::packet_id_aes_ack)
				{
					/* server responded with ack */
					pm_in_.pop();
					/* create packet processor thread, client callbacks are active now */
					packet_processor_thread_ = std::thread([p = this] {p->process_packets(); });
					return true;
				}
			}
		}
	}
}

void client_internal::register_packet_handler(xnet::client_packet_handler function, uint32_t packet_id)
{
	packet_handlers_[packet_id] = function;
}

void client_internal::remove_packet_handler(uint32_t packet_id)
{
	packet_handlers_.erase(packet_id);
}

void client_internal::send_packet(const void* p_data, uint32_t size, uint32_t packet_id)
{
	pm_out_.append(size, packet_id, (char*)p_data, &aes_key_, &aes_iv_);
}

xnet::error_code client_internal::get_last_error()
{
	return last_error_;
}

int client_internal::get_last_os_error()
{
	return WSAGetLastError();
}

bool client_internal::is_connected()
{
	return is_connected_;
}

void client_internal::set_last_error(xnet::error_code code)
{
	last_error_ = code;
}

void client_internal::run()
{
	while (!is_shutdown_)
	{
		/* take copy to not modify original revents */
		auto copy_fd = fd_;
		/* 1 ms delay if there is no events, to not hog the cpu, note that this wont BLOCK */
		if (WSAPoll(&copy_fd, 1, 1) > 0)
		{
			if (copy_fd.revents & POLLERR || copy_fd.revents & POLLHUP || copy_fd.revents & POLLNVAL)
			{
				shutdown(fd_.fd, SD_SEND);
				closesocket(fd_.fd);
				set_last_error(xnet::error_code::error_connection_lost);
				break;
			}

			/* read logic */
			if (copy_fd.revents & POLLRDNORM)
			{
				auto bytes_received = 0;
				auto& pm = pm_in_;

				if (pm.current_state == packet_manager_in::will_process_packet_header)
				{
					/* read packet header */
					bytes_received = recv(fd_.fd, (char*)&pm.current_packet.header + pm.current_extraction_offset,
						(int)(sizeof(packet_manager_in::packet::packet_header) - pm.current_extraction_offset), 0);
				}
				else
				{
					/* read packet contents */
					bytes_received = recv(fd_.fd, (char*)pm.current_packet.contents.get() +
						pm.current_extraction_offset, (int)(pm.current_packet.header.content_size - pm.current_extraction_offset), 0);
				}

				if (bytes_received == 0)
				{
					shutdown(fd_.fd, SD_SEND);
					closesocket(fd_.fd);;
					set_last_error(xnet::error_code::error_connection_lost);
					break;
				}

				if (bytes_received == SOCKET_ERROR)
				{
					if (WSAGetLastError() != WSAEWOULDBLOCK)
					{
						/* any other error than would block is reason for disconnect */
						shutdown(fd_.fd, SD_SEND);
						closesocket(fd_.fd);
						set_last_error(xnet::error_code::error_connection_lost);
						break;
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
						if (!aes_key_.empty() && !aes_iv_.empty())
							utils::decrypt_aes((byte*)&pm.current_packet.header, sizeof packet_manager_in::packet::packet_header,
								&aes_key_, &aes_iv_);

						/* read packet contents next */
						pm.current_packet.contents = std::make_unique<uint8_t[]>(pm.current_packet.header.content_size);
						pm.current_extraction_offset = 0;
						pm.current_state = packet_manager_in::will_process_packet_contents;
					}
					/* check if we fully received the packet itself */
					else if (pm.current_extraction_offset == pm.current_packet.header.content_size)
					{
						/* decrypt the packet contents and move it into queue */
						if (!aes_key_.empty() && !aes_iv_.empty())
							utils::decrypt_aes((byte*)pm.current_packet.contents.get(), pm.current_packet.header.content_size,
								&aes_key_, &aes_iv_);
						pm.on_parse_complete(); // we acquire a lock here
					}
				}
			}

			/* write logic */
			if (copy_fd.revents & POLLWRNORM)
			{
				auto& pm = pm_out_;
				std::lock_guard<std::mutex> lock{ pm.mutex_queue };
				while (pm.has_pending_packets())
				{
					auto* packet = pm.retrieve();
					const auto bytes_sent = send(fd_.fd, (char*)packet->buffer.get() + pm.buffer_offset,
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

		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		/* by using this type of design, we always receive the packets without the delay of what we are processing */
	}

	is_connected_ = false;
}

void client_internal::process_packets()
{
	while(!is_shutdown_)
	{
		if (!packet_handlers_.empty())
		{
			std::lock_guard<std::mutex> lock{ pm_in_.mutex_queue };
			while (pm_in_.has_pending_packets())
			{
				/* dispatch the incoming packet */
				auto* packet = pm_in_.retrieve();

				if (!packet_handlers_.contains(packet->header.id))
				{
					/* no handler for this packet, app should call retrieve_packet */
					set_last_error(xnet::error_code::error_no_handler);
					continue;
				}
				else
				{
					/* call client handler */
					packet_handlers_[packet->header.id](packet->contents.get(), packet->header.content_size);
				}
				
				pm_in_.pop();
			}
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

std::optional<xnet::client_packet> client_internal::retrieve_packet()
{
	std::lock_guard<std::mutex> lock{ pm_in_.mutex_queue };
	if (pm_in_.has_pending_packets())
	{
		auto* packet = pm_in_.retrieve();

		/* build packet structure to pass to client*/
		xnet::client_packet pkt;
		pkt.data = std::move(packet->contents);
		pkt.size = packet->header.content_size;
		pkt.packet_id = packet->header.id;

		pm_in_.pop(); // remove the packet from queue 

		return pkt;
	}
	
	return {};
}

