#pragma once
#include "../shared/xnet_definitions.h"

#include <cstdint>
#include <functional>
#include <string>
#include <memory>

/*todo set public key*/
/*todo set private key*/
/* client should include this header */
namespace xnet
{
	/* for packets */
	using client_packet_handler = std::function<void(uint8_t* p_data, uint32_t size)>;

	struct client_packet
	{
		std::unique_ptr<uint8_t[]> data;
		uint32_t size;
		uint32_t packet_id;
	};
	
	/* RSA public key to encrypt session AES key */
	inline char rsa_public_key[] = "30819D300D06092A864886F70D010101050003818B0030818702818100BD37374806233CC31A73DF54B73B5862B9343693C05AF16EEB593A575E890BFCCFE83711349280F7053EA155357E37FD8BA89B6AB9FE96FF7972ADA853805CD0BDA0EA132D6B77D1C34B4B2F4448B22AB7A05AF422BC01275F2570A38A190B23D23D2026C1FF1946ED9AD554DACB39D227AA1485C10FCF36ADED9E406FD02DE7020111";
	
	class client
	{
	public:
		/* always check for last error after initialization phase */
		static std::unique_ptr<client> initialize(std::string endpoint_ip, uint16_t endpoint_port, protocol proto);
		
		client() = default;
		client(const client&) = delete;
		client& operator=(const client&) = delete;
		client(client&&) = delete;
		client& operator=(client&&) = delete;
		virtual ~client() = default;

		virtual bool connect() = 0;

		virtual void register_packet_handler(client_packet_handler function, uint32_t packet_id) = 0;

		virtual void remove_packet_handler(uint32_t packet_id) = 0;

		virtual void send_packet(const void* p_data, uint32_t size, uint32_t packet_id) = 0;

		virtual bool is_connected() = 0;

		/* retrieve the first packet on queue, you should not use this type of handling with callbacks. */
		virtual std::optional<client_packet> retrieve_packet() = 0; 
		
		virtual error_code get_last_error() = 0;
		virtual int get_last_os_error() = 0;
	};
}
