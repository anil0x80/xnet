#pragma once
#include "../shared/xnet_definitions.h"

#include <cstdint>
#include <functional>
#include <string>
#include <memory>
#include <map>

namespace xnet
{
	inline char rsa_private_key[] = "30820275020100300D06092A864886F70D01010105000482025F3082025B02010002818100BD37374806233CC31A73DF54B73B5862B9343693C05AF16EEB593A575E890BFCCFE83711349280F7053EA155357E37FD8BA89B6AB9FE96FF7972ADA853805CD0BDA0EA132D6B77D1C34B4B2F4448B22AB7A05AF422BC01275F2570A38A190B23D23D2026C1FF1946ED9AD554DACB39D227AA1485C10FCF36ADED9E406FD02DE70201110281803D3782D38983DEF3D3DA31AA7784241FF09FF38A27A4F3C200D91A678F86B10E07075D1C2798CF5EFA2AD9D7CD8AB7C2F87A50664B3BC770C568DDD4937C5A42F92306AD151DADE1C8112C258B7CC1F4216A405B4CCDCBA3E5EB55CC67F044697D8EEE0E30104DD7BF184EAAEC4BEE1B201E5726C44B769382E9F2437996B391024100C269AF2A399C10176663C37A90092BCC5AD5FF2799C07D4E725E70EE953A025A0F0EDD1B37B9C6BCBDA5D45568079B6B17A01B934252E45863F7AB2B83A9E987024100F9280F0083FF4E464F9B2DCC4AEC74B1986AAC26B2DC82C70ED8539A3F3E355527D191C86A12ED923E640DD7DE360441C40948A9374807FF1268A92D173D30A102410094AB2B98C2A484C69997957BD78E8AE790C1C31E486605783957474D08B3E3AE47C0127E39AC2E9054CA1AD7E623EF51E4E3D8DA058AAE9DF217BF214690FDDF024100AFE00A96F3C3464FBFB8D508AD5B9DAA89B4B5C0F6B9C5B9B0203B0377EFAD2D0D0C66E7D267B6C19573CD89518F8A88C69D243B3614BA59B2A43B2EE33A407102407F1C6C99AD54EDE65BF144A065B45778763686CF6BBFA3E8B92A72F7E35C65344547A87270B212A5353DF441B9CC9A2E77EA4A84BD1356D8EA3B2766D8FC53D2";

	/* for client drop & new client notifications */
	using server_packet_handler = std::function<bool(uintptr_t client, uint32_t packet_id, uint8_t* p_data, uint32_t size)>;
	using server_client_drop_handler = std::function<void(uintptr_t client)>; // on client
	using server_new_client_handler = std::function<bool(uintptr_t client, uint32_t ip, std::string dns)>; // on client

	/* interface */
	class server
	{
	public:
		/* always check for last error after initialization phase */
		static std::unique_ptr<server> initialize(std::string ip, unsigned short port, protocol proto);

		server() = default;
		server(const server&) = delete;
		server& operator=(const server&) = delete;
		server(server&&) = delete;
		server& operator=(server&&) = delete;
		virtual ~server() = default;

		virtual bool start() = 0;
		virtual bool is_running() = 0;
		
		virtual void register_packet_handler(server_packet_handler function) = 0;
		virtual void register_client_drop_handler(server_client_drop_handler function) = 0;
		virtual void register_new_client_handler(server_new_client_handler function) = 0;

		/* client interaction */
		virtual bool send_to_client(uintptr_t client, const void* p_data, uint32_t size, uint32_t packet_id) = 0;
		virtual bool drop_client(uintptr_t client) = 0;

		/* debug */
		virtual error_code get_last_error() = 0;
		virtual int get_last_os_error() = 0;
		
		/* security */
		virtual void set_used_packet_ids_and_max_sizes(std::map<uint32_t, uint32_t> packets) = 0;
	};
}

