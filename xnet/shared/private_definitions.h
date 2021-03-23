#pragma once

namespace xnet
{
	inline uint32_t packet_id_aes_data = 0;
	inline uint32_t packet_id_aes_ack = 1;
	inline char dummy_packet[] = "CCC";
	
	struct packet_aes_data
	{
		char key[128]; //size of modulus when key size is 1024
		char iv[128];
	};

}
