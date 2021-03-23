#include PRECOMPILED_HEADER
#include "packet_manager.h"

#include "utils.h"

constexpr auto size_of_packet_header = sizeof(uint32_t) * 2;

packet_manager_in::packet* packet_manager_in::retrieve()
{
	return &packet_queue.front();
}

bool packet_manager_in::has_pending_packets()
{
	return !packet_queue.empty();
}

void packet_manager_in::pop()
{
	packet_queue.pop();
}

void packet_manager_in::on_parse_complete()
{
	/* move current packet to queue */
	{
		std::lock_guard<std::mutex> lock{ mutex_queue };
		packet_queue.push(std::move(current_packet));
	}


	/* we are done reading the packet, reset the state */
	current_state = will_process_packet_header;
	current_packet.header.content_size = 0;
	current_extraction_offset = 0;
}

void packet_manager_out::append(uint32_t packet_size, uint32_t packet_id, char* packet_contents,
	CryptoPP::SecByteBlock* key, CryptoPP::SecByteBlock* iv)
{
	/* create packet */
	packet pkt;
	pkt.size = packet_size + size_of_packet_header; // actual network size
	pkt.buffer = std::make_unique<uint8_t[]>(pkt.size);

	std::memcpy(pkt.buffer.get(), &packet_size, 4);
	std::memcpy(pkt.buffer.get() + 4, (void*)&packet_id, 4);
	std::memcpy(pkt.buffer.get() + size_of_packet_header, packet_contents, packet_size);

	/* encrypt packet */
	if (key && iv)
	{
		utils::encrypt_aes((CryptoPP::byte*)pkt.buffer.get(), size_of_packet_header, key, iv); //encrypt packet header
		utils::encrypt_aes((CryptoPP::byte*)pkt.buffer.get() + size_of_packet_header, packet_size, key, iv); // encrypt contents 
	}

	/* add to queue */
	{
		std::lock_guard<std::mutex> lock{ mutex_queue };
		packet_queue.push(std::move(pkt));
	}

}

void packet_manager_out::pop()
{
	packet_queue.pop();
}

void packet_manager_out::append_unencrypted_packet(packet&& pkt, CryptoPP::SecByteBlock* key, CryptoPP::SecByteBlock* iv)
{
	auto contents_size = pkt.size - size_of_packet_header;
	/* pkt is unencrypted, lets encrypt it first */
	utils::encrypt_aes((CryptoPP::byte*)pkt.buffer.get(), size_of_packet_header, key, iv); //encrypt packet header
	utils::encrypt_aes((CryptoPP::byte*)pkt.buffer.get() + size_of_packet_header, contents_size, key, iv); // encrypt contents

	/* add to queue */
	{
		std::lock_guard<std::mutex> lock{ mutex_queue };
		packet_queue.push(std::move(pkt));
	}
}

bool packet_manager_out::has_pending_packets()
{
	return !packet_queue.empty();
}

packet_manager_out::packet* packet_manager_out::retrieve()
{
	return &packet_queue.front();
}
