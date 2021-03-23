#pragma once

/* responsible for correctly parsing the incoming data */
class packet_manager_in
{
public:
	enum state
	{
		will_process_packet_header, // read 8 bytes, set packet_id and packet_size
		will_process_packet_contents // read packet_size bytes
	};

	struct packet
	{
		struct packet_header
		{
			uint32_t content_size{};
			uint32_t id{};
		} header{};

		std::unique_ptr<uint8_t[]> contents{};
	} current_packet;

	packet* retrieve();
	bool has_pending_packets();
	void pop();

	state current_state{ will_process_packet_header };
	uint32_t current_extraction_offset{};
	void on_parse_complete();

	std::mutex mutex_queue;

private:
	std::queue<packet> packet_queue;
};

/* responsible for correctly appending outgoing data */
class packet_manager_out
{
public:
	
	void append(uint32_t packet_size, uint32_t packet_id, char* packet_contents,
		CryptoPP::SecByteBlock* key, CryptoPP::SecByteBlock* iv);
	void pop();

	struct packet
	{
		uint32_t size{};
		std::unique_ptr<uint8_t[]> buffer{}; // we will just try sending this
	};

	void append_unencrypted_packet(packet&& pkt, CryptoPP::SecByteBlock* key, CryptoPP::SecByteBlock* iv);

	bool has_pending_packets();
	packet* retrieve();
	uint32_t buffer_offset{}; // how many bytes did we send for current packet in queue.

	std::mutex mutex_queue;
private:
	std::queue<packet> packet_queue;
};
