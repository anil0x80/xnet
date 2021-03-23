#pragma once
/* to be included by both this and client projects, defines the interface */
#include <cstdint>

namespace xnet
{
	enum class error_code
	{
		error_success,
		error_initialization,		// error during initialization phase
		error_unsupported_protocol, // udp is not supported yet
		error_crypto,			// crypto error
		error_socket_creation, // an error occurred, so we could not create a socket
		error_generic, // call get_os_error to look up the error code
		error_connection, // endpoint is unreachable
		error_connection_lost, // connection lost
		error_no_ack, // endpoint did not respond to aes data.
		error_no_handler, // no handlers found for a packet id that was received
		error_no_client, // a send packet request was made to invalid server client
	};

	enum class protocol
	{
		tcp,
		udp
	};

}
