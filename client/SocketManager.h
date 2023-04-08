#pragma once
#include <boost/asio/ip/tcp.hpp>

using boost::asio::io_context;
using boost::asio::ip::tcp;

constexpr size_t PACKET_SIZE = 1024;		// Fixed packet size

class SocketManager
{
public:
	// Constructors & Destroctors
	SocketManager();
	virtual ~SocketManager();

	// Functions
	void close();	//Used in the destructor.
	bool setSocket(const std::string& address, const std::string& port);
	bool connect();
	bool sendRequest(const uint8_t* const buffer, const size_t size) const;
	bool receiveResponse(uint8_t* const buffer, const size_t size) const;
	

private:

	io_context*					io_context;
	tcp::resolver*				resolver;
	tcp::socket*				socket;
	std::string					socket_address;
	std::string					socket_port;
	bool						connected;

};