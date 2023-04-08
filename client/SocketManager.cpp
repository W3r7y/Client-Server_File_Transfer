
#include "SocketManager.h"
#include <iostream>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;
using boost::asio::io_context;

SocketManager::SocketManager():io_context(nullptr), resolver(nullptr), socket(nullptr), connected(false)	//TODO: Maybe need to setup all default opptions for variables.
{
}

SocketManager::~SocketManager()
{
	close();
}

/* The function sets port and destination address for the socket. */
bool SocketManager::setSocket(const std::string& address, const std::string& port)
{ 
	socket_address = address;
	socket_port = port;
	return true;
}

/* The function attempts to connect to a TCP server, returns true if succseed, and false otherwise */
bool SocketManager::connect() {
	try {
		close();				// in case that there is an open socket.		
		io_context = new boost::asio::io_context;
		socket = new tcp::socket(*io_context);
		resolver = new tcp::resolver(*io_context);

		// Setup connection
		boost::asio::connect(*socket, resolver->resolve(socket_address, socket_port));
		socket->non_blocking(false);
		connected = true;
	}
	catch (...) {
		connected = false;		// Something went wrong 
	}
	return connected;
}

/* The function closes open socket connection */
void SocketManager::close()
{
	if (socket != nullptr) {
		try {
			socket->shutdown(boost::asio::socket_base::shutdown_both);
			socket->close();
		}
		catch (...) {
			// handle any exceptions thrown by shutdown() or close()
		}
		delete socket;
		socket = nullptr;
	}

	if (resolver != nullptr) {
		delete resolver;
		resolver = nullptr;
	}

	if (io_context != nullptr) {
		delete io_context;
		io_context = nullptr;
	}

	connected = false;
}

/*  This function sends a request over an open socket connection. It takes a buffer of bytes to send and the size of the buffer.
	The function splits the buffer into smaller packets of a fixed size, and sends each packet over the socket.
	The function returns true if the request was sent successfully, and false otherwise.
*/
bool SocketManager::sendRequest(const uint8_t* const buffer, const size_t size) const
{
	if (buffer == nullptr || socket == nullptr || size == 0)	
		return false;

	size_t bytesToSend = size;
	const uint8_t* ptr = buffer;

	while (bytesToSend > 0)
	{
		boost::system::error_code errorCode; // without this write() will throw exception.
		uint8_t tempBuffer[PACKET_SIZE] = { 0 };
		const size_t bytes_in_packet = (bytesToSend > PACKET_SIZE) ?  PACKET_SIZE : bytesToSend;	//Send no more then PACKET_SIZE

		memcpy(tempBuffer, ptr, bytes_in_packet);

		const size_t bytesWritten = write(*socket, boost::asio::buffer(tempBuffer, PACKET_SIZE), errorCode);

		if (bytesWritten == 0)
			return false;

		ptr += bytesWritten;
		if (bytesWritten > bytesToSend) {	// packet is bigget then the amout of bytes left to send.
			bytesToSend = 0;				
		}
		else {								// need another packet
			bytesToSend = bytesToSend - bytesWritten;
		}
	}
	return true;
}

/*  This function receives a response over an open socket connection, takes a buffer to store the received bytes and the size of the buffer.
	The function receives data from the socket in smaller packets of a fixed size, and appends the data to the buffer until the desired amount
	of data has been received. The function returns true if the response was received successfully, and false otherwise.
*/
bool SocketManager::receiveResponse(uint8_t* const buffer, const size_t size) const
{
	if (buffer == nullptr || socket == nullptr || size == 0){
		return false;
	}
	
	size_t bytesToRecieve = size;
	uint8_t* ptr = buffer;

	while (bytesToRecieve > 0)
	{
		uint8_t tempBuffer[PACKET_SIZE] = { 0 };
		boost::system::error_code errorCode; // without this read() will throw exception.
		size_t bytesRead = read(*socket, boost::asio::buffer(tempBuffer, PACKET_SIZE), errorCode);

		if (bytesRead == 0) {
			return false;     // Failed receiving.
		}
		const size_t bytesToCopy = (bytesToRecieve > bytesRead) ? bytesRead : bytesToRecieve;  // prevent buffer overflow.
		memcpy(ptr, tempBuffer, bytesToCopy);
		ptr += bytesToCopy;
		bytesToRecieve = (bytesToRecieve < bytesToCopy) ? 0 : (bytesToRecieve - bytesToCopy);  // unsigned protection.
	}
	return true;
}