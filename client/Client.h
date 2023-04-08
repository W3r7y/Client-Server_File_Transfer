#pragma once

#include "SocketManager.h"
#include "FileManager.h"
#include "Request.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"



constexpr auto TRANSFER_INFO = "transfer.info";
constexpr auto ME_INFO = "me.info";

class Client
{
public:

	// Functions

	Client();
	virtual ~Client();
	bool setServerInfo();
	bool setClientInfo();
	bool setTransferData();			
	bool registration();
	bool sendPublicKey();
	bool reconnect();
	int sendFile();
	bool sendFinalInvalidCrcRequest();

private:
	// Parameters
	FileManager* file_manager;			// Manager for work with files.
	SocketManager* socket_manager;		// Manager for work with socket.
	RSAPrivateWrapper* rsa_wrapper;		// RSA wrapper for encryption / decryption

	ClientID c_id;						// Client ID
	std::string c_username;				// Username
	std::string file_to_send;			// Name of the file user wonder to send to the server
	PublicKey public_key;				// Client public key
	SymetricKey symetric_key;			// Symetric key

	// Functions
	bool isExpectedHeader(const ResponseHeader& response_header, const ServerResponseCode expected_header_code);
	bool storeClientInfo();
};