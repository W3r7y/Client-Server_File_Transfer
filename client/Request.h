#pragma once

#include <cstdint>


// ============  Definition of data structures, constant variable and sizes.  ============

// Client request operation codes.

enum ClientRequestCode{	

	REQUEST_REGISTRATION = 1100,					
	REQUEST_SEND_PUBLIC_KEY = 1101,						
	REQUEST_RECONNECT = 1102,
	REQUEST_SEND_FILE = 1103,
	REQUEST_VALID_CRC = 1104,				//CRC is valid
	REQUEST_INVALID_CRC = 1105,				//Invalid CRC, may try to send the file again.
	REQUEST_FINAL_INVALID_CRC = 1106,
};


// Server response operation codes.
enum ServerResponseCode{

	RESPONSE_REGISTRATION_SUCCESS = 2100,
	RESPONSE_REGISTRATION_FAILURE = 2101,
	RESPONSE_KEY_EXCHANGE = 2102 ,				//Public key delivered, sending encrypted symetric AES key
	RESPONSE_FILE_DELIVERED_WITH_CRC = 2103,	//File delivered with CRC = ____
	RESPONSE_MESSAGE_DELIVERED = 2104,
	RESPONSE_RECONNECTION_ACCEPTED = 2105,		
	RESPONSE_RECONNECTION_DENIED = 2106,
	RESPONSE_SERVER_ERROR = 2107				//Server error
};


// Constant variables

constexpr size_t    CLIENT_ID_SIZE = 16;		// Users unique id, 16 bytes

constexpr uint8_t	VERSION_SIZE = 1;			// Client version
constexpr size_t	OPERATION_CODE_SIZE = 2;	// 2 bytes
constexpr size_t	PAYLOAD_SIZE = 4;			// 4 bytes
constexpr size_t	NAME_SIZE = 255;			// Client name / File name
constexpr size_t    PUBLIC_KEY_SIZE = 160;		// In the protocol 1024 bits
constexpr size_t    SYMETRIC_KEY_SIZE = 16;		// In The protocol 128 bits  

constexpr uint8_t	CLIENT_VERSION = 3;			// Client version
constexpr size_t	CONTENT_SIZE = 4;			// What is the size of the file that the user wants to send.
constexpr size_t	CRC_CKSUM_SIZE = 4;			// Check sum value size

#pragma pack(push, 1)


// Client ID structure.
struct ClientID{

	uint8_t client_id[CLIENT_ID_SIZE];
	ClientID() : client_id{0} {}

	//Overwriting the operators

	bool operator==(const ClientID& other) const {
		for (size_t i = 0; i < CLIENT_ID_SIZE; i++)
			if (client_id[i] != other.client_id[i])
				return false;
		return true;
	}

	bool operator!=(const ClientID& other) const {
		return !(*this == other);
	}

};

// Name structure.
struct Name
{
	uint8_t name[NAME_SIZE];  
	Name() : name{ "" } {}	//Nameless - we can change to something nice / default value.
};

// Public key structure
struct PublicKey
{
	uint8_t publicKey[PUBLIC_KEY_SIZE];
	PublicKey() : publicKey{ 0 } {}
};

// Symetric key structure
struct SymetricKey
{
	uint8_t symetricKey[SYMETRIC_KEY_SIZE];
	SymetricKey() : symetricKey{ 0 } {}
};


// Request header structure
struct RequestHeader{

	ClientID		cid;
	const uint8_t	version;		// 1 byte
	const uint16_t  code;			// 2 bytes
	uint32_t        payloadSize;	// 4 bytes
	RequestHeader(const uint16_t reqCode) : version(CLIENT_VERSION), code(reqCode), payloadSize(0) {}
	RequestHeader(const ClientID& id, const uint16_t reqCode) : cid(id), version(CLIENT_VERSION), code(reqCode), payloadSize(0) {}
};

// Response header structure
struct ResponseHeader{
	uint8_t		version;			// 1 byte
	uint16_t    code;				// 2 bytes
	uint32_t	payloadSize;		// 4 bytes
	ResponseHeader() : version(0), code(0), payloadSize(0) {}
};


// =============================  Types of requests ===================================

struct RegistrationRequest {

	RequestHeader req_header;
	
	struct {
		Name client_name;
	}payload;
	RegistrationRequest() : req_header(REQUEST_REGISTRATION) {}
};

struct SendPublicKeyRequest {

	RequestHeader req_header;

	struct {
		Name client_name;
		PublicKey key_pub;
	}payload;
	SendPublicKeyRequest() : req_header(REQUEST_SEND_PUBLIC_KEY) {}
};

struct ReconnectionRequest {

	RequestHeader req_header;

	struct {
		Name client_name;
	}payload;
	ReconnectionRequest() : req_header(REQUEST_RECONNECT) {}
};

struct SendFileRequest {

	RequestHeader req_header;

	struct {
		uint32_t contentSize;
		Name file_name;
		
		//Message content is sent and not used in the struct.
	}payload;
	SendFileRequest() : req_header(REQUEST_SEND_FILE) {}
};

struct ValidCrcRequest {

	RequestHeader req_header;

	struct {
		Name file_name;
	}payload;
	ValidCrcRequest() : req_header(REQUEST_VALID_CRC) {}
};


struct InvalidCrcRequest {

	RequestHeader req_header;

	struct {
		Name file_name;
	}payload;
	InvalidCrcRequest() : req_header(REQUEST_INVALID_CRC) {}
};

struct FinalInvalidCrcRequest {

	RequestHeader req_header;

	struct {
		Name file_name;
	}payload;
	FinalInvalidCrcRequest() : req_header(REQUEST_FINAL_INVALID_CRC) {}
};


// =============================  Types of responses ===================================

struct RegistrationSuccessResponse {

	ResponseHeader res_header;
	ClientID cid;
};


struct RegistrationFailResponse {

	ResponseHeader res_header;
};


struct SendPublicKeyResponse {		// got public key, sending back AES key

	ResponseHeader res_header;

	struct 
	{
		ClientID cid;
		uint8_t encrypted_sym_key[PUBLIC_KEY_SIZE]; 		//encrypted symetric key that we get from the server
	}payload;
};


struct SendFileResponse {

	ResponseHeader res_header;
	
	struct {
		ClientID cid;
		uint32_t ContentSize;		// 4 bytes
		Name file_name;
		uint32_t calculated_crc;	// 4 bytes
	}payload;
};

struct MessageDeliveredResponse {

	ResponseHeader res_header;
	ClientID cid;
};

struct ReconectionApprovedResponse {

	ResponseHeader res_header;
	struct {
		ClientID cid;
		uint8_t encrypted_sym_key[PUBLIC_KEY_SIZE];		// new encrypted symetric key.
	}payload;
};

struct ReconectionDeniedResponse {

	ResponseHeader res_header;
	ClientID cid;
};

struct GlobalErrorResponse {
	ResponseHeader res_header;
};

#pragma pack(pop)