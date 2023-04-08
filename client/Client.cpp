#include "Client.h"
#include <iostream>
#include <fstream>
#include "Request.h"
#include "Utils.h"

// Client class, manages all the possible activity that the client can do, setting information, sending request to the server, 
// recieving responses from the server, encryptin and decriptin data and updating the client.


// Constructor
Client::Client() {
	socket_manager = new SocketManager();
	file_manager = new FileManager();
	rsa_wrapper = new RSAPrivateWrapper();
}

// Destructor
Client::~Client() {
	delete socket_manager;
	delete file_manager;
	delete rsa_wrapper;
}

// The function sets the server information by reading from transfer.info file, gets servers IP address and port and returns true if, the
// information setted up as expected. If there is no transfer.info file provided, the function sets up default settings.
bool Client::setServerInfo() {		
	std::fstream my_file;
	std::string info;
	my_file.open(TRANSFER_INFO, std::ios::in);
	if (!my_file) {
		std::cout << "File not created";
	}
	else {
		getline(my_file, info);

		if (info== "") {	//There is nothing inside, just created.
			const std::string default_ip_address = "127.0.0.1";
			const std::string default_port = "1234";
			socket_manager->setSocket(default_ip_address, default_port);
			std::cout << "WARNING: There was no transfer.info file, default settings configured " << std::endl;
			return true;
		}
		my_file.close();
	}

	const auto pos = info.find(":");	
	const auto ipAddress = info.substr(0, pos);
	const auto port = info.substr(pos + 1);


	std::cout << "The settings are: assress:"<<ipAddress<< " and Port: "<<port << std::endl;
	//Set the settings to our socket.
	socket_manager->setSocket(ipAddress, port);

	return true;
}

// The function sets username and file name that client wants to send to the server, if the file is empty, or information is not found in place
// the function returns false, otherwise it return true.
bool Client::setTransferData() {	
	if (!file_manager->open(TRANSFER_INFO, false)) {
		std::cout << "Error: Failed to open: " << TRANSFER_INFO << ", tried to set transfer data." << std::endl;
		return false;
	}

	std::string line;

	//First line 
	if (!file_manager->readLine(line)) {
		if (line.empty()) {
			std::cout << "Empty file: "<<TRANSFER_INFO << " created / opened" << std::endl;
			return false;
		}
		std::cout << "Error: Cant read the first line in " << TRANSFER_INFO << std::endl;
		return false;
	}

	//Second line
	if (!file_manager->readLine(line)) {
		if (line.empty()) {
			std::cout << "Error: Second line is empty, no username is found in " << TRANSFER_INFO << std::endl;
			return false;
		}
		std::cout << "Error: Cant read the second line in " << TRANSFER_INFO << std::endl;
		return false;
	}
	if (line.length() > NAME_SIZE) {
		std::cout << "Error: Invalid name size in the second line in " << TRANSFER_INFO << std::endl;
		return false;
	}
	line = line.substr(0, line.length() - 1);
	c_username = line;

	//Third line 
	if (!file_manager->readLine(line)) {
		if (line.empty()) {
			std::cout << "Error: Third line is empty, no filename is found in " << TRANSFER_INFO << std::endl;
			return false;
		}
		std::cout << "Error: Cant read third line in " << TRANSFER_INFO << std::endl;
		return false;
	}
	if (line.length() > NAME_SIZE) {
		std::cout << "Error: Invalid file name size in third line in " << TRANSFER_INFO << std::endl;
		return false;
	}
	bool valid = Utils::isValidFilePath(line);		// returns true if valid and false if not.
	if (!valid) {
		std::cout << "Error: not valid file path in " << TRANSFER_INFO << std::endl;
		return false;
	}

	file_to_send = line;
	file_manager->close();

	return true;
}

// The function sets up information from me.info file. The information that is expected is, username, client ID and private key.
// It return true if the information exists, and setted up fine, and false otherwise.
bool Client::setClientInfo() {
	if (!file_manager->open(ME_INFO, false)) {
		std::cout << "Error: Failed to open: " << ME_INFO << ", tried to store new information." << std::endl;
		return false;
	}

	std::string line = "";

	if (!file_manager->readLine(line)) {
		if (line.empty()) {
			std::cout << "Empty file: " << ME_INFO << ", you have to register first." << std::endl;
			return false;
		}
		std::cout << "Error: Cant read the first line in " << ME_INFO << std::endl;
		return false;
	}

	if (line.length() > NAME_SIZE) {
		std::cout << "Error: Invalid name size in the first line in " << ME_INFO << std::endl;
		return false;
	}

	c_username = line;

	if (!file_manager->readLine(line)) {
		if (line.empty()) {
			std::cout << "Error: Second line is empty, no client ID found in" << ME_INFO << std::endl;
			return true;
		}
		std::cout << "Error: Cant read the second line in " << ME_INFO << std::endl;
		return false;
	}

	line = Utils::unhex(line);
	const char* unhexed = line.c_str();			

	if (strlen(unhexed) != sizeof(c_id.client_id)) {		//  Has to be exact number - server makes unique client ID
		memset(c_id.client_id, 0, sizeof(c_id.client_id));	
		std::cout << "Error: The size of client ID not exact as expected in "<< ME_INFO << std::endl;
		return false;
	}

	memcpy(c_id.client_id, unhexed, sizeof(c_id.client_id));

	std::string decodedKey;
	while (file_manager->readLine(line))				// Reading the key.
	{
		decodedKey.append(Utils::decodeBase64(line));
	}

	if (decodedKey.empty()) {
		std::cout << "Error: Third line is empty, private key found not found in " << ME_INFO << std::endl;
		return false;
	}

	try
	{
		delete rsa_wrapper;
		rsa_wrapper = new RSAPrivateWrapper(decodedKey);
	}
	catch (...)
	{
		std::cout << "Error: Did not succeed to pass the private key that in " << ME_INFO << std::endl;
		return false;
	}

	file_manager->close();
	return true;
}
	
/* The function stores clients information in me.info file, it also generates private key, the function returns true if wrote the information in the file without errors,
   and return false if did not succseed to do so. */
bool Client::storeClientInfo() {
	if (!file_manager->open(ME_INFO, true))
	{
		std::cout << "Error: Did not succeed to open " << ME_INFO << std::endl;
		return false;
	}

	// Write username
	if (!file_manager->writeLine(c_username))
	{
		std::cout << "Error: did not succees to write username into " << ME_INFO << std::endl;
		return false;
	}

	// Write Clients if in hexadecimal base.
	const auto hexClientID = Utils::hex(c_id.client_id, sizeof(c_id.client_id));
	if (!file_manager->writeLine(hexClientID))
	{
		std::cout << "Error: did not succees to write Clients ID into " << ME_INFO << std::endl;
		return false;
	}

	// Write Base64 encoded private key
	delete rsa_wrapper;
	rsa_wrapper = new RSAPrivateWrapper();
	const auto RSAprivate_key = rsa_wrapper->getPrivateKey();		// Generates private key
	const auto encodedKey = Utils::encodeBase64(RSAprivate_key);

	if (!file_manager->write(reinterpret_cast<const uint8_t*>(encodedKey.c_str()), encodedKey.size()))
	{
		std::cout << "Error: did not succees to write Clients private key into " << ME_INFO << std::endl;
		return false;
	}

	file_manager->close();
	return true;
}

/* The function handles the registration process, returns true if succseed and false otherwise. */
bool Client::registration() {

	RegistrationRequest request;
	RegistrationSuccessResponse response;		 

	if (!setTransferData()) {		
		return false;
	}
	
	std::string username = c_username;

	for (auto c : username) {
		if (!std::isalnum(c)) {
			std::cout << "Invalid username: username shoud contain only characters and numbers, other symbols forbiden" << std::endl;
			return false;
		}
	}

	request.req_header.payloadSize = sizeof(request.payload);
	strcpy_s(reinterpret_cast<char*>(request.payload.client_name.name), NAME_SIZE, username.c_str());

	socket_manager->connect();

	if (!socket_manager->sendRequest(reinterpret_cast<uint8_t* const>(&request), sizeof(request))) {
		std::cout << "Error: Something went wrong while tried to SEND request." << std::endl;
		socket_manager->close();	
		return false;
	}
	if (!socket_manager->receiveResponse(reinterpret_cast<uint8_t* const>(&response), sizeof(response))) {
		std::cout << "Error: Something went wrong while tried to RECIEVE response." << std::endl;
		socket_manager->close();
		return false;
	}

	// Check recieved header
	if (!isExpectedHeader(response.res_header, RESPONSE_REGISTRATION_SUCCESS)) {
		// Something went wrong with header check.
		socket_manager->close();
		return false; 
	}

	// now need to store client info.
	if (response.res_header.code == RESPONSE_REGISTRATION_SUCCESS) {
		c_id = response.cid;
		// Private key initialized here as well
		if (!storeClientInfo()) {
			std::cout << "Error: Something went wrong while tried to store information (registration) " << std::endl;
			socket_manager->close();
			return false;
		}
	}
	else {
		std::cout << "The server denied your registration. " << std::endl;
		socket_manager->close();
		return false;
	}
	socket_manager->close();
	return true;
}

/* The function checks if response header that client recieves from the server is the one that he expects, if the header is expected, the function
   calculates expected paylod size to make sure that no extra information arrived. The function returns true if it is the right header,
   and false otherwise. */
bool Client::isExpectedHeader(const ResponseHeader& response_header, const ServerResponseCode expected_header_code) {

	if (response_header.code == RESPONSE_SERVER_ERROR){
		std::cout << "Error: Global server error. Code:"<< RESPONSE_SERVER_ERROR << std::endl;
		return false;
	}

	if (response_header.code != expected_header_code)		// Not as expected
	{
		if (((expected_header_code == RESPONSE_REGISTRATION_SUCCESS) && (response_header.code == RESPONSE_REGISTRATION_FAILURE))) {
			;	// Do nothing, this is a special case.	(Expected for registration to succseed but it failed)
		}
		else{
			if((expected_header_code == RESPONSE_RECONNECTION_ACCEPTED) && (response_header.code == RESPONSE_RECONNECTION_DENIED))
			{
				;	// Do nothing, this is a special case.	(Expected reconnection accseptence but it denied)
			}
			else {
				std::cout << "ERROR: Unexpected response code received: " << response_header.code << ". Expected for: " << expected_header_code << std::endl;
				return false;
			}
		}
	}

	uint32_t expectedPayloadSize = 0;

	switch (response_header.code)
	{
	case RESPONSE_REGISTRATION_SUCCESS:
	{
		std::cout << std::endl << std::endl << "REGISTRATION SUCCESS" << std::endl << std::endl;
		expectedPayloadSize = sizeof(RegistrationSuccessResponse) - sizeof(ResponseHeader);	// sizeof(ClientID) expected
		break;
	}
	case RESPONSE_REGISTRATION_FAILURE:
	{
		std::cout << std::endl << std::endl << "REGISTRATION FAILURE" << std::endl << std::endl;
		expectedPayloadSize = 0;		//no payload expected
		break;
	}
	case RESPONSE_KEY_EXCHANGE:
	{
		expectedPayloadSize = response_header.payloadSize;			// Encrypted key can be in different sizes.
		break;
	}
	case RESPONSE_FILE_DELIVERED_WITH_CRC:
	{
		expectedPayloadSize = sizeof(SendFileResponse) - sizeof(ResponseHeader);
		break;
	}
	case RESPONSE_MESSAGE_DELIVERED:
	{
		expectedPayloadSize = sizeof(MessageDeliveredResponse) - sizeof(ResponseHeader);	// sizeof(ClientID) expected
		break;
	}
	case RESPONSE_RECONNECTION_ACCEPTED:
	{
		expectedPayloadSize = response_header.payloadSize;			// While reconecting, new key genereated and encrypted. Encrypted key can be in different sizes.
		break;		
	}
	case RESPONSE_RECONNECTION_DENIED:
	{
		expectedPayloadSize = sizeof(ReconectionDeniedResponse) - sizeof(ResponseHeader);	// sizeof(ClientID) expected
		break;
	}
	default:
	{
		return true;  // variable payload size. 
	}
	}
	
	// If payload size is not what expected.
	if (response_header.payloadSize != expectedPayloadSize)	
	{
		return false;
	}
	
	return true;
}

/* The function handles the key exchange process, it sends clients public key, and recieves AES key encrypted with the public key by the server,
*  decrypt the AES key by clients private key, and stores recieved AES key. The function returns true if passed as expected
*  and false otherwise.
*/
bool Client::sendPublicKey() {

	SendPublicKeyRequest request;
	SendPublicKeyResponse response;

	
	if (c_username == "") {
		std::cout << "Error: Username is not initialized " << std::endl;
		return false;
	}

	//Set client ID
	memcpy(request.req_header.cid.client_id, c_id.client_id, sizeof(c_id.client_id));
	
	const auto RSApublic_key = rsa_wrapper->getPublicKey();

	if (RSApublic_key.size() != PUBLIC_KEY_SIZE) {
		std::cout << "Error: Invalid public key size: "<< RSApublic_key.size()<<" and supposed to be:" << PUBLIC_KEY_SIZE << std::endl;
		return false;
	}

	// Prepare the request
	request.req_header.payloadSize = sizeof(request.payload);
	strcpy_s(reinterpret_cast<char*>(request.payload.client_name.name), NAME_SIZE, c_username.c_str());
	memcpy(request.payload.key_pub.publicKey, RSApublic_key.c_str(), sizeof(request.payload.key_pub.publicKey));

	socket_manager->connect();

	// Send the request
	if (!socket_manager->sendRequest(reinterpret_cast<uint8_t* const>(&request), sizeof(request))) {			//TODO:: check if needed const
		std::cout << "Error: Something went wrong while tried to SEND the request." << std::endl;
		socket_manager->close();	
		return false;
	}
	// Recieve response
	if (!socket_manager->receiveResponse(reinterpret_cast<uint8_t* const>(&response), sizeof(response))) {
		std::cout << "Error: Something went wrong while tried to RECIEVE the response." << std::endl;
		socket_manager->close();
		return false;
	}

	// Check the header
	if (!isExpectedHeader(response.res_header, RESPONSE_KEY_EXCHANGE)) {
		socket_manager->close();
		return false;
	}
	
	std::string key;
	key = rsa_wrapper->decrypt(response.payload.encrypted_sym_key, response.res_header.payloadSize - CLIENT_ID_SIZE);
	
	// Set clients public key
	public_key = request.payload.key_pub;
	// Set symetric key for the client 
	memcpy(symetric_key.symetricKey, key.data(), SYMETRIC_KEY_SIZE);
	
	socket_manager->close();

	return true; 
}

/* The function handles reconnection process, in case that the client is already registered he doest need to generate key once again, 
   he just send it and recieves new AES key for next file encryption. */
bool Client::reconnect() {

	ReconnectionRequest request;
	ReconectionApprovedResponse response;

	// Preparint the request
	memcpy(request.req_header.cid.client_id, c_id.client_id, sizeof(c_id.client_id));
	request.req_header.payloadSize = sizeof(request.payload);
	strcpy_s(reinterpret_cast<char*>(request.payload.client_name.name), NAME_SIZE, c_username.c_str());

	socket_manager->connect();

	// Sending request
	if (!socket_manager->sendRequest(reinterpret_cast<uint8_t* const>(&request), sizeof(request))) {			//TODO:: check if needed const
		std::cout << "Something went wrong while tried to send Reconnect request" << std::endl;
		socket_manager->close();	// dont leave the connection open
		return false;
	}
	// Recieving response
	if (!socket_manager->receiveResponse(reinterpret_cast<uint8_t* const>(&response), sizeof(response))) {
		std::cout << "Something went wrong while tried to recieve Reconnect response" << std::endl;
		socket_manager->close();
		return false;
	}
	// Check header
	if (!isExpectedHeader(response.res_header, RESPONSE_RECONNECTION_ACCEPTED)) {
		socket_manager->close();
		return false;
	}

	// now need to store client info.
	if (response.res_header.code == RESPONSE_RECONNECTION_ACCEPTED) {
		std::string key;
		key = rsa_wrapper->decrypt(response.payload.encrypted_sym_key, response.res_header.payloadSize - CLIENT_ID_SIZE);

		// Set NEW symetric key for the client 
		memcpy(symetric_key.symetricKey, key.data(), SYMETRIC_KEY_SIZE);

	}
	else {	// RESPONSE_RECONNECTION_DENIED
		std::cout << "Reconnection not approved " << std::endl;	
		socket_manager->close();
		return false;
	}
	socket_manager->close();
	return true;
}


/*  The function handles the sending file process, it checks for file to send, read it, calculates CRC value, encrypt it with AES key,
	and sends to the server. After recieving response from the server it checks what CRC value server got to make sure that the file transfered
	as expected, and sends coresponding request with walid or invalid CRC. The function returns FAILURE, VALID_CRC or INVALID_CRC, depends
	on what server responded or if any error appiered.*/
int Client::sendFile() {
	const int FAILURE = 0;			// Error
	const int VALID_CRC = 1;		// Valid crc recieved
	const int INVALID_CRC = 2;		// Invalid crc recieved

	SendFileRequest request;
	SendFileResponse response;

	if (!setTransferData()) {
		return FAILURE;
	}

	const std::string filename = file_to_send;
	std::string fileName;
	// find the last occurrence of a path separator
	size_t separatorPos = filename.find_last_of("/\\");

	// extract the substring after the last separator
	if (separatorPos != std::string::npos) {
		fileName = filename.substr(separatorPos + 1);
	}
	else {
		fileName = filename;
	}

	//Set client ID
	memcpy(request.req_header.cid.client_id, c_id.client_id , sizeof(c_id.client_id));

		
	if (filename.empty()) {
		std::cout << "Error: File name is empty." << std::endl;
		return FAILURE;
	}

	uint32_t crc_value = file_manager->calculate_crc(file_to_send);		// calculates CRC value of the file

	//std::cout << "The CRC value of file: " << file_to_send << " is: " << crc_value << std::endl;

	uint8_t* file = nullptr;
	size_t bytes;

	// After this "file" will point to the file byte stream, and bytes will have the size of the file in bytes.
	if (!file_manager->readFileIntoBuffer(filename, file, bytes)) {
		std::cout << "Error: File: " << filename << " not found." << std::endl;
		return FAILURE;
	}

	AESWrapper aes(symetric_key);
	const std::string encrypted = aes.encrypt(file, bytes);				//Has encrypted file

	uint8_t* content = nullptr;
	request.payload.contentSize = encrypted.size();						// content size = size of encrypted string
	content = new uint8_t[request.payload.contentSize];					// buffer for the content
	memcpy(content, encrypted.c_str(), request.payload.contentSize);	// copying encrypted string into content buffer

	delete[] file;			// done with the file, clients responsability to free the memmory.

	/* *******************************************SENDING FILE****************************************************/

	//Creating full request, with our regular request + content 

	size_t fileSize;			//size of new request
	uint8_t* fileToSend;		//new request

	request.req_header.payloadSize = sizeof(request.payload) + request.payload.contentSize;	
	memcpy(request.payload.file_name.name, fileName.c_str(), NAME_SIZE);	//File name 

	//content has the encrypted file.
	if (content == nullptr)
	{
		fileToSend = reinterpret_cast<uint8_t*>(&request);
		fileSize = sizeof(request);
	}
	else
	{
		fileToSend = new uint8_t[sizeof(request) + request.payload.contentSize];		// Final buffer to send
		memcpy(fileToSend, &request, sizeof(request));									// Set actual request
		memcpy(fileToSend + sizeof(request), content, request.payload.contentSize);		// Add the content of the file
		fileSize = sizeof(request) + request.payload.contentSize;						// total size
	}

	socket_manager->connect();
	// Send request
	if (!socket_manager->sendRequest(fileToSend, fileSize))
	{
		delete[] content;		// Not sent, can free the memmory.
		std::cout << " Error: Failed while tried to send \"Send File request\" " << std::endl;
		socket_manager->close();
		return FAILURE;
	}

	delete[] content;			// Already sent, can free the memmory.

	// Recieve response
	if (!socket_manager->receiveResponse(reinterpret_cast<uint8_t* const>(&response), sizeof(response))) {
		std::cout << "Error: Something went wrong while tried to recieve Send File response" << std::endl;
		socket_manager->close();
		return FAILURE;
	}
	socket_manager->close();	// Done for the first request
	// Check servers response

	if (!isExpectedHeader(response.res_header, RESPONSE_FILE_DELIVERED_WITH_CRC)) {
		socket_manager->close();
		return FAILURE;
	}

	// std::cout << "Recieved crc value is: " << response.payload.calculated_crc << std::endl;

	// Server does 1 request at a time.
	socket_manager->connect();

	// If CRC from the server is right.
	if (crc_value == response.payload.calculated_crc ) {
		//std::cout << "Valid CRC" << std::endl;
		// Prepare Valid CRC request
		ValidCrcRequest validCksumRequest;
		memcpy(validCksumRequest.payload.file_name.name, filename.c_str(), NAME_SIZE);
		validCksumRequest.req_header.payloadSize = sizeof(validCksumRequest.payload);
		memcpy(validCksumRequest.req_header.cid.client_id, c_id.client_id, sizeof(c_id.client_id));

		// Send request
		if (!socket_manager->sendRequest(reinterpret_cast<uint8_t* const>(&validCksumRequest), sizeof(validCksumRequest))) {			//TODO:: check if needed const
			std::cout << "Something went wrong while tried to send Reconnect request" << std::endl;
			socket_manager->close();	// dont leave the connection open
			return FAILURE;
		}

		MessageDeliveredResponse messageDlvResponse;	// expect for approval message

		// Recieve responce
		if (!socket_manager->receiveResponse(reinterpret_cast<uint8_t* const>(&messageDlvResponse), sizeof(messageDlvResponse))) {
			std::cout << "Something went wrong while tried to recieve Send File response" << std::endl;
			socket_manager->close();
			return FAILURE;
		}		

		// Header check
		if (!isExpectedHeader(messageDlvResponse.res_header, RESPONSE_MESSAGE_DELIVERED)) {
			socket_manager->close();
			return FAILURE;
		}

		std::cout << "File: " <<file_to_send <<" securly sent to the server and stored." << std::endl;

		socket_manager->close();
		return VALID_CRC;				// Return valid CRC to controller
	}
	else {
		
		//std::cout << "This is not correct CRC value" << std::endl;

		// Prepare invalid crc request
		InvalidCrcRequest invalidCksumrquest; 		
		memcpy(invalidCksumrquest.payload.file_name.name, filename.c_str(), NAME_SIZE);
		invalidCksumrquest.req_header.payloadSize = sizeof(invalidCksumrquest.payload);
		memcpy(invalidCksumrquest.req_header.cid.client_id, c_id.client_id, sizeof(c_id.client_id));

		// Send request
		if (!socket_manager->sendRequest(reinterpret_cast<uint8_t* const>(&invalidCksumrquest), sizeof(invalidCksumrquest))) {	
			std::cout << "Error: Something went wrong while tried to send Invalid CRC request" << std::endl;
			socket_manager->close();	
			return false;
		}

		socket_manager->close();
		return INVALID_CRC;				// Return invalid CRC to controller
	}
}

// The function handles the process of sending final invalid CRC request, after the client recieved 3 times invalid CRC request he sends 
// final invalid CRC request and return true if succseed and false otherwise.
bool Client::sendFinalInvalidCrcRequest() {

	FinalInvalidCrcRequest request;

	if (!setTransferData()) {
		socket_manager->close();
		return false;
	}

	const std::string filename = file_to_send;

	memcpy(request.payload.file_name.name, filename.c_str(), NAME_SIZE);
	request.req_header.payloadSize = sizeof(request.payload);
	memcpy(request.req_header.cid.client_id, c_id.client_id, sizeof(c_id.client_id));

	socket_manager->connect();

	if (!socket_manager->sendRequest(reinterpret_cast<uint8_t* const>(&request), sizeof(request))) {			//TODO:: check if needed const
		std::cout << "Error: Something went wrong while tried to send Final invalid CRC request" << std::endl;
		socket_manager->close();	
		return false;
	}

	MessageDeliveredResponse messageDlvResponse;	// expect for approval message

	// Recieve responce
	if (!socket_manager->receiveResponse(reinterpret_cast<uint8_t* const>(&messageDlvResponse), sizeof(messageDlvResponse))) {
		std::cout << "Something went wrong while tried to recieve Send File response" << std::endl;
		socket_manager->close();
		return false;
	}

	// Header check
	if (!isExpectedHeader(messageDlvResponse.res_header, RESPONSE_MESSAGE_DELIVERED)) {
		socket_manager->close();
		return false;
	}
	std::cout << "The server could not receive your file. " << std::endl;

	socket_manager->close();
	return true;
}