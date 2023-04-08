
#include "Utils.h"
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <fstream>
#include <base64.h>
#include <iostream>

/* This function converts a buffer of bytes, specified by the buffer pointer and size argument, into a hex string. */
std::string Utils::hex(const uint8_t* buffer, const size_t size)
{
	if (size == 0 || buffer == nullptr)
		return "";
	const std::string byteString(buffer, buffer + size);
	if (byteString.empty())
		return "";
	try
	{
		return boost::algorithm::hex(byteString);
	}
	catch (...)
	{
		return "";
	}
}

/* This function converts a hex string, into a string of bytes. */
std::string Utils::unhex(const std::string& hexString)
{
	if (hexString.empty())
		return "";
	try
	{
		return boost::algorithm::unhex(hexString);
	}
	catch (...)
	{
		return "";
	}
}

/* This function takes a string as input and returns its Base64 encoded representation as another string. */
std::string Utils::encodeBase64(const std::string& str)
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		)
	);

	return encoded;
}

/* This function decodes a given Base64-encoded string and returns the decoded string. */
std::string Utils::decodeBase64(const std::string& str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		) 
	);

	return decoded;
}

/* This function takes a string of hexadecimal characters as input and returns the corresponding string of bytes. */
std::string Utils::hex_to_string(const std::string& hex) {
	// have to be even, 1 hexidecimal character is 4 bit, to conver to byte we need 8 bits (2 hexadecimal characters)
	if (hex.size() % 2 != 0) {			
		return "";
	}

	const size_t byte_count = hex.size() / 2;
	uint8_t* bytes = new uint8_t[byte_count];

	std::stringstream ss(hex);
	for (size_t i = 0; i < byte_count; i++) {
		uint16_t byte_value;
		ss >> std::hex >> byte_value;
		bytes[i] = static_cast<uint8_t>(byte_value);
	}

	std::string result(reinterpret_cast<char*>(bytes), byte_count);
	delete[] bytes;
	return result;
}

/* This function takes a string input and returns its hexadecimal representation as a string. */
std::string Utils::stringToHex(const std::string& input)
{
	std::stringstream ss;
	for (int i = 0; i < input.length(); ++i)
		ss << std::hex << (int)input[i];
	std::string mystr = ss.str();
	return mystr;
}

/* This function takes a string path representing a file path and checks if the file exists and is accessible for reading. */
bool Utils::isValidFilePath(const std::string path) {
	std::ifstream file(path.c_str());
	return file.good();
}
