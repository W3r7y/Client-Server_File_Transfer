#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <bitset>

class Utils
{
public:
	static std::string hex(const uint8_t* buffer, const size_t size);
	static std::string unhex(const std::string& hexString);
	static std::string encodeBase64(const std::string& str);
	static std::string decodeBase64(const std::string& str);
	static std::string hex_to_string(const std::string& hex);
	static std::string stringToHex(const std::string& input);
	static bool isValidFilePath(const std::string path);
};