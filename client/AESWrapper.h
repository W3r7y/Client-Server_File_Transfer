#pragma once
#include <string>
#include "request.h"

class AESWrapper
{
public:
	AESWrapper(const SymetricKey& symKey);
	virtual ~AESWrapper() = default;
	AESWrapper(const AESWrapper& other) = delete;
	AESWrapper(AESWrapper&& other) noexcept = delete;

	AESWrapper& operator=(const AESWrapper& other) = delete;
	AESWrapper& operator=(AESWrapper&& other) noexcept = delete;

	SymetricKey getKey() const { return _key; }

	std::string encrypt(const std::string& plain) const;
	std::string encrypt(const uint8_t* plain, size_t length) const;
	std::string decrypt(const uint8_t* cipher, size_t length) const;

private:
	SymetricKey _key;
};