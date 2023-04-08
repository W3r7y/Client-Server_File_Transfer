

#include "FileManager.h"
#include <fstream>
#include <iostream>
#include <boost/crc.hpp>

FileManager::FileManager() : fstream(nullptr), isOpen(false)	
{
}

FileManager::~FileManager()
{
	close();
}


//	The function opens file for read or write. In case that the file does not existed before, it creates it in the same directory.
bool FileManager::open(const std::string& path, bool write) {

	if (path.empty())
		return false;

	const auto flags = write ? (std::fstream::binary | std::fstream::out) : (std::fstream::binary | std::fstream::in);

	try {
		close(); // close if was open before alocating new one.
		fstream = new std::fstream;
		fstream->open(path, flags);
		isOpen = fstream->is_open();
	}

	catch(...){	//something went wrong
		isOpen = false;
	}	
	return isOpen;
}


// The functiom closes file stream
void FileManager::close()
{
	try
	{
		if (fstream != nullptr)
			fstream->close();
	}
	catch (...)
	{
		// Possible Error Message
		std::cout << " Error, failed to close the file" << std::endl;
	}
	delete fstream;
	fstream = nullptr;
	isOpen = false;
}


/* The function calculate the file size which is opened by file stream. */
size_t FileManager::size() const
{
	if (fstream == nullptr || !isOpen)
		return 0;
	try
	{
		const auto cur = fstream->tellg();
		fstream->seekg(0, std::fstream::end);
		const auto size = fstream->tellg();
		if ((size <= 0) || (size > UINT32_MAX))    // do not support more than uint32 max size files. (up to 4GB).
			return 0;
		fstream->seekg(cur);    // restore position
		return static_cast<size_t>(size);
	}
	catch (...)
	{
		return 0;
	}
}

/* This function attempts to read a sequence of bytes from an open file and store them in the memory location pointed to by the dest parameter. */
bool FileManager::read(uint8_t* const dest, const size_t bytes) const
{
	if (fstream == nullptr || !isOpen)
		return false;
	try
	{
		fstream->read(reinterpret_cast<char*>(dest), bytes);
		return true;
	}
	catch (...)
	{
		return false;
	}
}


/*  This function attempts to write a sequence of bytes to an open file. Reciese pointer to the bytes, and number of them.
	Return true if everything worked fine, and else otherwise. */
bool FileManager::write(const uint8_t* const src, const size_t bytes) const
{
	if (fstream == nullptr || !isOpen)
		return false;
	try
	{
		fstream->write(reinterpret_cast<const char*>(src), bytes);
		return true;
	}
	catch (...)
	{
		return false;
	}
}

/* This function reads a single line from an open file and store it in the provided string parameter. */
bool FileManager::readLine(std::string& line) const{
	if (fstream == nullptr || !isOpen)
		return false;
	try
	{
		if (!std::getline(*fstream, line) || line.empty())
			return false;
		return true;
	}
	catch (...)
	{
		return false;
	}
}

/* The function writes a new line to a file, new line passed as parameter to the function. */
bool FileManager::writeLine(const std::string& line) const
{
	std::string newline = line;
	newline.append("\n");
	return write(reinterpret_cast<const uint8_t*>(newline.c_str()), newline.size());  
}

/*  The function attempts to read the entire contents of a file specified by the filepath parameter into a buffer of uint8_t bytes.
	The buffer pointer and the size of the file in bytes are returned through the file and bytes parameters respectively. 
	The function returns true if everything worked as expected.*/
bool FileManager::readFileIntoBuffer(const std::string& filepath, uint8_t*& file, size_t& bytes)
{
	if (!open(filepath))
		return false;

	bytes = size();
	if (bytes == 0)
		return false;

	file = new uint8_t[bytes];
	const bool success = read(file, bytes);
	if (!success)
	{
		delete[] file;
	}
	close();
	return success;
}

/* This function calculates the CRC checksum value of a file with the given filename. The function returns calculated CRC value. */
uint32_t FileManager::calculate_crc(const std::string& filename) {

	// Open the file in binary mode	
	std::ifstream file(filename, std::ios::binary);

	// Calculate the CRC checksum value using Boost C++ library
	boost::crc_32_type result;
	char buffer[4096];
	while (file.read(buffer, sizeof(buffer))) {
		result.process_bytes(buffer, sizeof(buffer));
	}
	result.process_bytes(buffer, file.gcount());

	// Close the file
	file.close();

	return result.checksum();
}