#pragma once
#include <string>
#include <fstream>

class FileManager
{
public:

    //      Constructors / Destructors
    FileManager();   
    virtual ~FileManager(); 

    //      Functions
    bool open(const std::string& path, bool write = false);
    void close();
    bool read(uint8_t* const dest, const size_t bytes) const;
    bool write(const uint8_t* const src, const size_t bytes) const;
    bool readLine(std::string& line) const;
    bool writeLine(const std::string& line) const;
    bool readServerInfo();
    bool readFileIntoBuffer(const std::string& filepath, uint8_t*& file, size_t& bytes);
    size_t size() const;

    uint32_t calculate_crc(const std::string& filename);

private:
    std::fstream* fstream;
    bool isOpen;  // file status (open/closed)
};