#include <cstdlib>
#include <cstring>
#include <iostream>
#include <boost/asio.hpp>
#include <fstream>

#include  "Client.h"
#include  "Controller.h"

using boost::asio::ip::tcp;


void clear(char message[], int length) {
	for (int i = 0; i < length; i++)
		message[i] = '\0';
}


int main()
{
	const int max_length = 1024;
	try
	{
		
		boost::asio::io_context io_context;
		tcp::socket s(io_context);
		tcp::resolver resolver(io_context);

		Controller c; 
		c.initialize();
		c.handle_menu();
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
}