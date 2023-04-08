#pragma once

#include "Client.h"
#include <iomanip>      // std::setw		for menu vizualization


class Controller
{
public:

	void initialize();
	void display_menu() const;
	void handle_menu();
	

private:

	Client client;

	class Menu
	{
	public:
		enum class Option
		{
			REGISTRATION = 1100,			//Registeration with the server
			SEND_PUBLIC_KEY = 1101,			//Sending public key to the server
			RECONNECT = 1102,				//In Case That the client is already registered
			SEND_FILE = 1103,				//Send file		
			MENU_EXIT = 9999
		};


		//Constructors

		Menu() :	number(5), option_code(Option::MENU_EXIT) {}
		
		Menu(const unsigned int num, const Option val,bool registratition, std::string descript):
						number(num), option_code(val),registratition(registratition), description(descript){}
		

		int getValue() const { 
			return number; 
		}

		std::string getDescription() const { 
			return description;
		}

		Option getOptionCode() const {
			return option_code;
		}

		//Overload for display
		friend std::ostream& operator<<(std::ostream& os, const Menu& option) {
			os << std::setw(2) << option.number 
							   << ".   " << option.description;
			return os;
		}

	private:
		unsigned int	number;				// Option number
		Option			option_code;		// Opcode
		bool			registratition;		// Registratition needed or not
		std::string		description;		
	};



private:

	const std::vector<Menu> menu{
		{ 1, Menu::Option::REGISTRATION,	false,	"Registrater to the server."},
		{ 2, Menu::Option::RECONNECT,		true,	"Reconnect to the server and send your file. (Once you already registered)"},
		{ 3, Menu::Option::SEND_FILE,		true,	"Exchange keys and send your file."},
		{ 4, Menu::Option::MENU_EXIT,		false,	"Exit."}
	};

	std::string readInput(std::string info_request) const;
	Menu validateUserChoise(std::string str);
	void sendFileHandle();

	//system call			
	void pause() const { system("pause"); }   // pause menu
};