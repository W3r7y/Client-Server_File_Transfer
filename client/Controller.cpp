#include "Controller.h"
#include <iostream>
#include <boost/algorithm/string/trim.hpp>

/* Controller initialize function */
void Controller::initialize(){
	client.setServerInfo();
	client.setClientInfo();
	client.setTransferData();
}


/* The function displays the menu */
void Controller::display_menu() const {
	std::cout << std::endl<< std::endl<< std::endl;
	std::cout << "===========   INITIAL MENU   ==========" << std::endl << std::endl;
	for (const auto& opt : menu)
		std::cout << opt << std::endl;
}

/* The function reads users input without the starting white symbols or tailing ones */
std::string Controller::readInput(std::string info_request) const
{
	std::cout << info_request << std::endl;
	std::string input;

	do
	{
		getline(std::cin, input);
		boost::algorithm::trim(input);
	} while (input.empty());

	return input;
}


/* The function validates users input, in case that it is not legal sets up default option.*/
Controller::Menu Controller::validateUserChoise(std::string str) {

	//Default option for invalid user choise
	Menu invalid(0, Menu::Option::MENU_EXIT,false, "Invalid Option.");

	for (Menu option : menu) {
		if (str == std::to_string(static_cast<uint32_t>(option.getValue()))) {			
			return option;
		}
	}

	return invalid;
}


/* handle_menu function handles the main menu of the program asks the user for hes willand does what he chooses,
*  The user can choose to register, make key exchange, reconnect to the server, or send he's file.
*/
void Controller::handle_menu() {
	
	Menu menu_option;
	std::string user_choise;

	do{
		display_menu();
		user_choise = readInput("What is your choise?");
		menu_option = validateUserChoise(user_choise);
		if (menu_option.getValue() == 0) {
			int tries = 3;
			do{
				tries--;
				std::cout << "Invalid choice, try again" << std::endl;
				user_choise = readInput("What is your choise?");
				menu_option = validateUserChoise(user_choise);
				if (menu_option.getValue() != 0)
					break;
			} while (tries > 0 );
		}

		//General switch

		switch (menu_option.getOptionCode())
		{
		case Menu::Option::MENU_EXIT:
		{
			std::cout << "Exiting menu. Good bye!" << std::endl;
			pause();
			exit(1);
		}

		case Menu::Option::REGISTRATION:
		{
			bool registrationSucseed;
			registrationSucseed = client.registration();

			if (registrationSucseed) {
				std::cout << "You are successfully registred!" << std::endl;
			}
			break;
		}

		case Menu::Option::RECONNECT:
		{
			if (!client.setClientInfo()) {
				//std::cout << "Error: Failed while tried to set data from:" << ME_INFO << std::endl;
				break;
			}
			if (!client.reconnect()) {
				std::cout << "Did not succseed to reconnect" << std::endl;
			}
			else {
				std::cout << "Successfuly reconnected" << std::endl;
				sendFileHandle();
			}
			break;
		}
		case Menu::Option::SEND_FILE:
		{
			if (!client.setClientInfo()) {
				//std::cout << "Error: Failed while tried to set data from:" << ME_INFO << std::endl;
				break;
			}
			if (!client.sendPublicKey()) {
				std::cout << "Something went wrond while tried to send public key." << std::endl;
			}
			else {
				std::cout << "Successfuly sent and recieved a key" << std::endl;
				sendFileHandle();
			}
			break;
		}
		default:
			break;
		}
	} while (menu_option.getValue() != 0 && 
		(menu_option.getOptionCode() != Menu::Option::SEND_FILE && menu_option.getOptionCode() != Menu::Option::RECONNECT));	
		// If you choosed to send file or reconnect, the programm will stop after finishing the task.
		// It is possible to change this while loop by repieting itself unless the user chooses to stop.
}

// The function handles the file sending process, and checks if valid crc returned or not, if CRC value invalid, the function tries to send
// the file 3 more time, if all failed, sends final invalid crc request.
void Controller::sendFileHandle() {
	const int FAILURE = 0;			// Error 
	const int VALID_CRC = 1;		// Valid crc case
	const int INVALID_CRC = 2;		// Invalid crc case

	int result = client.sendFile();
	if (result == FAILURE) {
		std::cout << "Failed to send file" << std::endl;
	}
	else {
		if (result == VALID_CRC) {
			//std::cout << "File sent successfully" << std::endl;
		}
		if (result == INVALID_CRC) {
			// Try to send the file 3 times.
			int count = 3;
			do {
				std::cout << "Tring to send " << count << " more times" << std::endl;
				result = client.sendFile();
				if (result == VALID_CRC) {
					std::cout << "File sent successfully" << std::endl;
					break;
				}
				else {
					count--;
				}
			} while (count != 0);

			// If reached here have to send final invalid crc request
			std::cout << "Tried to send 3 additional times without success, sending final invalid crc request" << std::endl;
			client.sendFinalInvalidCrcRequest();
		}
	}
	return;
}