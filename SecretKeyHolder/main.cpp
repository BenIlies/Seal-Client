#include "seal/seal.h"
#include <iostream>
#include <string>
#include <WS2tcpip.h>
#define STOP_MSG "Stop data"
#define END_BUFFER "End of buffer"
#define SIZE_BUFFER 8192
#pragma comment (lib, "ws2_32.lib")

/*
	Important :
	There might be an issue appearing if one of the buffer sent over the tcp connection is a multiple of SIZE_BUFFER.
	Hence, in the future it could be interesting to fix it
*/

using namespace seal;

int main()
{
	#ifndef SEAL_USE_ZLIB
		std::cerr << "ZLIB support is not enabled; this example is not available." << std::endl;
		std::cerr << std::endl;
		return -10;
	#else
		std::string ipAddress = "127.0.0.1";
		int port = 54000;


		// Initialize Winsock
		WSAData data;
		WORD ver = MAKEWORD(2, 2);
		int wsResult = WSAStartup(ver, &data);

		if (wsResult != 0)
		{
			std::cerr << "Can't start Winsock, Err #" << wsResult << std::endl;
			return -1;
		}


		// Create socket
		SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock == INVALID_SOCKET)
		{
			std::cerr << "Can't create socket, Err #" << WSAGetLastError << std::endl;
			WSACleanup();
			return -2;
		}

		// Fill in a hint structure
		sockaddr_in hint;
		hint.sin_family = AF_INET;
		hint.sin_port = htons(port);
		inet_pton(AF_INET, ipAddress.c_str(), &hint.sin_addr);

		// Connect to server
		int connResult = connect(sock, (sockaddr*)&hint, sizeof(hint));
		if (connResult == SOCKET_ERROR)
		{
			std::cerr << "Can't connect to server, Err #" << WSAGetLastError << std::endl;
			closesocket(sock);
			WSACleanup();
			return -3;
		}

		// Do-while loop to send and receive data
		char buf[SIZE_BUFFER];
		std::string userInput;

		std::stringstream parms_stream;
		std::stringstream pk_stream;
		EncryptionParameters parms;

		ZeroMemory(buf, SIZE_BUFFER);
		// We receive the SEAL context from the server and load it
		int bytesReceived = recv(sock, buf, SIZE_BUFFER, 0);
		std::cout << "SEAL context received from server, bytes received : " << bytesReceived << std::endl;
		parms_stream << std::string(buf, bytesReceived);
		parms.load(parms_stream);

		// We create the secret and public key
		parms_stream.seekg(0, parms_stream.beg);
		auto context = SEALContext::Create(parms);
		KeyGenerator keygen(context);
		auto sk = keygen.secret_key();
		auto pk = keygen.public_key();
		pk.save(pk_stream);

		// We send the public key to the server
		int bytesSent = send(sock, pk_stream.str().c_str(), pk_stream.str().length(), 0);
		std::cout << "Public key sent to the server, bytes sent : " << bytesSent << std::endl;
		


		// The client input the different data that will be encrypted
		std::vector <double> age;
		std::string input;
		do
		{
			std::cout << "> ";
			getline(std::cin, input);
			if (input.size() > 0)
			{
				try {
					age.push_back(stod(input));
				}
				catch (const std::invalid_argument&)
				{
					std::cout << "Please enter valid age" << std::endl;
				}
			}
			else
			{
				break;
			}
		} while (true);
		
		if (age.size() == 0)
		{
			std::cerr << "No values for the age" << WSAGetLastError << std::endl;
			closesocket(sock);
			WSACleanup();
			return -4;
		}

		// We then encode and encrypt our plaintext
		double scale = pow(2.0, 20);
		CKKSEncoder encoder(context);

		Encryptor encryptor(context, pk);
		Ciphertext encrypted1, encrypted2;

		// We send the data to the server
		Plaintext age_plain;
		int sumAgeInTheory = 0;
		for (double i : age)
		{
			std::stringstream data_stream;
			Plaintext age_plain;
			Ciphertext encryption_age;
			encoder.encode(i, scale, age_plain);
			encryptor.encrypt(age_plain, encryption_age);
			encryption_age.save(data_stream);
			bytesSent = send(sock, data_stream.str().c_str(), data_stream.str().length(), 0);
			sumAgeInTheory += (int)i;
			recv(sock, buf, SIZE_BUFFER, 0);
		}
		send(sock, STOP_MSG, (unsigned)strlen(STOP_MSG), 0);
		recv(sock, buf, SIZE_BUFFER, 0);
		std::cout << "Expected sum of all peoples age : " << sumAgeInTheory << std::endl;


		

		// We receive back the encrypted data
		std::stringstream data_stream;
		do
		{
			ZeroMemory(buf, SIZE_BUFFER);
			bytesReceived = recv(sock, buf, SIZE_BUFFER, 0);
			if (std::string(buf, bytesReceived) != END_BUFFER)
			{
				data_stream << std::string(buf, bytesReceived);
			}
		} while (bytesReceived == SIZE_BUFFER);
		std::cout << "Encrypted sum succesfully received from server" << std::endl;


		// We decrypt the sum
		Decryptor decryptor(context, sk);
		Ciphertext encrypted_result;
		encrypted_result.load(context, data_stream);

		Plaintext plain_result;
		decryptor.decrypt(encrypted_result, plain_result);
		std::vector<double> result;
		encoder.decode(plain_result, result);

		std::cout << "Result: " << result[0] <<std::endl;

		

		// Close down everything
		closesocket(sock);
		WSACleanup();

		return 0;
	#endif
}


