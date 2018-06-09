/********************************************************************************
** Author: James Meehan
** Date: 6/7/2018
** Description: This is the encryption server program for a one time pad. The server
** receives a plaintext file and a key file from the encryption client and sends a 
** ciphertext file back.
**
** These sources were used to help create this program **
** https://beej.us/guide/bgnet/
** http://www.linuxhowtos.org/C_C++/socket.htm
** Other sources providing more specific help may be cited within the function description
***********************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues
int authenticate(int sock);
int receiveSize(int socket);
void receiveMsg(int socket, char* msg, size_t size);
void encryptMsg(char *msg, char* key);

int main(int argc, char *argv[])
{
	int listenSocketFD, newSocketFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
	struct sockaddr_in serverAddress, clientAddress;

	if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) error("ERROR opening socket");

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
		error("ERROR on binding");
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	// keep server running continuously and allow multiple connections
	while (1)
	{
		// accept a client
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		newSocketFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (newSocketFD < 0) { fprintf(stderr, "ERROR on accept\n"); exit(1); }		

		// create a child process to handle the connected client
		pid_t pid = fork();
		if (pid < 0)
		{
			fprintf(stderr, "Error on fork\n");
			exit(1);
		}
		// sucessful fork
		if (pid == 0)
		{
			//authenticate connection
			if(!(authenticate(newSocketFD)))
				continue;

			char* text;
			char* key;
				
			// get plaintext file from client
			int msgSize = receiveSize(newSocketFD);
			text = malloc(msgSize);
			receiveMsg(newSocketFD, text, msgSize);

			// get key file from client
			msgSize = receiveSize(newSocketFD);
			key = malloc(msgSize);
			receiveMsg(newSocketFD, key, msgSize);
						
			// use key to encrypt the plaintext
			encryptMsg(text, key);

			// send the encrypted file back to the client
			int textSize = strlen(text);
			charsRead = send(newSocketFD, text, textSize, 0); 
			if (charsRead < 0) error("ERROR writing to socket");
	   	
			// clean up and close socket before child exit
			free(text);
			free(key);
			close(newSocketFD); // Close the existing socket which is connected to the client
			_exit(0);
		}
	}

	// close the listening socket
	close(listenSocketFD);
	return 0; 
}

/***********************************************************************************
** Description: authenticate() performs a handshake with the client.  The server
** receives a message from the client and if it's the correct message it will send
** the proper authentication message back.  otherwise, an error message is sent to
** the client.  
***********************************************************************************/
int authenticate(int sock)
{
	// receive message from client
	char buffer[14];
	receiveMsg(sock, buffer, 14);

	// check if client message matches expected authentication message
	// if not a match, send gargage back
	if (strcmp(buffer, "@@encryption@@") != 0)
	{
		char* bad = "@@@@@@nice try@@@@@@";
		send(sock, bad, 20, 0);
		return 0;
	}
	// else it's a match and send proper authentication message back
	else
	{
		char* auth = "@@encryptionServer@@";
		int authSize = strlen(auth);
		int charsRead = send(sock, auth, authSize, 0);
		if (charsRead < 0) { fprintf(stderr, "SERVER: Error sending authentication message\n"); }
		return 1;
	}
}

/****************************************************************************
** Description: receiveSize() takes a socket as a paramter and recevies an
** integer (size of an incoming file) from the client over that socket.  The
** number received is returned.
*****************************************************************************/
int receiveSize(int socket)
{
	int num;
	ssize_t a =0;
	a = read(socket, &num, sizeof(int));
	if (a < 0)
	{
		fprintf(stderr, "Error: Unable to receive file size through socket\n");
		return 0;
	}
	else
		return num;
}

/****************************************************************************
** Description: receiveMsg() takes a socket, message, and the size of the 
** message as paramters. The function recevies data from the client until
** the entire file has been received or an error occurs.  
****************************************************************************/
void receiveMsg(int socket, char* msg, size_t size)
{
	char buffer[size + 1];
	ssize_t a;
	size_t total = 0;

	// get file data until full file has been received
	while (total < size)
	{
		a = read(socket, buffer + total, size - total);
		total += a;

		if (a < 0)
		{
			fprintf(stderr, "Error: failed to receive message from client\n");
		}
	}

	// copy the message from the buffer to the msg array
	strncpy(msg, buffer, size);
}

/****************************************************************************
** Description: encryptMsg() takes a message and a key as parameters and 
** uses the key to create a cipthertext file.  The msg array paramter is 
** altered in the function to hold the ciphertext.
****************************************************************************/
void encryptMsg(char *msg, char* key)
{
	int i, msgNum, keyNum, cipherNum;
	int length = strlen(msg);
	
	// iterate through the msg and key arrays character by character
	for (i = 0; i < length; i++)
	{
		// get integer value of msg character
		msgNum = (int)msg[i];
	
		// make adjustment if it's a space
		if (msgNum == 32)
			msgNum = 91;
		
		// convert to 0-26 range
		msgNum -= 65;		

		// get integer value of key character
		keyNum = (int)key[i];
		
		// make adjustment if it's a space
		if (keyNum == 32)
			keyNum = 91;

		// convert to 0-26 range
		keyNum -= 65;

		// add msgNum and keyNum together and module 27 to get cipher value and add 65 back to get a letter value
		cipherNum = ((msgNum + keyNum) % 27) + 65;
		
		// convert to a space if cipherNum equals 91
		if (cipherNum == 91)
			cipherNum = 32;
		
		// put the cipher value into the msg array
		msg[i] = cipherNum; 
	}

	// tack on a null terminator at the end;
	msg[i] = '\0';
	return;
}

