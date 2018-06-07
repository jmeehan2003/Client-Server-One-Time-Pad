#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues
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

void receiveMsg(int socket, char* msg, size_t size)
{
	char buffer[size + 1];
	ssize_t a;
	size_t total = 0;

	while (total < size)
	{
		a = read(socket, buffer + total, size - total);
		total += a;

		if (a < 0)
		{
			fprintf(stderr, "Error: failed to receive message from client\n");
		}
	}

	strncpy(msg, buffer, size);
}

void decryptMsg(char *msg, char* key)
{
	int i, msgNum, keyNum, decryptedNum;
	int length = strlen(msg);
	
	for (i = 0; i < length; i++)
	{
		msgNum = (int)msg[i];
//		printf("textnum: %c %d", msg[i], msgNum); 
		if (msgNum == 32)
			msgNum = 91;
		msgNum -= 65;		

		keyNum = (int)key[i];
		if (keyNum == 32)
			keyNum = 91;
		keyNum -= 65;
		
		decryptedNum = msgNum - keyNum;
		if (decryptedNum < 0)
			decryptedNum += 27;

		decryptedNum = (decryptedNum % 27) + 65;
		if (decryptedNum == 91)
			decryptedNum = 32;
		
		msg[i] = decryptedNum; 
//		printf("cipher: %c,  msg[i]: %c \n", cipherNum, msg[i]);
	}

	msg[i] = '\0';
	return;
	
}

int authenticate(int sock)
{
	char buffer[14];
	receiveMsg(sock, buffer, 14);
	if (strcmp(buffer, "@@decryption@@") != 0)
	{
		fprintf(stderr, "SERVER: Error-> A spy is trying to connect to the super secret decryption server. Connection terminated.\n");
		char* bad = "@@@@@@nice try@@@@@@";
		send(sock, bad, 20, 0);
		return 0;
	}
	else
	{
		printf("sending client auth message\n");
		char* auth = "@@decryptionServer@@";
		int authSize = strlen(auth);
		int charsRead = send(sock, auth, authSize, 0);
		if (charsRead < 0) { fprintf(stderr, "SERVER: Error sending authentication message\n"); }
		return 1;
	}
}

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


	
	// Accept a connection, blocking if one is not available until one connects
	while (1)
	{
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		newSocketFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (newSocketFD < 0) error("ERROR on accept");
		printf("SERVER: Connected Client at port %d\n", ntohs(clientAddress.sin_port));

		authenticate(newSocketFD);
		char* cipherText;
		char* key;
	//	int msgCount = 0;
	//	while (msgCount < 2)
	//	{
				
			// Get the message from the client and display it
			// get file size from client
			int msgSize = receiveSize(newSocketFD);
//			printf("SERVER: the message size is %d\n", msgSize);
			cipherText = malloc(msgSize);
			receiveMsg(newSocketFD, cipherText, msgSize);
//			printf("SERVER: I received this from the client: \"%s\"\n", text);

			msgSize = receiveSize(newSocketFD);
//			printf("SERVER: the key message size is %d\n", msgSize);
			key = malloc(msgSize);
			receiveMsg(newSocketFD, key, msgSize);
			//memset(buffer, '\0', fileSize);
			//charsRead = recv(newSocketFD, buffer, fileSize, 0); // Read the client's message from the socket
			//if (charsRead < 0) error("ERROR reading from socket");
//			printf("SERVER: I received this from the client: \"%s\"\n", key);
	/*		if (msgCount == 0)
			{
				text = malloc(charsRead);
				strcpy(text, buffer);
			}
			else
			{
				key = malloc(charsRead);
				strcpy(key, buffer);
			}
						
	*/		
			// Send a Success message back to the client
//			charsRead = send(newSocketFD, "I received your files", 22, 0);
	//		if (charsRead < 0) error("ERROR writing to socket");
			
	//		msgCount++;
		//	printf("msgcount: %d", msgCount);
	//	}
		decryptMsg(cipherText, key);
		int decryptedSize = strlen(cipherText);
		charsRead = send(newSocketFD, cipherText, decryptedSize, 0); // Send success back
		
		/*printf("we got here\n");
		int i, j;
		int length = strlen(text);
		for (i = 0; i < length; i++)
			printf("%c ", text[i]);
		printf("\n");
		for (j = 0; j < length; j++)
			printf("%c ", key[j]);
		printf("\n");
		*/
		free(cipherText);
		free(key);
		close(newSocketFD); // Close the existing socket which is connected to the client
	}


	close(listenSocketFD); // Close the listening socket
	return 0; 
}
