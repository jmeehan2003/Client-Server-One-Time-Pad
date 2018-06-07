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

	//	printf("total: %d, size: %d\n", total, size);
	}

	strncpy(msg, buffer, size);
}

void encryptMsg(char *msg, char* key)
{
	int i, msgNum, keyNum, cipherNum;
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

		cipherNum = ((msgNum + keyNum) % 27) + 65;
		if (cipherNum == 91)
			cipherNum = 32;
		
		msg[i] = cipherNum; 
//		printf("cipher: %c,  msg[i]: %c \n", cipherNum, msg[i]);
	}

	msg[i] = '\0';
	return;
	
}

int authenticate(int sock)
{
	char buffer[14];
	receiveMsg(sock, buffer, 14);
//	printf("AUTH: Received %s from client\n", buffer); 
	if (strcmp(buffer, "@@encryption@@") != 0)
	{
		char* bad = "@@@@@@nice try@@@@@@";
		send(sock, bad, 20, 0);
		return 0;
	}
	else
	{
//		printf("sending client auth message\n");
		char* auth = "@@encryptionServer@@";
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

	while (1)
	{
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		newSocketFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (newSocketFD < 0) { fprintf(stderr, "ERROR on accept\n"); exit(1); }		

		// create a child process
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
	   	
			// clean up and close socket b efore child exit
			free(text);
			free(key);
			close(newSocketFD); // Close the existing socket which is connected to the client
			_exit(0);
		}
	}

	close(listenSocketFD); // Close the listening socket
	return 0; 
}
