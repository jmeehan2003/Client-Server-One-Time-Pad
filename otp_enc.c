#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h> 


void error(const char *msg) { perror(msg); exit(0); } // Error function used for reporting issues
int getFileSize(char* file)
{	
	FILE* fptr;
	char* data;
	int size;	
	fptr = fopen(file, "r");
	if (fptr == NULL)
	{
		fprintf(stderr, "Error opening file: %s\n", file); 
		return 0;
	}
	else
	{
		int c;
		size_t n = 0;
		fseek(fptr, 0, SEEK_END);
		size = ftell(fptr);
		fclose(fptr);

//		printf("Size of %s: %d bytes.\n", file, size);
		return size;
	} 

}

void sendNum(int socket, int num)
{
	ssize_t a = 0;
	a = write(socket, &num, sizeof(int));
	if (a < 0)
	{
		fprintf(stderr, "Error: Unable to receive number through socket\n");
	}
}

void sendMsg(int socketFD, char* msg, int size)
{
	ssize_t bytesSent = 0;
	while(bytesSent < size)
	{
		ssize_t temp; 
		if ((temp = send(socketFD, msg, size, 0)) < 0)
		{
			fprintf(stderr, "Error sending data\n");
			return;
		}

		bytesSent += temp;
	}
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
//		printf("total: %d, size: %d\n", total, size);
	}

	strncpy(msg, buffer, size);
}

void authenticate(int socketFD)
{
	char* auth = "@@encryption@@";
	int authSize = strlen(auth);
	sendMsg(socketFD, auth, authSize);
//	printf("did we make it here?\n");
	char buffer[20];
	receiveMsg(socketFD, buffer, 20);
//	printf( "Auth client: %s\n", buffer);
	int valid = strncmp(buffer, "@@encryptionServer@@", 20);
//	printf("%d\n", valid);
	if (valid != 0)
	{
		fprintf(stderr, "CLIENT: Error-> You are not connecting to the correct server. Please connect to the super secret encryption server.\n");
		exit(2);
	}
}

int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
//	char buffer[1024];
    
	if (argc != 4) { fprintf(stderr,"USAGE: %s [plaintext] [key] [port]\n", argv[0]); exit(0); } // Check usage & args

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
	{
		error("CLIENT: ERROR connecting");
		exit(1);
	}

	// authenticate: make sure connection is to the encryption server
	authenticate(socketFD);	

	int kSize, tSize;

	tSize = getFileSize(argv[1]);
	kSize = getFileSize(argv[2]);
	if (kSize < tSize)
	{
		fprintf(stderr, "Error: key file is shorter than text file\n");
		exit(1);
	}
	
	FILE *keyPtr, *textPtr;
	char* text;
	char* key;
	// get size of key file 
	// Source: http://www.cplusplus.com/reference/cstdio/ftell/
	// Source: stackoverflow.com/questions/4823177/reading-a-file-character-by-character-in-c/
	keyPtr = fopen(argv[2], "r");
	if (keyPtr == NULL) 
	{ 
		fprintf(stderr, "Error opening key file\n"); 
		exit(0); 
	}
	else
	{
		int c;
		size_t n = 0;
		fseek(keyPtr, 0, SEEK_SET);
		key = malloc(kSize);
		while ((c = fgetc(keyPtr)) != EOF)
		{
			if (isspace(c) || isalpha(c))
			{
				key[n] = (char)c;
				n++;
			}
			else
			{	
				fprintf(stderr, "Invalid character in key file\n");
				exit(1);
			}
		}
		if(key[kSize - 1] == '\n')
			key[kSize - 1] = '\0';
		fclose(keyPtr);
	} 

	//get size of text 
	textPtr = fopen(argv[1], "r");
	if (textPtr == NULL) 
	{ 
		fprintf(stderr, "Error opening text file\n"); 
		exit(0); 
	}
	else
	{
		int c;
		size_t n = 0;
		fseek(textPtr, 0, SEEK_SET);
		text = malloc(tSize);
		while ((c = fgetc(textPtr)) != EOF)
		{
			if (isspace(c) || isalpha(c))
			{
				text[n] = (char)c;
				n++;
			}
			else
			{	
				fprintf(stderr, "Invalid character in text file\n");
				exit(1);
			}
		}
		if(text[tSize - 1] == '\n')
			text[tSize - 1] = '\0';
		fclose(textPtr);
	} 


	

//	DEBUG
/*	printf("Up to debug\n");
	int i, j;
	for (i = 0; i < kSize; i++)
		printf("%c ", key[i]);
	printf("\n");

	for (j = 0; j < tSize; j++)
		printf("%c ", text[j]);
	printf("\n");
*/	

	// Get input message from user
/*	printf("CLIENT: Enter text to send to the server, and then hit enter: ");
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer array
	fgets(buffer, sizeof(buffer) - 1, stdin); // Get input from the user, trunc to buffer - 1 chars, leaving \0
	buffer[strcspn(buffer, "\n")] = '\0'; // Remove the trailing \n that fgets adds

	// Send message to server
	charsWritten = send(socketFD, buffer, strlen(buffer), 0); // Write to the server
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	if (charsWritten < strlen(buffer)) printf("CLIENT: WARNING: Not all data written to socket!\n");
*/
	sendNum(socketFD, tSize);
	sendMsg(socketFD, text, tSize);
/*	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");
	printf("CLIENT: I received this from the server: \"%s\"\n", buffer);
*/
//	printf("did we make it here?\n");
	sendNum(socketFD, kSize);
	sendMsg(socketFD, key, kSize);
/*	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");
	printf("CLIENT: I received this from the server: \"%s\"\n", buffer);
*/
/*
	ssize_t bytesSent = 0;
	while(bytesSent < tSize)
	{
		ssize_t temp; 
		if ((temp = send(socketFD, text, tSize, 0)) < 0)
		{
			fprintf(stderr, "Error sending data\n");
			exit(1);
		}

		bytesSent += temp;	
	}	*/
	// Get encrypted message from server
	char* encryptedMsg = malloc(tSize);
	receiveMsg(socketFD, encryptedMsg, tSize - 1);
	/*memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");*/
	printf("%s", encryptedMsg);
	printf("\n");


	free(text);
	free(key);
	free(encryptedMsg);
	close(socketFD); // Close the socket
	exit(0);
}


// ssize_t send(int sockfd, void *message, size_t message_size, int flags);
// char msg[1024];
// r = send(socketFD, msg, 1024, 0);
// if (r < 1024)
// 	{ handle possible error }
//
// ssize_t recv(in sockfd, void *buffer, size_t buffer_size, int flags);
//
// char buffer[1024];
// memset(buffer, '\0', sizeof(buffer));
// r = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
// if (r < sizeof(buffer) - 1)
// 	{ handle possible error };
