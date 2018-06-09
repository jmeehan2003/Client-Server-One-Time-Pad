/*****************************************************************************************
** Author: James Meehan
** Date: 6/7/2018
** Description: This is the encryption client program for a one time pad. The client
** sends a plaintext file and a key file to the encryption server and receives a 
** ciphertext file back.
**
** These sources were used to help create this program **
** https://beej.us/guide/bgnet/
** http://www.linuxhowtos.org/C_C++/socket.htm
** Other sources providing more specific help may be cited within the function description
*******************************************************************************************/
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
void authenticate(int socketFD);
int getFileSize(char* file);
void sendNum(int socket, int num);
void sendMsg(int socketFD, char* msg, int size);
void receiveMsg(int socket, char* msg, size_t size);


int main(int argc, char *argv[])
{
	// much of the initial socket setup and connection to server is heavily borrowed from the provided client.c file
	int socketFD, portNumber, kSize, tSize, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
    
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

	// get the sizes of the files
	tSize = getFileSize(argv[1]);
	kSize = getFileSize(argv[2]);

	// if the key file is less than the text file, print error message and exit with a value of 1
	if (kSize < tSize)
	{
		fprintf(stderr, "Error: key file is shorter than text file\n");
		exit(1);
	}
	
	FILE *keyPtr, *textPtr;
	char* text;
	char* key;
	
	// check key file for invalid characters 
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
		
		// go to the beginning of the file 
		fseek(keyPtr, 0, SEEK_SET);

		// go character by character by character. if it is a valid character, put it in the 
		// key array. otherwise, print error message and exit with a value of 1
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
				fprintf(stderr, "ERROR: Invalid character in key file (%s)\n", argv[2]);
				exit(1);
			}
		}
		
		// remove the newline character 
		if(key[kSize - 1] == '\n')
			key[kSize - 1] = '\0';

		// close the file
		fclose(keyPtr);
	} 

	// check plaintext file for invalid characters
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
		
		// go to the beginning of the file
		fseek(textPtr, 0, SEEK_SET);
		
		// go character by character by character. if it is a valid character, put it in the 
		// text array. otherwise, print error message and exit with a value of 1
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
				fprintf(stderr, "ERROR: Invalid character in text file (%s)\n", argv[1]);
				exit(1);
			}
		}

		// remove the newline character
		if(text[tSize - 1] == '\n')
			text[tSize - 1] = '\0';

		// close the file
		fclose(textPtr);
	} 


	// send plaintext file size to server
	sendNum(socketFD, tSize);

	// send plaintext file to server
	sendMsg(socketFD, text, tSize);

	// send key file size to server
	sendNum(socketFD, kSize);

	// send key file to server
	sendMsg(socketFD, key, kSize);

	// receive the encrypted message back from the server
	char* encryptedMsg = malloc(tSize);
	receiveMsg(socketFD, encryptedMsg, tSize - 1);
	
	// print the encrypted message to stdout
	printf("%s", encryptedMsg);
	printf("\n");

	// cleanup memory, close the socket, and exit
	free(text);
	free(key);
	free(encryptedMsg);
	close(socketFD); // Close the socket
	exit(0);
}

/*************************************************************************
** Description: authenticate() takes a socket as a parameter and sends
** an authentication message to the server.  If the server sends back the
** appropriate response, then the program has connected to the encryption 
** server.  Otherwise, the connection is to unauthorized server.
**************************************************************************/
void authenticate(int socketFD)
{
	// handshake process with server
	// create authentication message
	char* auth = "@@encryption@@";
	int authSize = strlen(auth);

	// send authentication message
	sendMsg(socketFD, auth, authSize);

	// receive message back from server
	char buffer[20];
	receiveMsg(socketFD, buffer, 20);

	// compare server response to authentication key and reject if not a match
	int valid = strncmp(buffer, "@@encryptionServer@@", 20);
	if (valid != 0)
	{
		fprintf(stderr, "CLIENT: Error-> THERE'S A SPY! OTP_ENC tried to connect to OTP_DEC_D, the super secret decryption server. This is not allowed.\n");
		exit(2);
	}
}

/********************************************************************
** Description: getFileSize() takes a filename as a parameter and
** returns the size of that file
// Source: http://www.cplusplus.com/reference/cstdio/ftell/
********************************************************************/
int getFileSize(char* file)
{	
	FILE* fptr;
	char* data;
	int size;	
	
	// open the file for reading
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
		
		// go to the end of the file
		fseek(fptr, 0, SEEK_END);
		
		// get the size of the file in bytes.  ftell provides the 
		// position of the file relative to the start of the file
		size = ftell(fptr);

		//close the file and return size
		fclose(fptr);
		return size;
	} 
}

/********************************************************************
** Description: sendNum() takes a socket and integer as parameters
** and sends the number over the socket. This function is primarily
** used to send the size of a file to the server.
********************************************************************/
void sendNum(int socket, int num)
{
	ssize_t a = 0;
	a = write(socket, &num, sizeof(int));
	if (a < 0)
	{
		fprintf(stderr, "Error: Unable to receive number through socket\n");
	}
}

/********************************************************************
** Description: sendMsg() takes a socket, a message, and the size of 
** that message as parameters.  The function continues until the full
** size is sent or an error occurs.
*********************************************************************/
void sendMsg(int socketFD, char* msg, int size)
{
	ssize_t bytesSent = 0;

	// send while bytesSent is less than the size of the file
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

/*********************************************************************
** Description: receiveMsg() takes a socket, message, and size as 
** parameters and continues until the ful message is received or an
** error occurs.
** Source: https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.3.0/com.ibm.zos.v2r3.bpxbd00/rtrea.htm
*********************************************************************/
void receiveMsg(int socket, char* msg, size_t size)
{
	char buffer[size + 1];
	ssize_t a;
	size_t total = 0;

	// receive while total is less than the size of the file
	while (total < size)
	{
		a = read(socket, buffer + total, size - total);
		total += a;

		if (a < 0)
		{
			fprintf(stderr, "Error: failed to receive message from client\n");
			return;
		}
	}

	// copy the message from the buffer to msg array
	strncpy(msg, buffer, size);
}

