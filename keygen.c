/*****************************************************************************
** Author: James Meehan
** Date: 6/7/2018
** Description: This program generates a random key for a one time pad and 
** sends it to stdout.
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		fprintf(stderr, "Error starting program\n"); 
		fprintf(stderr, "Usage: keygen [length of key file]\n");
		exit(1);
	}

	// use srand to get different random results each time
	srand(time(NULL));

	// convert user argument to an integer
	int size = atoi(argv[1]);

	int counter = 0;
	char letter;

	// get a random letter and print it to stdout until key file size has been reached
	while (counter < size)
	{
		// get random letter
		letter = (rand() % 27) + 65;

		// make adjustment for space character
		if (letter == 91)
			letter = 32;

		// print to stdout
		printf("%c", letter);

		// increment counter
		counter++;
	}

	// add newline at end
	printf("\n");

	return 0;
}
