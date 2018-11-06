/**
 * Owen Dunn, Reuben Wattenhofer, Cody Krueger
 * Project 3: TCP Encrypted Chat Program
 * 
 */

#include <sys/socket.h> // How to send/receive information over networks
#include <netinet/in.h> //includes information specific to internet protocol
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For close()
#include <arpa/inet.h>

//c++ stuff
#include <iostream> 
#include <map>
#include <string>
#include <sstream> 
#include <istream>

//compile with
//g++ tcp-echo-client.cpp -o client
//Run with
// ./client
// test file differences with
//diff -s filename1 filename2

int main(int argc, char** argv) {

	fd_set sockets;
	//initialize set of file descriptors
	//all caps because macro -- was a c coding standard at one point
	FD_ZERO(&sockets);
	//OS treats devices/sockets as files and gives them an integer for file descriptor

	int port;
	char ipaddress[50];
	char fileName[5000];
	// Get port number and ip address.
	char input[5000];
	printf("Enter a port number:");
	fgets(input, 5000, stdin);

	port = atoi(input);
	//printf("%i\n", port);

	printf("Enter an ip address:");
	fgets(input, 5000, stdin);

	//Copy the data from input to ipaddress
	for (int i = 0; i < 50; i++) {
		if (input[i] == '\n') {
			ipaddress[i] = '\0';
			break;
		} else {
			ipaddress[i] = input[i];
		}
	}
	//printf("%s\n", ipaddress);


	// on backend, stream sockets use a transport protocol called tcp
	// When you open a file, it's assigned a file description integer to identify
	// it.  The same thing happens when sockets are created.
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);  
	// For this kind of socket, reliability is handled behind the scenes.
	// We don't have to worry about breaking data into packets either.

	// Downside is that there isn't a direct correspondance between sends and
	// receive numbers (ie how many times send/receive are called)

	if (sockfd < 0) {
		printf("There was an error creating the socket\n");
		return 1;
	}
	// We have a socket connected to the network, but need to perform a few
	// extra steps to do anything with it.

	// sockaddr_in = "socket address for internet"
	struct sockaddr_in serveraddr;
	serveraddr.sin_family=AF_INET;
	// We need a standard byte order to send info over the network
	// htons = "h to ns" = "host to network short" = "take a short number
	// (2 bytes) in the order the host expects and put it in the order the
	// network expects"
	// ** May or may not switch the byte order, but need it in case it does. **
	// htonl also exists "host to network long"
	// Servers listen on a certain port number
	// What number should we use? arbitrary, but use for client and server;
	// needs to be within a certain range.
	serveraddr.sin_port=htons(port); //9876 will end up being sent with the data
	serveraddr.sin_addr.s_addr=inet_addr(ipaddress); //localhost; good for
	//testing programs "127.0.0.1" is localhost

	//connect() works for any socket types, not just internet sockets, so we
	//need to cast serveraddr to sockaddr.
	int e = connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
	// connect() will immediately send a packet to the server and see if it's
	// listening.
	if (e < 0) {
		printf("There was an error connecting\n");
		return 2;
	}

	//add sockfd to list of sockets
	FD_SET(sockfd, &sockets);
	// get file descriptor for stdin
	//int des = fileno(stdin);
	// or can just use defined constant
	FD_SET(STDIN_FILENO, &sockets);

	printf("\nEnter \"quit\" to end the session.\n");
	std::cout << "Enter \"ls\" to get a list of all clients connected \n"  
			 << "Enter \"bc [enter message]\" to broadcast message to all users \n" 
			 << "Enter \"c# [enter message]\" to send a direct message \n" 
			 << "Enter \"kick c# [password]\" to kick a client off the server \n" 
			 << std::endl;

	int quit = 0;
	while(quit == 0) {
		fd_set tmp_set = sockets;
		//checks to see if we can read from the sockets
		select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);

		// need to listen to two things at once
		// input from user or data from socket
		// put file descriptor for stdin into sockets

		//blocking operation, can do multiple things.  As configured, will wait until a socket is
		//available for reading.  &tmp_set will be modified to only contain sockets with data
		int j;

		for (j = 0; j < FD_SETSIZE; j++) {
			// is socket j in the list of sockets containing data?
			if(FD_ISSET(j, &tmp_set)) {
				if(j == sockfd) {
					char line2[10000];

					// Receive the data.  This is a blocking call! Will stop the program until
					//   data is received over the network.
					// sockfd - socket to receive data from
					// line2 - where to store the data
					// 5000 - how much we're willing to receive
					recv(sockfd, line2, 10000, 0);

					// Print what we received.
					printf("%s", line2);
					if (strcmp(line2, "quit\n") == 0) {
						quit = 1;
						break;
					}

				} else if (j == STDIN_FILENO) {
					//printf(" yes what's your pleasure ");
					char line[5000];
					//printf("%s\n", line);			
					fgets(line, 5000, stdin);
					send(sockfd, line, strlen(line)+1, 0);
					if (strcmp(line, "quit\n") == 0) {
						quit = 1;
						break;
					}
					
				}
			}
		}

		//printf("Enter a file name:");
		//fgets(input, 5000, stdin);
		

		// Sent the data!
		// sockfd - socket to send data over; don't need to specify address
		// line - data we want to send
		// length of data we want to send (number of characters)
		//   Don't use strlen if we're not sending a string!!
		//   The +1 is for the end of string symbol "\0"

		//send(sockfd, input, strlen(input)+1,0);

	}
		
	// Close the sockets.
	//close(sockfd);
	for (int j = 0; j < FD_SETSIZE; j++) {	
		close(j);
		FD_CLR(j, &sockets);
	}


	return 0;
}

