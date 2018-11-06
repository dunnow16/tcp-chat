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
#include <sys/select.h>

//c++ stuff
#include <iostream> 
#include <map>
#include <string>
#include <sstream> 
#include <istream>

using namespace std;

map <int, char*>  port2username;
map <string, int>  username2port;

int main(int argc, char** argv) {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	int port;

	fd_set sockets;
	//initialize set of file descriptors
	//all caps because macro -- was a c coding standard at one point
	FD_ZERO(&sockets);
	//OS treats devices/sockets as files and gives them an integer for file descriptor

	// Get port number
	char input[5000];
	printf("Enter a port number:");
	fgets(input, 5000, stdin);

	port = atoi(input);
	printf("%i\n", port);


	// Server needs to know its own address as well as its client
	struct sockaddr_in serveraddr, clientaddr;


	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port=htons(port);  //9876
	// Tell server its own address
	// INADDR_ANY = any address the computer has, as long as it contains the
	// port number -- ie we don't care.  Typical way to program a server since
	// we have no idea what the computer address might be.
	serveraddr.sin_addr.s_addr=INADDR_ANY;

	// bind() associates serveraddr with the socket
	// "anything sent to this address should be received on this socket"
	bind(sockfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));

	// listen() tells us to listen to connections from clients
	// 10 - backlog
	//    When clients connect, we need to accept those connections
	//    Max number of waiting clients to connect with eventually
	//       Anything past the max number will be rejected
	listen(sockfd, 10);

	//add sockfd to list of sockets
	FD_SET(sockfd, &sockets);
	// get file descriptor for stdin
	//int des = fileno(stdin);
	// or can just use defined constant
	FD_SET(STDIN_FILENO, &sockets);

	printf("\nEnter \"quit\" to end the session.\n");
    printf("Otherwise enter a message to send a broadcast to clients.\n");

	int quit = 0;
	// Infinite loops are pretty common with servers.
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
					printf("A client connected\n");
					// Actually accept the connections.
					int len = sizeof(clientaddr);
					// accept() is a blocking call; program will stop until it accepts a client
					// client address goes into len
					// The initial socket we created is only used for listening for connections;
					// We need to create a new socket for each client
					int clientsocket = accept(sockfd, (struct sockaddr*)&clientaddr, (socklen_t*) &len);
					FD_SET(clientsocket, &sockets);
					// Create a distinct username
					string username = "c1";

					int num = 0;
					while ( username2port.find(username) != username2port.end() ) {
						num++;
						username[1] = num + '0';
					}
					username2port[username] = clientsocket;
					port2username[clientsocket] = new char[3];
					memcpy(port2username[clientsocket], (char *) username.c_str(), 3);
					cout << "client name: " << username << " socket: " << username2port[username] << endl;
					// cout << "socket: " << clientsocket << " username: " << port2username[clientsocket] << endl;


					// int excit = 0;
					// int num = 0;
					// while ( !excit ) {
					// 	num++;
					// 	// http://www.cplusplus.com/forum/beginner/123379/
					// 	// iterate C++98 style
					// 	typedef std::map< int, char* >::iterator outer_iterator ;
					// 	// cout << "       name2port map:\n";
					// 	int doit = 1;
					// 	for( outer_iterator outer = port2username.begin() ; outer != port2username.end() ; ++outer )
					// 	{
					// 		if (atoi(&(outer->second[1])) == num) {
					// 			doit = 0;
					// 			break;
					// 		}
					// 		// std::cout << "      " << outer->first << ' ' ;
					// 		// std::cout << outer->second << '\n' ;
					// 	}

					// 	if (doit) {
					// 		username[1] = num + '0';
					// 		port2username[clientsocket] = username;
					// 		cout << "client name: " << port2username[clientsocket] << endl;
					// 		excit = 1;
					// 	}

					// 	// cout << "num: " << num << endl;

					// }
				} else if (j == STDIN_FILENO) {
					//printf(" yes what's your pleasure ");
					char line[5000];
					fgets(line, 5000, stdin);
					//printf("%s\n", line);			

					for (int i  = 0; i < FD_SETSIZE; i++) {
						// send line to a client (let's hope there's only one connected)
						if(FD_ISSET(i, &sockets) && i != sockfd && i != STDIN_FILENO) {
							send(i, line, strlen(line)+1, 0);
						}
					}
					if (strcmp(line, "quit\n") == 0) {
						quit = 1;
						break;
					}
				} else {
					// cout << "got message" << endl;
					// Sending and receiving works the same for the server as the client.
					char line[5000];
					// j is our socket number
					recv(j, line, 5000, 0);
					printf("Client: %s", line);
					if (strcmp(line, "quit\n") == 0) {
						// quit = 1;
						// Update maps
						string s(port2username[j]);
						port2username.erase(j);
						username2port.erase(s);

						close(j);
						FD_CLR(j, &sockets);
						break;
					}
					else if (strncmp(line, "ls", 2) == 0 ) {
						cout << "clients" << endl;

						stringstream clients;
						clients << "\nClient list:\n";

						typedef std::map< string, int >::iterator outer_iterator ;
						for( outer_iterator outer = username2port.begin() ; outer != username2port.end() ; ++outer )
						{
							clients << outer->first << "\n" ;
							// std::cout << outer->second << '\n' ;
						}
						string r = clients.str();
						const char* result = r.c_str();
						send(j, result, strlen(result)+1, 0);

					}
					else if (strncmp(line, "bc", 2) == 0 ) {
						char message[5000];
						memcpy(message, port2username[j], 2);
						message[2] = ':';
						message[3] = ' ';

						memcpy(message+4, line+2, strlen(line)-1);
						typedef std::map< string, int >::iterator outer_iterator ;
						for( outer_iterator outer = username2port.begin() ; outer != username2port.end() ; ++outer )
						{
							if (username2port[outer->first] != j) {
								send(username2port[outer->first], message, strlen(message)+1, 0);
							}
						}

					}
					else if (strncmp(line, "c", 1) == 0 ) {
						string key = "c_";
						key[1] = line[1];
						string fr = "c_";
						fr[1] = port2username[j][1];
						if (username2port.find(key) == username2port.end()) {
							string error = "No client with that name exists. Try using ls or bc\n";
							send(j, error.c_str(), strlen(error.c_str())+1, 0);
						}
						else {
							char message[5000];
							memcpy(message, fr.c_str(), 2);
							message[2] = ':';
							message[3] = ' ';

							memcpy(message+4, line+2, strlen(line)-1);

							send(username2port[key], message, strlen(message)+1, 0);
						}
					}
					else if (strncmp(line, "kick", 4) == 0 ) {
						string s_line(line);
						std::size_t found = s_line.find("password");
						//if password is found
  						if (found!=std::string::npos) {
							//if (strncmp(line, "c", 4) == 0 )
							string key1 = "c_"; //TODO currently only 9 clients possible from this implimentation
							key1[1] = line[6]; //key should = cX, where X is the client num 
							//client (c#) not found in keys
							if (username2port.find(key1) == username2port.end()) {
								string error = "No client with that name exists. Try using ls or bc\n";
								send(j, error.c_str(), strlen(error.c_str())+1, 0); //c_str returns c char array from c++ string
							}
							//if client is found
							else {
								//send quit to client to force quit it
								char q[] = "quit\n";
								send(username2port[key1], q, strlen(q)+1, 0);
								// Update maps
								int k = (username2port[key1]);
								username2port.erase(key1);
								port2username.erase(k);

								close(k);
								FD_CLR(k, &sockets);
							}
						}
					}

					//send(j, line, strlen(line)+1, 0);

					//close(j);
					//FD_CLR(j, &sockets);
				}
			}
		}
	}

	for (int j = 0; j < FD_SETSIZE; j++) {
		//send quit to client FIXME
		//const *char[] q = "quit\n";
		//send(j, q, strlen(q)+1, 0);	
		close(j);
		FD_CLR(j, &sockets);
	}

	return 0;  
} 
