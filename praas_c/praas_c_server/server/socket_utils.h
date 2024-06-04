/*
© 2024 Nokia
Licensed under the BSD 3-Clause Clear License
SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define PORT "3490"

#define BACKLOG 10

void sigchld_handler(int s)
{
	(void)s; // quiet unused variable warning

	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void setup_hints(struct addrinfo* hints, bool is_server)
{
	memset(hints, 0, sizeof(*hints));
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_STREAM;
	if (is_server)
	{
		hints->ai_flags = AI_PASSIVE; // use my IP
	}
}

int setup_socket_options(const char* server_address)
{
	int sock;
	struct addrinfo hints, *servinfo, *p;
	int yes;
	int rv;
	char s[INET6_ADDRSTRLEN];

	bool is_server = false;
	if (server_address == NULL)
	{
		is_server = true;
	}

	setup_hints(&hints, is_server);

	if ((rv = getaddrinfo(server_address, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}

		if (!is_server)
		{
			if (connect(sock, p->ai_addr, p->ai_addrlen) == -1)
			{
				perror("client: connect");
				close(sock);
				continue;
			}
		}
		else
		{
			if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
				perror("setsockopt");
				exit(1);
			}

			if (bind(sock, p->ai_addr, p->ai_addrlen) == -1) {
				close(sock);
				perror("server: bind");
				continue;
			}
		}

		break;
	}

	if (p == NULL)
	{
		if (is_server)
		{
			fprintf(stderr, "server: failed to bind\n");
		}
		else
		{
			fprintf(stderr, "client: failed to connect\n");
			return 2;
		}

		exit(1);
	}
	else
	{
		if (!is_server)
		{
			inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof(s));
			printf("client: connecting to %s\n", s);
		}
	}

	freeaddrinfo(servinfo);

	return sock;
}

int setup_client_socket(const char* server_address)
{
	int client_socket;

	client_socket = setup_socket_options(server_address);

	return client_socket;
}

void setup_signal_handler()
{
	struct sigaction sa;
	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}
}

int setup_server_socket()
{
	int server_socket;

	server_socket = setup_socket_options(NULL);

	setup_signal_handler();

	return server_socket;
}
