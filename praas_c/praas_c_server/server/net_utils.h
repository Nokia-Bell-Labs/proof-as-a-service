/*
© 2024 Nokia
Licensed under the BSD 3-Clause Clear License
SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include <sys/socket.h>

#define BUFFER_SIZE 4

void send_data(int client_socket, const char* data)
{
    size_t size = 0;
    size = strlen(data);
    send(client_socket, &size, sizeof(size), 0);
    
    //send(client_socket, data, size, 0);
    
    // send data in a loop
    int num_send = size / BUFFER_SIZE;
    int num_rem = size % BUFFER_SIZE;
    int pos = 0;
    for (int i = 0; i < num_send; i++)
    {
        send(client_socket, data+pos, BUFFER_SIZE, 0);
        pos += BUFFER_SIZE;
    }

    if (num_rem > 0)
    {
        send(client_socket, data+pos, num_rem, 0);
        pos += num_rem;
    }
}

char* receive_data(int client_socket)
{
    size_t size = 0;
    size_t nread = -1;
    size_t pos = 0;
    char* buf = NULL;
    char buffer[BUFFER_SIZE];
    recv(client_socket, &size, sizeof(size), 0);

    //printf("Expecting %ld bytes\n", size);

    buf = (char*) malloc(sizeof(char)* (size + 1));

    //recv(client_socket, buf, size, 0);

    // receive data in a loop
    int num_recv = size / BUFFER_SIZE;
    int num_rem = size % BUFFER_SIZE;
    int num_total = 0;
    //printf("num_recv: %d, num_rem: %d\n", num_recv, num_rem);
    for (int i = 0; i < num_recv; i++)
    {
        recv(client_socket, buffer, BUFFER_SIZE, 0);
        //printf("cur: %.*s\n", BUFFER_SIZE, buffer);
        memcpy(buf+i*BUFFER_SIZE, buffer, BUFFER_SIZE);
        num_total += BUFFER_SIZE;
        //printf("i: %d\n", i);
    }

    if (num_rem > 0)
    {
        recv(client_socket, buffer, BUFFER_SIZE, 0);
        //printf("rem: %.*s\n", num_rem, buffer);
        memcpy(buf+num_recv*BUFFER_SIZE, buffer, num_rem);
        num_total += num_rem;
    }

    buf[size] = '\0';

    //printf("last rem: %s\n", buf+size-num_rem);
    //printf("num_total: %d, expected: %ld\n", num_total, size);
    
    return buf;
}
