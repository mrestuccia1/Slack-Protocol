/* See server.h for details about the functions in this module */

#include <string.h>
#include "server.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <log.h>
#include "connection.h"
#include "message.h"
#include "handlers.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <user.h>

#define MAX_MSG 512

/* See server.h */

/**
 * Change this code to actually initialize the server!
*/
void chirc_server_init(chirc_server_t *server)
{
    server->servername = NULL;
    server->hostname = NULL;
    server->port = NULL;
    server->passwd = NULL;
    server->registered = false;

    server->conn = NULL;
}

/* See server.h */

// probably already good
void chirc_server_free(chirc_server_t *server)
{
    sdsfree(server->servername);
    sdsfree(server->hostname);
    sdsfree(server->port);
    sdsfree(server->passwd);
}


/**
 * This function deals with communicating with a client once it has connected
 * to one of our sockets.
*/

void *handle_client_on_socket(void *ptr) {

    struct worker_args *wa = (struct worker_args *) ptr;
    chirc_connection_t *connection = wa->conn;
    chilog(INFO, "Connected on port %s", connection->hostname);

    chirc_ctx_t *ctx = wa->ctx;
    int socket = connection->socket;
    int bytes_received;
    char buffer[MAX_MSG];
    char message[MAX_MSG];
    int messageIndex = 0;
    char prev = '\0';
    char cur = '\0';

    while ((bytes_received = recv(socket, buffer, MAX_MSG, 0)) > 0) {
        
        for (int i = 0; i < bytes_received; i++) { 
            cur = buffer[i];
            message[messageIndex++] = cur;

            if (prev == '\r' && cur == '\n') { 
            
                chirc_message_t *msg = malloc(sizeof(chirc_message_t));

                // must remove \r, \n here

                message[messageIndex] = '\0';

                chirc_message_from_string(msg, message);

                if (!connection->peer.server && !connection->peer.user) {
                    if (!strncmp(msg->cmd, "NICK", MSG_MAX) || !strncmp(msg->cmd, "USER", MSG_MAX)) { // user connection

                        chirc_user_t *newUser = (chirc_user_t *)malloc( sizeof(chirc_user_t) );
                        chirc_user_init(newUser);

                        // set the user hostname, connection's peer user
                        newUser->hostname = strndup( connection->hostname, MSG_MAX );
                        connection->peer.user = newUser;
                        newUser->conn = connection;
                        newUser->server = ctx->network.this_server;

                    } else { // server connection
                        chirc_server_t *newServer = (chirc_server_t *)malloc( sizeof(chirc_server_t) );
                        chirc_server_init(newServer);

                        // set the server hostname, connection's peer server
                        newServer->hostname = strndup( connection->hostname, MSG_MAX );
                        connection->peer.server = newServer;
                        newServer->conn = connection;
                    }
                }

                // should add in logic here to check return, exit if necessary
                if ( chirc_handle(ctx, connection, msg) == CHIRC_HANDLER_DISCONNECT) {
                    close(connection->socket);
                    return NULL; // stop listening for connections
                }

                messageIndex = 0;
                prev = '\0';
                cur = '\0';
                memset(message, 0, sizeof(message));
            }
            prev = cur;
        }
    }


    if (bytes_received == -1) {
        perror("recv");
        exit(EXIT_FAILURE);
    }

    return NULL;
}

void run_server(chirc_ctx_t *ctx) {
    // grab our server
    chirc_server_t *server = ctx->network.this_server;

    // initialize server, client sockets
    int server_socket, client_socket;

    
    struct addrinfo hints, *res, *p; // initialize pointers to pass into socketAPI functions
    struct sockaddr_storage *client_addr; // initialize client address struct
    socklen_t sin_size = sizeof(struct sockaddr_storage); // get size of client sockect struct


    // set all memory to 0, jic
    memset(&hints, 0, sizeof hints);

    // set hint parameters
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    sds port = server->port; // get port

    // attempt to get the address info. if it fails, 
    if (getaddrinfo(NULL, port, &hints, &res) != 0)
    {
        chilog(ERROR, "getaddrinfo() failed");
        exit(EXIT_FAILURE);
    }


    // iterate through all the addrinfo's we recieved until we connect to one
    for(p = res;p != NULL; p = p->ai_next)
    {
        // try and open a socket on the current addr
        if ((server_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            chilog(ERROR, "Server.c: Socket failed to open.");
            continue;
        }

        // try and bind to our socket with the address given
        if (bind(server_socket, p->ai_addr, p->ai_addrlen) == -1)
        {
            chilog(ERROR, "Server.c: Socket bind() failed");
            close(server_socket);
            continue;
        }

        // if the above passed, now try and listen on this socket
        if (listen(server_socket, 5) == -1)
        {
            // fprintf("Server.c: Socket listen() failed");
            chilog(ERROR, "Server.c: Socket listen() failed");
            close(server_socket);
            continue;
        }

        break;
    }

    // now we may free the res addr info
    freeaddrinfo(res);

    // if p is null we could not make a connection
    if (p == NULL)
    {
        chilog(ERROR, "Server.c: Could not find a socket to bind to.\n");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // now begin accepting client connections
    while(true) {
        /* Call accept(). At this point, we will block until a client establishes a connection. */
        client_addr = calloc(1, sin_size);
        if ((client_socket = accept(server_socket, (struct sockaddr *) client_addr, &sin_size)) == -1)
        {
            free(client_addr);
            // close(server_socket);
            chilog(ERROR,"Server.c: Could not accept() connection");
        }

        // initialize new connection
        chirc_connection_t *connection = (chirc_connection_t *)malloc(sizeof(chirc_connection_t));

        // if malloc fails return
        if (connection == NULL) {
            chilog(ERROR, "Memory allocation failed\n");
            free(client_addr);
            close(server_socket);
            exit(EXIT_FAILURE);
        }

        /**
         * Connection set up
        */
        // // get hostname
        getpeername(server_socket, (struct sockaddr *)client_addr, &sin_size);

        // // some stuff dealing with getting hostname

        // initialize the connection
        chirc_connection_init(connection);
        connection->socket = client_socket;
        chilog(INFO, "This is running on socket %d", connection->socket);

        // hash connection in
        // pthread_mutex_lock(ctx->ctx_lock);
         chirc_ctx_add_connection(ctx, connection);
        // pthread_mutex_lock(ctx->ctx_lock);

        // get hostname
        char host[NI_MAXHOST];
        if (getnameinfo((struct sockaddr *)client_addr, sin_size, host, NI_MAXHOST, NULL, 0, 0) != 0) {
            chilog(ERROR, "Server.c: Could not get name info");
            close(client_socket);
            free(connection);
            continue;
        }

        // not needed anymore so lets free
        free(client_addr);

        // set hostname
        char *hPtr = &host[0];
        while (*(++hPtr) == ':') {};
        connection->hostname = strndup(hPtr, MSG_MAX);

        /**
         * End connection set up
        */

        // if it fails free the useless client socket
        if (chirc_connection_create_thread(ctx, connection) == CHIRC_FAIL) { close(client_socket); }

    }

    return;
}