/* See connection.h for details about the functions in this module */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdio.h>

#include "ctx.h"
#include "connection.h"
#include "utils.h"
#include "message.h"
#include "handlers.h"
#include "chirc.h"
#include "log.h"
#include "server.h"

/* See connection.h */
void chirc_connection_init(chirc_connection_t *conn)
{
    /**
     * Set all values to null, 0, or whatever. Everything is going to be
     * set properly soon.
    */
    conn->type = CONN_TYPE_UNKNOWN;
    conn->hostname = NULL;
    conn->port = 0;
    conn->peer.server = NULL;
    conn->peer.user = NULL;
    conn->socket = 0;

}


/* See connection.h */
void chirc_connection_free(chirc_connection_t *conn)
{

    // I think this is all we need
    sdsfree(conn->hostname);

    // maybe free user???

}


/* See connection.h */
int chirc_connection_send_message(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg, bool free_msg)
{
    // chilog(INFO, 'made it before message to string');
    // convert the message to a string and send it!
    sds outputString;
    chirc_message_to_string(msg, &outputString);
    int outputSize = strlen(outputString);

    int sent = sendall(conn->socket, outputString, &outputSize);

    if (free_msg) {
        chirc_message_free(msg);
    }

    return CHIRC_OK;
}

/* See connection.h */
int chirc_connection_create_thread(chirc_ctx_t *ctx, chirc_connection_t *connection)
{

    // variables dealing with threading later on
    struct worker_args *wa;
    pthread_t worker_thread;

    wa = calloc(1, sizeof(struct worker_args));
    wa->conn = connection;
    wa->ctx = ctx;
    // handle_client_on_socket(ctx, connection);
    // Later on we'll need to thread here instead

    if (pthread_create(&worker_thread, NULL, handle_client_on_socket, wa) != 0)
    {
        chilog(ERROR, "Could not create a worker thread");
        free(wa);
        return CHIRC_FAIL;
    }

    return CHIRC_OK;
}

/* See connection.h */
int chirc_connection_close(chirc_ctx_t *ctx, chirc_connection_t *connection) {
    if (close(connection->socket) ) {
        chilog(ERROR, "chirc_connection_close: Error closing connection.");
        return 1;
    }
    
    // should likely remove the users too and stuff in here
    return 0;
}

int chirc_connection_relay_msg(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    chirc_connection_t *current_connection;
    chirc_connection_t *tmp;

    HASH_ITER(hh, ctx->connections, current_connection, tmp) {
        if (current_connection->type == CONN_TYPE_SERVER) {
            chirc_connection_send_message(ctx, current_connection, msg, false);
        }
    }
    
    chirc_message_free(msg);
    return CHIRC_OK;
}

struct server_connect_worker_args {
    chirc_ctx_t *ctx;
    chirc_connection_t *conn;
    chirc_message_t *msg;

    sds hostname;
    sds port;
    sds target_port;

    chirc_server_t *peer_server;
};

void *_chirc_connection_thread_connect(void *info) {
    struct server_connect_worker_args *wa = (struct server_connect_worker_args*)info;

    chirc_ctx_t *ctx = wa->ctx;
    chirc_connection_t *conn = wa->conn;

    sds target_port = wa->target_port;
    sds target_host = wa->hostname;

    struct sockaddr_storage *server_addr; // initialize server address struct
    socklen_t sin_size = sizeof(struct sockaddr_storage); // get size of client sockect struct

    int connection_socket;
    struct addrinfo hints, *res, *p;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // attempt to get the address info. if it fails, 
    if (getaddrinfo(target_host, target_port, &hints, &res) != 0)
    {
        chilog(ERROR, "getaddrinfo() failed");
        return NULL;
    }


    // iterate through all the addrinfo's we recieved until we connect to one
    for(p = res;p != NULL; p = p->ai_next)
    {
        // try and open a socket on the current addr
        connection_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (connection_socket == -1)
        {
            chilog(ERROR, "Server.c: Socket failed to open.");
            continue;
        }

        if ( connect(connection_socket, p->ai_addr, p->ai_addrlen) ) {
            chilog(ERROR, "Server.c: Connect failed.");
            continue;
        }

    }


    // now we may free the res addr info
    freeaddrinfo(res);

    // if p is null we could not make a connection
    if (connection_socket == -1)
    {
        chilog(ERROR, "Server.c: Could not find a socket to bind to.\n");
        close(connection_socket);
        return NULL;
    }


    chirc_connection_t *newConnection = (chirc_connection_t*)malloc(sizeof(chirc_connection_t));

    // if malloc fails return
    if (!newConnection) {
        chilog(ERROR, "Memory allocation failed\n");
        close(connection_socket);
        return NULL;
    }


    chirc_connection_init(newConnection);


    newConnection->socket = connection_socket;
    
    chirc_ctx_add_connection(ctx, newConnection);

    chirc_connection_create_thread(ctx, newConnection);
    newConnection->hostname = wa->hostname;
    newConnection->port = wa->port;
    newConnection->type = CONN_TYPE_SERVER;
    newConnection->peer.server = wa->peer_server;
    newConnection->peer.server->registered = true;

    chirc_message_t *passMsg = (chirc_message_t*)malloc(sizeof(chirc_message_t));
    chirc_message_construct(passMsg, NULL, "PASS");
    chirc_message_add_parameter(passMsg, wa->peer_server->passwd, false);
    chirc_connection_send_message(ctx, newConnection, passMsg, true);


    /* send SERVER msg */
    chirc_message_t *serverMsg = (chirc_message_t*)malloc(sizeof(chirc_message_t));
    chirc_message_construct(serverMsg, NULL, "SERVER");

    chirc_message_add_parameter(serverMsg, ctx->network.this_server->servername, false);

    chirc_message_add_parameter(serverMsg, "*", false);
    chirc_message_add_parameter(serverMsg, "*", false);
    chirc_message_add_parameter(serverMsg, "*", false);

    chirc_connection_send_message(ctx, newConnection, serverMsg, true);

    return newConnection;
}

/* See connection.h */
int chirc_connection_connect_servers(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {

    /** OK I need to connect these servers now. I should:
     * connect host name
     * connect port
     * 
     * make sure its good
     * 
     * if it is, the connection should be hashed
     * 
    */

   // variables dealing with threading later on
    struct server_connect_worker_args *wa;
    pthread_t worker_thread;

    wa = calloc(1, sizeof(struct server_connect_worker_args));
    wa->conn = conn;
    wa->ctx = ctx;
    wa->msg = msg;
    wa->port = ctx->network.this_server->port;


    sds target_server_name = msg->params[0];

    // find the target server
    chirc_server_t *target_server_struct;
    HASH_FIND_STR( ctx->network.servers, target_server_name, target_server_struct );

    if ( !target_server_struct ) {
        return CHIRC_FAIL;
    }

    wa->hostname = target_server_struct->hostname;
    wa->target_port = target_server_struct->port;
    wa->peer_server = target_server_struct;

   if (pthread_create(&worker_thread, NULL, _chirc_connection_thread_connect, wa) != 0)
    {
        chilog(ERROR, "Could not create a worker thread");
        free(wa);
        return CHIRC_FAIL;
    }

    // should actualy check here for a return of an int -> 0 good, non zero error
    // then return chirc_fail if bad

    void *val = NULL;
    pthread_join(worker_thread, &val);
    free(wa);

    if (!val) {
        chilog(ERROR, "CONNECT: Server connection could not be found.");
        return CHIRC_FAIL;
    }

    return CHIRC_OK;
}
