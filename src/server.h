/*! \file server.h
 *  \brief Functions related to chirc_server_t
 *
 *  This module provides functions related to the chirc_server_t struct.
 *
 *  It currently only includes functions for initializing and destroying
 *  a chirc_server_t struct.
 *
 */
#ifndef SERVER_H_
#define SERVER_H_

#include "chirc.h"

/*! \brief Initializes a chirc_server_t struct
 *
 * This function assumes that memory has already been allocated
 * for the struct, and will initialize its fields.
 *
 * \param server The server to initialize
 */
void chirc_server_init(chirc_server_t *server);


/*! \brief Frees a chirc_server_t struct
 *
 * This function frees memory allocated to the fields of s
 * chirc_server_t struct, but does not free the struct
 * itself (doing so is the responsibility of the caller
 * of this function)
 *
 * \param server The server to free
 */
void chirc_server_free(chirc_server_t *server);


/**
 * This function should deal with keeping the server running. We likely
 * need a while(true) {} loop for the sockets, then execture the following steps:
 * 
 * 1. socket() // maybe not needed, tbd
 * 2. bind()
 * 3. listen()
 * 3. accept()
 * 
 * This code was tweaked from the multi-threading example for testing
*/
void run_server(chirc_ctx_t *ctx);


// Arguements to pass to the worker function for handling the client
struct worker_args
{
    chirc_ctx_t *ctx;
    chirc_connection_t *conn;
};

/**
 * This function deals with communicating with a client once it has connected
 * to one of our sockets.
*/
void *handle_client_on_socket(void *ptr);

#endif /* SERVER_H_ */
