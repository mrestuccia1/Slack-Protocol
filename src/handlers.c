/*
 * Message handlers
 *
 * In chirc, the code to process each IRC command is contained in
 * a function that looks like this:
 *
 *     int chirc_handle_COMMAND(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
 *
 * e.g., the handler function for PRIVMSG would be chirc_handle_PRIVMSG
 * (with the same parameters shown above)
 *
 * These functions are added to a dispatch table that allows us
 * to easily dispatch messages to the correct function based
 * on their command.
 *
 * A dispatch table is basically a table that maps a key (in this
 * case, an IRC command) to a function pointer. So, given
 * a command name, we can find the function that will handle
 * that command. In our code, this table is implemented
 * via the "handlers" array contained in this module.
 *
 * To implement a new command, you will need to implement a
 * handler function for that command, and update the "handlers"
 * array to add an entry for the new command. See the code
 * below for more details.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <sys/socket.h>
#include <netdb.h>
#include "ctx.h"
#include "channel.h"
#include "channeluser.h"
#include "handlers.h"
#include "reply.h"
#include "log.h"
#include "connection.h"
#include "chirc.h"
#include "message.h"
#include "user.h"
#include "server.h"
#include "uthash.h"
#include "utils.h"

#define MAX_CODE_LEN 3
#define PROTOCOL "0210"


/* The following typedef defines a type called "handler_function"
 * for the function pointers in the handlers array. */
typedef int (*handler_function_t)(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/**
 * Section for forward declarations so that they may be used later on.
*/
void _chirc_handle_ERROR_reply(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg, char *errorCode);
void _chirc_handle_ERROR_message(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg, char *errorCode);


/* Forward declaration of handler functions */

int chirc_handle_PING(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_PONG(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_USER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_NICK(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_QUIT(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_PRIVMSG(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_NOTICE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_JOIN(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_PART(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_LUSERS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_WHOIS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_LIST(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_OPER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_MODE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_AWAY(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_SERVER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_PASS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_CONNECT(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_CONNECT(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);



/*! \struct handler_entry
 * \brief Entry in the handler dispatch table
 *
 * This struct represents one entry in the dispatch table:
 * a command name and a function pointer to a handler function
 * (using the handler_function_t type we defined earlier) */
struct handler_entry
{
    char *name;
    handler_function_t func;
};

/* Convenience macro for specifying entries in the dispatch table */
#define HANDLER_ENTRY(NAME) { #NAME, chirc_handle_ ## NAME}

/* Null entry in the dispatch table. This must always be the last
 * entry in the dispatch table */
#define NULL_ENTRY			{ NULL, NULL }


/* The dispatch table (an array of handler_entry structs).
 * To add a new entry (e.g., for command FOOBAR) add a new
 * line that looks like this:
 *
 *     HANDLER_ENTRY (FOOBAR)
 *
 * Make sure to add it *before* the NULL_ENTRY entry, which
 * must always come last.
 */
struct handler_entry handlers[] =
{
    HANDLER_ENTRY (PING),
    HANDLER_ENTRY (PONG),
    HANDLER_ENTRY (NICK),
    HANDLER_ENTRY (USER),
    HANDLER_ENTRY (QUIT),
    HANDLER_ENTRY (PRIVMSG),
    HANDLER_ENTRY (NOTICE),
    HANDLER_ENTRY (JOIN),
    HANDLER_ENTRY (PART),
    HANDLER_ENTRY (LUSERS),
    HANDLER_ENTRY (WHOIS),
    HANDLER_ENTRY (OPER),
    HANDLER_ENTRY (MODE),
    HANDLER_ENTRY (AWAY),
    HANDLER_ENTRY (LIST),
    HANDLER_ENTRY (SERVER),
    HANDLER_ENTRY (PASS),
    HANDLER_ENTRY (CONNECT),

    NULL_ENTRY
};


/* See handlers.h */
int chirc_handle(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    chirc_message_t reply;
    int rc=0, h;

    /* Print message to the server log */
    serverlog(INFO, conn, "Handling command %s", msg->cmd);
    for(int i=0; i<msg->nparams; i++)
        serverlog(INFO, conn, "%s[%i] = %s", msg->cmd, i + 1, msg->params[i]);

    /* Search the dispatch table for an entry corresponding to the
     * message we are processing */
    bool found_cmd = false;

    for(h=0; handlers[h].name != NULL; h++)
        if (!strncmp(msg->cmd, handlers[h].name, MSG_MAX))
        {
            found_cmd = true;
            rc = handlers[h].func(ctx, conn, msg);
            break;
        }

    // called a non-existant command
    bool registered = false;
    if (conn->type == CONN_TYPE_USER) {
        registered = conn->peer.user->registered;
    } else if (conn->type == CONN_TYPE_SERVER) { 
        registered = conn->peer.server->registered;
    }

    if (registered && !found_cmd && conn->type != CONN_TYPE_SERVER) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_UNKNOWNCOMMAND);
    }
    return rc;
}


/**
 * This function verifies the number of params for a given command.
*/
int _chirc_verify_num_params(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {

    sds cmd = msg->cmd;
    int nparams = msg->nparams;

    if ( !strncmp(cmd, "USER", MSG_MAX) && nparams != 4) {

        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NEEDMOREPARAMS);
        return CHIRC_FAIL;
    } else if ( !strncmp(cmd, "MODE", MSG_MAX) ) {

        if (nparams < 1)  {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NEEDMOREPARAMS);
            return CHIRC_FAIL;
        }

        if (nparams == 1 && msg->params[0][0] != '#') {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NEEDMOREPARAMS);
            return CHIRC_FAIL;
        }
        
    } else if ( !strncmp(cmd, "OPER", MSG_MAX) && nparams < 2) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NEEDMOREPARAMS);
        return CHIRC_FAIL;

    } else if (!strncmp(cmd, "NICK", MSG_MAX) && nparams < 1) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NONICKNAMEGIVEN);
        return CHIRC_FAIL;
    } else if ( !strncmp(cmd, "PASS", MSG_MAX) && nparams < 1) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NEEDMOREPARAMS);
        return CHIRC_FAIL;
    } else if ( !strncmp(cmd, "CONNECT", MSG_MAX) && nparams < 1) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NEEDMOREPARAMS);
        return CHIRC_FAIL;
    }

    return CHIRC_OK;
}

/**
 * This function deals with the server's error sending.
*/
void _chirc_handle_ERROR_message(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg, char *errorCode) {
    chirc_message_t *errorMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));

    char errorCmd[6] = "ERROR";
    chirc_message_construct(errorMsg, NULL, errorCmd);


    if ( !strncmp(errorCode, CLIENT_QUIT_CODE, MSG_MAX) ) {
        sds quit_message = (msg->nparams) ? msg->params[0] : "Client Quit";

        char total_msg[MSG_MAX];

        sprintf(total_msg, "Closing Link: %s (%s)", conn->hostname, quit_message);

        chirc_message_add_parameter(errorMsg, total_msg, true);

    } else if ( !strncmp(errorCode, SERVER_BAD_PASS, MSG_MAX) ) {

        sds bad_pass = "Bad password";
        chirc_message_add_parameter(errorMsg, bad_pass, true);

    } else if ( !strncmp(errorCode, SERVER_ALREADY_REG, MSG_MAX) ) {

        char already_reg[MSG_MAX];
        sprintf(already_reg, "ID \"%s\" already registered", conn->peer.server->servername);
        chirc_message_add_parameter(errorMsg, already_reg, true);
        
    } else if ( !strncmp(errorCode, SERVER_NAME_NOT_IN, MSG_MAX) ) {
        sds server_not_conf = "Server not configured here";
        chirc_message_add_parameter(errorMsg, server_not_conf, true);
    }

    chirc_connection_send_message(ctx, conn, errorMsg, true);

    return;
}

/**
 * This function deals with sending error replies. These are separate from proper error messages - error messages
 * are prefixed with an error command whereas these just send the error code as a reply.
*/
void _chirc_handle_ERROR_reply(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg, char *errorCode) {

    chirc_message_t *errorMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));

    if (!strncmp(errorCode, ERR_NONICKNAMEGIVEN, MAX_CODE_LEN) ) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_NONICKNAMEGIVEN);
        char noNick[] = "No nickname given";
        chirc_message_add_parameter(errorMsg, noNick, true);

    } else if (!strncmp(errorCode, ERR_NICKNAMEINUSE, MAX_CODE_LEN) ) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_NICKNAMEINUSE);
        chirc_message_add_parameter(errorMsg, msg->params[0], false);
        char nickInUse[] = "Nickname is already in use";
        chirc_message_add_parameter(errorMsg, nickInUse, true);

    } else if ( !strncmp(errorCode, ERR_NEEDMOREPARAMS, MAX_CODE_LEN) ) {
        
        sds cmd = msg->cmd;
        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_NEEDMOREPARAMS);
        chirc_message_add_parameter(errorMsg, cmd, false);
        char nmpString[] = "Not enough parameters";
        chirc_message_add_parameter(errorMsg, nmpString, true);

    } else if (!strncmp(errorCode, ERR_ALREADYREGISTRED, MAX_CODE_LEN) ) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_ALREADYREGISTRED);

        chilog(INFO, "Correct path");

        char arString[MSG_MAX];
        if (conn->type == CONN_TYPE_USER) {
            chilog(INFO, "client mode activated");
            strncpy(arString, "Connection already registered", MSG_MAX);
        } else if (conn->type == CONN_TYPE_SERVER) {
            chilog(INFO, "server mode activated");
            strncpy(arString, "Unauthorized command (already registered)", MSG_MAX);
        } else {
            chilog(INFO, "crash mode activated");
        }

        chirc_message_add_parameter(errorMsg, arString, true);

    } else if (!strncmp(errorCode, ERR_NOTREGISTERED, MAX_CODE_LEN)) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_NOTREGISTERED);
        char arString[] = "You have not registered";
        chirc_message_add_parameter(errorMsg, arString, true);

    } else if (!strncmp(errorCode, ERR_NORECIPIENT, MAX_CODE_LEN)) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_NORECIPIENT);
        char noRecipientString[] = "No recipient given (PRIVMSG)";
        chirc_message_add_parameter(errorMsg, noRecipientString, true);

    } else if (!strncmp(errorCode, ERR_NOTEXTTOSEND, MAX_CODE_LEN)) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_NOTEXTTOSEND);
        char noTextString[] = "No text to send";
        chirc_message_add_parameter(errorMsg, noTextString, true);

    } else if (!strncmp(errorCode, ERR_NOSUCHNICK, MAX_CODE_LEN)) {
        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_NOSUCHNICK);
        chirc_message_add_parameter(errorMsg, msg->params[0], false);
        char noSuchNickString[] = "No such nick/channel";
        chirc_message_add_parameter(errorMsg, noSuchNickString, true);

    } else if (!strncmp(errorCode, ERR_UNKNOWNCOMMAND, MAX_CODE_LEN)) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_UNKNOWNCOMMAND);
        chirc_message_add_parameter(errorMsg, msg->cmd, false);
        char noTextString[] = "Unknown command";
        chirc_message_add_parameter(errorMsg, noTextString, true);
    
    } else if (!strncmp(errorCode, ERR_CANNOTSENDTOCHAN, MAX_CODE_LEN)) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_CANNOTSENDTOCHAN);
        chirc_message_add_parameter(errorMsg, msg->params[0], false);
        char noTextString[] = "Cannot send to channel";
        chirc_message_add_parameter(errorMsg, noTextString, true);

    } else if (!strncmp(errorCode, ERR_NOSUCHCHANNEL, MAX_CODE_LEN)) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_NOSUCHCHANNEL);
        chirc_message_add_parameter(errorMsg, msg->params[0], false);
        char noTextString[] = "No such channel";
        chirc_message_add_parameter(errorMsg, noTextString, true);

    } else if (!strncmp(errorCode, ERR_NOTONCHANNEL, MAX_CODE_LEN)) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_NOTONCHANNEL);
        chirc_message_add_parameter(errorMsg, msg->params[0], false);
        char noTextString[] = "You're not on that channel";
        chirc_message_add_parameter(errorMsg, noTextString, true);

    } else if (!strncmp(errorCode, ERR_USERSDONTMATCH, MAX_CODE_LEN)) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_USERSDONTMATCH);
        char badChangeString[] = "Cannot change mode for other users";
        chirc_message_add_parameter(errorMsg, badChangeString, true);

    } else if ( !strncmp(errorCode, ERR_UMODEUNKNOWNFLAG, MAX_CODE_LEN) ) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_UMODEUNKNOWNFLAG);
        char badModeString[] = "Unknown MODE flag";
        chirc_message_add_parameter(errorMsg, badModeString, true);

    } else if ( !strncmp(errorCode, ERR_PASSWDMISMATCH, MAX_CODE_LEN) ) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_PASSWDMISMATCH);
        char badPassString[] = "Password incorrect";
        chirc_message_add_parameter(errorMsg, badPassString, true);

    } else if (!strncmp(errorCode, ERR_CHANOPRIVSNEEDED, MAX_CODE_LEN) ){

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_CHANOPRIVSNEEDED);

        sds channelName = NULL;

        for (int i = 0; i < msg->nparams; i++) {
            if (msg->params[i][0] == '#') {
                channelName = msg->params[i];
                i = msg->nparams;
            }
        }

        chirc_message_add_parameter(errorMsg, channelName, false);

        sds notUserStr = "You're not channel operator";
        chirc_message_add_parameter(errorMsg, notUserStr, true);

    } else if (!strncmp(errorCode, ERR_USERNOTINCHANNEL, MAX_CODE_LEN) ) {
 
        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_USERNOTINCHANNEL);

        chirc_message_add_parameter(errorMsg, msg->params[2], false);
        chirc_message_add_parameter(errorMsg, msg->params[0], false);

        char not_in_channel[] = "They aren't on that channel";
        chirc_message_add_parameter(errorMsg, not_in_channel, true);

    } else if ((!strncmp(errorCode, ERR_UNKNOWNMODE, MAX_CODE_LEN) )) {

        chirc_message_construct_reply(errorMsg, ctx, conn, ERR_UNKNOWNMODE);

        chirc_message_add_parameter(errorMsg, &msg->params[1][1], false);

        char unknown_mode[MSG_MAX];
        sprintf(unknown_mode, "is unknown mode char to me for %s", msg->params[0]);
        chirc_message_add_parameter(errorMsg, unknown_mode, true);

    }

    chilog(INFO, "Sending info");
    chirc_connection_send_message(ctx, conn, errorMsg, true);
    chilog(INFO, "sent info");
    return;
}

int chirc_handle_PING(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    // check that the user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }
    /* Construct a reply to the PING */
    chirc_message_t reply;
    chirc_message_construct(&reply, NULL, "PONG");
    chirc_message_add_parameter(&reply, ctx->network.this_server->servername, 0);

    /* Send the message */
    if(chirc_connection_send_message(ctx, conn, &reply, true))
    {
        return CHIRC_HANDLER_DISCONNECT;
    }
    
    return CHIRC_OK;
}

int chirc_handle_PONG(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* PONG messages are ignored, so we don't do anything */

    return CHIRC_OK;
}

/**
 * This function sends all the LUSERS information for a given context and connection.
 * 
 * It is pulled out into its own function like this because it was used in two separate functions
 * (registration handling and LUSERS) and it takes up a bunch of space.
*/
void _generate_LUSERS_mesages(chirc_ctx_t *ctx, chirc_connection_t *conn) {
    uint users = 0;
    uint unknown = 0;
    uint registered_users = 0;

    uint connections = 0;

    uint operators = 0;

    uint servers = 1;
    uint services = 0;
    uint channels = 0;

    /* ----- Calculate Values ----- */

    operators = chirc_ctx_numops(ctx);
    channels = chirc_ctx_numchannels(ctx);
    unknown = chirc_ctx_unknown_connections(ctx);
    users = chirc_ctx_numusers(ctx);

    chirc_server_t *curServer, *tmpServer = NULL;
    HASH_ITER(hh, ctx->network.servers, curServer, tmpServer) {
        servers++;
    }

    uint clients = 0;

    chirc_connection_t *curConn, *tmpConn = NULL;
    HASH_ITER(hh, ctx->connections, curConn, tmpConn) {
        clients++;
    }
    clients -= unknown;

    /* ----- End Calculate Values ----- */

    char rplMsgStr[MSG_MAX];
    /* ----- RPL_LUSERCLIENT ----- */
    chirc_message_t *userClient = (chirc_message_t*)malloc(sizeof(chirc_message_t));
    chirc_message_construct_reply(userClient, ctx, conn, RPL_LUSERCLIENT);

    sprintf(rplMsgStr, "There are %d users and %d services on %d servers", users, services, servers);

    chirc_message_add_parameter(userClient, rplMsgStr, true);
    chirc_connection_send_message(ctx, conn, userClient, true);

    /* ----- RPL_LUSEROP ----- */
    chirc_message_t *userOp = (chirc_message_t*)malloc(sizeof(chirc_message_t));
    chirc_message_construct_reply(userOp, ctx, conn, RPL_LUSEROP);

    char numOperators[10];

    sprintf(numOperators, "%d", operators);
    chirc_message_add_parameter(userOp, numOperators, false);

    sprintf(rplMsgStr, "operator(s) online");
    chirc_message_add_parameter(userOp, rplMsgStr, true);

    chirc_connection_send_message(ctx, conn, userOp, true);

    /* ----- RPL_LUSERUNKNOWN ----- */
    chirc_message_t *userUnknown = (chirc_message_t*)malloc(sizeof(chirc_message_t));
    chirc_message_construct_reply(userUnknown, ctx, conn, RPL_LUSERUNKNOWN);

    char numUnknown[10];

    sprintf(numUnknown, "%d", unknown);
    chirc_message_add_parameter(userUnknown, numUnknown, false);

    sprintf(rplMsgStr, "unknown connection(s)");
    chirc_message_add_parameter(userUnknown, rplMsgStr, true);

    chirc_connection_send_message(ctx, conn, userUnknown, true);

    /* ----- RPL_LUSERCHANNELS ----- */
    chirc_message_t *userChannel = (chirc_message_t*)malloc(sizeof(chirc_message_t));
    chirc_message_construct_reply(userChannel, ctx, conn, RPL_LUSERCHANNELS);

    char channelsStr[10];

    sprintf(channelsStr, "%d", channels);
    chirc_message_add_parameter(userChannel, channelsStr, false);

    sprintf(rplMsgStr, "channels formed");
    chirc_message_add_parameter(userChannel, rplMsgStr, true);

    chirc_connection_send_message(ctx, conn, userChannel, true);

    /* ----- RPL_LUSERME ----- */
    chirc_message_t *userMe = (chirc_message_t*)malloc(sizeof(chirc_message_t));
    chirc_message_construct_reply(userMe, ctx, conn, RPL_LUSERME);

    sprintf(rplMsgStr, "I have %d clients and %d servers", clients, servers);

    chirc_message_add_parameter(userMe, rplMsgStr, true);
    chirc_connection_send_message(ctx, conn, userMe, true);

    return;
}


/**
 * This function handles user registration once it has been reached. It is in here and not user.c because
 * it deals more with the reply message and what must be down around the user than on the user itself. 
 * 
 * It does the following:
 * * send a welcome message
 * * set the user's registered status to true
 * * adds the user to the "users" hashmap
*/
void _handle_user_register(chirc_ctx_t *ctx, chirc_connection_t *conn) {

    // first and foremost, get the user
    chirc_user_t* user = conn->peer.user;

    /**
     * If the nick is given, we should check to make sure that it is not in use.
    */
    chirc_user_t *checkUser = NULL;
    checkUser = chirc_ctx_get_user(ctx, user->nick);

    if (checkUser != NULL) {
         _chirc_handle_ERROR_reply(ctx, conn, NULL, ERR_NICKNAMEINUSE);
    }

    /**
     * Deal with user registration
    */
    user->registered = true;
    chirc_ctx_add_user(ctx, user);

    /**
     * End user registration
    */

    // variable about to be used in a bunch of stuff
    char msg_body[MSG_MAX];

    /********** RPL_WELCOME **********/
    // create the return message and initialize the reply welcome
    chirc_message_t *returnMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));
    chirc_message_construct_reply(returnMsg, ctx, conn, RPL_WELCOME);

    /**
     * Now the return message must be constructed, as seen below. The return message is made by passing in
     * the nickname, username, and peer_hostname to construct the desired return message.
    */
    sds nickName = user->nick;
    sds userName = user->username;
    sds peer_hostname = conn->hostname;

    sprintf(msg_body, "Welcome to the Internet Relay Network %s!%s@%s", nickName, userName, peer_hostname);
    //** end section

    // add the return string to the message
    chirc_message_add_parameter(returnMsg, msg_body, true);

    // send the message
    chirc_connection_send_message(ctx, conn, returnMsg, true);

    /* End RPL_WELCOME */

    /*********** RPL_YOURHOST ***********/

    // create the return message and initialize the reply welcome
    chirc_message_t *welcomeMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));
    chirc_message_construct_reply(welcomeMsg, ctx, conn, RPL_YOURHOST);

    /**
     * Now the return message must be constructed, as seen below. The return message is made by passing in
     * the nickname, username, and peer_hostname to construct the desired return message.
    */
    sds serverName = ctx->network.this_server->servername;
    sds version = ctx->version;

    sprintf(msg_body, "Your host is %s, running version %s", serverName, version);
    //** end section

    // add the return string to the message
    chirc_message_add_parameter(welcomeMsg, msg_body, true);

    // send the message
    chirc_connection_send_message(ctx, conn, welcomeMsg, true);

    /* End RPL_YOURHOST */

    /********* RPL_CREATED **********/

    // create the return message and initialize the reply welcome
    chirc_message_t *createdMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));
    chirc_message_construct_reply(createdMsg, ctx, conn, RPL_CREATED);

    /**
     * Now the return message must be constructed, as seen below. The return message is made by passing in
     * the nickname, username, and peer_hostname to construct the desired return message.
    */
    int creationDate = ctx->created.tm_sec;

    sprintf(msg_body, "This server was created %d", creationDate);

    // add the return string to the message
    chirc_message_add_parameter(createdMsg, msg_body, true);

    // send the message
    chirc_connection_send_message(ctx, conn, createdMsg, true);

    /* End RPL_CREATED */

    /********** RPL_MYINFO **********/

    // create the return message and initialize the reply welcome
    chirc_message_t *infoMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));
    chirc_message_construct_reply(infoMsg, ctx, conn, RPL_MYINFO);

    /**
     * Now the return message must be constructed, as seen below. The return message is made by passing in
     * the nickname, username, and peer_hostname to construct the desired return message.
    */
    // sds serverName = ctx->network.this_server->servername;
    // sds version = ctx->version;
    char aoMode[] = "ao";
    char mtovMode[] = "mtov";
    // char channelMode[] = "None";

    chirc_message_add_parameter(infoMsg, serverName, false);
    chirc_message_add_parameter(infoMsg, version, false);
    chirc_message_add_parameter(infoMsg, aoMode, false);
    chirc_message_add_parameter(infoMsg, mtovMode, false);
    // chirc_message_add_parameter(infoMsg, channelMode, false);

    // add the return string to the message
    // chirc_message_add_parameter(infoMsg, msg_body, true);

    // send the message
    chirc_connection_send_message(ctx, conn, infoMsg, true);

    /* End RPL_MYINFO */

    /* send all the lusers information! */
    _generate_LUSERS_mesages(ctx, conn);


    sprintf(msg_body, ":hostname 422 %s :MOTD File is missing\r\n", user->nick);
    int msgBodyLen = strlen(msg_body);
    int success = sendall(conn->socket, msg_body, &msgBodyLen);

    /* ----- Start Send NICK (server version) to all servers ----- */

    chirc_message_t * nick_msg = (chirc_message_t *)malloc(sizeof(chirc_message_t));
    chirc_message_construct(nick_msg, ctx->network.this_server->servername, "NICK");
    chirc_message_add_parameter(nick_msg, nickName, false);
    chirc_message_add_parameter(nick_msg, "1", false); // hopcount hardcode
    chirc_message_add_parameter(nick_msg, userName, false);
    chirc_message_add_parameter(nick_msg, user->hostname, false);
    chirc_message_add_parameter(nick_msg, "1", false); // servertoken hardcode
    chirc_message_add_parameter(nick_msg, "+", false); // umode hardcode
    chirc_message_add_parameter(nick_msg, user->fullname, true); 

    chirc_connection_relay_msg(ctx, conn, nick_msg);
    

    /* ----- End Send NICK (server version) to all servers ----- */

    return;
}

int chirc_handle_NICK(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    /**
     * For a nick command, there should only be 1 parameter which is the nick name
     * If this is not the case, do some error handling
    */

    if (_chirc_verify_num_params(ctx, conn, msg) == CHIRC_FAIL) {
        chilog(WARNING, "NICK handle: bad message received.");
        return CHIRC_OK;
    }
    if (conn->type == CONN_TYPE_SERVER) { // specific path for the server
        // Getting the info we need to initialize a user copy
        sds servername = sdsnew(msg->prefix);
        sds nickname = sdsnew(msg->params[0]);
        sds username = sdsnew(msg->params[2]);
        sds hostname = sdsnew(msg->params[3]);
        sds fullname = sdsnew(msg->params[6]);

        // Get the server they belong to
        chirc_server_t *other_server = chirc_ctx_get_server(ctx, servername);

        /* get the user, regardless if they exist or not, and update info */
        chirc_user_t *user_copy;
        chirc_ctx_get_or_create_user(ctx, nickname, &user_copy);
        user_copy->server = other_server;
        user_copy->username = username;
        user_copy->hostname = hostname;
        user_copy->fullname = fullname;

    } else {
        /**
         * If the nick is given, we should check to make sure that it is not in use.
        */
        sds nickname = sdsnew(msg->params[0]);

        chirc_user_t *checkUser = NULL;
        checkUser = chirc_ctx_get_user(ctx, nickname);

        // get the user for cleanliness coding
        chirc_user_t* user = conn->peer.user;

        // before tainting the potentially previous nickname, should grab it for later use
        char prevNick[MSG_MAX] = "";
        if ( user->nick != NULL) {
            sdscpy(prevNick, user->nick);
        }

        // by convention, the first param will be the nick
        user->nick = sdsdup(nickname);

        // check if nick in use now. it should be done here so that user->nick is
        // iniitalized and may be accessed in error call
        if (checkUser != NULL) {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NICKNAMEINUSE);
        }

        // if it is a user or nick command we know that the conn type is user
        conn->type = CONN_TYPE_USER;

        // check if user should now be registered
        if (!user->registered && (user->nick != NULL) && (user->username != NULL) && (user->fullname != NULL)) { _handle_user_register(ctx, conn); }


        /* Send NICK to channel logic */
        // if the user is in a channel, we should send a message alerting the channel
        chirc_channeluser_t *el, *tmp = NULL;

        chirc_message_t *channelMsg = (chirc_message_t*)malloc(sizeof(chirc_message_t));
        // chirc_message_construct(channelMsg, )
        char nickCmd[] = "NICK";


        char prefix[MSG_MAX];
        sprintf(prefix, "%s!%s@%s", prevNick, user->username, user->hostname);
        chirc_message_construct(channelMsg, prefix, nickCmd);

        chirc_message_add_parameter(channelMsg, user->nick, true);

        HASH_ITER(hh_from_channel, user->channels, el, tmp) {
            send_msg_to_channel(ctx, conn, channelMsg, el->channel, true);
        }
    }
    return CHIRC_OK;
}

int chirc_handle_USER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {

    // do number of parameter checking
    if ( _chirc_verify_num_params(ctx, conn, msg) == CHIRC_FAIL) { return CHIRC_OK; }

    // if it is a user or nick command we know that the conn type is user
    conn->type = CONN_TYPE_USER;

    // get the user
    chirc_user_t* user = conn->peer.user;

    // Check to see if the user is registered
    if (user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_ALREADYREGISTRED);

        return CHIRC_OK;
    }
    
    // grab the username, fullname which are the 1st and 4th parameters
    // respectively
    user->username = strdup( msg->params[0] );
    user->fullname = strdup( msg->params[3] );

    // check if user should now be registered. check is already done to see if user is registered
    if ((user->nick != NULL) && (user->username != NULL) && (user->fullname != NULL)) { _handle_user_register(ctx, conn); }

    return CHIRC_OK;
}

int chirc_handle_QUIT(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {

    // Check that user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }

    // handle the quit!
    chirc_user_t *user = conn->peer.user;

    _chirc_handle_ERROR_message(ctx, conn, msg, CLIENT_QUIT_CODE);

    chirc_channel_t *current_channel;
    chirc_channel_t *tmp;

    chirc_message_t *errorMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));
    char errorCmd[6] = "QUIT";

    // char prefix[MSG_MAX];
    // sprintf(prefix, "%s!%s@%s", user->nick, user->username, user->hostname);
    // chirc_message_construct(errorMsg, prefix, errorCmd);

    chirc_message_contruct_user_prefix_reply(errorMsg, user, errorCmd);

    sds quit_message = (msg->nparams) ? msg->params[0] : "Client Quit";
    char total_msg[MSG_MAX];
    sprintf(total_msg, "%s", quit_message);
    chirc_message_add_parameter(errorMsg, total_msg, true);

    HASH_ITER(hh, ctx->channels, current_channel, tmp) {
        send_msg_to_channel(ctx, conn, errorMsg, current_channel, false);
    }

    chirc_ctx_remove_user(ctx, user);
    free(user);
    return CHIRC_HANDLER_DISCONNECT;
}

// Used to send NOTICE or PRIVMSG messages to a user in a channel
int _send_msg_to_user(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg, chirc_user_t *target_user, sds channel_name) {
    chirc_connection_t *target_conn = target_user->conn;
    chirc_user_t *user;
    if (conn->type == CONN_TYPE_USER) {
        user = conn->peer.user;
    } else if (conn->type == CONN_TYPE_SERVER) {
        user = chirc_ctx_get_user(ctx, msg->prefix);
    }
    char prefix[MSG_MAX];
    sds targetNickName = target_user->nick;
    sds targetUserName = target_user->username;
    sds targetPeerHostname = target_conn->hostname;
    sprintf(prefix, "%s!%s@%s", user->nick, user->username, conn->hostname);

    chirc_message_t return_msg;
    chirc_message_construct(&return_msg, prefix, msg->cmd);

    sds name = (!channel_name) ? target_user->nick : channel_name;
    chirc_message_add_parameter(&return_msg, name, false);
    chirc_message_add_parameter(&return_msg, msg->params[1], true);
    /* Send the message */
    if(chirc_connection_send_message(ctx, target_conn, &return_msg, true))
    {
        chirc_message_free(&return_msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

int chirc_handle_PRIVMSG(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {

    // Check that user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }

    chirc_user_t *target_user = NULL;
    chirc_channel_t *target_channel = NULL;
    chirc_user_t *user;

    if (conn->type == CONN_TYPE_SERVER) {
        sds from_nick = sdsnew(msg->prefix);
        user = chirc_ctx_get_user(ctx, from_nick);
    } else {
        user = conn->peer.user;
    }
    
    if (!msg->params[0]) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NORECIPIENT);
        return CHIRC_OK;

    } else if (!msg->params[1]) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTEXTTOSEND);
        return CHIRC_OK;
    }

    target_user = chirc_ctx_get_user(ctx, sdsnew(msg->params[0]));
    target_channel = chirc_ctx_get_channel(ctx, sdsnew(msg->params[0]));

    if (!target_user && !target_channel) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOSUCHNICK);
    } else if (target_user) { // A message to a user
        /* Check to see if the user is in the server */

        if ( strncmp(target_user->server->servername, ctx->network.this_server->servername, MSG_MAX) ) { // the user is not in the server
            if (conn->type == CONN_TYPE_USER) {
                chirc_message_t *msgToServers = (chirc_message_t *)malloc(sizeof(chirc_message_t));
    

                char prefix[MSG_MAX];
                sprintf(prefix, "%s", user->nick);
                chirc_message_construct(msgToServers, prefix, "PRIVMSG");

                chirc_message_add_parameter(msgToServers, msg->params[0], false);
                chirc_message_add_parameter(msgToServers, msg->params[1], true);

                chirc_connection_relay_msg(ctx, conn, msgToServers);
            
            }
            else { // we recieved from a server so check if the user is in here

                if (target_user->conn) {
                    chirc_connection_send_message(ctx, target_user->conn, msg, false);
                }

            }

        } else { // the user is in the server
            _send_msg_to_user(ctx, conn, msg, target_user, NULL);
            if (target_user->awaymsg) {
                chirc_message_t* away_reply = (chirc_message_t*)malloc( sizeof(chirc_message_t) );
                chirc_message_construct_reply(away_reply, ctx, conn, RPL_AWAY);
                chirc_message_add_parameter(away_reply, target_user->nick, false);
        
                chirc_message_add_parameter(away_reply, target_user->awaymsg, true);
                chirc_connection_send_message(ctx, conn, away_reply, true);
            }
        }

    } else if (!chirc_channeluser_get(target_channel, user)) { // The user has not yet joined the channel
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_CANNOTSENDTOCHAN);
        
    } else { // A message to a channel
        // before a message is sent to the channel, check for permissions!
        chirc_channeluser_t * channel_user = chirc_channeluser_get(target_channel, user);

        if ( chirc_channel_has_mode( target_channel, 'm') ) {
            if ( !(chirc_user_has_mode(user, 'o') || chirc_channeluser_has_mode(channel_user, 'v') || chirc_channeluser_has_mode(channel_user, 'o')) ) {
                _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_CANNOTSENDTOCHAN);
                return CHIRC_OK;
            }
        }

        // creating the message
        chirc_message_t *msgToServers = (chirc_message_t *)malloc(sizeof(chirc_message_t));

        if (conn->type == CONN_TYPE_USER) {
            char prefix[MSG_MAX];
            sprintf(prefix, "%s", user->nick);
            chirc_message_construct(msgToServers, prefix, "PRIVMSG");

            chirc_message_add_parameter(msgToServers, msg->params[0], false);
            chirc_message_add_parameter(msgToServers, msg->params[1], true);

            chirc_connection_relay_msg(ctx, conn, msgToServers);
        }

        // relaying the message
        chirc_channeluser_t *current_user;
        chirc_channeluser_t *tmp;
        HASH_ITER(hh_from_channel, target_channel->users, current_user, tmp) {
            chirc_user_t * target_user = current_user->user; //get the user
    
            if (target_user->nick != user->nick) {

                if ( !strncmp(target_user->server->servername, ctx->network.this_server->servername, MSG_MAX) ) { // the user is in the server
                    _send_msg_to_user(ctx, conn, msg, target_user, target_channel->name);
                }
            }
        }
    }

    return CHIRC_OK;
}

int chirc_handle_NOTICE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    // Check that user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }

    chirc_user_t *target_user = NULL;
    chirc_channel_t *target_channel = NULL;
    chirc_user_t *user = conn->peer.user;
    
    if (!msg->params[0] || !msg->params[1]) {
        return CHIRC_OK;
    }

    target_user = chirc_ctx_get_user(ctx, sdsnew(msg->params[0]));
    target_channel = chirc_ctx_get_channel(ctx, sdsnew(msg->params[0]));

    if (!target_user && !target_channel) {
        return CHIRC_OK;

    } else if (target_user) { // A message to a user
        _send_msg_to_user(ctx, conn, msg, target_user, NULL);

    } else if (!chirc_channeluser_get(target_channel, user)) { // The user has not yet joined the channel
        return CHIRC_OK;
        
    } else { // A message to a channel
        chirc_channeluser_t * channel_user = chirc_channeluser_get(target_channel, user);
        // before a message is sent to the channel, check for permissions!
        if ( chirc_channel_has_mode( target_channel, 'm') ) {
            if ( !(chirc_user_has_mode(user, 'o') || chirc_channeluser_has_mode(channel_user, 'v') || chirc_channeluser_has_mode(channel_user, 'o')) ) {
                return CHIRC_OK;
            }
        }

        chirc_channeluser_t *current_user;
        chirc_channeluser_t *tmp;
        HASH_ITER(hh_from_channel, target_channel->users, current_user, tmp) {
            if (current_user->user->nick != user->nick) {
                _send_msg_to_user(ctx, conn, msg, current_user->user, target_channel->name);
            }
           
        }
    }

    return CHIRC_OK;
}


int chirc_handle_JOIN(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    // Check that user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }

    if (msg->nparams < 1) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NEEDMOREPARAMS);
        return CHIRC_OK;
    }

    chirc_user_t *user;
    if (conn->type == CONN_TYPE_SERVER) {
        user = chirc_ctx_get_user(ctx, msg->prefix);
    } else {
        user = conn->peer.user;
    }

    chirc_channel_t *channel;
    bool created_channel;

    created_channel = chirc_ctx_get_or_create_channel(ctx, msg->params[0], &channel);

    // create channel_user
    chirc_channeluser_t *channeluser;
    bool created_user;

    created_user = chirc_channeluser_get_or_create(channel, user, &channeluser);
    
    if (!created_user) {
        return CHIRC_OK;
    }

    if (conn->type == CONN_TYPE_SERVER) {
        chirc_message_t *returnMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));
        char prefix[MSG_MAX];

        chirc_message_construct(returnMsg, sdsnew(msg->prefix), "JOIN");
        chirc_message_add_parameter(returnMsg, channel->name, false);

        send_msg_to_channel(ctx, conn, returnMsg, channel, true);

    } else if (conn->type == CONN_TYPE_USER) {
        if (created_channel) {
            chirc_channeluser_set_mode(channeluser, 'o');
        }

        char prefix[MSG_MAX];
        chirc_message_t *returnMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));

        sprintf(prefix, "%s!%s@%s", user->nick, user->username, user->hostname);
        chirc_message_construct(returnMsg, prefix, "JOIN");
        chirc_message_add_parameter(returnMsg, channel->name, false);

        send_msg_to_channel(ctx, conn, returnMsg, channel, true);
        chirc_message_t *relayedMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));
        sprintf(prefix, "%s", user->nick);
        chirc_message_construct(relayedMsg, prefix, "JOIN");
        chirc_message_add_parameter(relayedMsg, channel->name, false);

        chirc_connection_relay_msg(ctx, conn, relayedMsg);

        /* Send the necesarry replies to joining user */
        if (!msg->prefix) {
            char msg_body[MSG_MAX];
            sprintf(msg_body, ":hostname 353 %s = #foobar :foobar1 foobar2 foobar3\r\n", user->nick);
            int lenMsgBody = strlen(msg_body);
            int succ = sendall(conn->socket, msg_body, &lenMsgBody);
            
            sprintf(msg_body, ":hostname 366 %s #foobar :End of NAMES list\r\n", user->nick);
            lenMsgBody = strlen(msg_body);
            succ = sendall(conn->socket, msg_body, &lenMsgBody);
        }
    }
    return CHIRC_OK;
}

int chirc_handle_PART(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    // Check that user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }

    chirc_user_t *user = conn->peer.user;

    if (msg->nparams < 1) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NEEDMOREPARAMS);
    }
    
    chirc_channel_t *target_channel = NULL;
    target_channel = chirc_ctx_get_channel(ctx, sdsnew(msg->params[0]));

    // If there is no such channel
    if (!target_channel) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOSUCHCHANNEL);
    }

    // Get Channel User
    chirc_channeluser_t *channel_user = chirc_channeluser_get(target_channel, user);
    if (!channel_user) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTONCHANNEL);
    }
    
    // create the message
    chirc_message_t *returnMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));
    char prefix[MSG_MAX];
    sprintf(prefix, "%s!%s@%s", user->nick, user->username, user->hostname);
    chirc_message_construct(returnMsg, prefix, "PART");
    chirc_message_add_parameter(returnMsg, msg->params[0], false);
    if (msg->nparams == 2) {
        chirc_message_add_parameter(returnMsg, msg->params[1], true);
    }
    
    // relay the message
    send_msg_to_channel(ctx, conn, returnMsg, target_channel, true);

    chirc_channeluser_remove(channel_user); // Remove the user from the desired channel
    chirc_channeluser_free(channel_user);
    free(channel_user);
    
    if (chirc_channel_num_users(target_channel) == 0) {
        chirc_ctx_remove_channel(ctx, target_channel);
        chirc_channel_free(target_channel);
        free(target_channel);
    }

    return CHIRC_OK;
}

int chirc_handle_LUSERS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {

    // Check that user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }

    /* once again, send the lusers messages. look how simple it is... */
   _generate_LUSERS_mesages(ctx, conn);

    return CHIRC_OK;
}

int chirc_handle_WHOIS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    // Check that user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }

    // if nparams == 0, should silently return
    if (!msg->nparams) { return CHIRC_OK; }

    // search for user
    chirc_user_t *foundUser = NULL;
    foundUser = chirc_ctx_get_user(ctx, sdsnew(msg->params[0]));
    
    // if user not found, alert the user
    if ( !foundUser ) {

        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOSUCHNICK);

        return CHIRC_OK;
    }
    
    // else send the replies!
    /* ----- RPL_WHOISUSER ------ */
    chirc_message_t* wIUser = (chirc_message_t*)malloc( sizeof(chirc_message_t) );
    chirc_message_construct_reply(wIUser, ctx, conn, RPL_WHOISUSER);

    chirc_message_add_parameter(wIUser, foundUser->nick, false);
    chirc_message_add_parameter(wIUser, foundUser->username, false);
    chirc_message_add_parameter(wIUser, foundUser->hostname, false);
    chirc_message_add_parameter(wIUser, "*", false);
    chirc_message_add_parameter(wIUser, foundUser->fullname, true);
    
    chirc_connection_send_message(ctx, conn, wIUser, true);

    /* ------ RPL_WHOISCHANNELS ------ */
    if ( chirc_user_num_channels( foundUser ) ) {

        chirc_message_t* wIChannel = (chirc_message_t*)malloc( sizeof(chirc_message_t) );
        chirc_message_construct_reply(wIChannel, ctx, conn, RPL_WHOISCHANNELS);
        chirc_message_add_parameter(wIChannel, foundUser->nick, false);

        bool first = true;
        chirc_channeluser_t *el, *tmp = NULL;

        char totalMsg[MSG_MAX + 1];

        HASH_ITER(hh_from_user, foundUser->channels, el, tmp) {
            char currMsg[MSG_MAX];

            sds chanPrefix = ( has_mode( el->modes, 'o') ) ? "@" :
            ( /* has_mode(el->channel->modes, 'm' ) && */ has_mode(el->modes, 'v') ) ? "+" : "";

            sprintf(currMsg, " %s%s", chanPrefix, el->channel->name);

            // chirc_message_add_parameter(wIChannel, currMsg, first);
            // first = false;

            strncat(totalMsg, currMsg, MSG_MAX);
        }

        strncat(totalMsg, " ", 1);
        char outputMsg[512];
        strncpy(outputMsg, totalMsg+1, MSG_MAX);

        chirc_message_add_parameter(wIChannel, totalMsg, true);
        chirc_connection_send_message(ctx, conn, wIChannel, true);
    }

    /* ----- RPL_WHOISSERVER ------ */
    chirc_message_t* wIServer = (chirc_message_t*)malloc( sizeof(chirc_message_t) );

    chirc_message_construct_reply(wIServer, ctx, conn, RPL_WHOISSERVER);
    chirc_message_add_parameter(wIServer, foundUser->nick, false);
    chirc_message_add_parameter(wIServer, foundUser->server->servername, false);
    chirc_message_add_parameter(wIServer, ctx->network.this_server->hostname, true);
    chirc_connection_send_message(ctx, conn, wIServer, true);

    /* ------ RPL_AWAY ------ */
    if (foundUser->awaymsg) {
        chirc_message_t* rpl_away = (chirc_message_t*)malloc( sizeof(chirc_message_t) );
        chirc_message_construct_reply(rpl_away, ctx, conn, RPL_AWAY);

        chirc_message_add_parameter(rpl_away, foundUser->nick, false);
        chirc_message_add_parameter(rpl_away, foundUser->awaymsg, true);

        chirc_connection_send_message(ctx, conn, rpl_away, true);
    }

    /* ------ RPL_WHOISOPERATOR ------ */
    if ( has_mode(foundUser->modes, 'o') ) {
        chirc_message_t* wIOperator = (chirc_message_t*)malloc( sizeof(chirc_message_t) );
        chirc_message_construct_reply(wIOperator, ctx, conn, RPL_WHOISOPERATOR);

        chirc_message_add_parameter(wIOperator, foundUser->nick, false);

        sds operatorTxt = "is an IRC operator";
        chirc_message_add_parameter(wIOperator, operatorTxt, true);

        chirc_connection_send_message(ctx, conn, wIOperator, true);
    }
    
    /* ----- RPL_ENDOFWHOIS ------ */
    chirc_message_t* wIEnd = (chirc_message_t*)malloc( sizeof(chirc_message_t) );
    chirc_message_construct_reply(wIEnd, ctx, conn, RPL_ENDOFWHOIS);

    chirc_message_add_parameter(wIEnd, foundUser->nick, false);
    
    sds endWIMsg = "End of WHOIS list";
    chirc_message_add_parameter(wIEnd, endWIMsg, true);

    chirc_connection_send_message(ctx, conn, wIEnd, true);


    return CHIRC_OK;
}

int chirc_handle_LIST(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    // Check that user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }
    chirc_user_t *user = conn->peer.user;
    int user_count = 0;

    chirc_channel_t *current_channel;
    chirc_channel_t *tmp;

    HASH_ITER(hh, ctx->channels, current_channel, tmp) {

        if (!msg->nparams || (strncmp(msg->params[0], current_channel->name, MSG_MAX) == 0)) {

            user_count = chirc_channel_num_users(current_channel);

            // Build and send the message:
            chirc_message_t* list_reply = (chirc_message_t*)malloc( sizeof(chirc_message_t) );
            chirc_message_construct_reply(list_reply, ctx, conn, RPL_LIST);
            chirc_message_add_parameter(list_reply, current_channel->name, false);
            
            char number_users[MSG_MAX];
            sprintf(number_users, "%d", user_count);
            chirc_message_add_parameter(list_reply, number_users, false);

            sds long_param = "";
            chirc_message_add_parameter(list_reply, long_param, true);
            chirc_connection_send_message(ctx, conn, list_reply, true);

        }
    }

    // Send END of LIST message :frost 323 m :End of LIST
    chirc_message_t* eol_reply = (chirc_message_t*)malloc( sizeof(chirc_message_t) );
    chirc_message_construct_reply(eol_reply, ctx, conn, RPL_LISTEND);

    sds long_param = "End of LIST";
    chirc_message_add_parameter(eol_reply, long_param, true);
    chirc_connection_send_message(ctx, conn, eol_reply, true);
    return CHIRC_OK;
}

int chirc_handle_OPER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    // Check that user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }

    if ( _chirc_verify_num_params(ctx, conn, msg) == CHIRC_FAIL ) {
        return CHIRC_OK;
    }

    sds name = msg->params[0];
    sds pass = msg->params[1];

    if (strncmp(ctx->oper_passwd, pass, MSG_MAX)) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_PASSWDMISMATCH);
        return CHIRC_OK;
    }

    chirc_user_set_mode(conn->peer.user, 'o');

    // else reply with the rpl_youroper
    chirc_message_t *yourOper = (chirc_message_t *)malloc( sizeof(chirc_message_t) );
    chirc_message_construct_reply(yourOper, ctx, conn, RPL_YOUREOPER);

    char yourOperString[] = "You are now an IRC operator";
    chirc_message_add_parameter(yourOper, yourOperString, true);

    chirc_connection_send_message(ctx, conn, yourOper, true);

    return CHIRC_OK;
}

int _chirc_handle_MODE_user(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {

    // make sure nicks are the same

    sds msgNick = msg->params[0];
    sds connNick = conn->peer.user->nick;

    // if users don't match, throw error
    if ( strncmp(msgNick, connNick, MSG_MAX) ) {

        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_USERSDONTMATCH);
        return CHIRC_OK;
    }


    char allowedChange[2] = {'+', '-'};

    bool needToSendUnknownOpError = false;

    sds currOp = msg->params[1];
    
    if (strlen(currOp) != 2) {
        needToSendUnknownOpError = true;
    }

    if ((!strncmp(currOp, "+a", 2)) || (!strncmp(currOp, "-a", 2)) || (!strncmp(currOp, "+o", 2))) {
        return CHIRC_OK;
    }

    if ((strlen(currOp) > 0) && 
        (currOp[0] != allowedChange[0] &&
        currOp[0] != allowedChange[1]) ||
        (currOp[1] != 'a' &&
        currOp[1] != 'o')) {
        needToSendUnknownOpError = true;
    }

    if (currOp[0] == '+' ) {
        chirc_user_set_mode(conn->peer.user, currOp[1]);
    }
    else {
        chirc_user_remove_mode(conn->peer.user, currOp[1]);
    }

    // do error reply
    if ( needToSendUnknownOpError ) {

        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_UMODEUNKNOWNFLAG);

    } else { // no error
        chirc_message_t *replyMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));

        char prefix[MSG_MAX];
        chirc_user_t *user = conn->peer.user;
        sds targetNickName = user->nick;
        sds targetUserName = user->username;
        sds targetPeerHostname = user->hostname;
        
        chirc_message_construct(replyMsg, user->nick, "MODE");

        chirc_message_add_parameter(replyMsg, msg->params[0], false);
        chirc_message_add_parameter(replyMsg, msg->params[1], true);

        chirc_connection_send_message(ctx, conn, replyMsg, true);
    }

    return CHIRC_OK;
}

int _chirc_handle_MODE_channel(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {

    // IF CHANNEL DOES EXIST THIS
    chirc_channel_t *outChannel = NULL;
    outChannel = chirc_ctx_get_channel(ctx, sdsnew(msg->params[0]));

    if (!outChannel) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOSUCHCHANNEL);
        return CHIRC_OK;
    }

    if (msg->nparams == 1) {

        // print modes
        chirc_message_t *printModes = (chirc_message_t *)malloc(sizeof(chirc_message_t));
        chirc_message_construct_reply(printModes, ctx, conn, RPL_CHANNELMODEIS);

        chirc_message_add_parameter(printModes, msg->params[0], false);

        char modeString[MSG_MAX];
        sprintf(modeString, "+%s", outChannel->modes);

        chirc_message_add_parameter(printModes, modeString, false);
        chirc_connection_send_message(ctx, conn, printModes, true);


    } else if (msg->nparams == 2) {

        sds mode = msg->params[1];

        if (strlen(mode) < 2) {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_UNKNOWNMODE);
            return CHIRC_OK;
         }

        bool validMode = false;
        char modesArray[] = {'m', 't'};

        if (mode[1] != modesArray[0] && mode[1] != modesArray[1]) {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_UNKNOWNMODE);
            return CHIRC_OK;
        }

        // check to see if the user can actually make changes

        // need to handle channel priveleges now!
        chirc_user_t *user = conn->peer.user;
        chirc_channeluser_t *chanUser = chirc_channeluser_get(outChannel, user);

        if (!chanUser) {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_USERNOTINCHANNEL);
            return CHIRC_OK;
        }
        bool userNotAllowed = !(chirc_channeluser_has_mode(chanUser, 'o') || chirc_user_has_mode(user, 'o'));


        if (userNotAllowed) {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_CHANOPRIVSNEEDED);
            return CHIRC_OK;
        }

        if (mode[0] == '+') {
            chirc_channel_set_mode(outChannel, mode[1]);
        }
        else {
            chirc_channel_remove_mode(outChannel, mode[1]);
        }

        chirc_message_t *succesMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));

        char prefix[MSG_MAX];
        sds targetNickName = user->nick;
        sds targetUserName = user->username;
        sds targetPeerHostname = user->hostname;
        sprintf(prefix, "%s!%s@%s", user->nick, user->username, conn->hostname);
        
        chirc_message_construct(succesMsg, prefix, "MODE");

        for (int p = 0; p < msg->nparams; p++) {
            chirc_message_add_parameter(succesMsg, msg->params[p], false);
        }

        send_msg_to_channel(ctx, conn, succesMsg, outChannel, true);

    } else if (msg->nparams == 3) { // member status mode!

        // get the parameters
        sds channel = sdsnew(msg->params[0]);
        sds mode = sdsnew(msg->params[1]);
        sds name = sdsnew(msg->params[2]);



        // check to see if the user is in the channel
        chirc_user_t *checkUser = NULL;
        checkUser = chirc_ctx_get_user(ctx, name);

        if (!checkUser) {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_USERNOTINCHANNEL);
            return CHIRC_OK;
        }

        chirc_channeluser_t *targetUser = chirc_channeluser_get(outChannel, checkUser);

        if (!targetUser) {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_USERNOTINCHANNEL);
            return CHIRC_OK;
        }
        
        // now should have channel user

        // check to see if the sending user is in the channel
        chirc_user_t *user = conn->peer.user;
        chirc_channeluser_t *sendingUser = chirc_channeluser_get(outChannel, user);

        if (!sendingUser) {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_CHANOPRIVSNEEDED);
            return CHIRC_OK;
        }


        // check to see if the sending user has the permissions to make another user operator
        if (!chirc_channeluser_has_mode(sendingUser, 'o') && (!chirc_user_has_mode(user, 'o'))) {

            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_CHANOPRIVSNEEDED);
            return CHIRC_OK;
        }

        // check to see if the mode exists
        if (strlen(mode) < 2) {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_UNKNOWNMODE);
            return CHIRC_OK;
        }

        if ( !(mode[1] == 'o' || mode[1] == 'v') ) {
            _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_UNKNOWNMODE);
            return CHIRC_OK;
        }

        if (mode[0] == '-') {
            chirc_channeluser_remove_mode(targetUser, mode[1]);
        } else {
            chirc_channeluser_set_mode(targetUser, mode[1]);
        }

        chirc_message_t *succesMsg = (chirc_message_t *)malloc(sizeof(chirc_message_t));

        char prefix[MSG_MAX];
        sds targetNickName = user->nick;
        sds targetUserName = user->username;
        sds targetPeerHostname = user->hostname;
        sprintf(prefix, "%s!%s@%s", user->nick, user->username, conn->hostname);
        
        chirc_message_construct(succesMsg, prefix, "MODE");

        for (int p = 0; p < msg->nparams; p++) {
            chirc_message_add_parameter(succesMsg, msg->params[p], false);
        }

        send_msg_to_channel(ctx, conn, succesMsg, outChannel, true);
    }

    return CHIRC_OK;
}

int chirc_handle_MODE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    // Check that user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }
    
    // ensure enough parameters - should move this after we check if it's a channel or not
    if ( _chirc_verify_num_params(ctx, conn, msg) == CHIRC_FAIL) { return CHIRC_OK; }

    // detect nick vs channel
    bool isUser = !(msg->params[0][0] == '#');

    if (isUser) {
        _chirc_handle_MODE_user(ctx, conn, msg);
    }
    else {
        _chirc_handle_MODE_channel(ctx,  conn, msg);
    }

    return CHIRC_OK;
}

int chirc_handle_AWAY(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    // Check that user is registered
    if (!conn->peer.user->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOTREGISTERED);
        return CHIRC_OK;
    }

    chirc_user_t *user = conn->peer.user;

    if ( !msg->nparams ) {

        user->awaymsg = NULL;

        // send reply
        chirc_message_t* unaway_reply = (chirc_message_t*)malloc( sizeof(chirc_message_t) );
        chirc_message_construct_reply(unaway_reply, ctx, conn, RPL_UNAWAY);
        // chirc_message_add_parameter(unaway_reply, user->nick, false);
        
        sds reply_body = "You are no longer marked as being away";
        chirc_message_add_parameter(unaway_reply, reply_body, true);
        chirc_connection_send_message(ctx, conn, unaway_reply, true);
    } else {

        user->awaymsg = msg->params[0];

        // send return message
        chirc_message_t* nowaway_reply = (chirc_message_t*)malloc( sizeof(chirc_message_t) );
        chirc_message_construct_reply(nowaway_reply, ctx, conn, RPL_NOWAWAY);
        // chirc_message_add_parameter(nowaway_reply, user->nick, false);
        
        sds reply_body = "You have been marked as being away";
        chirc_message_add_parameter(nowaway_reply, reply_body, true);
        chirc_connection_send_message(ctx, conn, nowaway_reply, true);
    }

    return CHIRC_OK;
}

int _chirc_set_conn_to_server(chirc_ctx_t *ctx, chirc_connection_t *conn) {
    if (conn->type == CONN_TYPE_USER) {
        chilog(WARNING, "USER tried to give server command.");
        return CHIRC_FAIL;
    }

    if (conn->type == CONN_TYPE_SERVER) { return CHIRC_OK; }

    conn->type = CONN_TYPE_SERVER;

    return CHIRC_OK;
}

int _handle_server_registration(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    chirc_server_t *server = conn->peer.server;
    chilog(INFO, "We are using conn %d and the server is %d", conn->socket, server->registered);

     // check that the server name is in the network
    chirc_server_t *active_server = chirc_ctx_get_server(ctx, server->servername);
    if (!active_server) {
        _chirc_handle_ERROR_message(ctx, conn, NULL, SERVER_NAME_NOT_IN);
        return CHIRC_OK;
    }

    // case where the passwords did not match
    if ( strncmp(server->passwd, ctx->network.this_server->passwd, MSG_MAX) ) {
        _chirc_handle_ERROR_message(ctx, conn, NULL, SERVER_BAD_PASS);
        return CHIRC_OK;
    }

    // check to make sure servername is not already registered in some connection
    if (active_server->registered) {
        _chirc_handle_ERROR_message(ctx, conn, NULL, SERVER_ALREADY_REG);
        return CHIRC_OK;
    }

    chilog(INFO, "setting them to true fr");
    active_server->registered = true; // that it is registered in some connection
    server->registered = true; // it is registered in this connection

    // don't send messages back if there is a prefix, i.e. this is the active server
    if (msg->prefix != NULL) { return CHIRC_OK; }

    sds passive_servername = ctx->network.this_server->servername;
    chilog(INFO, "WE BOUTTA SEND SOME RESPONSE PASSES");
    // Sending PASS response
    chirc_message_t * pass_msg = (chirc_message_t *)malloc(sizeof(chirc_message_t));
    chirc_message_construct(pass_msg, passive_servername, "PASS");
    chirc_message_add_parameter(pass_msg, active_server->passwd, false);
    chirc_message_add_parameter(pass_msg, PROTOCOL, false);
    chirc_message_add_parameter(pass_msg, "chirch|0.6", false);
    chirc_connection_send_message(ctx, conn, pass_msg, true);

    // Sending SERVER response
    chirc_message_t * server_msg = (chirc_message_t *)malloc(sizeof(chirc_message_t));
    chirc_message_construct(server_msg, passive_servername, "SERVER");
    chirc_message_add_parameter(server_msg, ctx->network.this_server->servername, false);
    chirc_message_add_parameter(server_msg, "1", false);
    chirc_message_add_parameter(server_msg, "1", false);
    chirc_message_add_parameter(server_msg, "chirc", true);
    chirc_connection_send_message(ctx, conn, server_msg, true);
    return CHIRC_OK;
}

int chirc_handle_PASS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    chilog(INFO, "The server is set to %d", conn->peer.server->registered);
    if (_chirc_set_conn_to_server(ctx, conn)) { return CHIRC_OK; }
    if (_chirc_verify_num_params(ctx, conn, msg) ) { return CHIRC_OK; }

    sds password = msg->params[0];
    chirc_server_t *server = conn->peer.server;

    // check to make sure servername is not already registered in this connection
    if (server->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, NULL, ERR_ALREADYREGISTRED);
        return CHIRC_OK;
    }

    server->passwd = strndup(password, MSG_MAX);
    
    if (!server->registered && (server->passwd != NULL) && (server->servername != NULL)) { _handle_server_registration(ctx, conn, msg); }

    return CHIRC_OK;

}

int chirc_handle_SERVER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {
    chilog(INFO, "The server is set to %d", conn->peer.server->registered);

    if (_chirc_set_conn_to_server(ctx, conn)) { return CHIRC_OK; }

    chirc_server_t *server = conn->peer.server;

    // check to make sure servername is not already registered in this connection
    if (server->registered) {
        _chirc_handle_ERROR_reply(ctx, conn, NULL, ERR_ALREADYREGISTRED);
        return CHIRC_OK;
    }

    server->servername = strndup(msg->params[0], MSG_MAX);

    if (!server->registered && (server->passwd != NULL) && (server->servername != NULL)) { _handle_server_registration(ctx, conn, msg); }

    return CHIRC_OK;
}

int chirc_handle_CONNECT(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg) {

    chirc_user_t *user = conn->peer.user;
    if ( !has_mode( user->modes, 'o' ) ) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOPRIVILEGES);
        return CHIRC_OK;
    }

    if (_chirc_verify_num_params(ctx, conn, msg) ) { return CHIRC_OK; }

    sds target_server_name = msg->params[0];

    // find the target server
    chirc_server_t *target_server_struct;

    /* RESUBMISSION - added lock */
    pthread_mutex_lock( &ctx->locks.server_lock );
    HASH_FIND_STR( ctx->network.servers, target_server_name, target_server_struct );
    pthread_mutex_unlock( &ctx->locks.server_lock );

    if ( !target_server_struct ) {
        _chirc_handle_ERROR_reply(ctx, conn, msg, ERR_NOSUCHSERVER);
        return CHIRC_OK;
    }

    // try and connect to server
    chirc_connection_connect_servers(ctx, conn, msg);

    return CHIRC_OK;
}