#ifndef __INXPECT_SERVER_H__
#define __INXPECT_SERVER_H__

#define PORT 8080
#define BUFFER_SIZE 1024

enum inxpect_server__message_code_t
{
    INXPECT_SERVER__MESSAGE_CODE__RESPONSE = 0, // server only
    INXPECT_SERVER__MESSAGE_CODE__EVENT_SET = 1,
    INXPECT_SERVER__MESSAGE_CODE__EVENT_GET = 2,
    INXPECT_SERVER__MESSAGE_CODE__SAMPLE_RATE_SET = 3,
    INXPECT_SERVER__MESSAGE_CODE__PSECTIONS_GET = 4
};

enum inxpect_server__message_error_t
{
    INXPECT_SERVER__MESSAGE_ERROR__NONE = 0,
    INXPECT_SERVER__MESSAGE_ERROR__UNKNOWN_CMD = 1,
    INXPECT_SERVER__MESSAGE_ERROR__INVALID = 2,
    INXPECT_SERVER__MESSAGE_ERROR__INTERNAL = 3
};

struct inxpect_server__message_t
{
    int code;
    int value;
    char *buffer;
};

/*
 * json structure, send and receive:
 * {
 *   "code": 0,
 *   "value": 0,
 *   "buffer": ""
 * }
 */

void inxpect_server__message_to_json(struct inxpect_server__message_t *message, char *json);
void inxpect_server__json_to_message(char *json, struct inxpect_server__message_t *message);
void inxpect_server__psection_to_json(struct psection_t *psection, char *json);
void inxpect_server__event_to_json(struct event *event, char *json);

int inxpect_server__init_server(int port);
int inxpect_server__start_and_polling();
int handler();
void inxpect_server__close();
int inxpect_response__unknown(int sock, struct inxpect_server__message_t *msg);

// ----- SERVER RESPONSES -----
int inxpect_response__event_set(int sock, struct inxpect_server__message_t *msg);
int inxpect_response__event_get(int sock, struct inxpect_server__message_t *msg);
int inxpect_response__sample_rate_set(int sock, struct inxpect_server__message_t *msg);
int inxpect_response__psections_get(int sock, struct inxpect_server__message_t *msg);
int inxpect_response__stats_get_by_psection_name(int sock, struct inxpect_server__message_t *msg);
// ----------------------------

#endif // __INXPECT_SERVER_H__