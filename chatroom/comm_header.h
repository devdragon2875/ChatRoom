 
#include <stdint.h>

#define SA struct sockaddr
#define CRED_FILE "dmishra_server_cred_file"
#define MAX_CONCURRENCY_LIMIT 10

enum packet_type_t {
	PKT_REGISTER = 1,
	PKT_LOGIN,
	PKT_LOGOUT,
	PKT_SEND,
	PKT_SEND2,
	PKT_SENDA,
	PKT_SENDA2,
	PKT_SENDF,
	PKT_SENDF2,
	PKT_LIST_REQ,
	PKT_LIST_RESP,
  PKT_ERR,
};

        
#define PKT_TYPE_HELLO   1    // Hello message - no action
#define PKT_TYPE_PRINT   2    // Prints the message
#define PKT_TYPE_FORWARD 3  // Forward the packet to destination
#define PKT_TYPE_CLOSE   4    // Close the connection

/*
 * When a packet is forwarded, the type is converted to PRINT
 * The first HELLO packet is used to identify clientID
 * Server sends a HELLO packet after client establishes connection.
 * Client must wait for the HELLO packet to identify its own
 * clientID before sending any messages to server
 */

#define DEST_BROADCAST 0xFF
#define SERVER_ID 0xFD

typedef struct _pkt_header {
	uint32_t pkt_type;
	uint32_t pkt_data_len; // Excludes this header
} pkt_header_t;

typedef struct _pkt_register {
	char username[8];
	char password[8];
} pkt_register_t;

typedef struct _pkt_login {
	char username[8];
	char password[8];
} pkt_login_t;

typedef struct _pkt_send {
    char username[8];
	char message[256];
} pkt_send_t;

typedef struct _pkt_send2 {
	char username[8];
	char message[256];
} pkt_send2_t;

typedef struct _pkt_senda {
	char message[256];
} pkt_senda_t;

typedef struct _pkt_senda2 {
	char username[8];
	char message[256];
} pkt_senda2_t;

typedef struct _pkt_sendf {
	char username[8];
	char file_name[32];
	uint32_t file_len;
	uint32_t pad;
} pkt_sendf_t;

typedef struct _pkt_sendf2 {
	char username[8];
	char file_name[32];
	uint32_t file_len;
	uint32_t pad;
} pkt_sendf2_t;

typedef struct _pkt_list_resp {
	uint32_t count;
	char username[MAX_CONCURRENCY_LIMIT][8];
	uint32_t pad[3];
} pkt_list_resp_t;

typedef struct _pkt_err {
	char message[256];
} pkt_err_t;

enum conn_state_t {
  LOGGED_OUT,
	LOGGED_IN
	
};

typedef struct _client_t {
	uint32_t valid; /* Is this a valid online client? */
	enum conn_state_t state; /* state of the conneciton */
	int	 socket_id; 
	char	 useranme[8];
	uint32_t client_id;   /* index into username/password entry */

	uint32_t send_bytes;
	uint8_t  *send_ptr;
	uint8_t  send_buf[10*1024*1024];

	uint32_t recv_bytes;
	uint8_t  *recv_ptr;
	uint8_t  recv_buf[10*1024*1024];
} client_t;

typedef struct _credential_t {
	char username[8];
	char password[8];
} credential_t;

