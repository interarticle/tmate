#ifndef TMATE_H
#define TMATE_H

#include <sys/types.h>
#include <msgpack.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <event.h>

#include "tmux.h"

#define tmate_debug(...) log_debug("[tmate] " __VA_ARGS__)
#define tmate_warn(...)   log_warn("[tmate] " __VA_ARGS__)
#define tmate_info(...)   log_info("[tmate] " __VA_ARGS__)
#define tmate_fatal(...) log_fatal("[tmate] " __VA_ARGS__)

/* tmate-encoder.c */

#define TMATE_MAX_MESSAGE_SIZE (16*1024)

#define TMATE_PROTOCOL_VERSION 4

enum tmate_commands {
	TMATE_HEADER,
	TMATE_SYNC_LAYOUT,
	TMATE_PTY_DATA,
	TMATE_EXEC_CMD,
	TMATE_FAILED_CMD,
	TMATE_STATUS,
	TMATE_SYNC_COPY_MODE,
	TMATE_WRITE_COPY_MODE,
};

struct tmate_encoder {
	msgpack_packer pk;
	struct evbuffer *buffer;
	struct event ev_readable;
};

extern void tmate_encoder_init(struct tmate_encoder *encoder);

extern void tmate_write_header(void);
extern void tmate_sync_layout(void);
extern void tmate_pty_data(struct window_pane *wp, const char *buf, size_t len);
extern int tmate_should_replicate_cmd(const struct cmd_entry *cmd);
extern void tmate_exec_cmd(const char *cmd);
extern void tmate_failed_cmd(int client_id, const char *cause);
extern void tmate_status(const char *left, const char *right);
extern void tmate_sync_copy_mode(struct window_pane *wp);
extern void tmate_write_copy_mode(struct window_pane *wp, const char *str);

/* tmate-decoder.c */

enum tmate_client_commands {
	TMATE_NOTIFY,
	TMATE_CLIENT_PANE_KEY,
	TMATE_CLIENT_RESIZE,
	TMATE_CLIENT_EXEC_CMD,
	TMATE_CLIENT_ENV,
	TMATE_CLIENT_READY,
};

struct tmate_decoder {
	struct msgpack_unpacker unpacker;
	int ready;
};

extern int tmate_sx;
extern int tmate_sy;

extern void tmate_decoder_init(struct tmate_decoder *decoder);
extern void tmate_decoder_get_buffer(struct tmate_decoder *decoder,
				     char **buf, size_t *len);
extern void tmate_decoder_commit(struct tmate_decoder *decoder, size_t len);

/* tmate-ssh-client.c */

enum tmate_ssh_client_state_types {
	SSH_NONE,
	SSH_INIT,
	SSH_CONNECT,
	SSH_AUTH_SERVER,
	SSH_AUTH_CLIENT,
	SSH_OPEN_CHANNEL,
	SSH_BOOTSTRAP,
	SSH_READY,
};

struct tmate_ssh_client {
	/* XXX The "session" word is used for three things:
	 * - the ssh session
	 * - the tmate sesssion
	 * - the tmux session
	 * A tmux session is associated 1:1 with a tmate session.
	 * An ssh session belongs to a tmate session, and a tmate session
	 * has one ssh session, except during bootstrapping where
	 * there is one ssh session per tmate server, and the first one wins.
	 */
	struct tmate_session *tmate_session;
	TAILQ_ENTRY(tmate_ssh_client) node;

	char *server_ip;

	int has_encoder;
	int state;

	/*
	 * ssh_callbacks is allocated because the libssh API sucks (userdata
	 * has to be in the struct itself).
	 */
	struct ssh_callbacks_struct ssh_callbacks;
	char *tried_passphrase;
	ssh_session session;
	ssh_channel channel;

	struct event ev_ssh;
	struct event ev_ssh_reconnect;
};
TAILQ_HEAD(tmate_ssh_clients, tmate_ssh_client);

extern struct tmate_ssh_client *tmate_ssh_client_alloc(struct tmate_session *session,
						       const char *server_ip);

/* tmate-session.c */

struct tmate_session {
	struct tmate_encoder encoder;
	struct tmate_decoder decoder;

	/*
	 * This list contains one connection per IP. The first connected
	 * client wins, and saved in *client. When we have a winner, the
	 * losers are disconnected and killed.
	 */
	struct tmate_ssh_clients clients;
	int need_passphrase;
	char *passphrase;

	// Auto reconnect
	struct event ev_client_shutdown;
	struct event ev_client_reconnect;
	bool clients_initiated;
};

extern struct tmate_session tmate_session;
extern void tmate_session_init(void);
extern void tmate_session_start(void);

/* tmate-debug.c */
extern void tmate_print_trace(void);
extern void tmate_catch_sigsegv(void);

/* tmate-msg.c */

extern void __tmate_status_message(const char *fmt, va_list ap);
extern void printflike1 tmate_status_message(const char *fmt, ...);

/* tmate-env.c */

extern int tmate_has_received_env(void);
extern void tmate_set_env(const char *name, const char *value);
extern void tmate_format(struct format_tree *ft);

#endif
