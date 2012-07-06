/*
 * Copyright (c) 2012 Rafael F. Zalamena <rzalamena@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <fcntl.h>
#include <err.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define DEBUG 1
#define dbg(fmt, args...)						\
	do {								\
		if (DEBUG)						\
			fprintf(stderr, "%s:%d(%s) " fmt "\n",		\
			    __FILE__, __LINE__, __func__, ## args);	\
	} while (0);


#ifndef __OpenBSD__
#include "openbsd.h"
#endif /* ! __OpenBSD__ */

#undef USE_SHA_COMPAT
#ifdef USE_SHA_COMPAT
#define SHA_LEN			256

#define SHA512Data(src, src_len, dst)		\
	SHA1_Linux(src, src_len, dst)

void
SHA1_Linux(const char *src, size_t len, char *dst)
{
	char	*sptr;
	int	 i, cer;
	char	 aux[8], tmp[SHA_LEN];

	sptr = &aux[5];

	bzero(dst, SHA_LEN);
	SHA1(src, len, dst);

	bzero(tmp, sizeof(tmp));
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		cer = (i % 2 == 0) ? i : i + 2;
		snprintf(aux, sizeof(aux), "%08x", dst[i]);
		strlcat(tmp, sptr, sizeof(tmp));
	}
	strlcpy(dst, tmp, sizeof(tmp));
}
#else

#include <sha2.h>
#define SHA_LEN			SHA512_DIGEST_STRING_LENGTH

#endif /* USE_SHA_COMPAT */


#define tostr(str)	       	#str

#define CHAT_PORT		8021
#define CHAT_PORT_STR		tostr(CHAT_PORT)
#define USER_LEN		64
#define PASS_LEN		64
#define KEY_SIZE		1024
#define EXPO			3

#define IP_VERSION		AF_INET

#define PASSWD_LINE_LEN		(SHA_LEN + USER_LEN + 2)
#define CHAT_PASSWD_FILE	"messenger.passwd"

#define USER_FLAG		(1 << 0)
#define PASS_FLAG		(1 << 1)
#define SET_USER_FLAG(flags)	flags |= USER_FLAG
#define SET_PASS_FLAG(flags)	flags |= PASS_FLAG
#define USER_IS_SET(flags)	(flags & USER_FLAG)
#define PASS_IS_SET(flags)	(flags & PASS_FLAG)

enum {
	CHAT_CLIENT,
	CHAT_SERVER,
	CREATE_USER,
	GENERATE_KEY,
	NO_SELECTION
} mode;

enum exchange_action {
	RECEIVE_PUBKEY,
	SEND_PUBKEY
};

static int	 connect_address(const char *);
static void	 usage(void);
static int	 receive_connection(void);
static void	 start_chat(const char *, const char *);
static RSA	*load_private_key(const char *);
static int	 generate_rsa_key_pair(const char *, const char *);
static RSA	*exchange_rsa(int, const char *, enum exchange_action);
static int	 send_rsa_pub_key(int, const char *);
static RSA	*receive_rsa_pub_key(int);


static void
usage(void)
{
	extern const char	*__progname;

	printf("%s: [-C | -G | -S | -U] <-c address> <-u user -p password>\n"
	    "\t-C - Start chat client\n"
	    "\t-S - Start chat server\n"
	    "\t-U - Create User\n"
	    "\t-G - Generate key\n",
	    __progname);
	exit(EXIT_SUCCESS);
}

static RSA *
load_private_key(const char *user)
{
	RSA	*rsa;
	FILE	*fs;
	char	 filename[128];

	snprintf(filename, sizeof(filename), "%s.prv", user);
	fs = fopen(filename, "r");
	if (fs == NULL)
		err(1, "Could not open private key %s", filename);

	rsa = RSA_new();
	if (rsa == NULL)
		err(1, "rsa_new");
	PEM_read_RSAPrivateKey(fs, &rsa, NULL, NULL);

	fclose(fs);

	return (rsa);
}

static int
send_rsa_pub_key(int sd, const char *user)
{
	FILE	*fs;
	char	 buf[128], filename[128];
	int	 ret;

	printf("Sending RSA public key.\n");

	snprintf(filename, sizeof(filename), "%s.pub", user);
	fs = fopen(filename, "r");
	if (fs == NULL)
		err(1, "Could not open public key %s", filename);

	ret = fread(buf, 1, sizeof(buf), fs);
	while (ret != 0) {
		buf[ret] = 0;
		if (ret == -1)
			err(1, "Reading public key");

		ret = write(sd, buf, ret);
		if (ret == -1)
			err(1, "Sending public key");

		ret = fread(buf, 1, sizeof(buf), fs);
	}

	strlcpy(buf, "DONE", sizeof(buf));
	ret = write(sd, buf, strlen(buf));
	fclose(fs);

	return (0);
}

static RSA *
receive_rsa_pub_key(int sd)
{
	RSA	*rsa_peer, *rsa_aux;
	FILE	*fs;
	size_t	 len;
	int	 ret, done;
	char	 buf[128], *aux;

	printf("Receiving RSA public key.\n");

	fs = fopen("tmp.pub", "w");
	if (fs == NULL)
		err(1, "Creating temporary pub key");

	done = 0;
	ret = read(sd, buf, sizeof(buf) - 1);
	while (ret != 0) {
		buf[ret] = 0;
		if (ret == -1)
			err(1, "Retrieving peer's public key");

		len = ret;
		if (len < sizeof(buf))
			buf[ret] = 0;
		else
			buf[sizeof(buf) - 1] = 0;

		len = strlen(buf);
		aux = &buf[len] - 4;
		if (strcmp(aux, "DONE") == 0) {
			*aux = 0;
			done = 1;
		}

		ret = fwrite(buf, 1, strlen(buf), fs);
		if (ret == -1)
			err(1, "Writing peer's public temporary file");

		if (done)
			break;

		ret = read(sd, buf, sizeof(buf) - 1);
	}
	fclose(fs);

	fs = fopen("tmp.pub", "r");
	if (fs == NULL)
		err(1, "Opening public peer's key");

	rsa_peer = RSA_new();
	if (rsa_peer == NULL)
		err(1, "Allocating peers key");
	rsa_peer = NULL;

	rsa_aux = PEM_read_RSAPublicKey(fs, &rsa_peer, NULL, NULL);
	if (rsa_aux == NULL)
		err(1, "Reading peers key");

	fclose(fs);

	return (rsa_peer);
}

static RSA *
exchange_rsa(int sd, const char *user, enum exchange_action action)
{
	RSA	*rsa_peer;

	switch (action) {
	case RECEIVE_PUBKEY:
		send_rsa_pub_key(sd, user);
		rsa_peer = receive_rsa_pub_key(sd);
		break;

	case SEND_PUBKEY:
		rsa_peer = receive_rsa_pub_key(sd);
		send_rsa_pub_key(sd, user);
		break;

	default:
		printf("ERROR invalid exchange operation.\n");
		exit(EXIT_FAILURE);
	}
	return (rsa_peer);
}

static int
connect_address(const char *name)
{
	int			 ret, sd;
	struct addrinfo		*addrlist, *it, hints;

	bzero(&hints, sizeof(hints));
	hints.ai_family = IP_VERSION;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(name, "8021", &hints, &addrlist);
	if (ret != 0) {
		printf("ERROR: unable to resolv host %s.\n"
		    "%s: getaddrinfo\n", name, gai_strerror(ret));
		exit(EXIT_FAILURE);
	}
	for (it = addrlist; it != NULL; it = it->ai_next) {
		sd = socket(it->ai_family, it->ai_socktype,
		    it->ai_protocol);
		if (sd == -1) {
			warn("socket");
			continue;
		}

		if (connect(sd, it->ai_addr, it->ai_addrlen) == -1) {
			warn("connect");
			close(sd);
			sd = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(addrlist);

	return (sd);
}

static int
receive_connection(void)
{
	int			 sd, ret, on;
	struct sockaddr_in	 sa;
	socklen_t		 sa_len;
	char			 peer_address[128];

	on = 1;
	sd = socket(IP_VERSION, SOCK_STREAM, 0);
	if (sd == -1)
		err(1, "socket");

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
	    &on, sizeof(on)) == -1)
		warn("setsockopt");

	bzero(&sa, sizeof(sa));
	sa.sin_family = IP_VERSION;
	sa.sin_port = htons(CHAT_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sa_len = sizeof(struct sockaddr_in);

	ret = bind(sd, (struct sockaddr *) &sa, sa_len);
	if (ret == -1)
		err(1, "bind");

	ret = listen(sd, 5);
	if (ret == -1)
		err(1, "listen");

	ret = accept(sd, (struct sockaddr *) &sa, &sa_len);
	if (ret == -1)
		err(1, "accept");

	/* Stop listening, we got the client */
	close(sd);
	sd = ret;

	if (inet_ntop(IP_VERSION, &(sa.sin_addr.s_addr), peer_address,
	    sizeof(peer_address)) == NULL) {
		warn("WARNING error solving IP address.\n");
		return (sd);
	}
	printf("Peer %s has connected, starting chat.\n",
	    peer_address);
	return (sd);
}

static void
start_chat(const char *address, const char *user)
{
	int		 sd, ret, stdin_fd;
	char		*cptr;
	char		 buf[128], aux[128], msg[128];
	fd_set		 read_set, read_copy;
	RSA		*rsa_mine, *rsa_peer;

	rsa_mine = load_private_key(user);
	assert(rsa_mine != NULL);
	dbg("Loaded Private key");

	sd = 0;
	switch (mode) {
	case CHAT_CLIENT:
		sd = connect_address(address);
		if (sd == -1) {
			printf("Could not connect to %s.\n", address);
			exit(EXIT_FAILURE);
		}
		rsa_peer = exchange_rsa(sd, user, SEND_PUBKEY);
		assert(rsa_peer != NULL);
		dbg("Loaded Peer's Public key");
		break;

	case CHAT_SERVER:
		sd = receive_connection();
		if (sd == -1) {
			printf("Could not connect to %s.\n", address);
			exit(EXIT_FAILURE);
		}
		rsa_peer = exchange_rsa(sd, user, RECEIVE_PUBKEY);
		assert(rsa_peer != NULL);
		dbg("Loaded Peer's Public key");
		break;

	default:
		printf("ERROR: invalid mode for chat.\n");
		exit(EXIT_FAILURE);
		/* NOTREACHED */
	}

	FD_ZERO(&read_set);
	FD_SET(sd, &read_set);
	stdin_fd = fileno(stdin);
	FD_SET(stdin_fd, &read_set);
	memcpy(&read_copy, &read_set, sizeof(read_copy));

	while (select(sd + 1, &read_set, NULL, NULL, NULL) != -1) {
		if (FD_ISSET(stdin_fd, &read_set)) {
			if (fgets(buf, sizeof(buf), stdin) == NULL) {
				memcpy(&read_set, &read_copy, sizeof(read_copy));
				continue;
			}

			buf[sizeof(buf) - 1] = 0;
			cptr = strchr(buf, '\n');
			if (cptr != NULL)
				*cptr = 0;

			snprintf(aux, sizeof(aux), "%s: %s", user, buf);

			ret = RSA_private_encrypt(strlen(aux), aux, msg, rsa_mine, RSA_PKCS1_PADDING);
			if (ret == -1) {
				ERR_error_string(ERR_get_error(), msg);
				printf("ERROR could not crypto the message: %s\n",
				    msg);
				exit(EXIT_FAILURE);
			}

			ret = write(sd, msg, sizeof(msg));
			if (ret < 0) {
				printf("WARNING: the full message wasn't sent.\n");
			}
		}

		if (FD_ISSET(sd, &read_set)) {
			ret = read(sd, msg, sizeof(msg));
			if (ret == 0) {
				printf("The other side closed the connection.\n");
				exit(EXIT_SUCCESS);
			}
			if (ret < sizeof(msg)) {
				printf("WARNING could not receive the complete message");
				continue;
			}

			bzero(aux, sizeof(aux));
			ret = RSA_public_decrypt(sizeof(msg), msg, aux, rsa_peer, RSA_PKCS1_PADDING);
			if (ret == -1) {
				ERR_error_string(ERR_get_error(), msg);
				printf("ERROR could not crypto the message: %s\n",
				    msg);
				exit(EXIT_FAILURE);
			}

			aux[sizeof(aux) - 1] = 0;
			printf("%s\n", aux);
		}
		memcpy(&read_set, &read_copy, sizeof(read_copy));
	}

	/* Should not reach here */
	close(sd);

	/* Should only exit through signal */
	err(1, "select");
}

static int
add_user(const char *user, const char *password)
{
	int		 ret;
	FILE		*fs;
	char		 buf[PASSWD_LINE_LEN], sha[SHA_LEN];
	struct stat	 st;

	ret = stat(CHAT_PASSWD_FILE, &st);
	if (ret == -1) {
		fs = fopen(CHAT_PASSWD_FILE, "w");

		if (fs == NULL)
			err(1, "fopen");

		goto skip_reading;
	} else
		fs = fopen(CHAT_PASSWD_FILE, "r+");

	if (fs == NULL)
		err(1, "fopen");

	while (fgets(buf, sizeof(buf), fs) != NULL) {
		strtok(buf, ":");
		if (strcmp(buf, user) == 0) {
			printf("ERROR the user already exists.\n");
			fclose(fs);
			exit(EXIT_FAILURE);
		}
	}

skip_reading:
	bzero(sha, sizeof(sha));
	SHA512Data(password, strlen(password), sha);

	snprintf(buf, sizeof(buf), "%s:%s\n", user, sha);
	ret = fwrite(buf, 1, strlen(buf), fs);
	if (ret == -1)
		err(1, "fwrite");

	fclose(fs);

	return (0);
}

static int
generate_rsa_key_pair(const char *user, const char *password)
{
	RSA	*rsa;
	FILE	*fs;
	char	 filename[128];
	char	 kstr[PASS_LEN];

	RAND_seed(password, strlen(password));

	rsa = RSA_generate_key(KEY_SIZE, EXPO, NULL, NULL);
	if (rsa == NULL) {
		printf("ERROR allocating rsa key.\n");
		exit(EXIT_FAILURE);
	}

	snprintf(filename, sizeof(filename), "%s.prv", user);
	fs = fopen(filename, "w");
	if (fs == NULL)
		err(1, "Writing private key");

	bcopy(password, kstr, sizeof(kstr));
	PEM_write_RSAPrivateKey(fs, rsa, NULL,
	    kstr, strlen(password),
	    NULL, NULL);
	fclose(fs);

	snprintf(filename, sizeof(filename), "%s.pub", user);
	fs = fopen(filename, "w");
	if (fs == NULL)
		err(1, "Writing public key");

	PEM_write_RSAPublicKey(fs, rsa);
	fclose(fs);

	RSA_free(rsa);

	return (0);
}

static int
generate_key(const char *user, const char *password)
{
	int		 ret;
	FILE		*fs;
	char		*ptr;
	char		 buf[PASSWD_LINE_LEN], sha[SHA_LEN];
	struct stat	 st;

	ret = stat(CHAT_PASSWD_FILE, &st);
	if (ret == -1) {
		printf("ERROR no users registred.\n");
		exit(EXIT_FAILURE);
	} else
		fs = fopen(CHAT_PASSWD_FILE, "r");

	if (fs == NULL)
		err(1, "fopen");

	ret = 0;
	while (fgets(buf, sizeof(buf), fs) != NULL) {
		strtok_r(buf, ":", &ptr);
		if (strcmp(buf, user) == 0) {
			ret++;
			break;
		}
	}
	if (ret <= 0) {
		printf("ERROR user %s not found.\n", user);
		fclose(fs);
		exit(EXIT_FAILURE);
	}

	SHA512Data(password, strlen(password), sha);
	ret = memcmp(sha, ptr, strlen(sha));
	if (ret != 0) {
		printf("ERROR invalid password for user %s.\n", user);
		fclose(fs);
		exit(EXIT_FAILURE);
	}

	generate_rsa_key_pair(user, password);
	fclose(fs);

	return (0);
}

int
main(int argc, char **argv)
{
	char	 option;
	int	 add_flag = 0;
	char	 buf[128], user[USER_LEN], password[PASS_LEN];

	/* Data de entrega 19/06/12 */
	/*
	 * 1 - conectar com uso de criptografia
	 * 2 - cadastrar usuario
	 * 3 - gerar chaves
	 *   - Gerar arquivos com chaves
	 * 4 - Sair
	 */
	/* TODO list
	 * 1 - Envio / recebimento de mensagens - OK
	 * 2 - Cadastro e autenticacao de usuario - OK
	 * 3 - Impressao na tela de tudo que esta acontecendo (debug)
	 * 4 - Mostrar os pacotes atraves de sniffer e explicar o que esta acontecendo
	 */
	buf[0] = 0;
	mode = NO_SELECTION;
	while ((option = getopt(argc, argv, "CSUGc:u:p:")) != -1) {
		switch (option) {
		case 'C':
			if (mode != NO_SELECTION) {
				printf("ERROR two or more modes selected.\n");
				exit(EXIT_FAILURE);
			}
			mode = CHAT_CLIENT;
			break;

		case 'S':
			if (mode != NO_SELECTION) {
				printf("ERROR two or more modes selected.\n");
				exit(EXIT_FAILURE);
			}
			mode = CHAT_SERVER;
			break;

		case 'U':
			if (mode != NO_SELECTION) {
				printf("ERROR two or more modes selected.\n");
				exit(EXIT_FAILURE);
			}
			mode = CREATE_USER;
			break;

		case 'G':
			if (mode != NO_SELECTION) {
				printf("ERROR two or more modes selected.\n");
				exit(EXIT_FAILURE);
			}
			mode = GENERATE_KEY;
			break;

		case 'c':
			strlcpy(buf, optarg, sizeof(buf));
			break;

		case 'u':
			SET_USER_FLAG(add_flag);
			strlcpy(user, optarg, sizeof(user));
			break;

		case 'p':
			SET_PASS_FLAG(add_flag);
			strlcpy(password, optarg, sizeof(password));
			break;
		}
	}

	switch (mode) {
	case NO_SELECTION:
		printf("No mode selected.\n");
		usage();
		/* NOTREACHED */

	case CHAT_CLIENT:
		if (buf[0] == 0) {
			printf("ERROR no address specified.\n");
			exit(EXIT_FAILURE);
		}
		if (!USER_IS_SET(add_flag)) {
			printf("ERROR no username specified.\n");
			exit(EXIT_FAILURE);
		}
		start_chat(buf, user);
		/* NOTREACHED */

	case CHAT_SERVER:
		if (!USER_IS_SET(add_flag)) {
			printf("ERROR no username specified.\n");
			exit(EXIT_FAILURE);
		}
		start_chat(NULL, user);
		/* NOTREACHED */

	case CREATE_USER:
		if (!USER_IS_SET(add_flag) ||
		    !PASS_IS_SET(add_flag))
			usage();
		add_user(user, password);
		break;

	case GENERATE_KEY:
		if (!USER_IS_SET(add_flag) ||
		    !PASS_IS_SET(add_flag))
			usage();
		generate_key(user, password);
		break;
	}

	exit(EXIT_SUCCESS);
}
