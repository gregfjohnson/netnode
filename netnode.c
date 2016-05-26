/****************************************************************************
 * Copyright (c) Greg Johnson, Gnu Public Licence v. 2.0.
 * File Name    : netnode.c
 *
 * Author       : Greg Johnson
 *
 * Description : set up a communication graph.
 *               The program can be used to set up a graph of
 *               communicating netnode instances of different machines.  
 *
 * Usage:  netnode [-P port] [-U port] [-p [host:]port]* [-u [host:]port]* \
 *                 [-k] [-e] [-f] [-b]
 *
 *   -P port:  tcp server port to open
 *   -p [host:]port:  connect as tcp client to host:port
 *   -U port:  udp server port to open
 *   -u [host:]port:  communicate as udp client to host:port
 *   -l port:  udp server port to open for listening but no sending
 *   -w interface:  communicate to raw interface (eth1, wlan0, etc.)
 *   -s:  open a file (such as /dev/ttyS0 or a named pipe)
 *   -m:  mark the previous command-line interface
 *   -x:  exclude output from the previous command-line interface to the
 *             marked command-line interface.
 *             example:  server -P 6622 -p 7777 -m -s /dev/ttyS0 -x
 *                       would exclude output from /dev/ttyS0 to port 7777.
 *                       so, another program that connected to the 7777 server
 *                       would only see traffic coming to port 6622 and would
 *                       not see traffic from /dev/ttyS0.
 *   -k:  connect as "client" to keyboard (stdin, stdout)
 *   -v:  verbose debug output
 *   -e:  echo every message back to clients
 *   -f:  for a tcp connection, fork a separate process for each client
 *   -a:  die_if_lose_server
 *   -D:  dontwait
 *   -X n:  exclude port n from previous interface
 *   -N:  time out bad client
 *   -F:  don't do udp pinger.
 *   -i:  input only
 *   -o:  output only
 *   -t:  text output
 *   -b:  hex output
 *   -T:  timestamp and direction
 *
 * Return values:
 *    0:  normal exit
 *    1:  error exit
 *
 * 03/21/2007 gfj - Created.
 * 03/28/2007 gfj - added udp, server forking
 * 04/02/2007 gfj - added multiple clients, sending data among them
 ****************************************************************************/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <math.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include "hexdump.h"

#ifdef WINDOWS
    #include "windows.h"
#else
    #include <sys/uio.h>
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <netinet/in.h>
     #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
#endif

#ifdef LINUX
    #include <net/if.h>
    #include <sys/ioctl.h>
    #ifdef LINUX_RAW
        #include <linux/if_packet.h>
        #include <linux/if_ether.h>   /* The L2 protocols */
    #endif
#endif

#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "netnode.h"

#ifdef PCAP_LIB
    #define HAVE_REMOTE
    #include "pcap.h"
    #include <pthread.h>
#endif

#define BUFSIZE 65536
#define MAX_EXCLUDE 16

#define false 0
#define true 1

typedef unsigned char byte;

#ifndef MSG_NOSIGNAL
    #define MSG_NOSIGNAL 0
#endif

typedef enum {
    connect_unknown = 0,
    connect_udp_server,
    connect_udp_client,
    connect_udp_listener,
    connect_tcp_server,             // the -P port to which tcp clients connect
    connect_tcp_client,             // we are a "-p" tcp client
    connect_tcp_inbound_client,     // this is a connect to our "-P"
    connect_raw_client,
    connect_pcap_client,
    connect_keyboard,
    connect_file,
} connect_type_t;

typedef struct _fd_t {

    /* eventually move all individual bits below to this guy. */
    connect_type_t connect_type;

    /* file descriptor of this connection */
    int fd;

    /* indicates if this record has an active connection */
    int fd_active;

    char no_input;
    char no_output;

    /* yes for command-line udp servers, our udp server if we are one,
     * no for tcp clients, our tcp accept socket.
     * not used for udp clients; they are handled separately.
     */
    char udp_target;

    /* true for keyboard, udp clients, tcp clients, and raw ethernet
     * interfaces.  we shut down if the server we are attached to
     * goes away.
     */
    char ima_client;

    char pcap_client;

    char raw_client;

    #ifdef PCAP_LIB
        pcap_t *adhandle;
    #endif

    /* the hosts and ports of udp servers for whom we are a client based on
     * '-u host:port' command-line arguments
     */
    struct sockaddr_in udp_sockaddr;

    /* the source port for a udp client '-u src_port:host:host_port' */
    int udp_src_port;

    /* for incoming udp messages, the sockaddr containing the source
     * port and IP address
     */
    struct sockaddr_in msg_sockaddr;

    #ifdef LINUX_RAW
        struct sockaddr_ll raw_send_recv;
    #endif

    int priority;

    int port;
    char *host;

    int (*read)(server_fd_ptr_t voidp_fd_desc, byte *buf, int buf_len);
    int (*write)(server_fd_ptr_t voidp_fd_desc, byte *buf, int buf_len);
    int (*close)(server_fd_ptr_t voidp_fd_desc);
    int (*have_input)(server_fd_ptr_t voidp_fd_desc);

    /* pointer to a packet source that we are not supposed to send
     * packets out from.
     */
    struct _fd_t *exclude_out;

    int exclude_port_count;
    int exclude_ports[MAX_EXCLUDE];

    int error_count;
    long long last_packet_recvd;

    /* print text output for this interface? */
    int text_msgs;

    /* print time and source with interface? */
    int time_and_source;

    /* print hex dump output for this interface? */
    int hex_msgs;
} fd_t;

void verify(int shouldBeTrue, const char *msg) {
    if (!shouldBeTrue) {
        fprintf(stderr, "%s", msg);
        exit(1);
    }
}

int server_fd(server_fd_ptr_t voidp_fd_desc) {
    fd_t *fd_desc = (fd_t *) voidp_fd_desc;
    return fd_desc->fd;
}

/* used by modules that import this API */
int server_fd_size() {
    return sizeof(fd_t);
}

/* used by modules that import this API */
server_fd_ptr_t server_fd_new() {
    fd_t *result = (fd_t *) malloc(sizeof(fd_t));

    return (server_fd_ptr_t) result;
}

#ifdef WINDOWS
    static char initwin_done = false;

    static void initwin(void) {
        WORD version;
        WSADATA wsa_data;
        int err;
        if (initwin_done) {
            return;
        }

        fprintf(stderr, "initwin..\n");
        version = MAKEWORD(2,2);
        err = WSAStartup(version, &wsa_data);
        if (err != 0) {
            fprintf(stderr, "WSAStartup failed.\n");
            exit(1);
        }
        fprintf(stderr, "initwin done..\n");
        initwin_done = true;
    }
#else
    static void initwin(void) {}
#endif

/*****************************************************************************
 * Function name:  int do_open_server_socket(int port)
 * Description:
 *    open a udp or tcp server socket
 * Args:
 *    int port:  the server port to open
 * Returns:
 *    a file descriptor that can be used for accept calls
 *****************************************************************************/
static int do_open_server_socket(int port, int connection_type) {
    int sock;
    struct sockaddr_in sin;

    #ifdef WINDOWS
        initwin();
    #endif

    /* attempt to open a socket */

    sock = socket(
        #ifdef WINDOWS
            AF_INET,
        #else
            PF_INET,
        #endif
        connection_type, 0);

    if (sock == -1) {
        #ifdef WINDOWS
            int error = WSAGetLastError();
            fprintf(stderr, "socket failed:  %d\n", error);
        #else
            fprintf(stderr, "socket failed:  %s\n", strerror(errno));
        #endif
        return -1;
    }

    #if !defined(USE_ARM)
    {
        int on = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
            return -1;
        }
    }
    #endif

    /* assign the socket family and the connection port */

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port   = htons(port);

    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        #ifdef WINDOWS
            int error = WSAGetLastError();
            fprintf(stderr, "bind failed:  %d\n", error);
        #else
            fprintf(stderr, "bind failed:  %s\n", strerror(errno));
        #endif
        return -1;
    }

    if (connection_type == SOCK_STREAM) {
        if (listen(sock, 5) == -1) {
            fprintf(stderr, "listen failed:  %s\n", strerror(errno));
            return -1;
        }
    }

    return sock;

} /* do_open_server_socket() */

/*****************************************************************************
 * Function name:  int open_server_socket(int port)
 * Description:
 *    open a server socket
 * Args:
 *    int port:  the server port to open
 * Returns:
 *    a file descriptor that can be used for accept calls
 *****************************************************************************/
int open_udp_server_socket(int port) {
    return (do_open_server_socket(port, SOCK_DGRAM));
}

/*****************************************************************************
 * Function name:  int open_server_socket(int port)
 * Description:
 *    open a server socket
 * Args:
 *    int port:  the server port to open
 * Returns:
 *    a file descriptor that can be used for accept calls
 *****************************************************************************/
int open_server_socket(int port) {
    return(do_open_server_socket(port, SOCK_STREAM));
}

/*****************************************************************************
 * Function name:  int accept_server_socket(int sock)
 * Description:
 *    accept an incoming connection to our port from a client
 * Args:
 *    int sock:  the server socket from open_server_socket()
 * Returns:
 *    a file descriptor that can be used to read or write to the client
 *****************************************************************************/
int accept_server_socket(int sock) {
    socklen_t otheraddrlen;
    struct sockaddr_in otheraddr;
    int fd;

    if (sock != -1) {
        otheraddrlen = sizeof(otheraddr);
        fd = accept(sock, (struct sockaddr *)&otheraddr, &otheraddrlen);
    }

    return fd;

} /* accept_server_socket() */

/*****************************************************************************
 * Function name:  void check_valid(int check, char *format, ...)
 * Description:
 *    if check is true, do nothing.  else, print error message and exit(1).
 * Args:
 *    check:  boolean condition to check
 *    char *format, ...: fprintf-compatible error message
 * Returns:
 *    exit(1) the process
 *****************************************************************************/
static void check_valid(int check, char *format, ...) {
    if (!check) {
        va_list ap;
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);

        exit(1);
    }
}

/*****************************************************************************
 * Function name:  void get_host_ports(char **host, int *port, int *src_port,
 *                                     char *arg)
 * Description:
 *    parse arg to get host, port, and source port.  syntax of arg:
 *    [[source_port:]host:]dest_port
 *
 *    if no host or null host, return "localhost" in host parameter.
 *    if no source_port, return -1 in src_port parameter.
 *
 *    NOTE:  this function modifies arg in place.  fix this.
 * Args:
 *    host:      out parm pointing to host name
 *    port:      out parm pointing to destination port
 *    src_port:  out parm pointing to source port
 *    arg:       input char string to parse.
 * Returns:
 *    no return value.  on failure, print error message and abort program.
 *****************************************************************************/
int get_host_ports(char **host, int *port, int *src_port, char *arg) {
    char *port_str = NULL,
         *host_str = NULL,
         *src_port_str = NULL,
         *p, *p2;

    if ((p = strchr(arg, (int) ':')) == NULL) {
        port_str = arg;

    } else {
        *p = '\0';
        p++;

        if ((p2 = strchr(p, (int) ':')) == NULL) {
            host_str = arg;
            port_str = p;

        } else {
            *p2 = '\0';
            p2++;

            src_port_str = arg;
            host_str = p;
            port_str = p2;
        }
    }

    check_valid(sscanf(port_str, "%d", port) == 1,
            "`%s' does not have a valid port\n", port_str);

    if (src_port_str != NULL) {
        check_valid(sscanf(optarg, "%d", src_port) == 1,
                "`%s' does not have a valid source port\n", src_port_str);

    } else {
        *port_str = -1;
    }

    if (host_str != NULL && strlen(host_str) > 0) {
        *host = host_str;

    } else {
        *host = "localhost";
    }

    return 0;
}

#ifdef LINUX_RAW

int read_raw_interface(server_fd_ptr_t voidp_fd_desc, byte *buf,
    int buf_len)
{
    socklen_t recv_arg_len;
    struct sockaddr_ll recv_arg;
    fd_t *fd_desc = (fd_t *) voidp_fd_desc;

    recv_arg_len = sizeof(recv_arg_len);
    int result = recvfrom(fd_desc->fd, buf, buf_len, MSG_DONTWAIT,
            (struct sockaddr *) &recv_arg, &recv_arg_len);

    if (result < 0 && errno != EAGAIN) {
        #ifdef VERBOSE
            fprintf(stderr, "recvfrom failed:  %d; %s\n",
                    errno, strerror(errno));
        #endif
    }

    return result;
}

int write_raw_interface(server_fd_ptr_t voidp_fd_desc, byte *buf, int buf_len) {
    fd_t *fd_desc = (fd_t *) voidp_fd_desc;
    int result;

    while (buf_len > 0) {
        result = sendto(fd_desc->fd, buf, buf_len <= 1500 ? buf_len : 1500,
                MSG_NOSIGNAL | MSG_DONTWAIT,
                (struct sockaddr *) &fd_desc->raw_send_recv,
                sizeof(fd_desc->raw_send_recv));

        if (result < 0) {
            break;
        }

        buf_len -= result;

        buf += result;
    }

    return result;
}

void setup_raw_interface(char *dev_name, server_fd_ptr_t voidp_fd_desc) {
    fd_t *fd_desc = (fd_t *) voidp_fd_desc;
    int dev_ifindex;
    int result;
    struct sockaddr_ll bind_arg;
    struct packet_mreq mreq;
    struct ifreq get_index;

    #ifdef VERBOSE
        fprintf(stderr, "setup_interface(%s)..\n", dev_name);
    #endif

    fd_desc->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    verify(fd_desc->fd >= 0, "raw interface socket call failed\n");

    snprintf(get_index.ifr_name, sizeof(get_index.ifr_name), "%s", dev_name);
    result = ioctl(fd_desc->fd, SIOCGIFINDEX, &get_index);
    verify(result == 0, "raw interface get_index failed\n");
    dev_ifindex = get_index.ifr_ifindex;

    memset(&bind_arg, 0, sizeof(bind_arg));
    bind_arg.sll_family = AF_PACKET;
    bind_arg.sll_ifindex = get_index.ifr_ifindex;
    bind_arg.sll_protocol = htons(ETH_P_ALL);

    result = bind(fd_desc->fd, (struct sockaddr *) &bind_arg,
            sizeof(bind_arg));
    verify(result == 0, "raw interface bind failed\n");

    /* put the interface in promiscuous mode so that it gets all packets */
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = dev_ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    result = setsockopt(fd_desc->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
            &mreq, sizeof(mreq));
    verify(result == 0, "raw interface setsockopt failed\n");

    memset(&fd_desc->raw_send_recv, 0, sizeof(fd_desc->raw_send_recv));
    fd_desc->raw_send_recv.sll_family = AF_PACKET;
    fd_desc->raw_send_recv.sll_ifindex = dev_ifindex;
    fd_desc->raw_send_recv.sll_protocol = htons(ETH_P_ALL);
    fd_desc->raw_send_recv.sll_halen = 6;

    fd_desc->read = &read_raw_interface;
    fd_desc->write = &write_raw_interface;
}

#endif

/*****************************************************************************
 * Function name:  int get_sockaddr(struct sockaddr_in *sock_addr,
 *                                  char *host,
 *                                  int port)
 * Description:
 *    populate sock_addr with port and IP address of host
 * Args:
 *    struct sockaddr_in *sock_addr:  the struct to populate
 *    char *host:  the name (or text-string IP address) of the host
 *    int port:    the port on the host
 * Returns:
 *    0 on success, -1 on error
 *****************************************************************************/
int get_sockaddr(void *vp_sock_addr, char *host, int port) {
    struct sockaddr_in *sock_addr = (struct sockaddr_in *) vp_sock_addr;
    unsigned long host_ip_address;
    struct in_addr in_addr;

    initwin();

    if (isdigit((int) *host)) {
        if (inet_aton(host, &in_addr) == 0)
            return -1;

        host_ip_address = in_addr.s_addr;

        memcpy(&sock_addr->sin_addr, &host_ip_address,
                sizeof(sock_addr->sin_addr));

    } else {
        struct hostent *host_name;

        host_name = gethostbyname(host);

        if (!host_name)
            return -1;

        memcpy(&sock_addr->sin_addr, host_name->h_addr,
                sizeof(sock_addr->sin_addr));
    }

    sock_addr->sin_family = AF_INET;
    sock_addr->sin_port   = htons(port);

    #ifdef ISO_SERVER_HACK
    {
        sock_addr->sin_addr.s_addr = 0x7f000001;
        sock_addr->sin_port = 6700;
    }
    #endif

    return 0;
} /* get_sockaddr */

/*****************************************************************************
 * Function name:  int do_open_client_socket(char *host,
 *                                           int port,
 *                                           int connection_type)
 * Description:
 *    connect to a udp or tcp server on the given host at the given port
 * Args:
 *    char *host:  the name (or text-string IP address) of the host
 *    int port:    the port to connect to on the host
 *    int connection_type:  udp or tcp server
 * Returns:
 *    a file descriptor to read or write to communicate with the server
 *    or -1 on any failure
 *****************************************************************************/
static int do_open_client_socket(char *host,
                                 int port,
                                 int connection_type)
{
    struct sockaddr_in  sin;
    int                 sock;
    int res;
 
    initwin();

    /* attempt to create a new socket */

    #ifdef VERBOSE
        fprintf(stderr, "do_open_client_socket %s:%d..\n", host, port);
    #endif

    sock = socket(PF_INET, connection_type, 0);
    if (sock == -1) {
        fprintf(stderr, "socket() failed\n");
        return -1;
    }

    if (connection_type != SOCK_STREAM) {
        int on = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
            return -1;
        }

        return sock;
    }

    /* if we are setting up a tcp connection, connect to the server */
    if (get_sockaddr(&sin, host, port) < 0) {
        fprintf(stderr, "get_sockaddr() failed\n");
        close(sock);
        return -1;
    }

    #ifdef VERBOSE
        fprintf(stderr, "sin %x:%d %d\n", *(unsigned int *) &sin.sin_addr,
                (unsigned int) sin.sin_port,
                (unsigned int) sin.sin_family);
    #endif

    if ((res=connect(sock, (struct sockaddr *) &sin, sizeof (sin))) == -1) {
        // fprintf(stderr, "connect() failed:  %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

/*****************************************************************************
 * Function name:  int open_client_socket(char *host,
 *                                        int port)
 * Description:
 *    connect to a tcp server on the given host at the given port
 * Args:
 *    char *host:  the name (or text-string IP address) of the host
 *    int port:    the port to connect to on the host
 * Returns:
 *    a file descriptor to read or write to communicate with the server
 *    or -1 on any failure
 *****************************************************************************/
int open_client_socket(char *host, int port) {
    return do_open_client_socket(host, port, SOCK_STREAM);
}

/*****************************************************************************
 * Function name:  int open_client_socket(char *host,
 *                                        int port)
 * Description:
 *    connect to a udp server on the given host at the given port
 * Args:
 *    char *host:  the name (or text-string IP address) of the host
 *    int port:    the port to connect to on the host
 * Returns:
 *    a file descriptor to read or write to communicate with the server
 *    or -1 on any failure
 *****************************************************************************/
int open_udp_client_socket(char *host, int port) {
    return do_open_client_socket(host, port, SOCK_DGRAM);
}

int server_write(server_fd_ptr_t voidp_fd_desc, byte *buffer, int buf_len) {
    fd_t *fd_desc = (fd_t *) voidp_fd_desc;

    if (fd_desc->write == NULL)
        return -1;

    return fd_desc->write(fd_desc, buffer, buf_len);
}

int write_udp_client(server_fd_ptr_t voidp_fd_desc, byte *buffer, int buf_len) {
    int result;
    fd_t *fd_desc = (fd_t *) voidp_fd_desc;

    result = sendto(fd_desc->fd, buffer, buf_len, MSG_NOSIGNAL,
            (struct sockaddr *) &fd_desc->udp_sockaddr,
            sizeof(fd_desc->udp_sockaddr));

    return result;
}

void setup_udp_client_interface(char *host_port, server_fd_ptr_t voidp_fd_desc)
{
    int port;
    char *host;
    int udp_src_port = -1;
    fd_t *fd_desc = (fd_t *) voidp_fd_desc;
    int result;

    get_host_ports(&host, &port, &udp_src_port, host_port);

    fd_desc->fd = open_udp_client_socket(host, port);
    check_valid(fd_desc->fd >= 0, "open_udp_client_socket failed");

    /* see if host is valid */
    check_valid(get_sockaddr(
            &fd_desc->udp_sockaddr, host, port) >= 0,
            "invalid host '%s'", host);

    if (udp_src_port != -1) {
        struct sockaddr_in src_port;
        int result;

        src_port.sin_family = AF_INET;
        src_port.sin_port = htons((short) udp_src_port);
        src_port.sin_addr.s_addr = INADDR_ANY;

        result = bind(fd_desc->fd, (struct sockaddr *) &src_port,
                sizeof(src_port));

        check_valid(result >= 0,
                "could not bind to source port %d:  %s; errno %d\n",
                udp_src_port, strerror(errno), errno);

    } else {
        /* WinXP/cygwin apparently has a problem if a process
         * does a udp write implicitly binding the source
         * port and then another process does a write on the
         * same socket.  the other process does not know
         * about the already-bound status of the source port.
         * so, we do a null write here before the fork below
         * so that both processes will know about the
         * implicitly assigned udp source port.
         */
        result = sendto(fd_desc->fd, NULL, 0, 0,
                (struct sockaddr *) &fd_desc->udp_sockaddr,
                sizeof(fd_desc->udp_sockaddr));

        check_valid(result >= 0,
                "initial sendto failed:  %s; errno %d\n",
                strerror(errno), errno);
    }

    fd_desc->udp_src_port = udp_src_port;

    fd_desc->write = write_udp_client;
}

#if defined(MAIN)

static int verbose = 0;

static char text_msgs = false;
static char hex_msgs = false;

static char no_output = false;
static char no_input = false;

static char time_and_source = false;

static char echo = 0;
static char do_fork = 0;
static int close_inbound_tcp_clients = 1;

static int my_udp_server_fd = -1;
static char do_udp_pinger = 1;

static int die_if_lose_server = 0;

static int debug[] = {
    0,
    0,
    0,
};

static char dontwait = 1;

static char timeout_bad_client = 0;

static char use_priorities = 1;

#define MAX_FD 256

/* descriptors of open connections */
static fd_t *fds[MAX_FD];

/* for efficiency we make fds[] above a bunch of pointers, and instead
 * of using malloc we point them to elements of the record array below.
 */
static fd_t fd_recs[MAX_FD];

/* fds[0 .. fd_count-1] are in use.  fd_count is 'owned' by add_fd()
 * and compact_fds() and should only be changed by those routines.
*/
static int fd_count = 0;

/* the number of elements in fds[] that have fd_active false.
 * this is a little tricky.  in multiple places in the code, we
 * iterate over the fds[] array with a for-loop, but in some cases
 * during those iterations we discover that we need to close a file
 * descriptor.  we want the active fds to be tightly packed to the left
 * of the fds[] array, but don't want to move them around in the middle
 * of iterations.  so, if we notice that one needs to be shut down we
 * mark it inactive, bump the fds_closed variable below, and then
 * compact the array when it's safe to do so.
 */
static int fds_closed = 0;

/* read host and udp port from incoming udp client messages sent to us
 * as a udp server.  we add these guys to our list of connected nodes
 * and send information back to them.
 */
#define MAX_UDP_CLIENT 256
struct sockaddr_in udp_client_sockaddr[MAX_UDP_CLIENT];
static int udp_client_count = 0;

static fd_t *marked = NULL;

/* convenience function for setting breakpoints in debuggers */
static void server_bp1() {}

static void packet_recvd(fd_t *fd, int result);

/*****************************************************************************
 * Function name:  void add_fd(int fd, char udp_target, char ima_client,
 *                             char pcap_client, char raw_client,
 *                             connect_type_t connect_type)
 * Description:
 *    add a file descriptor to the fds[] array; error-exit if too many.
 * Args:
 *    fd:  file descriptor of newly opened connection.
 *    udp_target:  we are a command-line udp client or a command-line
 *        udp server.  not used for inbound udp clients if we are a
 *        udp server.
 *    ima_client:  if we are a command-line tcp client and our tcp server
 *        crumps, we exit.  (that's the only place it's currently used.)
 *        false if this is a command-line tcp server record or command-line udp
 *        server record or if this is an inbound tcp connection.
 *    pcap_client:  command-line windows raw pcap interface.
 *    raw_client:  command-line linux raw interface.
 *    connect_type:  should subsume all of the above; this connection type.
 * Returns:
 *    no return value.
 *****************************************************************************/
static void add_fd(int fd, char udp_target,
                   char ima_client,
                   char pcap_client, char raw_client,
                   connect_type_t connect_type)
{
    if (fd_count >= MAX_FD) {
        fprintf(stderr, "too many files\n");
        exit(1);
    }

    memset(fds[fd_count], 0, sizeof(*fds[fd_count]));

    fds[fd_count]->connect_type = connect_type;
    fds[fd_count]->fd = fd;

    fds[fd_count]->no_output = no_output;
    no_output = false;

    fds[fd_count]->time_and_source = time_and_source;
    time_and_source = false;

    fds[fd_count]->no_input = no_input;
    no_input = false;

    fds[fd_count]->hex_msgs = hex_msgs;
    hex_msgs = false;

    fds[fd_count]->text_msgs = text_msgs;
    text_msgs = false;

    fds[fd_count]->udp_target = udp_target;
    fds[fd_count]->ima_client = ima_client;
    fds[fd_count]->raw_client = raw_client;
    fds[fd_count]->pcap_client = pcap_client;
    fds[fd_count]->read = NULL;
    fds[fd_count]->write = NULL;
    fds[fd_count]->close = NULL;
    fds[fd_count]->have_input = NULL;
    fds[fd_count]->fd_active = 1;
    fds[fd_count]->priority = 1;

    fd_count++;
}

/*****************************************************************************
 * Function name:  void compact_fds()
 * Description:
 *    compact active fd records to the left in the fds[] array.
 *    we look at fds[i]->fd_active, and garbage collect the false ones.
 *    so as not to have to run over the whole array every time, fds_closed
 *    is set whenever an fd_active field is made false.
 * Args:
 *    none
 * Returns:
 *    no return value.
 *****************************************************************************/
static void compact_fds() {
    int i;
    int did_something;

    if (fds_closed == false) {
        return;
    }

    /* this is kinda cautious and conservative, but we only do this rarely.
     * for each record that is not active, swap it to the end and put
     * a (possibly active) record from the end in its place.
     * just do one each time through, and when we find one start over.
     */
    do {
        did_something = 0;

        for (i = 0; i < fd_count; i++) {
            if (fds[i]->fd_active) {
                continue;
            }

            /* put the element we don't need at the end, and then
             * decrement count.
             */
            fd_t *tmp = fds[i];
            fds[i] = fds[fd_count - 1];
            fds[fd_count - 1] = tmp;

            fd_count--;
            if (verbose > 0)
                fprintf(stderr, "compact_fds; fd_count decremented to %d.\n",
                        fd_count);

            did_something = 1;

            break;
        }
    } while (did_something);

    fds_closed = false;
}

#ifdef PCAP_LIB
    static const unsigned char *pcap_data;
    static struct pcap_pkthdr *header;
#endif

static int read_file_interface(server_fd_ptr_t voidp_fd_desc,
    byte *buf, int buf_len)
{
    int result;

    fd_t *fd_desc = (fd_t *) voidp_fd_desc;

    result = read(fd_desc->fd, buf, buf_len);

    return result;
}

static int write_file_interface(server_fd_ptr_t voidp_fd_desc,
    byte *buf, int buf_len)
{
    fd_t *fd_desc = (fd_t *) voidp_fd_desc;

    return write(fd_desc->fd, buf, buf_len);
}

static void setup_file_interface(char *dev_name, server_fd_ptr_t voidp_fd_desc)
{
    int flags = O_RDWR;
    fd_t *fd_desc = (fd_t *) voidp_fd_desc;

    if (fd_desc->no_input) flags = O_WRONLY;
    if (fd_desc->no_output) flags = O_RDONLY;
    fd_desc->fd = open(dev_name, flags);
    verify(fd_desc->fd >= 0, "file open failed\n");
    fd_desc->read = &read_file_interface;
    fd_desc->write = &write_file_interface;
}

#ifdef PCAP_LIB
/*****************************************************************************
 * Function name:  int open_pcap(char *name)
 * Description:
 *    open the pcap windows interface.
 * Args:
 *    name:  the name of the interface to open.
 * Returns:
 *    0 on success, -1 on failure
 *****************************************************************************/
static int open_pcap(char *name) {
    char errbuf[PCAP_ERRBUF_SIZE];

    add_fd(-1, false, true, true, false, connect_pcap_client);

    /* Open the adapter */
    fds[fd_count - 1]->adhandle
            = pcap_open(
                    name,
                    65536,
                    PCAP_OPENFLAG_PROMISCUOUS
                    | PCAP_OPENFLAG_NOCAPTURE_LOCAL
                    | PCAP_OPENFLAG_MAX_RESPONSIVENESS,
                    10,
                    NULL,
                    errbuf);
                                                       
    if (fds[fd_count - 1]->adhandle == NULL) {
        fprintf(stderr,"\nUnable to open the adapter.  "
                "%s is not supported by WinPcap\n", optarg);
        return -1;
    }
    /* test-send a bunch of packets quickly to pcap interface */
    {
        char buf[40];
        int j, result;
        for (j = 0; j < 20; j++)
        {
            snprintf(buf, 40, "%d........................", j);
            result = pcap_sendpacket(fds[fd_count-1]->adhandle, buf, 40);
            fprintf(stderr, "pcap_sendpacket result %d\n", result);
        }
    }

    return 0;
}
#endif

void server_exit() {
    int i;

    for (i = 0; i < fd_count; i++) {
        if (!fds[i]->fd_active) {
            continue;
        }

        if (fds[i]->close) {
            fds[i]->close(fds[i]);
        }
    }

    exit(0);
}

/*****************************************************************************
 * Function name:  void close_tcp_connection(int fd_ind)
 * Description:
 *    close a tcp connection
 * Args:
 *    name:  the name of the interface to close.
 * Returns:
 *    0 on success, -1 on failure
 *****************************************************************************/
static void close_tcp_connection(int fd_ind, char *title) {
    if (verbose > 0)
        fprintf(stderr, "close_tcp_connection from %s; fd %d..\n", title,
                fds[fd_ind]->fd);

    if (fds[fd_ind]->connect_type != connect_tcp_server
        && fds[fd_ind]->connect_type != connect_tcp_client
        && fds[fd_ind]->connect_type != connect_tcp_inbound_client)
    {
        return;
    }

    close(fds[fd_ind]->fd);

    if (fds[fd_ind]->fd_active) {
        fds[fd_ind]->fd_active = 0;
        fds_closed = true;
    }

    if (do_fork) {
        server_exit(0);

    } else if (fds[fd_ind]->ima_client) {
        if (fds[fd_ind]->fd != 0) {
            fprintf(stderr, "server stopped\n");
        }
        server_exit(0);
    }

    fprintf(stderr, "client stopped\n");
}

static void do_close_inbound_tcp_clients(void) {
    int i;
    for (i = 0; i < fd_count; ++i) {
        if (fds[i]->connect_type == connect_tcp_inbound_client) {
            close_tcp_connection(i, "inbound tcp client");
        }
    }
}

static void tcp_server_closed(void) {
    fprintf(stderr, "tcp server closed.\n");

    if (close_inbound_tcp_clients)
        do_close_inbound_tcp_clients();
}

/*****************************************************************************
 * Function name:  void reopen_tcp_connection(int fd_ind)
 * Description:
 *    reopen a tcp connection
 * Args:
 *    name:  the name of the interface to open.
 * Returns:
 *    0 on success, -1 on failure
 *****************************************************************************/
static void reopen_tcp_connection(int fd_ind, char *title) {
    fd_t *fd_struct = fds[fd_ind];

    if (fd_struct->connect_type != connect_tcp_client) {
        if (verbose > 0)
            fprintf(stderr, "not a connect_tcp_client; return..\n");

        close_tcp_connection(fd_ind, title);
        return;
    }

    if (fd_struct->fd >= 0) {
        printf("ick.  tcp server closed connection.  set fd to -1..\n");
        tcp_server_closed();
    }

    close(fd_struct->fd);

    int fd = open_client_socket(fd_struct->host, fd_struct->port);

    if (fd < 0) {
        fd_struct->fd = -1;

    } else {
        fd_struct->fd = fd;
    }
}

double start_time;

double time__usec() {
    struct timeval tm;
    long long now;
    gettimeofday(&tm, NULL);
    now = ((long long) tm.tv_sec) * 1000000LL + (long long) tm.tv_usec;
    return (double) now / 1000000.;
}

static void print_time_and_source(int sourceFd) {
    double now = time__usec();
    printf("%12.6lf >> %d >> ", now - start_time, sourceFd);
}

static void print_text_msg(byte *buffer, int length) {
    int i;

    for (i = 0; i < length; i++) {
        char c = buffer[i];

        if (c == 0x0a) {
            printf("\n");

        } else if (c == 0x0d) {
            printf("\r");

        } else if (isprint((int) c)) {
            printf("%c", c);

        } else {
            printf("\\0x%02x", 0xff & (unsigned int) c);
        }
    }
    fflush(stdout);
}

static void print_hex_msg(byte *buffer, int length) {
    fprintf(stderr, "out message:\n");
    hexdump(buffer, length);
}

/*****************************************************************************
 * Function name:  void do_output(int fd_ind, byte *buffer, int length,
 *                                char got_udp_msg)
 * Description:
 *    send the packet to every destination that should receive it.
 * Args:
 *    fd_ind:  index in fds array of source of the packet
 *    buffer:  the packet to send
 *    length:  the length in bytes of the packet to send
 *    got_udp_msg:  the packet was received via udp 
 * Returns:
 *    no return value.
 *****************************************************************************/
static void do_output(int fd_ind, byte *buffer, int length, char got_udp_msg,
    int errno_arg)
{
    int result;
    int i, j;
    unsigned int sock_addr_len;
    int read_fd = fds[fd_ind]->fd;
    fd_t *src_fd = fds[fd_ind];

    if (debug[0]) {
        fprintf(stderr, "do_output; read fd %d got result %d", read_fd, length);
        if (got_udp_msg) {
            fprintf(stderr, " from udp client %08x:%d",
                    (unsigned int) fds[fd_ind]->msg_sockaddr.sin_addr.s_addr,
                    ntohs(fds[fd_ind]->msg_sockaddr.sin_port));
        }
        fprintf(stderr, "\n");
        hexdump(buffer, length);
    }

    /* if read failed and we are doing tcp, close the connection */
    if (length <= 0) {
        if (fds[fd_ind]->connect_type == connect_file
            || fds[fd_ind]->connect_type == connect_keyboard)
        {
            if (verbose > 0)
                fprintf(stderr, "got eof (0-length read) on stdin or file.  "
                    "exiting.\n");

            server_exit(0);
        }

        if (!got_udp_msg
            && !fds[fd_ind]->raw_client
            && !fds[fd_ind]->pcap_client)
        {
            fds[fd_ind]->error_count++;

            if (verbose > 0)
                fprintf(stderr, "1 problem with sendto:  %s; errno %d; "
                        "return %d\n",
                        strerror(errno), errno, length);

            if (die_if_lose_server)
                server_exit(0);

            if (errno_arg != EAGAIN)
                reopen_tcp_connection(fd_ind, "do_output 1");
        }

        return;
    }

    /* send received message to our tcp clients and to servers
     * for whom we are clients.
     */
    for (i = 0; i < fd_count; i++) {
        if (!fds[i]->fd_active) {
            continue;
        }

        if (fds[i]->no_output) {
            continue;
        }

        /* are we supposed to echo the message back to the client? */
        if (fds[i]->fd == read_fd && !echo) {
            continue;
        }

        if (fds[i]->connect_type == connect_tcp_server) {
            continue;
        }

        if (fds[i]->connect_type == connect_udp_listener) {
            continue;
        }

        if (src_fd->exclude_out == fds[i]) {
            continue;
        }

        if (fds[i]->fd == my_udp_server_fd) {
            continue;
        }

        if (fds[i]->exclude_port_count > 0) {
            unsigned int found = false;
            for (j = 0; j < fds[i]->exclude_port_count; j++) {
                if (fds[i]->exclude_ports[j]
                    == ntohs(fds[fd_ind]->msg_sockaddr.sin_port))
                {
                    found = true;
                    break;
                }
            }
            if (found)
                continue;
        }

        if (fds[i]->connect_type == connect_keyboard) {
            if (fds[i]->text_msgs) {
                if (fds[i]->time_and_source) {
                    print_time_and_source(read_fd);
                }
                print_text_msg(buffer, length);

            } else if (fds[i]->hex_msgs) {
                print_hex_msg(buffer, length);

            } else {
                /* write to stdout */
                if (write(1, buffer, length) < 0) {
                    if (verbose > 0) {
                        fprintf(stderr, "problem with write:  %s\n",
                                strerror(errno));
                    }
                }
            }
        }

        if (fds[i]->write != NULL) {
            result = fds[i]->write(fds[i], buffer, length);
        }

        #ifdef PCAP_LIB
        else if (fds[i]->pcap_client) {
            if (debug[1]) {
                fprintf(stderr, "try pcap_sendpacket '%s' (len %d)..\n",
                        buffer, length);
            }
            if (length < 14) {
                fprintf(stderr, "packet too short; not sending to pcap.\n");
                continue;
            }

            result = pcap_sendpacket(fds[i]->adhandle, buffer, length);

            if (result == 0) {
                result = length;
            }
        }
        #endif

        /* command-line udp connection ("-u" or "-U")? */
        else if (fds[i]->udp_target) {
            sock_addr_len = sizeof(fds[0]->udp_sockaddr);

            result = sendto(fds[i]->fd, buffer, length, MSG_NOSIGNAL,
                    (struct sockaddr *) &fds[i]->udp_sockaddr,
                    sock_addr_len);

            if (debug[1]) {
                fprintf(stderr, "wrote to udp server %x:%d; got result "
                        "%d\n",
                        (unsigned int)
                            fds[i]->udp_sockaddr.sin_addr.s_addr,
                        ntohs(fds[i]->udp_sockaddr.sin_port),
                        result);
            }
        }

        /* tcp connection? */
        else { /* not fds[i]->udp_target */
            int lcl_errno;
            result = send(fds[i]->fd, buffer, length,
                    MSG_NOSIGNAL | (dontwait ? MSG_DONTWAIT : 0));
            lcl_errno = errno;

            if (debug[1]) {
                fprintf(stderr, "wrote to fd %d; got result %d\n",
                        fds[i]->fd, result);
            }

            if (timeout_bad_client)
                packet_recvd(fds[i], result >= 0);

            if (result < 1) {
                fds[fd_ind]->error_count++;

                if (verbose > 0)
                    fprintf(stderr, "2 problem with sendto:  %s; errno %d\n",
                            strerror(lcl_errno), lcl_errno);

                if (lcl_errno != EAGAIN)
                    reopen_tcp_connection(i, "do_output 2");
            }
        }
    }

    /* send received message to udp clients */
    for (i = 0; i < udp_client_count; i++) {
        sock_addr_len = sizeof(udp_client_sockaddr[i]);

        /* if the message came from this guy and we're not in echo
         * mode, don't send it to him.
         */
        if (got_udp_msg
            && memcmp(&src_fd->msg_sockaddr, &udp_client_sockaddr[i],
                    sizeof(src_fd->msg_sockaddr)) == 0
            && !echo)
        {
            continue;
        }

        result = sendto(my_udp_server_fd, buffer, length, MSG_NOSIGNAL,
                (struct sockaddr *) &udp_client_sockaddr[i],
                sock_addr_len);

        if (result < 1) {
            if (verbose > 0)
                fprintf(stderr, "3 problem with sendto:  %s; errno %d\n",
                        strerror(errno), errno);
        }

        if (debug[1]) {
            fprintf(stderr, "wrote to udp client %x:%d; got result "
                    "%d\n",
                    (unsigned int)
                        udp_client_sockaddr[i].sin_addr.s_addr,
                    ntohs(udp_client_sockaddr[i].sin_port),
                    result);
        }
    }
}

/*****************************************************************************
 * Function name:  void fork_udp_pinger(int fd)
 * Description:
 *    fork a process that sends an empty message once per second to
 *    a udp server.  the udp server might start after this udp client,
 *    and the server has to hear at least one message from this client 
 *    to become aware of it.
 * Args:
 *    fd:  the open udp socket
 * Returns:
 *    no return value.
 *****************************************************************************/
static void fork_udp_pinger(int fd) {
    int i;
    pid_t pid;
    int my_fd_ind = -1;

    pid = fork();

    if (pid == -1) {
        fprintf(stderr, "udp pinger fork failed.\n");
        exit(1);
    }

    if (pid != 0) {
        return;
    }

    for (i = 0; i < fd_count; i++) {
        if (fds[i]->fd != fd) {
            close(fds[i]->fd);
        }

        if (fds[i]->fd == fd) {
            my_fd_ind = i;
        }
    }

    close(0);
    close(1);

    if (my_fd_ind == -1) {
        fprintf(stderr, "udp pinger could not find fd record.\n");
        exit(1);
    }

    while (1) {
        int sock_addr_len = sizeof(fds[my_fd_ind]->udp_sockaddr);

        int result = sendto(fd, NULL, 0, MSG_NOSIGNAL,
                (struct sockaddr *) &fds[my_fd_ind]->udp_sockaddr,
                sock_addr_len);

        if (result == -1) {
            fprintf(stderr, "udp pinger error:  %s\n", strerror(errno));
        }

        sleep(1);
    }
}

/*****************************************************************************
 * Function name:  int fd_iterate(int *iter_ind)
 * Description:
 *    iterator for fd indices.  the fd array has a priority field,
 *    currently just 1 or larger than 1.  we want to iterate over
 *    the file descriptors with available incoming data in priority order.
 *    iter_ind goes from 0 to 2 * fd_count - 1; first half is high priority
 *    fd's, second half is low-priority fds.
 * Args:
 *    iter_ind:  in-out parm indicating next iterator
 * Returns:
 *    next index in 0 .. (fd_count-1) range to consider
 *****************************************************************************/
static int fd_iterate(int *iter_ind) {
    while (1) {
        if ((!use_priorities && *iter_ind >= fd_count)
            || (use_priorities && *iter_ind >= fd_count * 2)
            || *iter_ind >= fd_count * 2)
        {
            return -1;
        }

        *iter_ind += 1;

        if (*iter_ind < fd_count && fds[*iter_ind]->priority > 1) {
            return *iter_ind;
        }

        if (*iter_ind >= fd_count && fds[*iter_ind - fd_count]->priority <= 1) {
            return *iter_ind - fd_count;
        }
    }
}

/* process result of read attempt.  result != 0 iff read was successful.
 * decide whether to close the connection from which the packet was read.
 */
static void packet_recvd(fd_t *fd, int result) {
    struct timeval tm;
    long long now;

    if (result) {
        fd->error_count = 0;
        return;
    }

    if (fd->error_count == 0) {
        fd->error_count = 1;

        gettimeofday(&tm, NULL);
        fd->last_packet_recvd = ((long long) tm.tv_sec) * 1000000LL
                + (long long) tm.tv_usec;
        return;
    }

    if (fd->error_count++ < 100)
        return;

    gettimeofday(&tm, NULL);
    now = ((long long) tm.tv_sec) * 1000000LL + (long long) tm.tv_usec;

    if (now < fd->last_packet_recvd + 1000000ll)
        return;

    if (verbose > 0)
        fprintf(stderr, "time's up, too many errors.  close the sucker.\n");

    if (fd->close)
        fd->close(fd);
    else
        close(fd->fd);

    if (fd->fd_active) {
        fds_closed = true;
        fd->fd_active = false;
    }
}

int accept_tcp_client(int fd_ind) {
    int fd;

    /* if this is a tcp client trying to connect to us, accept the
     * incoming client connection.
     */
    fd = accept_server_socket(fds[fd_ind]->fd);
    fprintf(stderr, "attempt to accept on %d got back %d\n",
            fds[fd_ind]->fd, fd);

    if (fd == -1) {
        fprintf(stderr, 
                "attempt to accept connection from a client failed.\n");
        return -1;

    } else {
        fprintf(stderr, "new connection from client established; "
                "fd %d\n", fd);
    }

    if (fd_count >= MAX_FD) {
        fprintf(stderr, "too many clients\n");
        close(fd);

    } else {
        add_fd(fd, false, false, false, false,
                connect_tcp_inbound_client);

        fds[fd_count-1]->exclude_out = fds[fd_ind]->exclude_out;
        fds[fd_count-1]->hex_msgs = fds[fd_ind]->hex_msgs;
    }

    #ifdef LINUX
    /* if we are supposed to fork a separate server process for
     * each tcp client, do that now.
     */
    if (do_fork) {
        pid_t child_pid = fork();

        if (child_pid < 0) {
            fprintf(stderr, "server fork failed:  %s\n", strerror(errno));
            close(fd);
            return -1;
        }

        /* if we are the parent process, go back and wait for another
         * client.  if we are the child process, interact with the
         * client until it exits, and then we exit.
         */
        if (child_pid > 0) {
            printf("child pid %d\n", child_pid);
            return 0;
        }
    }
    #endif

    return 0;
}

void usage() {
    printf("-p/-P:  tcp client/server.\n");
    printf("\n");
    printf("-u/-U:  udp client/server; client does pings to notify server.\n");
    printf("\n");
    printf("-k:     text-based stdin/stdout.\n");
    printf("-r:     raw stdin/stdout\n");
    printf("-b:     hex-based stdout.\n");
    printf("\n");
    printf("-t:     next interface (which must use stdout) has time/direction\n");
    printf("-i/o    next interface is only input (resp. output)\n");
    printf("\n");
    printf("-s      use file system file.  works for /dev/ttyS0 etc., named pipes, regular files.\n");
    printf("\n");
    printf("-w      raw network device interface eth0 etc.  (requires sudo.)\n");
    exit(0);
}

/*****************************************************************************
 * Function name:  int main(int argc, char ** argv)
 * Description:
 *    main routine
 * Args:
 *    int argc:  number of input arguments
 *    char **argv:  vector of input arguments
 * Returns:
 *    0 if no errors, 1 otherwise
 *****************************************************************************/
int main(int argc, char **argv) {
    #ifdef WINDOWS
        int error;
    #endif
    int fd, max_fd;
    int my_server_port = -1;
    socklen_t sock_addr_len;
    int unconnected_tcp_client;
    int c;
    int i, j, fd_ind, result;
    byte buffer[BUFSIZE];
    byte got_something;
    char *host;
    int port;
    int lcl_errno;

    #ifdef WINDOWS
        initwin();
    #endif

    start_time = time__usec();

    memset(fd_recs, 0, sizeof(fd_recs));

    for (i = 0; i < MAX_FD; i++) {
        fds[i] = &fd_recs[i];
    }

    /* process command-line arguments */
    while ((c = getopt(argc, argv, "abdDefFhikl:mNop:rP:s:tu:U:vw:xX:")) != EOF) {
        if (c == '?') continue;

        switch (c) {
            case 'h':
                usage();
                break;

            case 'v':
                verbose++;
                break;

            case 'i':
                no_output = true;
                if (no_input) {
                    fprintf(stderr,
                            "'i' and 'o' option cannot be used together.\n");
                    exit(1);
                }
                break;

            case 'o':
                no_input = true;
                if (no_output) {
                    fprintf(stderr,
                            "'o' and 'i' option cannot be used together.\n");
                    exit(1);
                }
                break;

            case 'k':
                #ifdef WINDOWS
                    fprintf(stderr, "'k' option invalid on Windows; "
                            "build and use cserver.exe instead\n");
                    exit(1);
                #endif
                text_msgs = 1;
                add_fd(0, false, true, false, false, connect_keyboard);
                break;

            case 'b':
                no_input = true;
                if (no_output) {
                    fprintf(stderr,
                            "'b' and 'i' option cannot be used together.\n");
                    exit(1);
                }
                hex_msgs = 1;
                add_fd(0, false, true, false, false, connect_keyboard);
                break;

            case 'r':
                add_fd(0, false, true, false, false, connect_keyboard);
                break;

            case 't':
                time_and_source = 1;
                break;

            case 'e':
                echo = 1;
                break;

            case 'a':
                die_if_lose_server = 1;
                break;

            #ifdef PCAP_LIB
            case 'w': {
                if (open_pcap(optarg) == -1) {
                    fprintf(stderr,"\nUnable to open the adapter.  "
                            "%s is not supported by WinPcap\n", optarg);
                    return -1;
                }

                break;
            }
            #elif defined(LINUX_RAW)
            case 'w':
                add_fd(-1, false, true, false, true, connect_raw_client);
                fds[fd_count-1]->priority = 10;
                setup_raw_interface(optarg, fds[fd_count - 1]);
                break;
            #endif

            case 'D':
                dontwait = 0;
                break;

            case 'X': {
                fd_t *fp = fds[fd_count-1];
                if (fd_count == 0) {
                    fprintf(stderr, "-X must come after an interface\n");
                    return 1;
                }
                if (fp->exclude_port_count >= MAX_EXCLUDE
                    || sscanf(optarg, "%d",
                        &fp->exclude_ports[fp->exclude_port_count++]) != 1)
                {
                    fprintf(stderr, "-X error\n");
                    return 1;
                }
                break;
            }

            case 's':
                add_fd(-1, false, true, false, false, connect_file);
                setup_file_interface(optarg, fds[fd_count - 1]);
                break;

            case 'm':
                if (fd_count <= 0) {
                    fprintf(stderr, "-m option must come after an interface\n");
                    return -1;
                }
                marked = fds[fd_count-1];
                break;

            case 'x': {
                if (fd_count <= 0 || marked == NULL) {
                    fprintf(stderr, "-x option must come after a marked "
                            "interface\n");
                    return -1;
                }
                fds[fd_count-1]->exclude_out = marked;
                break;
            }

            case 'N':
                timeout_bad_client = true;
                break;

            case 'u':
                check_valid(fd_count < MAX_FD, "too many connections");

                add_fd(-1, true, true, false, false, connect_udp_client);

                setup_udp_client_interface(strdup(optarg), fds[fd_count - 1]);

                break;

            case 'p': {
                char *p;
                if (strchr(optarg, (int) ':') != NULL) {
                    host = strdup(optarg);
                    p = strchr(host, (int) ':');
                    *p = '\0';
                    p++;

                } else {
                    host = "localhost";
                    p = optarg;
                }

                check_valid(sscanf(p, "%d", &port) == 1,
                        "`%s' is not a valid port\n", optarg);

                fd = open_client_socket(host, port);
                // check_valid(fd >= 0, "open_client_socket failed\n");

                add_fd(fd, false, true, false, false, connect_tcp_client);
                fds[fd_count-1]->host = host;
                fds[fd_count-1]->port = port;

                break;
            }

            case 'f':
                do_fork = 1;
                break;

            case 'F':
                do_udp_pinger = 0;
                break;

            case 'l':
                result = sscanf(optarg, "%d", &port);
                if (result != 1) {
                    fprintf(stderr, "`%s' is not a valid port\n", optarg);
                    exit(1);
                }
                fd = open_udp_server_socket(port);
                fprintf(stderr, "open udp server socket %d returned %d\n",
                        port, fd);
                if (fd < 0) {
                    exit(1);
                }

                add_fd(fd, true, false, false, false, connect_udp_listener);
                break;

            case 'U':
            case 'P': {
                char use_udp;
                result = sscanf(optarg, "%d", &my_server_port);
                if (result != 1) {
                    fprintf(stderr, "`%s' is not a valid port\n", optarg);
                    exit(1);
                }

                use_udp = (c == 'U');

                if (use_udp) {
                    fd = open_udp_server_socket(my_server_port);
                    fprintf(stderr, "open udp server socket %d returned %d\n",
                            my_server_port, fd);
                    if (fd < 0) {
                        exit(1);
                    }

                    add_fd(fd, true, false, false, false, connect_udp_server);
                    my_udp_server_fd = fd;

                } else {
                    int accept_socket = open_server_socket(my_server_port);
                    fprintf(stderr, "open server socket %d returned %d\n",
                            my_server_port, accept_socket);

                    if (accept_socket == -1) {
                        exit(1);
                    }

                    add_fd(accept_socket, false, false, false, false,
                            connect_tcp_server);
                }

                break;
            }

            default:
                fprintf(stderr, "hmmmm.  don't understand option '%c'\n", c);
                break;
        }
    } /* while process command-line arguments */

    if (fd_count == 0 /*&& my_server_port == -1*/) {
        fprintf(stderr, "no servers or clients specified\n");
        exit(0);
    }

    if (do_udp_pinger) {
        for (i = 0; i < fd_count; i++)
            if (fds[i]->connect_type == connect_udp_client)
                fork_udp_pinger(fds[i]->fd);
    }

    /* accept incoming connections and data from clients */
    while (1) {
        fd_set io_set;

        compact_fds();

        got_something = false;

        #ifdef PCAP_LIB
            for (i = 0; i < fd_count; i++) {
                int pcap_result;

                if (!fds[i]->fd_active) {
                    continue;
                }

                if (!fds[i]->pcap_client) {
                    continue;
                }

                server_bp1();

                pcap_result = pcap_next_ex(fds[i]->adhandle, &header,
                        &pcap_data);

                if (pcap_result > 0) {
                    do_output(i, (char *) pcap_data, header->len, false, 0);
                    got_something = true;
                    goto end_loop;
                }
            }
        #endif

        // fprintf(stderr, "fd_count %d, udp_client_count %d\n",
                // fd_count, udp_client_count);

        FD_ZERO(&io_set);
        max_fd = -1;
        unconnected_tcp_client = 0;

        /* set up the select bit vector */
        for (i = 0; i < fd_count; i++) {
            if (fds[i]->pcap_client) {
                continue;
            }

            if (fds[i]->no_input) {
                continue;
            }

            if (!fds[i]->fd_active) {
                continue;
            }

            if (fds[i]->connect_type == connect_tcp_client && fds[i]->fd == -1) {
                reopen_tcp_connection(i, "pre-select");

                if (fds[i]->fd == -1) {
                    unconnected_tcp_client = 1;
                    continue;
                }
            }

            if (fds[i]->fd > max_fd) {
                max_fd = fds[i]->fd;
            }

            FD_SET(fds[i]->fd, &io_set);
        }

        if (max_fd == -1) {
            continue;
        }

        {
            struct timeval tv = {0,0};
            #ifdef NONBLOCKING_SELECT
                result = select(max_fd + 1, &io_set, NULL, NULL, &tv);
            #else
                if (unconnected_tcp_client) {
                    tv.tv_usec = 100000;
                    result = select(max_fd + 1, &io_set, NULL, NULL, &tv);

                } else {
                    result = select(max_fd + 1, &io_set, NULL, NULL, NULL);
                }
            #endif
            server_bp1();
        }

        if (result <= 0) {
            // fprintf(stderr, "didn't get anything..\n");
            goto end_loop;
        }

        got_something = true;

        /* go through the selected file descriptors and read data from
         * each, and then output the data to all outbound receivers of data
         */

        int iter = -1;
        while ((fd_ind = fd_iterate(&iter)) >= 0) {
            char got_udp_msg;
            int length;
            int read_fd;

            if (!fds[fd_ind]->fd_active) {
                continue;
            }

            if (fds[fd_ind]->pcap_client) {
                continue;
            }

            read_fd = fds[fd_ind]->fd;

            if (read_fd < 0 || !FD_ISSET(read_fd, &io_set)) {
                continue;
            }

            if (fds[fd_ind]->read != NULL) {
                length = fds[fd_ind]->read(fds[fd_ind], buffer, BUFSIZE-1);

                if (timeout_bad_client)
                    packet_recvd(fds[fd_ind], length >= 0);

                do_output(fd_ind, buffer, length, false, 0);

            } else if (fds[fd_ind]->udp_target) {
                char found;

                got_udp_msg = 1;

                sock_addr_len = sizeof(fds[fd_ind]->msg_sockaddr);
                length = recvfrom(read_fd, buffer, BUFSIZE-1, 0,
                        (struct sockaddr *) &fds[fd_ind]->msg_sockaddr,
                        &sock_addr_len);

                if (timeout_bad_client)
                    packet_recvd(fds[fd_ind], length >= 0);

                // fprintf(stderr, "source port of received message:  %d\n",
                        // ntohs(fds[fd_ind]->msg_sockaddr.sin_port));

                do_output(fd_ind, buffer, length, got_udp_msg, 0);

                /* if this is a udp client communicating to us, add them to
                 * our list of clients and include them in our broadcasts
                 * of future messages.
                 */
                if (read_fd == my_udp_server_fd && length >= 0) {
                    found = 0;
                    for (i = 0; i < udp_client_count; i++) {
                        if (memcmp(&fds[fd_ind]->msg_sockaddr,
                            &udp_client_sockaddr[i],
                            sizeof(fds[fd_ind]->msg_sockaddr)) == 0)
                        {
                            found = 1;
                            break;
                        }
                    }

                    if (!found) {
                        if (udp_client_count >= MAX_UDP_CLIENT) {
                            for (i = 0; i < MAX_UDP_CLIENT - 1; i++) {
                                udp_client_sockaddr[i]
                                    = udp_client_sockaddr[i + 1];
                            }
                            udp_client_count--;
                        }

                        udp_client_sockaddr[udp_client_count++]
                            = fds[fd_ind]->msg_sockaddr;
                    }
                }

                if (read_fd == my_udp_server_fd && length < 0) {
                    found = 0;
                    for (i = 0; i < udp_client_count; i++) {
                        if (memcmp(&fds[fd_ind]->msg_sockaddr,
                            &udp_client_sockaddr[i],
                            sizeof(fds[fd_ind]->msg_sockaddr)) == 0)
                        {
                            found = 1;
                            break;
                        }
                    }

                    if (found) {
                        for (j = i; j < udp_client_count - 1; j++) {
                            udp_client_sockaddr[j]
                                = udp_client_sockaddr[j + 1];
                        }
                        udp_client_count--;
                    }
                }

                continue;
            }

            #ifndef WINDOWS
            else if (read_fd == 0) { /* keyboard input? */
                got_udp_msg = 0;

                length = read(read_fd, buffer, BUFSIZE-1);

                if (timeout_bad_client)
                    packet_recvd(fds[fd_ind], length >= 0);

                #ifdef WINDOWS
                    error = WSAGetLastError();
                #endif

                do_output(fd_ind, buffer, length, got_udp_msg, 0);
            }
            #endif

            else if (fds[fd_ind]->connect_type == connect_tcp_server) {
                accept_tcp_client(fd_ind);
                goto end_loop;

            } else {
                got_udp_msg = 0;

                length = recv(read_fd, buffer, BUFSIZE-1, 0);
                lcl_errno = errno;

                if (length < 0) {
                    if (verbose > 0)
                        fprintf(stderr, "recv failed:  %s\n", strerror(errno));
                }

                if (timeout_bad_client)
                    packet_recvd(fds[fd_ind], length >= 0);

                #ifdef WINDOWS
                    error = WSAGetLastError();
                #endif

                do_output(fd_ind, buffer, length, got_udp_msg, lcl_errno);
            }
        } /* send stuff to other clients .. */

        end_loop:;

        /* sleep .01 second if we didn't receive anything from any interface */
        if (!got_something) {
            #if defined(LINUX)
                usleep(10000);
            #elif defined(WINDOWS)
                Sleep(10);
            #endif
        }

    } /* while accepting incoming connections and messages from clients.. */
}
#endif // defined(MAIN)
