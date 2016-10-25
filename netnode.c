/****************************************************************************
 * Copyright (c) Greg Johnson, Gnu Public Licence v. 2.0.
 * File Name    : netnode.c
 *
 * Author       : Greg Johnson
 *
 * Description : set up a communication graph.
 *               The program can be used to set up a graph of
 *               communicating netnode instances on different machines.  
 *
 * Return values:
 *    0:  normal exit
 *    1:  error exit
 ****************************************************************************/

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
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

#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#ifdef LINUX_RAW
    #include <linux/if_packet.h>
    #include <linux/if_ether.h>   /* The L2 protocols */
#endif

#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "netnode.h"

#define RELEASE_VERSION  1
#define MAJOR_VERSION    0
#define MINOR_VERSION    2

#ifdef PCAP_LIB
    #define HAVE_REMOTE
    #include "pcap.h"
    #include <pthread.h>
#endif

#define BUFSIZE 65536
#define MAX_EXCLUDE 16

typedef unsigned char byte;

byte buffer1[BUFSIZE];
byte buffer2[BUFSIZE];

byte *buffer = buffer1;

#ifndef MSG_NOSIGNAL
    #define MSG_NOSIGNAL 0
#endif

typedef enum {
    connect_unknown = 0,

    connect_udp_server,
    connect_udp_client,
    connect_udp_inbound_client,

    connect_tcp_server,             // the -P port to which clients connect
    connect_tcp_client,             // we are a "-p" tcp client
    connect_tcp_inbound_client,     // client connection to our "-P"

    connect_tcp_proxy_server,       // my tcp server port for proxy clients
    connect_tcp_proxy_client,
    connect_tcp_proxy_inbound_client,

    connect_raw_client,
    connect_pcap_client,

    connect_keyboard,
    connect_file,

} connect_type_t;

typedef struct _fd_t {
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

    /* the host and port of udp server for whom we are a client based on
     * '-u host:port' command-line arguments.
     * or, if this is a connect_udp_inbound_client, their return address.
     */
    struct sockaddr_in udp_sockaddr;

    /* the source port for a udp client '-u src_port:host:host_port' */
    int udp_src_port;

    /* for incoming udp messages, the sockaddr containing the source
     * port and IP address
     */
    // struct sockaddr_in msg_sockaddr;

    #ifdef LINUX_RAW
        struct sockaddr_ll raw_send_recv;
    #endif

    int priority;

    int port;
    char *host;

    struct _fd_t *proxy_partner;

    int (*read)(server_fd_ptr_t voidp_fd_desc, byte *buf, int buf_len);
    int (*write)(server_fd_ptr_t voidp_fd_desc, byte *buf, int buf_len);
    int (*close)(server_fd_ptr_t voidp_fd_desc);

    int error_count;
    long long last_packet_recvd;

    /* print text output for this interface? */
    int text_msgs;

    /* print time and source with interface? */
    int time_and_source;

    /* print hex dump output for this interface? */
    int hex_msgs;
} fd_t;

static void add_fd(int            fd,
                   char           udp_target,
                   char           ima_client,
                   char           pcap_client,
                   char           raw_client,
                   connect_type_t connect_type);

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

/*****************************************************************************
 * Open a udp or tcp server socket
 * Args:
 *    int port:  the server port to open
 * Returns:
 *    a file descriptor that can be used for accept calls
 *****************************************************************************/
static int do_open_server_socket(int port, int connection_type) {
    int sock;
    struct sockaddr_in sin;

    /* attempt to open a socket */

    sock = socket(PF_INET, connection_type, 0);

    if (sock == -1) {
        fprintf(stderr, "socket failed:  %s\n", strerror(errno));
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
        fprintf(stderr, "bind failed:  %s\n", strerror(errno));
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
 * Open a udp server socket
 * Args:
 *    int port:  the server port to open
 * Returns:
 *    a file descriptor that can be used for accept calls
 *****************************************************************************/
int open_udp_server_socket(int port) {
    return (do_open_server_socket(port, SOCK_DGRAM));
}

/*****************************************************************************
 * Open a tcp server socket
 * Args:
 *    int port:  the server port to open
 * Returns:
 *    a file descriptor that can be used for accept calls
 *****************************************************************************/
int open_server_socket(int port) {
    return(do_open_server_socket(port, SOCK_STREAM));
}

/*****************************************************************************
 * Accept an incoming connection to our tcp port from a client
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

}

/*****************************************************************************
 * If check is true, do nothing.  else, print error message and exit(1).
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
 * Parse arg to get host, port, and source port.  syntax of arg:
 * [[source_port:]host:]dest_port
 *
 * if no host or null host, return "localhost" in host parameter.
 * if no source_port, return -1 in src_port parameter.
 *
 * NOTE:  this function modifies arg in place.
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

int read_raw_interface(server_fd_ptr_t voidp_fd_desc, byte *buf, int buf_len)
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
 * Populate sock_addr with port and IP address of host
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
}

/*****************************************************************************
 * Connect to a udp or tcp server on the given host at the given port
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
 * Connect to a tcp server on the given host at the given port
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
 * Connect to a udp server on the given host at the given port
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

void setup_udp_client_interface(char *host_port, server_fd_ptr_t voidp_fd_desc) {
    int port;
    char *host;
    int udp_src_port = -1;
    fd_t *fd_desc = (fd_t *) voidp_fd_desc;
    int result;

    get_host_ports(&host, &port, &udp_src_port, host_port);

    fd_desc->fd = open_udp_client_socket(host, port);
    check_valid(fd_desc->fd >= 0, "open_udp_client_socket failed");

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
typedef struct {
    struct sockaddr_in sockaddr;
    fd_t *udp_inbound_client_fd_desc;
} sockaddr_with_fd_t;

sockaddr_with_fd_t udp_client_sockaddr[MAX_UDP_CLIENT];
static int udp_client_count = 0;

fd_t *findUdpInboundClient(struct sockaddr_in *inbound_msg_sockaddr) {
    int i;
    fd_t *result = NULL;
    bool found = false;

    for (i = 0; i < udp_client_count; i++) {
        if (memcmp(inbound_msg_sockaddr,
            &udp_client_sockaddr[i].sockaddr,
            sizeof(struct sockaddr_in)) == 0)
        {
            found = true;
            break;
        }
    }

    if (found) {
        result = udp_client_sockaddr[i].udp_inbound_client_fd_desc;
    }

    return result;
}

void ensureRoomForNewInboundUdpClient() {
    if (udp_client_count >= MAX_UDP_CLIENT) {
        int i;
        for (i = 0; i < MAX_UDP_CLIENT - 1; i++) {
            udp_client_sockaddr[i] = udp_client_sockaddr[i + 1];
        }
        udp_client_count--;
    }
}

void addUdpInboundClient(struct sockaddr_in *inbound_msg_sockaddr, fd_t *my_udp_server_fd) {
    ensureRoomForNewInboundUdpClient();

    add_fd(my_udp_server_fd->fd, true, true, false, false, connect_udp_inbound_client);
    fds[fd_count-1]->udp_sockaddr = *inbound_msg_sockaddr;

    fds[fd_count-1]->no_input  = my_udp_server_fd->no_input;
    fds[fd_count-1]->no_output = my_udp_server_fd->no_output;
    fds[fd_count-1]->text_msgs = my_udp_server_fd->text_msgs;
    fds[fd_count-1]->hex_msgs = my_udp_server_fd->hex_msgs;
    fds[fd_count-1]->time_and_source = my_udp_server_fd->time_and_source;

    udp_client_sockaddr[udp_client_count].udp_inbound_client_fd_desc = fds[fd_count-1];
    udp_client_sockaddr[udp_client_count].sockaddr = *inbound_msg_sockaddr;

    ++udp_client_count;
}

void removeUdpInboundClient(struct sockaddr_in *inbound_msg_sockaddr) {
    int i, j;
    fd_t *fd = NULL;
    bool found = false;

    for (i = 0; i < udp_client_count; i++) {
        if (memcmp(&inbound_msg_sockaddr,
            &udp_client_sockaddr[i].sockaddr,
            sizeof(struct sockaddr_in)) == 0)
        {
            found = true;
            break;
        }
    }

    if (found) {
        fd = udp_client_sockaddr[i].udp_inbound_client_fd_desc;
        if (fd->fd_active) {
            fds_closed = true;
            fd->fd_active = false;
        }

        for (j = i; j < udp_client_count - 1; ++j) {
            udp_client_sockaddr[j] = udp_client_sockaddr[j + 1];
        }
        udp_client_count--;
    }
}

static void packet_recvd(fd_t *fd, int result);

/*****************************************************************************
 * Add a file descriptor to the fds[] array; error-exit the program if too many.
 *     (Look before you leap.)
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
static void add_fd(int            fd,
                   char           udp_target,
                   char           ima_client,
                   char           pcap_client,
                   char           raw_client,
                   connect_type_t connect_type)
{
    if (fd_count >= MAX_FD) {
        fprintf(stderr, "too many files\n");
        exit(1);
    }

    memset(fds[fd_count], 0, sizeof(*fds[fd_count]));

    fds[fd_count]->connect_type = connect_type;
    fds[fd_count]->fd = fd;

    // options for all interfaces
        fds[fd_count]->no_output = no_output;
        no_output = false;

        fds[fd_count]->no_input = no_input;
        no_input = false;

    // options for stdout
        fds[fd_count]->time_and_source = time_and_source;
        time_and_source = false;

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
    fds[fd_count]->fd_active = 1;
    fds[fd_count]->priority = 1;

    fd_count++;
}

/*****************************************************************************
 * Compact active fd records to the left in the fds[] array.
 * we look at fds[i]->fd_active, and garbage collect the false ones.
 * so as not to have to run over the whole array every time, fds_closed
 * is set whenever an fd_active field is made false.
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

static void setup_file_interface(char *dev_name, server_fd_ptr_t voidp_fd_desc) {
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
 * Open the pcap windows interface.
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
        if (fds[i]->fd_active) {

            if (fds[i]->close != NULL) {
                fds[i]->close(fds[i]);

            } else if (fds[i]->fd >= 0) {
                close(fds[i]->fd);
            }
        }
    }

    exit(0);
}

/*****************************************************************************
 * Close a tcp connection, and exit the program
 *     if global do_fork is true or fd_desc->ima_client.
 * Args:
 *    name:  the name of the interface to close.
 * Returns:
 *    0 on success, -1 on failure
 *****************************************************************************/
static void close_tcp_connection(struct _fd_t *fd_desc, char *title) {
    if (verbose > 0) {
        fprintf(stderr, "close_tcp_connection from %s; fd %d..\n", title,
                fd_desc->fd);
    }

    if (!fd_desc->fd_active) return;

    if (   fd_desc->connect_type != connect_tcp_server
        && fd_desc->connect_type != connect_tcp_client
        && fd_desc->connect_type != connect_tcp_inbound_client
        && fd_desc->connect_type != connect_tcp_proxy_server
        && fd_desc->connect_type != connect_tcp_proxy_client
        && fd_desc->connect_type != connect_tcp_proxy_inbound_client)
    {
        return;
    }

    close(fd_desc->fd);

    fd_desc->fd_active = 0;
    fds_closed = true;

    if (do_fork) {
        server_exit(0);

    } else if (fd_desc->ima_client) {
        server_exit(0);
    }

    fprintf(stderr, "client stopped\n");
}

/*****************************************************************************
 * Reset a tcp connection.
 * Args:
 *    fd_ind:  index in fds[] of the connection to reset.
 *    title:   debug message to print if verbose output.
 * Returns:
 *    no return value.
 *****************************************************************************/
static void reset_tcp_connection(int fd_ind, char *title) {
    fd_t *fd_struct = fds[fd_ind];

    if (   fd_struct->connect_type != connect_tcp_client
        && fd_struct->connect_type != connect_tcp_proxy_client)
    {
        if (verbose > 0)
            fprintf(stderr, "not a connect_tcp_client; return..\n");

        close_tcp_connection(fds[fd_ind], title);
        return;
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

static void close_proxy_tcp_connection(fd_t *fd_desc) {
    if (fd_desc->fd != -1) {
        close(fd_desc->fd);
        fd_desc->fd = -1;
        fd_desc->fd_active = 0;
        fds_closed = true;
        close_proxy_tcp_connection(fd_desc->proxy_partner);
    }
}

static int prev_sourceFd = -1;

static int print_time_and_source(char *outBuf, int outBufLen, int sourceFd) {
    int resultLen = 0;

    if (sourceFd != prev_sourceFd) {
        double now = time__usec();
        resultLen = snprintf(outBuf, outBufLen, "\n%12.6lf >> %d >>\n", now - start_time, sourceFd);
        if (resultLen > outBufLen - 1) {
            resultLen = outBufLen - 1;
        }
        prev_sourceFd = sourceFd;
    }
    return resultLen;
}

static int print_text_msg(byte *outBuf, int outBufLen, byte *buffer, int length) {
    int i;
    int resultLen = 0;

    for (i = 0; i < length; i++) {
        if (resultLen >= outBufLen - 1) break;

        char c = buffer[i];

        if (isprint((int) c) || c == '\n') {
            outBuf[resultLen++] = c;
            --outBufLen;

        } else {
            int len;
            len = snprintf((char *) &outBuf[resultLen], outBufLen, "\\0x%02x", 0xff & (unsigned int) c);
            if (len > outBufLen - 1) {
                len = outBufLen - 1;
            }
            resultLen += len;
            outBufLen -= len;
        }
    }

    if (outBufLen > 0) {
        outBuf[resultLen] = '\0';
    }

    return resultLen;
}

void getOutputMessage(byte **outBuffer, int *outLen, byte *buffer, int length, 
                      int time_and_source,
                      int text_msgs,
                      int hex_msgs,
                      int sourceFd)
{
    int bufLen = BUFSIZE;

    if (!time_and_source && !hex_msgs && !text_msgs) {
        *outBuffer = buffer;
        *outLen = length;
        return;
    }

    *outBuffer = buffer2;

    byte *outBuf = *outBuffer;

    if (time_and_source) {
        int len = print_time_and_source((char *) outBuf, bufLen, sourceFd);
        bufLen -= len;
        outBuf += len;
    }

    if (hex_msgs) {
        int len = hexdump((char *) outBuf, bufLen, buffer, length);
        bufLen -= len;
        outBuf += len;

    } else if (text_msgs) {
        int len = print_text_msg(outBuf, bufLen, buffer, length);
        bufLen -= len;
        outBuf += len;

    } else {
        int i;
        for (i = 0; i < length; ++i) {
            if (bufLen <= 1) break;
            *outBuf++ = *buffer++;
            --bufLen;
        }
        if (bufLen > 0)
            *outBuf = '\0';
    }

    *outLen = outBuf - *outBuffer;
}

/*****************************************************************************
 * Send the packet to every destination that should receive it.
 * Args:
 *    fd_ind:  index in fds array of source of the packet
 *    buffer:  the packet to send
 *    length:  the length in bytes of the packet to send
 *    got_udp_msg:  the packet was received via udp 
 * Returns:
 *    no return value.
 *****************************************************************************/
static void do_output(int read_fd_ind, byte *buffer, int length, char got_udp_msg,
    int errno_arg)
{
    int          result;
    int          i;
    unsigned int sock_addr_len;
    int          read_fd        = fds[read_fd_ind]->fd;
    byte*        outBuffer;
    int          outLength;

    /* if read failed or gave EOF.. */
    if (length <= 0) {
        if (   fds[read_fd_ind]->connect_type == connect_file
            || fds[read_fd_ind]->connect_type == connect_keyboard)
        {
            if (verbose > 0)
                fprintf(stderr, "got eof (0-length read) on stdin or file.  "
                    "exiting.\n");

            server_exit(0);
        }

        if (   fds[read_fd_ind]->connect_type == connect_tcp_proxy_client
            || fds[read_fd_ind]->connect_type == connect_tcp_proxy_inbound_client)
        {
            close_proxy_tcp_connection(fds[read_fd_ind]);

        } else if (!got_udp_msg
            && !fds[read_fd_ind]->raw_client
            && !fds[read_fd_ind]->pcap_client)
        {
            fds[read_fd_ind]->error_count++;

            if (verbose > 0)
                fprintf(stderr, "1 problem with sendto:  %s; errno %d; "
                        "return %d\n",
                        strerror(errno), errno, length);

            if (die_if_lose_server)
                server_exit(0);

            if (errno_arg != EAGAIN)
                reset_tcp_connection(read_fd_ind, "do_output 1");
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

        if (fds[i]->fd == 1 && read_fd == 0 && !echo) {
            continue;
        }

        if (fds[i]->connect_type == connect_tcp_server) {
            continue;
        }

        if (fds[i]->connect_type == connect_tcp_proxy_server) {
            continue;
        }

        if (fds[i]->connect_type == connect_udp_server) {
            continue;
        }

        if (  (fds[i]->connect_type == connect_tcp_proxy_client
            || fds[i]->connect_type == connect_tcp_proxy_inbound_client)
            && fds[i]->proxy_partner != fds[read_fd_ind])
        {
            continue;
        }

        getOutputMessage(&outBuffer, &outLength, buffer, length, 
                         fds[i]->time_and_source,
                         fds[i]->text_msgs,
                         fds[i]->hex_msgs,
                         read_fd);

        if (fds[i]->connect_type == connect_keyboard) {
            if (write(1, outBuffer, outLength) < 0) {
                if (verbose > 0) {
                    fprintf(stderr, "problem with write:  %s\n",
                            strerror(errno));
                }
            }
        }

        else if (fds[i]->write != NULL) {
            result = fds[i]->write(fds[i], outBuffer, outLength);
        }

        #ifdef PCAP_LIB
        else if (fds[i]->pcap_client) {
            if (debug[1]) {
                fprintf(stderr, "try pcap_sendpacket '%s' (len %d)..\n",
                        outBuffer, outLength);
            }
            if (outLength < 14) {
                fprintf(stderr, "packet too short; not sending to pcap.\n");
                continue;
            }

            result = pcap_sendpacket(fds[i]->adhandle, outBuffer, outLength);

            if (result == 0) {
                result = outLength;
            }
        }
        #endif

        /* udp connection ("-u", "-U", or inbound client to "U")? */
        else if (fds[i]->udp_target) {
            sock_addr_len = sizeof(fds[0]->udp_sockaddr);

            result = sendto(fds[i]->fd, outBuffer, outLength, MSG_NOSIGNAL,
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
            result = send(fds[i]->fd, outBuffer, outLength,
                    MSG_NOSIGNAL | (dontwait ? MSG_DONTWAIT : 0));
            lcl_errno = errno;

            if (debug[1]) {
                fprintf(stderr, "wrote to fd %d; got result %d\n",
                        fds[i]->fd, result);
            }

            if (timeout_bad_client)
                packet_recvd(fds[i], result >= 0);

            if (result < 1) {
                fds[read_fd_ind]->error_count++;

                if (verbose > 0)
                    fprintf(stderr, "2 problem with sendto:  %s; errno %d\n",
                            strerror(lcl_errno), lcl_errno);

                if (lcl_errno != EAGAIN)
                    reset_tcp_connection(i, "do_output 2");
            }
        }
    }

    #if 0
    /* send received message to udp clients */
    for (i = 0; i < udp_client_count; i++) {
        sock_addr_len = sizeof(udp_client_sockaddr[i].sockaddr);

        /* if the message came from this guy and we're not in echo
         * mode, don't send it to him.
         */
        if (got_udp_msg
            && memcmp(&read_fd_desc->msg_sockaddr, &udp_client_sockaddr[i].sockaddr,
                    sizeof(read_fd_desc->msg_sockaddr)) == 0
            && !echo)
        {
            continue;
        }

        fd_t *server_desc = udp_client_sockaddr[i].udp_server_fd_desc;

        getOutputMessage(&outBuffer, &outLength, buffer, length, 
                         server_desc->time_and_source,
                         server_desc->text_msgs,
                         server_desc->hex_msgs,
                         read_fd);

        result = sendto(server_desc->fd, outBuffer, outLength, MSG_NOSIGNAL,
                (struct sockaddr *) &udp_client_sockaddr[i].sockaddr,
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
                        udp_client_sockaddr[i].sockaddr.sin_addr.s_addr,
                    ntohs(udp_client_sockaddr[i].sockaddr.sin_port),
                    result);
        }
    }
    #endif
}

/*****************************************************************************
 * Fork a process that sends an empty message once per second to
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
 * Iterator for fd indices.  the fd array has a priority field,
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

/*****************************************************************************
 * Process result of read attempt.
 *     Decide whether to close the connection from which the packet was read.
 * Returns
 *     0 iff read was successful.
 *****************************************************************************/
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

void selectPrint(char const * const title, int maxFd, fd_set *fds) {
    int i;
    printf("%s:  ", title);
    for (i = 0; i <= maxFd; ++i) {
        if (FD_ISSET(i, fds)) printf("%d ", i);
    }
    printf("\n");
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
        add_fd(fd, false, false, false, false, connect_tcp_inbound_client);

        fds[fd_count-1]->no_input  = fds[fd_ind]->no_input;
        fds[fd_count-1]->no_output = fds[fd_ind]->no_output;
        fds[fd_count-1]->text_msgs = fds[fd_ind]->text_msgs;
        fds[fd_count-1]->hex_msgs = fds[fd_ind]->hex_msgs;
        fds[fd_count-1]->time_and_source = fds[fd_ind]->time_and_source;
    }

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

    return 0;
}

void add_tcp_proxy_client(int tcp_server_accept_fd_ind) {
    fd_t *accept_fd = fds[tcp_server_accept_fd_ind];
    int fd;
    printf("add_tcp_proxy_client..\n");

    if (accept_tcp_client(tcp_server_accept_fd_ind) >= 0) {
        printf("add_tcp_proxy_client ok..\n");
        fds[fd_count-1]->connect_type = connect_tcp_proxy_inbound_client;

        fd = open_client_socket(accept_fd->host, accept_fd->port);

        add_fd(fd, false, true, false, false, connect_tcp_client);
        fds[fd_count-1]->connect_type = connect_tcp_proxy_client;

        fds[fd_count-1]->proxy_partner = fds[fd_count-2];
        fds[fd_count-2]->proxy_partner = fds[fd_count-1];

        fds[fd_count-1]->host = accept_fd->host;
        fds[fd_count-1]->port = accept_fd->port;
    }
    printf("done add_tcp_proxy_client..\n");
}

int addSelectFd(int fd, fd_set *fds, int max_fd) {
    if (fd > max_fd) {
        max_fd = fd;
    }
    if (fd >= 0) {
        FD_SET(fd, fds);
    }

    return max_fd;
}

void usage() {
    printf("netnode v. %d.%d.%d\n", RELEASE_VERSION, MAJOR_VERSION, MINOR_VERSION);
    printf("    -p/-P:  tcp client/server.\n");
    printf("    -u/-U:  udp client/server; client does pings to notify server.\n");
    printf("    -k:     stdin/stdout.\n");
    printf("    -s:     filename.  works for /dev/ttyS0 etc., named pipes, regular files.\n");
    printf("    -X:     tcp proxy; local_server:remote_host:remote_port\n");
    #ifdef LINUX_RAW
    printf("    -w:     raw network device interface eth0 etc.  (requires sudo.)\n");
    #endif
    printf("\n");
    printf("    -i      next interface is input only\n");
    printf("    -o      next interface is output only\n");
    printf("\n");
    printf("    -d:     next interface is prefaced with time/direction\n");
    printf("    -b:     next interface prints data formatted as hex dump\n");
    printf("    -t:     next interface shows non-printable characters in hex\n");

    exit(0);
}

/*****************************************************************************
 * Main routine
 * Args:
 *    int argc:  number of input arguments
 *    char **argv:  vector of input arguments
 * Returns:
 *    0 if no errors, 1 otherwise
 *****************************************************************************/
int main(int argc, char **argv) {
    int fd, max_fd;
    int my_server_port = -1;
    socklen_t sock_addr_len;
    int unconnected_tcp_client;
    int c;
    int i, fd_ind, result;
    byte got_something;
    char *host;
    int port;
    int lcl_errno;

    start_time = time__usec();

    memset(fd_recs, 0, sizeof(fd_recs));

    for (i = 0; i < MAX_FD; i++) {
        fds[i] = &fd_recs[i];
    }

    /* process command-line arguments */
    while ((c = getopt(argc, argv, "abdDefFhikNop:P:s:tu:U:vw:X:")) != EOF) {

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

            case 'k': {
                int lcl_hex_msgs = hex_msgs;
                int lcl_text_msgs = text_msgs;
                int lcl_time_and_source = time_and_source;

                if (!no_input) {
                    add_fd(0, false, true, false, false, connect_keyboard);
                    fds[fd_count-1]->no_output = 1;
                }
                no_input = 0;

                if (!no_output) {
                    hex_msgs        = lcl_hex_msgs;
                    text_msgs       = lcl_text_msgs;
                    time_and_source = lcl_time_and_source;

                    add_fd(1, false, true, false, false, connect_keyboard);
                    fds[fd_count-1]->no_input = 1;
                }
                no_output = 0;

                break;
            }

            case 'b':
                hex_msgs = 1;
                break;

            case 't':
                text_msgs = 1;
                break;

            case 'd':
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

            case 's':
                add_fd(-1, false, true, false, false, connect_file);
                setup_file_interface(optarg, fds[fd_count - 1]);
                break;

            case 'N':
                timeout_bad_client = true;
                break;

            case 'u':
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

            case 'X': {
                char *arg = strdup(optarg);
                char *remoteHost;
                int proxyServerPort;
                int remoteHostServerPort;
                get_host_ports(&remoteHost, &remoteHostServerPort, &proxyServerPort, arg);
                int accept_socket = open_server_socket(proxyServerPort);

                fprintf(stderr, "open proxy server socket %d returned %d\n",
                        proxyServerPort, accept_socket);

                if (accept_socket == -1) {
                    exit(1);
                }

                add_fd(accept_socket, false, false, false, false, connect_tcp_proxy_server);
                fds[fd_count-1]->host = remoteHost;
                fds[fd_count-1]->port = remoteHostServerPort;

                break;
            }

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
                exit(1);
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

            if (fds[i]->fd == -1
                && (fds[i]->connect_type == connect_tcp_client
                    || fds[i]->connect_type == connect_tcp_proxy_client))
            {
                // we would like to try this now, because if we have unconnected
                // tcp clients we want to do a select with timeout instead of a
                // "forever" select.
                reset_tcp_connection(i, "pre-select");

                if (fds[i]->fd == -1) {
                    unconnected_tcp_client = 1;
                    continue;
                }
            }

            max_fd = addSelectFd(fds[i]->fd, &io_set, max_fd);
        }

        {
            struct timeval tv = {0,0};
            #ifdef NONBLOCKING_SELECT
                result = select(max_fd + 1, &io_set, NULL, NULL, &tv);
            #else
                if (unconnected_tcp_client) {
                    // in this case we don't want to block forever until
                    // there's some input; we repetitively try to re-connect
                    // to a tcp server.
                    tv.tv_usec = 100000;
                    result = select(max_fd + 1, &io_set, NULL, NULL, &tv);

                } else {
                    result = select(max_fd + 1, &io_set, NULL, NULL, NULL);
                }
            #endif
        }
        #ifdef DEBUG1
            selectPrint("past select", max_fd, &io_set);
            printf("fd_count:  %d\n", fd_count);
            for (int i = 0; i < fd_count; ++i) printf("<ctp %d, fd %d> ",
                    fds[i]->connect_type, fds[i]->fd);
            printf("\n");
        #endif

        if (result <= 0) {
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

            } else if (fds[fd_ind]->connect_type == connect_udp_server) {
                struct sockaddr_in inbound_msg_sockaddr;

                got_udp_msg = 1;

                sock_addr_len = sizeof(inbound_msg_sockaddr);
                length = recvfrom(read_fd, buffer, BUFSIZE-1, 0,
                        (struct sockaddr *) &inbound_msg_sockaddr,
                        &sock_addr_len);

                // may have multiple inbound clients; they would
                // all have this same server/udp-receiver fd.
                // only want to try to read it once.
                FD_CLR(read_fd, &io_set);

                if (timeout_bad_client)
                    packet_recvd(fds[fd_ind], length >= 0);

                do_output(fd_ind, buffer, length, got_udp_msg, 0);

                /* if this is an inbound udp client communicating to us, add them to
                 * our list of clients and include them in our broadcasts
                 * of future messages.
                 */
                if (fds[fd_ind]->connect_type == connect_udp_server && length >= 0) {
                    fd_t *found = findUdpInboundClient(&inbound_msg_sockaddr);

                    if (found == NULL) {
                        addUdpInboundClient(&inbound_msg_sockaddr, fds[fd_ind]);
                        goto end_loop;
                    }
                }

                // did an inbound client message give us a bad return value?
                // if so, garbage-collect the inbound client record.

                if (fds[fd_ind]->connect_type == connect_udp_server && length < 0) {
                    removeUdpInboundClient(&inbound_msg_sockaddr);
                    goto end_loop;
                }

                continue;
            }

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

            else if (fds[fd_ind]->connect_type == connect_tcp_server) {
                accept_tcp_client(fd_ind);
                goto end_loop;

            } else if (fds[fd_ind]->connect_type == connect_tcp_proxy_server) {
                add_tcp_proxy_client(fd_ind);
                goto end_loop;

            } else {
                got_udp_msg = 0;

                length = recv(read_fd, buffer, BUFSIZE-1, 0);
                lcl_errno = errno;

                if (length < 0) {
                    if (verbose > 0)
                        fprintf(stderr, "recv failed:  %s\n", strerror(errno));
                }

                if (timeout_bad_client) {
                    packet_recvd(fds[fd_ind], length >= 0);
                }

                do_output(fd_ind, buffer, length, got_udp_msg, lcl_errno);
            }
        } /* send stuff to other clients .. */

        end_loop:;

        /* sleep .01 second if we didn't receive anything from any interface */
        if (!got_something) {
            usleep(10000);
        }

    } /* while accepting incoming connections and messages from clients.. */
}
#endif // defined(MAIN)
