#ifndef NETNODE_H
#define NETNODE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void *server_fd_ptr_t;

extern int server_fd_size();
extern int server_fd(server_fd_ptr_t voidp_fd_desc);
extern int open_server_socket(int port);
extern int open_udp_server_socket(int port);

extern int open_client_socket(char *host, int port);
extern int open_udp_client_socket(char *host, int port);

extern int accept_server_socket(int sock);
extern int get_host_ports(char **host, int *port, int *src_port, char *arg);

extern void setup_raw_interface(char *dev_name, server_fd_ptr_t voidp_fd_desc);
extern int read_raw_interface(server_fd_ptr_t voidp_fd_desc,
    unsigned char *buf, int buf_len);
extern int write_raw_interface(server_fd_ptr_t voidp_fd_desc,
    unsigned char *buf, int buf_len);

extern void setup_udp_client_interface(char *dev_name,
    server_fd_ptr_t voidp_fd_desc);

extern int server_write(server_fd_ptr_t voidp_fd_desc, unsigned char *buffer,
    int buf_len);

#ifdef __cplusplus
}
#endif

#endif
