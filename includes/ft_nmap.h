#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <arpa/inet.h>
# include <ctype.h>
# include <errno.h>
# include <fcntl.h>
# include <ifaddrs.h>
# include <limits.h>
# include <netdb.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <pcap.h>
# include <pcap/pcap.h>
# include <pthread.h>
# include <signal.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <sys/select.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <sys/types.h>
# include <sys/wait.h>
# include <unistd.h>

# define SCAN_OPEN "open"
# define SCAN_CLOSED "closed"
# define SCAN_FILTERED "filtered"
# define SCAN_UNFILTERED "unfiltered"
# define SCAN_OPEN_FILTERED "open|filtered"

# define TIMEOUT 500

typedef enum e_scan_type
{
	SCAN_SYN = 1 << 0,      // 000001
	SCAN_NULL = 1 << 1,     // 000010
	SCAN_ACK = 1 << 2,      // 000100
	SCAN_FIN = 1 << 3,      // 001000
	SCAN_XMAS = 1 << 4,     // 010000
	SCAN_UDP = 1 << 5,      // 100000
	SCAN_ALL = (1 << 6) - 1 // 111111
}					t_scan_type;

typedef enum e_scan_index
{
	INDEX_SYN = 0,
	INDEX_NULL,
	INDEX_ACK,
	INDEX_FIN,
	INDEX_XMAS,
	INDEX_UDP,
	INDEX_COUNT
}					t_scan_index;

typedef struct s_result
{
	int				port;
	char			*service;
	char			*scan_results[INDEX_COUNT];
	char			*conclusion;
}					t_result;

typedef struct s_host
{
	char *hostname;  // nom donné (ex: "scanme.nmap.org")
	char *ip;        // IP résolue
	int *ports_list; // liste de ports pour ce host
	int				ports_count;
	t_result *result; //  résultat liés aux ports
}					t_host;

typedef struct s_config
{
	// Legacy fields (for backward compatibility)
	char *ip;        // adresse IP unique
	char **ips_list; // liste d'adresses IP (legacy)
	int ips_count;   // nombre d'adresses IP (legacy)
	char *file;      // fichier contenant des IPs

	// New host-based fields
	t_host *hosts;   // tableau de hosts à scanner
	int hosts_count; // nombre de hosts

	// Common fields
	char *ports;                    // string representation of ports
	int *ports_list;                // ports globaux
	int ports_count;                // nombre de ports
	int speedup;                    // threads max
	int scans;                      // bitmask des scans
	char *scan_type;                // string user input des scans
	int show_help;                  // flag pour afficher l'aide
	char local_ip[INET_ADDRSTRLEN]; // ip local
	long			last_packet_time;
	pthread_mutex_t result_mutex; // mutex for result
	pthread_mutex_t	packet_time_mutex;
	int				datalink_offset;
}					t_config;

typedef struct s_thread_arg
{
	t_config		*config;
	t_host			*host;
	int				sock;
	int				port_start;
	int				port_end;
}					t_thread_arg;

typedef struct s_listener_arg
{
	t_config		*config;
	pcap_t			*handle;
	pthread_mutex_t	handle_mutex;
}					t_listener_arg;

typedef struct s_pseudo_tcp
{
	unsigned int	src_addr;
	unsigned int	dst_addr;
	unsigned char	zero;
	unsigned char	protocol;
	unsigned short	tcp_length;
}					t_pseudo_tcp;

// Main
int					parse_args(t_config *config, int argc, char **argv);
int					resolve_hostname(const char *hostname, char **ip);
char				**parse_ips_from_file(const char *filename, int *count);
void				*thread_listener(void *arg);
void				*thread_send(void *arg);

// Packets
int					create_tcp_packet(char *buff, const char *src_ip,
						const char *dst_ip, int sport, int dport,
						int scan_type);
int					create_udp_packet(char *buff, const char *src_ip,
						const char *dst_ip, int sport, int dport);

// Utils
size_t				ft_strlcat(char *dst, const char *src, size_t dstsize);
int					get_local_ip(char *buffer, size_t buflen);
int					get_datalink_offset(pcap_t *handle);
unsigned short		cksum(unsigned short *buf, int n);
long				get_now_ms(void);
void				print_help(void);
void				print_config(const t_config *config);
void				print_results(t_config *config);
void				free_config(t_config *config);

#endif
