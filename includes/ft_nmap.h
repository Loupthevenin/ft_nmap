#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <arpa/inet.h>
# include <ctype.h>
# include <errno.h>
# include <fcntl.h>
# include <limits.h>
# include <netdb.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
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
// # include <pcap.h>

typedef enum e_scan_type
{
	SCAN_SYN = 1 << 0,      // 000001
	SCAN_NULL = 1 << 1,     // 000010
	SCAN_ACK = 1 << 2,      // 000100
	SCAN_FIN = 1 << 3,      // 001000
	SCAN_XMAS = 1 << 4,     // 010000
	SCAN_UDP = 1 << 5,      // 100000
	SCAN_ALL = (1 << 6) - 1 // 111111
}				t_scan_type;

typedef enum e_scan_index
{
	INDEX_SYN = 0,
	INDEX_NULL,
	INDEX_ACK,
	INDEX_FIN,
	INDEX_XMAS,
	INDEX_UDP,
	INDEX_COUNT
}				t_scan_index;

typedef struct s_result
{
	int			port;
	char		*service;
	char		*scan_results[INDEX_COUNT];
	char		*conclusion;
}				t_result;

typedef struct s_host
{
	char *hostname;  // nom donné (ex: "scanme.nmap.org")
	char *ip;        // IP résolue
	int *ports_list; // liste de ports pour ce host
	int			ports_count;
	t_result *result; //  résultat liés aux ports
}				t_host;

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
	char *ports;     // string representation of ports
	int *ports_list; // ports globaux
	int ports_count; // nombre de ports
	int speedup;     // threads max
	int scans;       // bitmask des scans
	char *scan_type; // string user input des scans
	char *iface;     // interface réseau
	int show_help;   // flag pour afficher l'aide
}				t_config;

typedef struct s_thread_arg
{
	t_config	*config;
	t_host		*host;
	int			port;
	t_result	*result;
}				t_thread_arg;

// Main
int				parse_args(t_config *config, int argc, char **argv);
int				resolve_hostname(const char *hostname, char **ip);
char			**parse_ips_from_file(const char *filename, int *count);
void			scan_port(t_config *config, t_host *host, int port,
					t_result *result);

// Pcap
pcap_t			*pcap_open_handle(const char *iface, const char *ip_filter);
int				pcap_wait_response(pcap_t *handle, int dport, int proto,
					char *out_state, size_t out_len);
int				send_tcp(const char *dst_ip, int dport, int flags);
int				send_udp(const char *dst_ip, int dport);

// Utils
void			print_help(void);
void			print_config(const t_config *config);
void			free_config(t_config *config);

#endif
