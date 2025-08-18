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

typedef enum e_scan_type
{
	SCAN_SYN = 1 << 0,      // 000001
	SCAN_NULL = 1 << 1,     // 000010
	SCAN_ACK = 1 << 2,      // 000100
	SCAN_FIN = 1 << 3,      // 001000
	SCAN_XMAS = 1 << 4,     // 010000
	SCAN_UDP = 1 << 5,      // 100000
	SCAN_ALL = (1 << 6) - 1 // 111111
}		t_scan_type;

typedef struct s_config
{
	char *ip;    // adresse IP
	char *file;  // fichier contenant des IPs
	char *ports; // plage ou liste de ports
	int speedup; // nombre de threads max
	// int scans;     // bitmask
	char *scan_type; // type de scan
	int show_help;   // flag pour afficher l'aide
}		t_config;

// parser.c
int		validate_config(t_config *config);
int		is_valid_port(const char *port);
int		is_valid_argument(const char *arg);
int		is_valid_ip(const char *ip);
int		is_valid_scan_type(const char *type);
int		is_valid_speedup(int speedup);
int		file_exists(const char *filename);
int		validate_ports(const char *ports_str);
void	init_config(t_config *config);
void	free_config(t_config *config);
int		parse_args(t_config *config, int argc, char **argv);

// Utils
void	print_help(void);
void	print_config(const t_config *config);
void	free_args(char **args);

#endif
