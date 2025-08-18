#include "../includes/ft_nmap.h"

void	print_help(void)
{
	printf("ft_nmap [OPTIONS]\n");
	printf("--help\t\tPrint this help screen\n");
	printf("--ports\t\tPorts to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
	printf("--ip\t\tIP address to scan in dot format\n");
	printf("--file\t\tFile name containing IP addresses to scan\n");
	printf("--speedup\t[250 max] Number of parallel threads to use\n");
	printf("--scan\t\tSYN/NULL/FIN/XMAS/ACK/UDP\n");
}
