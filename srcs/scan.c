#include "../includes/ft_nmap.h"

static void	syn_scan(t_config *config, int port)
{
	(void)config;
	(void)port;
}

static void	fin_scan(t_config *config, int port)
{
	(void)config;
	(void)port;
}

static void	xmas_scan(t_config *config, int port)
{
	(void)config;
	(void)port;
}

static void	null_scan(t_config *config, int port)
{
	(void)config;
	(void)port;
}

static void	ack_scan(t_config *config, int port)
{
	(void)config;
	(void)port;
}

static void	udp_scan(t_config *config, int port)
{
	(void)config;
	(void)port;
}

void	scan_port(t_config *config, int port)
{
	int	scan_type;

	scan_type = config->scans;
	if (scan_type & SCAN_SYN)
		syn_scan(config, port);
	if (scan_type & SCAN_FIN)
		fin_scan(config, port);
	if (scan_type & SCAN_XMAS)
		xmas_scan(config, port);
	if (scan_type & SCAN_NULL)
		null_scan(config, port);
	if (scan_type & SCAN_ACK)
		ack_scan(config, port);
	if (scan_type & SCAN_UDP)
		udp_scan(config, port);
}
