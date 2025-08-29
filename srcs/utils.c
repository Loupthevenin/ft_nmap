#include "../includes/ft_nmap.h"

unsigned short	cksum(unsigned short *buf, int n)
{
	register long	sum;
	unsigned short	oddbyte;
	register short	answer;

	sum = 0;
	while (n > 1)
	{
		sum += *buf++;
		n -= 2;
	}
	if (n == 1)
	{
		oddbyte = 0;
		*((unsigned char *)&oddbyte) = *(unsigned char *)buf;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = (short)~sum;
	return (answer);
}

int	get_local_ip(char *buffer, size_t buflen)
{
	int					sock;
	struct sockaddr_in	serv;
	struct sockaddr_in	name;
	socklen_t			namelen;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return (-1);
	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr("8.8.8.8");
	// n’importe quelle IP externe
	serv.sin_port = htons(53);
	if (connect(sock, (struct sockaddr *)&serv, sizeof(serv)) < 0)
	{
		close(sock);
		return (-1);
	}
	namelen = sizeof(name);
	if (getsockname(sock, (struct sockaddr *)&name, &namelen) < 0)
	{
		close(sock);
		return (-1);
	}
	inet_ntop(AF_INET, &name.sin_addr, buffer, buflen);
	close(sock);
	return (0);
}

void	print_help(void)
{
	printf("Help Screen\n");
	printf("ft_nmap [OPTIONS]\n");
	printf("--help Print this help screen\n");
	printf("--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
	printf("--ip ip addresses to scan in dot format\n");
	printf("--file File name containing IP addresses to scan,\n");
	printf("--speedup [250 max] number of parallel threads to use\n");
	printf("--scan SYN/NULL/FIN/XMAS/ACK/UDP\n");
}

void	print_config(const t_config *config)
{
	int		first;
	t_host	*host;

	printf("Configuration:\n");
	printf("  IP Address: %s\n", config->ip ? config->ip : "None");
	if (config->hosts_count > 0)
	{
		printf("  Hosts (%d):\n", config->hosts_count);
		for (int h = 0; h < config->hosts_count; h++)
		{
			host = &config->hosts[h];
			printf("    Hostname: %s, IP: %s\n",
					host->hostname ? host->hostname : "N/A",
					host->ip ? host->ip : "N/A");
			printf("      Ports (%d): ", host->ports_count);
			for (int p = 0; p < host->ports_count; p++)
			{
				printf("%d", host->ports_list[p]);
				if (p < host->ports_count - 1)
					printf(", ");
			}
			printf("\n");
		}
	}
	else if (config->ips_count > 0 && config->ips_list)
	{
		printf("  Legacy IPs (%d): ", config->ips_count);
		for (int i = 0; i < config->ips_count; i++)
		{
			printf("%s", config->ips_list[i]);
			if (i < config->ips_count - 1)
				printf(", ");
		}
		printf("\n");
	}
	printf("  Ports (global): %s\n", config->ports ? config->ports : "None");
	if (config->ports_count > 0 && config->ports_list)
	{
		printf("  Ports list: ");
		for (int i = 0; i < config->ports_count; i++)
		{
			printf("%d", config->ports_list[i]);
			if (i < config->ports_count - 1)
				printf(", ");
		}
		printf("\n");
	}
	printf("  Speedup (threads): %d\n", config->speedup);
	printf("  Scan Types: ");
	if (config->scans == SCAN_ALL)
		printf("All\n");
	else
	{
		first = 1;
		if (config->scans & SCAN_SYN)
		{
			if (!first)
				printf(", ");
			printf("SYN");
			first = 0;
		}
		if (config->scans & SCAN_NULL)
		{
			if (!first)
				printf(", ");
			printf("NULL");
			first = 0;
		}
		if (config->scans & SCAN_ACK)
		{
			if (!first)
				printf(", ");
			printf("ACK");
			first = 0;
		}
		if (config->scans & SCAN_FIN)
		{
			if (!first)
				printf(", ");
			printf("FIN");
			first = 0;
		}
		if (config->scans & SCAN_XMAS)
		{
			if (!first)
				printf(", ");
			printf("XMAS");
			first = 0;
		}
		if (config->scans & SCAN_UDP)
		{
			if (!first)
				printf(", ");
			printf("UDP");
			first = 0;
		}
		printf("\n");
	}
	if (config->file)
		printf("  IP File: %s\n", config->file);
	if (config->show_help)
		printf("  Show help: Yes\n");
	else
		printf("  Show help: No\n");
}

void	print_results(t_config *config)
{
	t_host		*host;
	t_result	*res;
	int			is_open;

	for (int h = 0; h < config->hosts_count; h++)
	{
		host = &config->hosts[h];
		printf("Results for host %s (%s):\n", host->hostname, host->ip);
		printf("Open ports:\n");
		printf("Port  Service Name           Results       Conclusion\n");
		printf("------------------------------------------------------\n");
		for (int i = 0; i < host->ports_count; i++)
		{
			res = &host->result[i];
			// Vérifie si une des scans indique ouvert
			is_open = 0;
			for (int j = 0; j < INDEX_COUNT; j++)
			{
				if (res->scan_results[j] && strstr(res->scan_results[j],
						"Open"))
				{
					is_open = 1;
					break ;
				}
			}
			if (is_open)
			{
				printf("%-5d %-20s ", res->port,
						res->service ? res->service : "Unassigned");
				for (int j = 0; j < INDEX_COUNT; j++)
				{
					if (res->scan_results[j])
						printf("%s ", res->scan_results[j]);
				}
				printf("%s\n", res->conclusion ? res->conclusion : "");
			}
		}
		printf("\nClosed/Filtered/Unfiltered ports:\n");
		printf("Port  Service Name           Results       Conclusion\n");
		printf("------------------------------------------------------\n");
		for (int i = 0; i < host->ports_count; i++)
		{
			res = &host->result[i];
			is_open = 0;
			for (int j = 0; j < INDEX_COUNT; j++)
			{
				if (res->scan_results[j] && strstr(res->scan_results[j],
						"Open"))
				{
					is_open = 1;
					break ;
				}
			}
			if (!is_open)
			{
				printf("%-5d %-20s ", res->port,
						res->service ? res->service : "Unassigned");
				for (int j = 0; j < INDEX_COUNT; j++)
				{
					if (res->scan_results[j])
						printf("%s ", res->scan_results[j]);
				}
				printf("%s\n", res->conclusion ? res->conclusion : "");
			}
		}
		printf("\n");
	}
}

// Free
void	free_config(t_config *config)
{
	if (config->ports)
		free(config->ports);
	if (config->ports_list)
		free(config->ports_list);
	if (config->ip)
		free(config->ip);
	if (config->file)
		free(config->file);
	if (config->scan_type)
		free(config->scan_type);
}

void	free_results(t_result *results, int count)
{
	if (!results)
		return ;
	for (int i = 0; i < count; i++)
	{
		free(results[i].service);
		free(results[i].conclusion);
		for (int j = 0; j < 6; j++)
			free(results[i].scan_results[j]);
	}
	free(results);
}
