#include "../includes/ft_nmap.h"

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
	int	first;

	printf("Configuration:\n");
	printf("  IP Address: %s\n", config->ip ? config->ip : "None");
	printf("  Ports: %s\n", config->ports);
	printf("  Speedup: %d\n", config->speedup);
	printf("  Scan Type: ");
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
