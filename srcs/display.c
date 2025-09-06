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

static const char	*scan_to_string(int scan_type)
{
	if (scan_type & SCAN_SYN)
		return ("SYN");
	if (scan_type & SCAN_NULL)
		return ("NULL");
	if (scan_type & SCAN_ACK)
		return ("ACK");
	if (scan_type & SCAN_FIN)
		return ("FIN");
	if (scan_type & SCAN_XMAS)
		return ("XMAS");
	if (scan_type & SCAN_UDP)
		return ("UDP");
	return (NULL);
}

void	print_header(t_config *config)
{
	int			first;
	t_scan_type	scan;

	printf("=============================================\n");
	printf("              Scan Configurations            \n");
	printf("=============================================\n");
	for (int h = 0; h < config->hosts_count; h++)
		printf("Target Ip-Address : %s\n", config->hosts[h].ip);
	printf("No of Ports to scan : %d\n", config->ports_count);
	printf("Scans to be performed : ");
	first = 1;
	for (int i = 0; i < 6; i++)
	{
		scan = (1 << i);
		if (config->scans & scan)
		{
			if (!first)
				printf(" ");
			printf("%s", scan_to_string(scan));
			first = 0;
		}
	}
	printf("\n");
	printf("No of threads : %d\n", config->speedup);
	printf("=============================================\n");
}

static int	cmp_ports(const void *a, const void *b)
{
	const t_result	*ra;
	const t_result	*rb;

	ra = (const t_result *)a;
	rb = (const t_result *)b;
	return (ra->port - rb->port);
}

static const char	*get_conclusion(t_result *res)
{
	int	has_open;
	int	has_closed;
	int	has_filtered;
	int	has_unfiltered;

	has_open = 0;
	has_closed = 0;
	has_filtered = 0;
	has_unfiltered = 0;
	for (int j = 0; j < INDEX_COUNT; j++)
	{
		if (!res->scan_results[j])
			continue ;
		if (strcmp(res->scan_results[j], SCAN_OPEN) == 0)
			has_open = 1;
		if (strcmp(res->scan_results[j], SCAN_CLOSED) == 0)
			has_closed = 1;
		if (strcmp(res->scan_results[j], SCAN_FILTERED) == 0)
			has_filtered = 1;
		if (strcmp(res->scan_results[j], SCAN_UNFILTERED) == 0)
			has_unfiltered = 1;
	}
	if (has_open)
		return (SCAN_OPEN);
	if (has_closed && !has_filtered && !has_unfiltered)
		return (SCAN_CLOSED);
	if (has_filtered)
		return (SCAN_FILTERED);
	if (has_unfiltered)
		return (SCAN_UNFILTERED);
	return (SCAN_CLOSED);
}

static void	print_port_results(t_result *res)
{
	printf("%-7d %-25s ", res->port,
			res->service ? res->service : get_service_name(res->port, "tcp"));
	for (int j = 0; j < INDEX_COUNT; j++)
	{
		if (res->scan_results[j])
		{
			switch (j)
			{
			case INDEX_SYN:
				printf("SYN(%s) ", res->scan_results[j]);
				break ;
			case INDEX_NULL:
				printf("NULL(%s) ", res->scan_results[j]);
				break ;
			case INDEX_FIN:
				printf("FIN(%s) ", res->scan_results[j]);
				break ;
			case INDEX_XMAS:
				printf("XMAS(%s) ", res->scan_results[j]);
				break ;
			case INDEX_ACK:
				printf("ACK(%s) ", res->scan_results[j]);
				break ;
			case INDEX_UDP:
				printf("UDP(%s) ", res->scan_results[j]);
				break ;
			default:
				break ;
			}
		}
	}
	if (res->conclusion)
	{
		if (strcmp(res->conclusion, SCAN_OPEN) == 0)
			printf("%s%s%s", COLOR_GREEN, res->conclusion, COLOR_RESET);
		else if (strcmp(res->conclusion, SCAN_CLOSED) == 0)
			printf("%s%s%s", COLOR_RED, res->conclusion, COLOR_RESET);
		else if (strcmp(res->conclusion, SCAN_FILTERED) == 0)
			printf("%s%s%s", COLOR_YELLOW, res->conclusion, COLOR_RESET);
		else if (strcmp(res->conclusion, SCAN_UNFILTERED) == 0)
			printf("%s%s%s", COLOR_BLUE, res->conclusion, COLOR_RESET);
		else
			printf("%s", res->conclusion);
	}
	printf("\n");
}

void	print_results(t_config *config)
{
	t_host		*host;
	t_result	*res;

	for (int h = 0; h < config->hosts_count; h++)
	{
		host = &config->hosts[h];
		printf("=============================================\n");
		printf("Results for host %s (%s):\n", host->hostname, host->ip);
		// Trier les résultats par port
		qsort(host->result, host->ports_count, sizeof(t_result), cmp_ports);
		// Calculer la conclusion de tous les ports
		for (int i = 0; i < host->ports_count; i++)
		{
			res = &host->result[i];
			res->conclusion = (char *)get_conclusion(res);
		}
		// Afficher les ports Open
		printf("Open ports:\n");
		printf("Port    Service Name              Results                             Conclusion\n");
		printf("---------------------------------------------------------------------------------------------------\n");
		for (int i = 0; i < host->ports_count; i++)
		{
			res = &host->result[i];
			if (strcmp(res->conclusion, SCAN_OPEN) == 0)
				print_port_results(res);
		}
		// Afficher les autres ports
		printf("\nClosed/Filtered/Unfiltered ports:\n");
		printf("Port    Service Name              Results                             Conclusion\n");
		printf("---------------------------------------------------------------------------------------------------\n");
		for (int i = 0; i < host->ports_count; i++)
		{
			res = &host->result[i];
			if (strcmp(res->conclusion, SCAN_OPEN) != 0)
				print_port_results(res);
		}
		printf("\n");
	}
}

void	print_timer(struct timespec *start, struct timespec *end)
{
	double	elapsed;

	elapsed = (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->tv_nsec)
		/ 1e9;
	printf("\nft_nmap done: %.2f seconds\n", elapsed);
}
