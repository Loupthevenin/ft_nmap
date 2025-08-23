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
	printf("Configuration:\n");
	printf("  IP Address: %s\n", config->ip ? config->ip : "None");
	printf("  Ports: %s\n", config->ports);
	printf("  Speedup: %d\n", config->speedup);
	printf("  Scan Type: %s\n", config->scan_type ? config->scan_type : "None");
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
