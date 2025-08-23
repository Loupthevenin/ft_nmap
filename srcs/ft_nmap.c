#include "../includes/ft_nmap.h"

static void	*thread_scan(void *arg)
{
	t_thread_arg	*targ;

	targ = (t_thread_arg *)arg;
	scan_port(targ->config, targ->host, targ->port, targ->result);
	free(targ);
	return (NULL);
}

static void	init_result(t_result *result, int port)
{
	result->port = port;
	result->service = NULL;
	result->conclusion = NULL;
	for (int i = 0; i < 6; i++)
		result->scan_results[i] = NULL;
}

static void	run_scan(t_config *config)
{
	int				i;
	pthread_t		*threads;
	int				active_threads;
	t_thread_arg	*targ;
	t_result		*results;

	i = 0;
	active_threads = 0;
	threads = malloc(sizeof(pthread_t) * config->speedup);
	if (!threads)
		return ;
	results = malloc(sizeof(t_result) * config->ports_count);
	if (!results)
		return ;
	for (int k = 0; k < config->ports_count; k++)
		init_result(&results[k], config->ports_list[k]);
	// TODO: prendre en compte si plage d'ip ?
	while (i < config->ports_count)
	{
		targ = malloc(sizeof(t_thread_arg));
		targ->config = config;
		targ->port = config->ports_list[i];
		targ->result = &results[i];
		pthread_create(&threads[active_threads], NULL, thread_scan, targ);
		active_threads++;
		if (active_threads == config->speedup)
		{
			for (int j = 0; j < active_threads; j++)
				pthread_join(threads[j], NULL);
			active_threads = 0;
		}
		i++;
	}
	for (int j = 0; j < active_threads; j++)
		pthread_join(threads[j], NULL);
	free(threads);
}

int	main(int argc, char **argv)
{
	t_config	config;

	if (parse_args(&config, argc, argv) == -1)
	{
		free_config(&config);
		return (1);
	}
	if (config.show_help)
	{
		print_help();
		free_config(&config);
		return (0);
	}
	config.pcap_handle = pcap_open_handle(config.iface, config.ip);
	if (!config.pcap_handle)
	{
		fprintf(stderr, "[-] Failed to open pcap handle on %s\n", config.iface);
		free_config(&config);
		return (1);
	}
	print_config(&config);
	printf("\nStarting ft_nmap scan...\n");
	run_scan(&config);
	if (config.pcap_handle)
		pcap_close(config.pcap_handle);
	free_config(&config);
	return (0);
}
