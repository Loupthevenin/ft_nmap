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

static void	allocate_results_for_hosts(t_config *config)
{
	t_host	*host;

	for (int h = 0; h < config->hosts_count; h++)
	{
		host = &config->hosts[h];
		// Copier les ports globaux dans le host
		host->ports_count = config->ports_count;
		host->iface = NULL;
		host->ports_list = malloc(sizeof(int) * host->ports_count);
		if (!host->ports_list)
			continue ;
		for (int i = 0; i < host->ports_count; i++)
			host->ports_list[i] = config->ports_list[i];
		// Allouer et initialiser les résultats
		host->result = malloc(sizeof(t_result) * host->ports_count);
		if (!host->result)
			continue ;
		for (int k = 0; k < host->ports_count; k++)
			init_result(&host->result[k], host->ports_list[k]);
	}
}

static void	run_scan(t_config *config)
{
	int				i;
	pthread_t		*threads;
	int				active_threads;
	t_thread_arg	*targ;
	t_host			*host;

	active_threads = 0;
	threads = malloc(sizeof(pthread_t) * config->speedup);
	if (!threads)
		return ;
	for (int h = 0; h < config->hosts_count; h++)
	{
		host = &config->hosts[h];
		i = 0;
		while (i < host->ports_count)
		{
			targ = malloc(sizeof(t_thread_arg));
			targ->config = config;
			targ->host = host;
			targ->port = host->ports_list[i];
			targ->result = &host->result[i];
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
	print_config(&config);
	allocate_results_for_hosts(&config);
	printf("\nStarting ft_nmap scan...\n");
	run_scan(&config);
	print_results(&config);
	free_config(&config);
	return (0);
}
