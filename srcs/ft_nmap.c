#include "../includes/ft_nmap.h"

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

static int	set_socket(void)
{
	int	sock;
	int	one;

	// On forge TOUT l’IP header → donc IPPROTO_RAW
	one = 1;
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0)
	{
		perror("socket");
		return (-1);
	}
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
	{
		perror("setsockopt IP_HDRINCL");
		close(sock);
		return (-1);
	}
	return (sock);
}

static t_listener_arg	*create_listener(pthread_t *listener, t_config *config)
{
	t_listener_arg	*larg;

	larg = malloc(sizeof(t_listener_arg));
	if (!larg)
		return (NULL);
	larg->config = config;
	larg->handle = NULL;
	pthread_mutex_init(&larg->handle_mutex, NULL);
	pthread_create(listener, NULL, &thread_listener, larg);
	return (larg);
}

static void	create_sender(int sock, t_config *config)
{
	pthread_t		*threads;
	t_thread_arg	*targ;
	t_host			*host;
	int				start;
	int				end;
	int				ports_per_thread;
	int				active_threads;

	threads = malloc(sizeof(pthread_t) * config->speedup);
	if (!threads)
		return ;
	for (int h = 0; h < config->hosts_count; h++)
	{
		host = &config->hosts[h];
		ports_per_thread = (config->ports_count + config->speedup - 1)
			/ config->speedup;
		active_threads = 0;
		for (int t = 0; t < config->speedup; t++)
		{
			start = t * ports_per_thread;
			end = (t + 1) * ports_per_thread;
			if (start >= config->ports_count)
				break ;
			if (end > config->ports_count)
				end = config->ports_count;
			targ = malloc(sizeof(t_thread_arg));
			targ->config = config;
			targ->host = host;
			targ->sock = sock;
			targ->port_start = start;
			targ->port_end = end;
			pthread_create(&threads[active_threads], NULL, thread_send, targ);
			active_threads++;
		}
		for (int j = 0; j < active_threads; j++)
			pthread_join(threads[j], NULL);
	}
	free(threads);
}

static void	run_scan(t_config *config)
{
	int				sock;
	pthread_t		listener;
	t_listener_arg	*larg;
	pcap_t			*handle;

	get_local_ip(config->local_ip, sizeof(config->local_ip));
	larg = create_listener(&listener, config);
	if (!larg)
		return ;
	sock = set_socket();
	create_sender(sock, config);
	close(sock);
	// TODO: penser autrement pour attendre le handle ?
	handle = NULL;
	while (!handle)
	{
		pthread_mutex_lock(&larg->handle_mutex);
		handle = larg->handle;
		pthread_mutex_unlock(&larg->handle_mutex);
		usleep(1000);
	}
	pcap_breakloop(handle);
	pthread_join(listener, NULL);
	pthread_mutex_destroy(&larg->handle_mutex);
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
