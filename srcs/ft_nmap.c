#include "../includes/ft_nmap.h"

static void	init_scan_results(t_result *res, int scans)
{
	for (int i = 0; i < INDEX_COUNT; i++)
	{
		switch (i)
		{
		case INDEX_SYN:
			res->scan_results[i] = (scans & SCAN_SYN) ? SCAN_FILTERED : NULL;
			res->sport[i] = 0;
			break ;
		case INDEX_NULL:
			res->scan_results[i] = (scans & SCAN_NULL) ? SCAN_OPEN_FILTERED : NULL;
			res->sport[i] = 0;
			break ;
		case INDEX_ACK:
			res->scan_results[i] = (scans & SCAN_ACK) ? SCAN_FILTERED : NULL;
			res->sport[i] = 0;
			break ;
		case INDEX_FIN:
			res->scan_results[i] = (scans & SCAN_FIN) ? SCAN_OPEN_FILTERED : NULL;
			res->sport[i] = 0;
			break ;
		case INDEX_XMAS:
			res->scan_results[i] = (scans & SCAN_XMAS) ? SCAN_OPEN_FILTERED : NULL;
			res->sport[i] = 0;
			break ;
		case INDEX_UDP:
			res->scan_results[i] = (scans & SCAN_UDP) ? SCAN_OPEN_FILTERED : NULL;
			res->sport[i] = 0;
			break ;
		default:
			res->scan_results[i] = NULL;
			res->sport[i] = 0;
		}
		res->conclusion = NULL;
	}
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
		// Allouer et initialiser les résultats
		host->result = malloc(sizeof(t_result) * host->ports_count);
		if (!host->result)
			continue ;
		for (int i = 0; i < host->ports_count; i++)
		{
			host->ports_list[i] = config->ports_list[i];
			host->result[i].port = config->ports_list[i];
			host->result[i].service = NULL;
			init_scan_results(&host->result[i], config->scans);
		}
	}
}

static int	set_socket(void)
{
	int	sock;
	int	one;

	one = 1;
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
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

static int	set_socket_udp(void)
{
	int	sock;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror("socket");
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

static void	create_sender(int sock_tcp, int sock_udp, t_config *config)
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
			targ->sock_tcp = sock_tcp;
			targ->sock_udp = sock_udp;
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

static void	wait_for_timeout(t_config *config, t_listener_arg *larg,
		pthread_t *listener)
{
	pcap_t	*handle;
	long	now;
	long	last_packet_time;

	while (1)
	{
		pthread_mutex_lock(&config->packet_time_mutex);
		last_packet_time = config->last_packet_time;
		pthread_mutex_unlock(&config->packet_time_mutex);
		now = get_now_ms();
		if (now - last_packet_time >= TIMEOUT)
			break ;
		usleep(100000);
	}
	pthread_mutex_lock(&larg->handle_mutex);
	handle = larg->handle;
	if (handle)
		pcap_breakloop(handle);
	pthread_mutex_unlock(&larg->handle_mutex);
	pthread_join(*listener, NULL);
	pcap_close(handle);
}

static void	run_scan(t_config *config)
{
	int				sock_tcp;
	int				sock_udp;
	pthread_t		listener;
	t_listener_arg	*larg;

	sock_tcp = -1;
	sock_udp = -1;
	get_local_ip(config->local_ip, sizeof(config->local_ip));
	larg = create_listener(&listener, config);
	if (!larg)
		return ;
	usleep(100000);
	if (config->scans & (SCAN_SYN | SCAN_NULL | SCAN_ACK | SCAN_XMAS | SCAN_FIN))
		sock_tcp = set_socket();
	if (config->scans & SCAN_UDP)
		sock_udp = set_socket_udp();
	create_sender(sock_tcp, sock_udp, config);
	if (sock_tcp > 0)
		close(sock_tcp);
	if (sock_udp > 0)
		close(sock_udp);
	wait_for_timeout(config, larg, &listener);
	// TODO: fonction de cleanup
	pthread_mutex_destroy(&larg->handle_mutex);
	pthread_mutex_destroy(&config->result_mutex);
	pthread_mutex_destroy(&config->packet_time_mutex);
	pthread_mutex_destroy(&config->sport_mutex);
	free(larg);
}

int	main(int argc, char **argv)
{
	t_config		config;
	struct timespec	start_time;
	struct timespec	end_time;

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
	allocate_results_for_hosts(&config);
	print_header(&config);
	printf("\nStarting ft_nmap scan...\n");
	clock_gettime(CLOCK_MONOTONIC, &start_time);
	run_scan(&config);
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	print_results(&config);
	print_timer(&start_time, &end_time);
	free_config(&config);
	return (0);
}
