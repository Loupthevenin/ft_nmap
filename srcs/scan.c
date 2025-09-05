#include "../includes/ft_nmap.h"

static int	generate_unique_sport(t_config *config)
{
	int	sport;
	int	unique;

	unique = 0;
	while (!unique)
	{
		sport = 40000 + (rand() % 20000);
		unique = 1;
		for (int h = 0; h < config->hosts_count; h++)
		{
			for (int p = 0; p < config->hosts[h].ports_count; p++)
			{
				for (int s = 0; s < INDEX_COUNT; s++)
				{
					if (config->hosts[h].result[p].sport[s] == sport)
					{
						unique = 0;
						break ;
					}
				}
			}
			if (!unique)
				break ;
		}
		if (!unique)
			break ;
	}
	return (sport);
}

static int	send_packet(int sock, t_config *config, t_host *host, int dport,
		int proto, int flags, int sport)
{
	char				packet[4096];
	const char			*payload;
	struct sockaddr_in	dest;
	ssize_t				packet_size;

	// Préparer la destination
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = inet_addr(host->ip);
	// Construire le paquet selon le protocole
	if (proto == IPPROTO_TCP)
		packet_size = create_tcp_packet(packet, config->local_ip, host->ip,
				sport, dport, flags);
	else if (proto == IPPROTO_UDP)
	{
		payload = "FT_NMAP";
		packet_size = strlen(payload);
		memcpy(packet, payload, packet_size);
		dest.sin_port = htons(dport);
	}
	else
	{
		fprintf(stderr, "Unsupported proto\n");
		return (-1);
	}
	// Envoyer le paquet
	if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest,
			sizeof(dest)) < 0)
	{
		perror("sendto");
		return (-1);
	}
	return (0);
}

static void	send_scans(t_config *config, t_host *host, int port, int port_index,
		t_thread_arg *targ)
{
	int	scan_type;
	int	sport;

	scan_type = config->scans;
	sport = -1;
	if (scan_type & SCAN_SYN)
	{
		pthread_mutex_lock(&config->sport_mutex);
		sport = generate_unique_sport(config);
		host->result[port_index].sport[INDEX_SYN] = sport;
		pthread_mutex_unlock(&config->sport_mutex);
		send_packet(targ->sock_tcp, config, host, port, IPPROTO_TCP, TH_SYN,
				sport);
		usleep(2000);
	}
	if (scan_type & SCAN_FIN)
	{
		pthread_mutex_lock(&config->sport_mutex);
		sport = generate_unique_sport(config);
		host->result[port_index].sport[INDEX_FIN] = sport;
		pthread_mutex_unlock(&config->sport_mutex);
		send_packet(targ->sock_tcp, config, host, port, IPPROTO_TCP, TH_FIN,
				sport);
		usleep(2000);
	}
	if (scan_type & SCAN_XMAS)
	{
		pthread_mutex_lock(&config->sport_mutex);
		sport = generate_unique_sport(config);
		host->result[port_index].sport[INDEX_XMAS] = sport;
		pthread_mutex_unlock(&config->sport_mutex);
		send_packet(targ->sock_tcp, config, host, port, IPPROTO_TCP,
				TH_FIN | TH_PUSH | TH_URG, sport);
		usleep(2000);
	}
	if (scan_type & SCAN_NULL)
	{
		pthread_mutex_lock(&config->sport_mutex);
		sport = generate_unique_sport(config);
		host->result[port_index].sport[INDEX_NULL] = sport;
		pthread_mutex_unlock(&config->sport_mutex);
		send_packet(targ->sock_tcp, config, host, port, IPPROTO_TCP, 0, sport);
		usleep(2000);
	}
	if (scan_type & SCAN_ACK)
	{
		pthread_mutex_lock(&config->sport_mutex);
		sport = generate_unique_sport(config);
		host->result[port_index].sport[INDEX_ACK] = sport;
		pthread_mutex_unlock(&config->sport_mutex);
		send_packet(targ->sock_tcp, config, host, port, IPPROTO_TCP, TH_ACK,
				sport);
		usleep(2000);
	}
	if (scan_type & SCAN_UDP)
	{
		send_packet(targ->sock_udp, config, host, port, IPPROTO_UDP, 0, -1);
		usleep(2000 * 2);
	}
}

void	*thread_send(void *arg)
{
	t_thread_arg	*targ;
	t_host			*host;
	int				port;

	targ = (t_thread_arg *)arg;
	host = targ->host;
	for (int i = targ->port_start; i < targ->port_end; i++)
	{
		port = host->ports_list[i];
		send_scans(targ->config, targ->host, port, i, targ);
	}
	free(targ);
	return (NULL);
}
