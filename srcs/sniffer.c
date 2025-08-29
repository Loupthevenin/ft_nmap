#include "../includes/ft_nmap.h"

static const char	*tcp_scan_result(struct tcphdr *tcp, int scan_index)
{
	switch (scan_index)
	{
	case INDEX_SYN:
		return (tcp->syn
			&& tcp->ack) ? SCAN_OPEN : (tcp->rst ? SCAN_CLOSED : NULL);
	case INDEX_FIN:
		return ((tcp->fin && !tcp->syn && !tcp->rst && !tcp->psh && !tcp->ack
				&& !tcp->urg) ? (tcp->rst ? SCAN_CLOSED : SCAN_OPEN_FILTERED) : NULL);
	case INDEX_NULL:
		return ((!tcp->fin && !tcp->syn && !tcp->rst && !tcp->psh && !tcp->ack
				&& !tcp->urg) ? (tcp->rst ? SCAN_CLOSED : SCAN_OPEN_FILTERED) : NULL);
	case INDEX_XMAS:
		return ((tcp->fin && tcp->psh
				&& tcp->urg) ? (tcp->rst ? SCAN_CLOSED : SCAN_OPEN_FILTERED) : NULL);
	case INDEX_ACK:
		return ((tcp->ack
				&& !tcp->syn) ? (tcp->rst ? SCAN_UNFILTERED : SCAN_FILTERED) : NULL);
	default:
		return (NULL);
	}
}

static void	handle_packet(t_config *config, const unsigned char *packet)
{
	struct ip		*ip;
	char			*src_ip;
	int				src_port;
	t_host			*host;
	struct tcphdr	*tcp;
	struct udphdr	*udp;
	const char		*res;

	ip = (struct ip *)packet;
	src_ip = inet_ntoa(ip->ip_src);
	for (int h = 0; h < config->hosts_count; h++)
	{
		host = &config->hosts[h];
		if (strcmp(src_ip, host->ip) != 0)
			continue ;
		if (ip->ip_p == IPPROTO_TCP)
		{
			tcp = (struct tcphdr *)(packet + ip->ip_hl * 4);
			src_port = ntohs(tcp->source);
			for (int i = 0; i < host->ports_count; i++)
			{
				if (host->ports_list[i] != src_port)
					continue ;
				for (int s = 0; s < INDEX_COUNT; s++)
				{
					res = tcp_scan_result(tcp, s);
					printf("res port: %s\n", res);
					pthread_mutex_lock(&config->result_mutex);
					if (res)
						host->result[i].scan_results[s] = (char *)res;
					pthread_mutex_unlock(&config->result_mutex);
				}
			}
		}
		else if (ip->ip_p == IPPROTO_UDP)
		{
			udp = (struct udphdr *)(packet + ip->ip_hl * 4);
			src_port = ntohs(udp->source);
			for (int i = 0; i < host->ports_count; i++)
			{
				if (host->ports_list[i] != src_port)
					continue ;
				pthread_mutex_lock(&config->result_mutex);
				host->result[i].scan_results[INDEX_UDP] = SCAN_OPEN_FILTERED;
				pthread_mutex_unlock(&config->result_mutex);
			}
		}
	}
}

static void	packet_handler(unsigned char *user, const struct pcap_pkthdr *h,
		const unsigned char *bytes)
{
	t_config			*config;
	const unsigned char	*packet;

	(void)h;
	config = (t_config *)user;
	// Decalage header ethernet;
	packet = bytes + 14;
	// Recup header IP;
	handle_packet(config, packet);
}

static int	build_filter(pcap_t *handle, struct bpf_program *fp)
{
	char	filter[1024];

	snprintf(filter, sizeof(filter), "ip and (tcp or udp or icmp)");
	if (pcap_compile(handle, fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
		pcap_setfilter(handle, fp) == -1)
	{
		fprintf(stderr, "error: pcap_compile/setfilter failed: %s\n",
				pcap_geterr(handle));
		return (-1);
	}
	return (0);
}

void	*thread_listener(void *arg)
{
	t_listener_arg		*larg;
	t_config			*config;
	pcap_t				*handle;
	char				errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program	fp;

	larg = (t_listener_arg *)arg;
	config = larg->config;
	// TODO: changer DEFAULT_IFACE par une fonction get_interface;
	handle = pcap_open_live(DEFAULT_IFACE, BUFSIZ, 1, 1000, errbuf);
	if (!handle)
	{
		fprintf(stderr, "error: pcap_open_live failed: %s\n", errbuf);
		return (NULL);
	}
	pthread_mutex_lock(&larg->handle_mutex);
	larg->handle = handle;
	pthread_mutex_unlock(&larg->handle_mutex);
	if (build_filter(handle, &fp) == -1)
	{
		fprintf(stderr, "error: build_filter failed\n");
		return (NULL);
	}
	if (pcap_loop(handle, -1, packet_handler, (unsigned char *)config) < 0)
		fprintf(stderr, "error: pcap_loop returned an error: %s\n",
				pcap_geterr(handle));
	pcap_freecode(&fp);
	return (NULL);
}
