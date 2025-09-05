#include "../includes/ft_nmap.h"

static void	update_scan_result(t_config *config, t_host *host, int port,
		int index, const char *status)
{
	for (int i = 0; i < host->ports_count; i++)
	{
		if (host->ports_list[i] == port)
		{
			pthread_mutex_lock(&config->result_mutex);
			host->result[i].scan_results[index] = status;
			pthread_mutex_unlock(&config->result_mutex);
		}
	}
}

static const char	*scan_result(struct tcphdr *tcp, int scan_index)
{
	if (!tcp && scan_index != INDEX_UDP)
		return (NULL);
	switch (scan_index)
	{
	case INDEX_SYN:
		if (tcp->syn && tcp->ack)
			return (SCAN_OPEN);
		if (tcp->rst)
			return (SCAN_CLOSED);
		return (NULL);
	case INDEX_FIN:
		if (tcp->rst)
			return (SCAN_CLOSED);
		else if (tcp->fin && !tcp->syn && !tcp->ack && !tcp->psh && !tcp->urg)
			return (SCAN_OPEN_FILTERED);
		return (NULL);
	case INDEX_NULL:
		if (tcp->rst)
			return (SCAN_CLOSED);
		if (!tcp->fin && !tcp->syn && !tcp->rst && !tcp->psh && !tcp->ack
			&& !tcp->urg)
			return (SCAN_OPEN_FILTERED);
		return (NULL);
	case INDEX_XMAS:
		if (tcp->rst)
			return (SCAN_CLOSED);
		if (tcp->fin && tcp->psh && tcp->urg)
			return (SCAN_OPEN_FILTERED);
		return (NULL);
	case INDEX_ACK:
		if (tcp->rst)
			return (SCAN_UNFILTERED);
		return (SCAN_FILTERED);
	default:
		return (NULL);
	}
}

static int	is_scanned_host(t_config *config, const char *ip)
{
	for (int i = 0; i < config->hosts_count; i++)
	{
		if (strcmp(config->hosts[i].ip, ip) == 0)
			return (1);
	}
	return (0);
}

static void	update_last_packet_time(t_config *config)
{
	pthread_mutex_lock(&config->packet_time_mutex);
	config->last_packet_time = get_now_ms();
	pthread_mutex_unlock(&config->packet_time_mutex);
}

static int	match_sport(t_host *host, int dst_port, int *scan_index)
{
	for (int i = 0; i < host->ports_count; i++)
	{
		for (int s = 0; s < INDEX_COUNT; s++)
		{
			if (host->result[i].sport[s] == dst_port)
			{
				*scan_index = s;
				return (i); // retourne l'index correspondant
			}
		}
	}
	return (-1);
}

static void	check_packet(t_config *config, t_host *host, int dst_port,
		struct tcphdr *tcp)
{
	const char	*res;
	int			idx;
	int			scan_idx;

	pthread_mutex_lock(&config->sport_mutex);
	idx = match_sport(host, dst_port, &scan_idx);
	pthread_mutex_unlock(&config->sport_mutex);
	if (idx < 0)
		return ;
	printf("[DEBUG] Packet arrived at my source port! (port_idx=%d, "
			"scan_idx=%d)\n",
			idx,
			scan_idx);
	fflush(stdout);
	res = scan_result(tcp, scan_idx);
	if (res)
	{
		printf("[DEBUG] Scan index %d result: %s\n", scan_idx, res);
		fflush(stdout);
		pthread_mutex_lock(&config->result_mutex);
		host->result[idx].scan_results[scan_idx] = (char *)res;
		pthread_mutex_unlock(&config->result_mutex);
	}
}

static void	handle_icmp(t_config *config, t_host *host,
		const struct icmphdr *icmp)
{
	struct iphdr	*orig_iph;
	struct udphdr	*orig_udp;
	int				dst_port;

	printf("[DEBUG] ICMP packet: type=%d code=%d\n", icmp->type, icmp->code);
	fflush(stdout);
	if (icmp->type == 3)
	{
		orig_iph = (struct iphdr *)((unsigned char *)icmp
				+ sizeof(struct icmphdr));
		if (orig_iph->protocol == IPPROTO_UDP)
		{
			orig_udp = (struct udphdr *)((unsigned char *)orig_iph
					+ orig_iph->ihl * 4);
			dst_port = ntohs(orig_udp->dest);
			if (icmp->code == 3)
				update_scan_result(config, host, dst_port, INDEX_UDP,
						SCAN_CLOSED);
			else if (icmp->code == 1 || icmp->code == 2 ||
						icmp->code == 9 || icmp->code == 10 ||
						icmp->code == 13)
				update_scan_result(config, host, dst_port, INDEX_UDP,
						SCAN_FILTERED);
		}
	}
}

static void	check_protocols(t_config *config, t_host *host, struct iphdr *iph,
		const unsigned char *packet)
{
	struct tcphdr	*tcp;
	struct udphdr	*udp;
	struct icmphdr	*icmp;
	int				src_port;
	int				dst_port;

	switch (iph->protocol)
	{
	case IPPROTO_TCP:
		tcp = (struct tcphdr *)(packet + iph->ihl * 4);
		src_port = ntohs(tcp->source);
		dst_port = ntohs(tcp->dest);
		printf("[DEBUG] TCP packet: src_port=%d dst_port=%d\n", src_port,
				dst_port);
		fflush(stdout);
		check_packet(config, host, dst_port, tcp);
		update_last_packet_time(config);
		break ;
	case IPPROTO_UDP:
		udp = (struct udphdr *)(packet + iph->ihl * 4);
		src_port = ntohs(udp->source);
		dst_port = ntohs(udp->dest);
		update_scan_result(config, host, src_port, INDEX_UDP, SCAN_OPEN);
		update_last_packet_time(config);
		break ;
	case IPPROTO_ICMP:
		icmp = (struct icmphdr *)(packet + iph->ihl * 4);
		handle_icmp(config, host, icmp);
		update_last_packet_time(config);
		break ;
	default:
		break ;
	}
}

static void	handle_packet(t_config *config, const unsigned char *packet)
{
	struct iphdr	*iph;
	char			src_ip[INET_ADDRSTRLEN];
	char			dst_ip[INET_ADDRSTRLEN];
	t_host			*host;

	iph = (struct iphdr *)packet;
	inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &iph->daddr, dst_ip, sizeof(dst_ip));
	printf("[DEBUG] IP packet received: src=%s dst=%s proto=%d\n", src_ip,
			dst_ip, iph->protocol);
	fflush(stdout);
	// Ignore packets not coming from scanned hosts
	if (!is_scanned_host(config, src_ip))
		return ;
	for (int h = 0; h < config->hosts_count; h++)
	{
		host = &config->hosts[h];
		check_protocols(config, host, iph, packet);
	}
}

static void	packet_handler(unsigned char *user, const struct pcap_pkthdr *h,
		const unsigned char *bytes)
{
	t_config			*config;
	const unsigned char	*packet;
	long unsigned int	ip_len;

	(void)h;
	config = (t_config *)user;
	// Decalage header ethernet;
	packet = bytes + config->datalink_offset;
	ip_len = h->caplen - config->datalink_offset;
	printf("[DEBUG] Packet captured: caplen=%u datalink_offset=%d ip_len=%lu\n",
			h->caplen,
			config->datalink_offset,
			ip_len);
	fflush(stdout);
	if (sizeof(struct ip) > ip_len)
	{
		printf("error packet \n");
		return ;
	}
	// Recup header IP;
	handle_packet(config, packet);
}

static int	build_filter(pcap_t *handle, struct bpf_program *fp,
		bpf_u_int32 *netmask, t_config *config)
{
	char	filter[2048];
	char	hosts[1024];

	hosts[0] = '\0';
	for (int i = 0; i < config->hosts_count; i++)
	{
		if (i)
			ft_strlcat(hosts, " or ", sizeof(hosts));
		ft_strlcat(hosts, "src host ", sizeof(hosts));
		ft_strlcat(hosts, config->hosts[i].ip, sizeof(hosts));
	}
	snprintf(filter, sizeof(filter), "(%s) and (tcp or udp or icmp or icmp6)",
			hosts[0] ? hosts : "ip");
	printf("filter: %s\n", filter);
	if (pcap_compile(handle, fp, filter, 0, *netmask) == -1 ||
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
	int					offset;
	bpf_u_int32			netmask;

	larg = (t_listener_arg *)arg;
	config = larg->config;
	netmask = PCAP_NETMASK_UNKNOWN;
	handle = pcap_open_live("any", BUFSIZ, 1, 50, errbuf);
	if (!handle)
	{
		fprintf(stderr, "error: pcap_open_live failed: %s\n", errbuf);
		return (NULL);
	}
	pthread_mutex_lock(&larg->handle_mutex);
	larg->handle = handle;
	pthread_mutex_unlock(&larg->handle_mutex);
	offset = get_datalink_offset(handle);
	if (offset < 0)
		return (NULL);
	config->datalink_offset = offset;
	if (build_filter(handle, &fp, &netmask, config) == -1)
	{
		fprintf(stderr, "error: build_filter failed\n");
		return (NULL);
	}
	if (pcap_loop(handle, -1, packet_handler, (unsigned char *)config) ==
		-1)
		fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
	pcap_freecode(&fp);
	return (NULL);
}
