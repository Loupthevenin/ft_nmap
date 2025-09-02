#include "../includes/ft_nmap.h"

// TODO: revoir toutes les verifs pour les scans;
static const char	*scan_result(struct tcphdr *tcp, int scan_index)
{
	if (!tcp && scan_index != INDEX_UDP)
		return (NULL);
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
		return (tcp->rst ? SCAN_UNFILTERED : SCAN_FILTERED);
	// TODO: revoir la logique pour udp sur open
	case INDEX_UDP:
		return (!tcp ? SCAN_OPEN : NULL);
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

static void	check_packet(t_config *config, t_host *host, int src_port,
		int dst_port, struct tcphdr *tcp)
{
	const char	*res;

	if (dst_port == 54321)
	{
		printf("[DEBUG] Packet arrived at my source port!\n");
		fflush(stdout);
		for (int i = 0; i < host->ports_count; i++)
		{
			if (host->ports_list[i] == src_port)
			{
				printf("[DEBUG] Matching host port: %d\n", src_port);
				fflush(stdout);
				for (int s = 0; s < INDEX_COUNT; s++)
				{
					// Ne traiter que les scans set
					if (!(config->scans & (1 << s)))
						continue ;
					res = scan_result(tcp, s);
					if (res)
					{
						printf("[DEBUG] Scan index %d result: %s\n", s, res);
						fflush(stdout);
						pthread_mutex_lock(&config->result_mutex);
						host->result[i].scan_results[s] = (char *)res;
						pthread_mutex_unlock(&config->result_mutex);
					}
				}
			}
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

	if (iph->protocol == IPPROTO_TCP)
	{
		tcp = (struct tcphdr *)(packet + iph->ihl * 4);
		src_port = ntohs(tcp->source);
		dst_port = ntohs(tcp->dest);
		printf("[DEBUG] TCP packet: src_port=%d dst_port=%d\n", src_port,
				dst_port);
		fflush(stdout);
		check_packet(config, host, src_port, dst_port, tcp);
		update_last_packet_time(config);
	}
	else if (iph->protocol == IPPROTO_UDP)
	{
		udp = (struct udphdr *)(packet + iph->ihl * 4);
		src_port = ntohs(udp->source);
		dst_port = ntohs(udp->dest);
		check_packet(config, host, src_port, dst_port, NULL);
		update_last_packet_time(config);
	}
	else if (iph->protocol == IPPROTO_ICMP)
	{
		// TODO: implement icmp;
		icmp = (struct icmphdr *)(packet + iph->ihl * 4);
		printf("[DEBUG] ICMP packet: type=%d code=%d\n", icmp->type,
				icmp->code);
		fflush(stdout);
		if (icmp->type == 3)
		{
		}
		update_last_packet_time(config);
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
	handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
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
	if (pcap_loop(handle, -1, packet_handler, (unsigned char *)config) == -1)
		fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
	pcap_freecode(&fp);
	return (NULL);
}
