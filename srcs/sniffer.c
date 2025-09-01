#include "../includes/ft_nmap.h"

static const char	*scan_result(struct tcphdr *tcp, int scan_index)
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
	// TODO: revoir la logique pour udp sur open
	case INDEX_UDP:
		return (SCAN_OPEN);
	default:
		return (NULL);
	}
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
	}
	else if (iph->protocol == IPPROTO_UDP)
	{
		udp = (struct udphdr *)(packet + iph->ihl * 4);
		src_port = ntohs(udp->source);
		dst_port = ntohs(udp->dest);
		check_packet(config, host, src_port, dst_port, NULL);
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
		bpf_u_int32 *netmask)
{
	char	filter[1024];

	snprintf(filter, sizeof(filter), "ip");
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
	bpf_u_int32			mask;
	const char			*iface;

	larg = (t_listener_arg *)arg;
	config = larg->config;
	// TODO: prendre en compte le localhost donc rendre l'interface dynamique en fonction des plages d'ips;
	iface = get_interface(config->hosts[0].ip);
	printf("interface : %s\n", iface);
	if (pcap_lookupnet(iface, &netmask, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Error lookupnet: %s\n", errbuf);
		return (NULL);
	}
	handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (!handle)
	{
		fprintf(stderr, "error: pcap_open_live failed: %s\n", errbuf);
		return (NULL);
	}
	pthread_mutex_lock(&larg->handle_mutex);
	larg->handle = handle;
	offset = get_datalink_offset(handle);
	pthread_mutex_unlock(&larg->handle_mutex);
	if (offset < 0)
		return (NULL);
	config->datalink_offset = offset;
	if (build_filter(handle, &fp, &netmask) == -1)
	{
		fprintf(stderr, "error: build_filter failed\n");
		return (NULL);
	}
	if (pcap_loop(handle, -1, packet_handler, (unsigned char *)config) == -1)
		fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
	pcap_freecode(&fp);
	return (NULL);
}
