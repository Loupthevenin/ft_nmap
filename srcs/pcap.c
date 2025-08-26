#include "../includes/ft_nmap.h"

int	build_filter(pcap_t *handle, const char *ip, int is_udp,
		struct bpf_program *fp)
{
	char	filter[1024];

	if (!is_udp)
		// TCP
		snprintf(filter, sizeof(filter), "tcp and src host "
											"%s and dst port 54321",
					ip);
	else
		// UDP
		snprintf(filter, sizeof(filter), "(udp or icmp) and src host "
											"%s and (src port 54321 or icmp[0] == 3)",
					ip);
	if (pcap_compile(handle, fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
		pcap_setfilter(handle, fp) == -1)
		return (-1);
	return (0);
}

char	*wait_and_interpret(pcap_t *handle, int port, t_scan_params *params)
{
	char	state[32];

	if (pcap_wait_response(handle, port,
			params->is_udp ? IPPROTO_UDP : IPPROTO_TCP, state, sizeof(state)))
	{
		if (!params->is_udp && params->interpret)
			return (strdup(params->interpret(state)));
		else
			return (strdup(state));
	}
	else
		return (strdup(params->is_udp ? "Open|Filtered" : params->interpret("Filtered")));
}

int	pcap_wait_response(pcap_t *handle, int dport, int proto, char *out_state,
		size_t out_len)
{
	struct pcap_pkthdr	*header;
	const u_char		*packet;
	struct ip			*iph;
	struct tcphdr		*tcph;
	struct udphdr		*udph;
	int					res;
	struct ip			*orig_ip;
	struct icmphdr		*icmph;
	struct udphdr		*orig_udp;
	struct timeval		start;
	struct timeval		now;

	gettimeofday(&start, NULL);
	while (1)
	{
		res = pcap_next_ex(handle, &header, &packet);
		if (res == -1)
		{
			snprintf(out_state, out_len, "Error");
			return (0);
		}
		else if (res == 0)
			continue ;
		iph = (struct ip *)(packet + 14);
		printf("[PCAP] Packet captured proto=%d src=%s dst=%s len=%d\n",
				iph->ip_p,
				inet_ntoa(iph->ip_src),
				inet_ntoa(iph->ip_dst),
				header->len);
		// TCP RESPONSE
		if (iph->ip_p == IPPROTO_TCP && proto == IPPROTO_TCP)
		{
			tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4);
			if (ntohs(tcph->th_sport) == dport)
			{
				if ((tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
					snprintf(out_state, out_len, "Open");
				else if (tcph->th_flags & TH_RST)
					snprintf(out_state, out_len, "Closed");
				else
					snprintf(out_state, out_len, "Filtered");
				return (1);
			}
		}
		// UDP RESPONSE
		else if (iph->ip_p == IPPROTO_UDP && proto == IPPROTO_UDP)
		{
			udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);
			if (ntohs(udph->uh_sport) == dport)
			{
				snprintf(out_state, out_len, "Open");
				return (1);
			}
		}
		else if (iph->ip_p == IPPROTO_ICMP && proto == IPPROTO_UDP)
		{
			icmph = (struct icmphdr *)(packet + 14 + iph->ip_hl * 4);
			if (icmph->type == 3 && icmph->code == 3)
			{
				orig_ip = (struct ip *)(u_char *)icmph + sizeof(struct icmphdr);
				if (orig_ip->ip_p == IPPROTO_UDP)
				{
					orig_udp = (struct udphdr *)(u_char *)orig_ip
						+ orig_ip->ip_hl * 4;
					if (ntohs(orig_udp->source) == 54321
						&& ntohs(orig_udp->dest) == dport)
					{
						snprintf(out_state, out_len, "Closed");
						return (1);
					}
				}
			}
		}
		gettimeofday(&now, NULL);
		if ((now.tv_sec - start.tv_sec) >= 3)
		{ // timeout 3 secondes
			snprintf(out_state, out_len, "Filtered");
			return (0);
		}
	}
	snprintf(out_state, out_len, "Filtered");
	return (0);
}

int	get_local_ip(char *buffer, size_t buflen)
{
	int					sock;
	struct sockaddr_in	serv;
	struct sockaddr_in	name;
	socklen_t			namelen;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return (-1);
	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr("8.8.8.8");
	// n’importe quelle IP externe
	serv.sin_port = htons(53);
	if (connect(sock, (struct sockaddr *)&serv, sizeof(serv)) < 0)
	{
		close(sock);
		return (-1);
	}
	namelen = sizeof(name);
	if (getsockname(sock, (struct sockaddr *)&name, &namelen) < 0)
	{
		close(sock);
		return (-1);
	}
	inet_ntop(AF_INET, &name.sin_addr, buffer, buflen);
	close(sock);
	return (0);
}

int	send_raw(const char *dst_ip, int dport, int proto, int flags)
{
	char				packet[4096];
	struct sockaddr_in	dest;
	char				src_ip[INET_ADDRSTRLEN];
	ssize_t				packet_size;
	int					sock;
	int					one;

	one = 1;
	int sport = 54321; // port source fixe pour la capture
	if (get_local_ip(src_ip, sizeof(src_ip)) < 0)
		return (-1);
	// On forge TOUT l’IP header → donc IPPROTO_RAW
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
	if (proto == IPPROTO_TCP)
		packet_size = create_tcp_packet(packet, src_ip, dst_ip, sport, dport,
				flags);
	else if (proto == IPPROTO_UDP)
		packet_size = create_udp_packet(packet, src_ip, dst_ip, sport, dport);
	else
	{
		fprintf(stderr, "Unsupported proto\n");
		close(sock);
		return (-1);
	}
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(dport);
	dest.sin_addr.s_addr = inet_addr(dst_ip);
	if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest,
			sizeof(dest)) < 0)
	{
		perror("sendto");
		close(sock);
		return (-1);
	}
	close(sock);
	return (0);
}
