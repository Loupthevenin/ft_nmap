#include "../includes/ft_nmap.h"

int	build_filter(pcap_t *handle, const char *target_ip, const char *local_ip,
		struct bpf_program *fp)
{
	char	filter[1024];

	snprintf(filter, sizeof(filter), "ip and (tcp or udp or icmp) and src host "
										"%s and dst host %s",
				target_ip,
				local_ip);
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
		{
			usleep(1000);
			continue ;
		}
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
		if ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec)
			/ 1000 >= 3000)
		{ // timeout 3 secondes
			snprintf(out_state, out_len, "Filtered");
			return (0);
		}
	}
	snprintf(out_state, out_len, "Filtered");
	return (0);
}
