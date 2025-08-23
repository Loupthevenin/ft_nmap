#include "../includes/ft_nmap.h"

pcap_t	*pcap_open_handle(const char *iface, const char *ip_filter)
{
	char				errbuf[PCAP_ERRBUF_SIZE];
	char				filter_exp[128];
	pcap_t				*handle;
	struct bpf_program	fp;

	handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (!handle)
	{
		fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
		return (NULL);
	}
	snprintf(filter_exp, sizeof(filter_exp), "(tcp or udp or icmp) and host %s",
			ip_filter);
	if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1
		|| pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "pcap filter error: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return (NULL);
	}
	return (handle);
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
	int					attempts;
	int					max_attempts;

	attempts = 0;
	max_attempts = 5;
	while (attempts < max_attempts)
	{
		res = pcap_next_ex(handle, &header, &packet);
		if (res == -1)
		{
			snprintf(out_state, out_len, "Error");
			return (0);
		}
		iph = (struct ip *)(packet + 14);
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
		else if (iph->ip_p == IPPROTO_UDP && proto == IPPROTO_UDP)
		{
			udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);
			if (ntohs(udph->uh_sport) == dport)
			{
				snprintf(out_state, out_len, "Open");
				return (1);
			}
		}
		attempts++;
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
	serv.sin_addr.s_addr = inet_addr("8.8.8.8"); // n’importe quelle IP externe
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

int	send_tcp(const char *dst_ip, int dport, int flags)
{
	int					sock;
	char				packet[4096];
	struct ip			*iph;
	struct tcphdr		*tcph;
	struct sockaddr_in	dest;
	char				src_ip[INET_ADDRSTRLEN];

	memset(packet, 0, sizeof(packet));
	iph = (struct ip *)packet;
	tcph = (struct tcphdr *)(packet + sizeof(struct ip));
	// 🔹 récupérer l'IP locale (src_ip)
	if (get_local_ip(src_ip, sizeof(src_ip)) < 0)
		return (-1);
	// Raw socket
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
		return (-1);
	// Build IP header
	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_ttl = 64;
	iph->ip_p = IPPROTO_TCP;
	iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
	iph->ip_src.s_addr = inet_addr(src_ip);
	iph->ip_dst.s_addr = inet_addr(dst_ip);
	// Build TCP header
	tcph->th_sport = htons(12345 + (rand() % 1000));
	// port source pseudo-aléatoire
	tcph->th_dport = htons(dport);
	tcph->th_seq = htonl(rand());
	tcph->th_off = 5;
	tcph->th_flags = flags;
	tcph->th_win = htons(65535);
	// Destination
	dest.sin_family = AF_INET;
	dest.sin_port = tcph->th_dport;
	dest.sin_addr.s_addr = iph->ip_dst.s_addr;
	// Send packet
	if (sendto(sock, packet, sizeof(struct ip) + sizeof(struct tcphdr), 0,
			(struct sockaddr *)&dest, sizeof(dest)) < 0)
	{
		close(sock);
		return (-1);
	}
	close(sock);
	return (0);
}

int	send_udp(const char *dst_ip, int dport)
{
	int					sock;
	char				packet[4096];
	struct ip			*iph;
	struct udphdr		*udph;
	struct sockaddr_in	dest;
	char				src_ip[INET_ADDRSTRLEN];

	memset(packet, 0, sizeof(packet));
	iph = (struct ip *)packet;
	udph = (struct udphdr *)(packet + sizeof(struct ip));
	// 🔹 récupérer l'IP locale (src_ip)
	if (get_local_ip(src_ip, sizeof(src_ip)) < 0)
		return (-1);
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0)
		return (-1);
	// Build IP header
	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_ttl = 64;
	iph->ip_p = IPPROTO_UDP;
	iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr));
	iph->ip_src.s_addr = inet_addr(src_ip);
	iph->ip_dst.s_addr = inet_addr(dst_ip);
	// Build UDP header
	udph->uh_sport = htons(12345 + (rand() % 1000));
	udph->uh_dport = htons(dport);
	udph->uh_ulen = htons(sizeof(struct udphdr));
	// Destination
	dest.sin_family = AF_INET;
	dest.sin_port = udph->uh_dport;
	dest.sin_addr.s_addr = iph->ip_dst.s_addr;
	if (sendto(sock, packet, sizeof(struct ip) + sizeof(struct udphdr), 0,
			(struct sockaddr *)&dest, sizeof(dest)) < 0)
	{
		close(sock);
		return (-1);
	}
	close(sock);
	return (0);
}
