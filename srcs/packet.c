#include "../includes/ft_nmap.h"

static unsigned short	tcp_checksum(struct ip *iph, struct tcphdr *tcph,
		unsigned char *options, int options_len, unsigned char *payload,
		int payload_len)
{
	t_pseudo_tcp	pseudo_header;
	int				tcp_size;
	int				total_len;
	char			*buf;
	unsigned short	sum;

	tcp_size = sizeof(struct tcphdr) + options_len + payload_len;
	pseudo_header.src_addr = iph->ip_src.s_addr;
	pseudo_header.dst_addr = iph->ip_dst.s_addr;
	pseudo_header.placeholder = 0;
	pseudo_header.proto = IPPROTO_TCP;
	pseudo_header.tcp_length = htons(tcp_size);
	total_len = sizeof(pseudo_header) + tcp_size;
	buf = malloc(total_len);
	if (!buf)
		return (0);
	memcpy(buf, &pseudo_header, sizeof(pseudo_header));
	memcpy(buf + sizeof(pseudo_header), tcph, sizeof(struct tcphdr));
	if (options_len > 0)
		memcpy(buf + sizeof(pseudo_header) + sizeof(struct tcphdr), options,
				options_len);
	if (payload_len > 0)
		memcpy(buf + sizeof(pseudo_header) + sizeof(struct tcphdr)
				+ options_len, payload, payload_len);
	sum = cksum((unsigned short *)buf, (total_len + 1) / 2);
	free(buf);
	return (sum);
}

static int	create_ip_packet(char *buff, const char *src_ip, const char *dst_ip,
		int proto, size_t payload_len)
{
	struct ip	*iph;

	iph = (struct ip *)buff;
	memset(buff, 0, sizeof(struct ip) + payload_len);
	memset(iph, 0, sizeof(struct ip));
	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_ttl = 64;
	iph->ip_p = proto;
	iph->ip_len = htons(sizeof(struct ip) + payload_len);
	iph->ip_src.s_addr = inet_addr(src_ip);
	iph->ip_dst.s_addr = inet_addr(dst_ip);
	// Checksum
	iph->ip_id = htons(rand() % 65535);
	iph->ip_off = 0;
	iph->ip_sum = 0; // mettre à 0 avant le calcul
	iph->ip_sum = cksum((unsigned short *)iph, sizeof(struct ip) / 2);
	return (sizeof(struct ip));
}

int	create_tcp_packet(char *buff, const char *src_ip, const char *dst_ip,
		int sport, int dport, int flags)
{
	struct ip		*iph;
	struct tcphdr	*tcph;
	size_t			ip_size;
	int				options_len;
	int				payload_len;

	options_len = 0;
	payload_len = 0;
	iph = (struct ip *)buff;
	ip_size = create_ip_packet(buff, src_ip, dst_ip, IPPROTO_TCP,
			sizeof(struct tcphdr));
	tcph = (struct tcphdr *)(buff + ip_size);
	memset(tcph, 0, sizeof(struct tcphdr));
	// TCP header
	tcph->source = htons(sport);
	tcph->dest = htons(dport);
	tcph->seq = htonl(rand());
	tcph->ack_seq = 0;
	tcph->doff = (sizeof(struct tcphdr) + options_len) / 4;
	tcph->window = htons(14600);
	// Flags
	tcph->fin = (flags & TH_FIN) ? 1 : 0;
	tcph->syn = (flags & TH_SYN) ? 1 : 0;
	tcph->rst = (flags & TH_RST) ? 1 : 0;
	tcph->psh = (flags & TH_PUSH) ? 1 : 0;
	tcph->ack = (flags & TH_ACK) ? 1 : 0;
	tcph->urg = (flags & TH_URG) ? 1 : 0;
	tcph->urg_ptr = 0;
	tcph->check = 0;
	// pseudo-header
	tcph->check = tcp_checksum(iph, tcph, NULL, options_len, NULL, payload_len);
	return (ip_size + sizeof(struct tcphdr) + options_len + payload_len);
}

int	create_udp_packet(char *buff, const char *src_ip, const char *dst_ip,
		int sport, int dport)
{
	struct udphdr	*udph;
	size_t			ip_size;

	ip_size = create_ip_packet(buff, src_ip, dst_ip, IPPROTO_UDP,
			sizeof(struct udphdr));
	udph = (struct udphdr *)(buff + ip_size);
	memset(udph, 0, sizeof(struct udphdr));
	// UDP header
	udph->source = htons(sport);
	udph->dest = htons(dport);
	udph->len = htons(sizeof(struct udphdr));
	udph->check = 0; // optionnel, Linux RAW socket ignore
	return (ip_size + sizeof(struct udphdr));
}
