#include "../includes/ft_nmap.h"

static int	create_ip_packet(char *buff, const char *src_ip, const char *dst_ip,
		int proto, size_t payload_len)
{
	struct ip	*iph;

	iph = (struct ip *)buff;
	memset(buff, 0, sizeof(struct ip) + payload_len);
	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_ttl = 64;
	iph->ip_p = proto;
	iph->ip_len = htons(sizeof(struct ip) + payload_len);
	iph->ip_src.s_addr = inet_addr(src_ip);
	iph->ip_dst.s_addr = inet_addr(dst_ip);
	iph->ip_sum = cksum((unsigned short *)iph, sizeof(struct ip) / 2);
	return (sizeof(struct ip));
}

int	create_tcp_packet(char *buff, const char *src_ip, const char *dst_ip,
		int sport, int dport, int scan_type)
{
	struct ip		*iph;
	struct tcphdr	*tcph;
	size_t			ip_size;
	t_pseudo_tcp	pseudo;

	iph = (struct ip *)buff;
	ip_size = create_ip_packet(buff, src_ip, dst_ip, IPPROTO_TCP,
			sizeof(struct tcphdr));
	tcph = (struct tcphdr *)(buff + ip_size);
	// TCP header
	tcph->source = htons(sport);
	tcph->dest = htons(dport);
	tcph->seq = htonl(rand());
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->fin = (scan_type == SCAN_FIN || scan_type == SCAN_XMAS);
	tcph->syn = (scan_type == SCAN_SYN);
	tcph->rst = 0;
	tcph->psh = (scan_type == SCAN_XMAS);
	tcph->ack = (scan_type == SCAN_ACK);
	tcph->urg = (scan_type == SCAN_XMAS);
	tcph->window = htons(14600);
	tcph->urg_ptr = 0;
	tcph->check = 0;
	// pseudo-header
	pseudo.src_addr = iph->ip_src.s_addr;
	pseudo.dst_addr = iph->ip_dst.s_addr;
	pseudo.placeholder = 0;
	pseudo.proto = IPPROTO_TCP;
	pseudo.len = htons(sizeof(struct tcphdr));
	memcpy(&pseudo.tcp, tcph, sizeof(struct tcphdr));
	tcph->check = cksum((unsigned short *)&pseudo, sizeof(t_pseudo_tcp) / 2);
	return (ip_size + sizeof(struct tcphdr));
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
