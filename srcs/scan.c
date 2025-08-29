#include "../includes/ft_nmap.h"

static int	send_packet(int sock, const char *src_ip, const char *dst_ip,
		int dport, int proto, int flags)
{
	char				packet[4096];
	struct sockaddr_in	dest;
	ssize_t				packet_size;

	// TODO: random port
	int sport = 54321; // port source fixe pour la capture
	// Construire le paquet selon le protocole
	if (proto == IPPROTO_TCP)
		packet_size = create_tcp_packet(packet, src_ip, dst_ip, sport, dport,
				flags);
	else if (proto == IPPROTO_UDP)
		packet_size = create_udp_packet(packet, src_ip, dst_ip, sport, dport);
	else
	{
		fprintf(stderr, "Unsupported proto\n");
		return (-1);
	}
	// Préparer la destination
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(dport);
	dest.sin_addr.s_addr = inet_addr(dst_ip);
	// Envoyer le paquet
	if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest,
			sizeof(dest)) < 0)
	{
		perror("sendto");
		return (-1);
	}
	return (0);
}

static void	send_scans(t_config *config, char *ip, int port, int sock)
{
	int	scan_type;

	scan_type = config->scans;
	if (scan_type & SCAN_SYN)
		send_packet(sock, config->local_ip, ip, port, IPPROTO_TCP, TH_SYN);
	if (scan_type & SCAN_FIN)
		send_packet(sock, config->local_ip, ip, port, IPPROTO_TCP, TH_FIN);
	if (scan_type & SCAN_XMAS)
		send_packet(sock, config->local_ip, ip, port, IPPROTO_TCP,
				TH_FIN | TH_PUSH | TH_URG);
	if (scan_type & SCAN_NULL)
		send_packet(sock, config->local_ip, ip, port, IPPROTO_TCP, 0);
	if (scan_type & SCAN_ACK)
		send_packet(sock, config->local_ip, ip, port, IPPROTO_TCP, TH_ACK);
	if (scan_type & SCAN_UDP)
		send_packet(sock, config->local_ip, ip, port, IPPROTO_UDP, 0);
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
		send_scans(targ->config, targ->host->ip, port, targ->sock);
	}
	free(targ);
	return (NULL);
}
