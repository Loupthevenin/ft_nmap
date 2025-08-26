#include "../includes/ft_nmap.h"

static const char	*interpret_syn(const char *state)
{
	return (state);
}

static const char	*interpret_fin(const char *state)
{
	if (strcmp(state, "Closed") == 0)
		return ("Closed");
	return ("Open|Filtered");
}

static const char	*interpret_null(const char *state)
{
	if (strcmp(state, "Closed") == 0)
		return ("Closed");
	return ("Open|Filtered");
}

static const char	*interpret_xmas(const char *state)
{
	if (strcmp(state, "Closed") == 0)
		return ("Closed");
	return ("Open|Filtered");
}

static const char	*interpret_ack(const char *state)
{
	if (strcmp(state, "Closed") == 0 || strcmp(state, "Open") == 0)
		return ("Unfiltered");
	return ("Filtered");
}

static void	scan(t_host *host, int port, t_result *res, t_scan_params params)
{
	char				errbuf[PCAP_ERRBUF_SIZE];
	pcap_t				*handle;
	struct bpf_program	fp;
	char				local_ip[INET_ADDRSTRLEN];

	if (get_local_ip(local_ip, sizeof(local_ip)) < 0)
	{
		res->scan_results[params.index] = strdup("Error (local ip)");
		return ;
	}
	handle = pcap_open_live(DEFAULT_IFACE, BUFSIZ, 1, 1000, errbuf);
	if (!handle)
	{
		res->scan_results[params.index] = strdup("Error");
		return ;
	}
	if (build_filter(handle, host->ip, local_ip, params.is_udp, &fp) == -1)
	{
		res->scan_results[params.index] = strdup("Error");
		pcap_close(handle);
		return ;
	}
	pcap_freecode(&fp);
	// Envoi du paquet
	send_raw(host->ip, port, params.is_udp ? IPPROTO_UDP : IPPROTO_TCP,
			params.flags, local_ip);
	// Attente de la réponse
	res->scan_results[params.index] = wait_and_interpret(handle, port, &params);
	pcap_close(handle);
}

void	scan_port(t_config *config, t_host *host, int port, t_result *result)
{
	int	scan_type;

	scan_type = config->scans;
	if (scan_type & SCAN_SYN)
		scan(host, port, result, (t_scan_params){INDEX_SYN, TH_SYN, 0,
				interpret_syn});
	if (scan_type & SCAN_FIN)
		scan(host, port, result, (t_scan_params){INDEX_FIN, TH_FIN, 0,
				interpret_fin});
	if (scan_type & SCAN_XMAS)
		scan(host, port, result, (t_scan_params){INDEX_XMAS,
				TH_FIN | TH_PUSH | TH_URG, 0, interpret_xmas});
	if (scan_type & SCAN_NULL)
		scan(host, port, result, (t_scan_params){INDEX_NULL, 0, 0,
				interpret_null});
	if (scan_type & SCAN_ACK)
		scan(host, port, result, (t_scan_params){INDEX_ACK, TH_ACK, 0,
				interpret_ack});
	if (scan_type & SCAN_UDP)
		scan(host, port, result, (t_scan_params){INDEX_UDP, 0, 1, NULL});
}
