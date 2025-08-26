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
	char				state[32];
	char				errbuf[PCAP_ERRBUF_SIZE];
	pcap_t				*handle;
	struct bpf_program	fp;
	char				filter[1024];

	handle = pcap_open_live(DEFAULT_IFACE, BUFSIZ, 1, 5000, errbuf);
	if (!handle)
	{
		res->scan_results[params.index] = strdup("Error");
		return ;
	}
	if (!params.is_udp)
	{
		// TCP
		snprintf(filter, sizeof(filter), "tcp and src host "
											"%s and dst port 54321",
					host->ip);
	}
	else
	{
		// UDP
		snprintf(filter, sizeof(filter), "(udp or icmp) and src host "
											"%s and (src port 54321 or icmp[0] == 3)",
					host->ip);
	}
	if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
		pcap_setfilter(handle, &fp) == -1)
	{
		res->scan_results[params.index] = strdup("Error");
		pcap_close(handle);
		return ;
	}
	pcap_freecode(&fp);
	// Envoi du paquet
	send_raw(host->ip, port, params.is_udp ? IPPROTO_UDP : IPPROTO_TCP,
			params.flags);
	// Attente de la réponse
	if (pcap_wait_response(handle, port,
			params.is_udp ? IPPROTO_UDP : IPPROTO_TCP, state, sizeof(state)))
	{
		if (!params.is_udp && params.interpret)
			res->scan_results[params.index] = strdup(params.interpret(state));
		else
			res->scan_results[params.index] = strdup(state);
	}
	else
	{
		res->scan_results[params.index] =
			strdup(params.is_udp ? "Open|Filtered" : params.interpret("Filtered"));
	}
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
