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

static void	tcp_scan(t_host *host, int port, t_result *res, int scan_index,
		int flags, const char *(*interpret)(const char *))
{
	char				state[32];
	char				errbuf[PCAP_ERRBUF_SIZE];
	pcap_t				*handle;
	struct bpf_program	fp;
	char				filter[1024];

	handle = pcap_open_live(DEFAULT_IFACE, BUFSIZ, 1, 5000, errbuf);
	if (!handle)
	{
		res->scan_results[scan_index] = strdup(interpret("Error"));
		return ;
	}
	snprintf(filter, sizeof(filter), "tcp and src host %s and dst port 54321",
			host->ip);
	if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
		pcap_setfilter(handle, &fp) == -1)
	{
		res->scan_results[scan_index] = strdup(interpret("Error"));
		pcap_close(handle);
		return ;
	}
	pcap_freecode(&fp);
	send_raw(host->ip, port, IPPROTO_TCP, flags);
	if (pcap_wait_response(handle, port, IPPROTO_TCP, state, sizeof(state)))
		res->scan_results[scan_index] = strdup(interpret(state));
	else
		res->scan_results[scan_index] = strdup(interpret("Filtered"));
	pcap_close(handle);
}

static void	udp_scan(t_host *host, int port, t_result *res)
{
	char				state[32];
	char				errbuf[PCAP_ERRBUF_SIZE];
	pcap_t				*handle;
	struct bpf_program	fp;
	char				filter[1024];

	handle = pcap_open_live(DEFAULT_IFACE, BUFSIZ, 1, 1000, errbuf);
	if (!handle)
	{
		res->scan_results[INDEX_UDP] = strdup("Error");
		return ;
	}
	// Filtre pcap pour UDP + ICMP port unreachable
	snprintf(filter, sizeof(filter), "(udp or icmp) and src host"
										"%s and (src port %d or icmp[0] == 3)",
				host->ip,
				54321);
	if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
		pcap_setfilter(handle, &fp) == -1)
	{
		res->scan_results[INDEX_UDP] = strdup("Error");
		pcap_close(handle);
		return ;
	}
	pcap_freecode(&fp);
	send_raw(host->ip, port, IPPROTO_UDP, 0);
	if (pcap_wait_response(handle, port, IPPROTO_UDP, state, sizeof(state)))
		res->scan_results[INDEX_UDP] = strdup(state);
	else
		res->scan_results[INDEX_UDP] = strdup("Open|Filtered");
	pcap_close(handle);
}

void	scan_port(t_config *config, t_host *host, int port, t_result *result)
{
	int	scan_type;

	scan_type = config->scans;
	if (scan_type & SCAN_SYN)
		tcp_scan(host, port, result, INDEX_SYN, TH_SYN, interpret_syn);
	if (scan_type & SCAN_FIN)
		tcp_scan(host, port, result, INDEX_FIN, TH_FIN, interpret_fin);
	if (scan_type & SCAN_XMAS)
		tcp_scan(host, port, result, INDEX_XMAS, TH_FIN | TH_PUSH | TH_URG,
				interpret_xmas);
	if (scan_type & SCAN_NULL)
		tcp_scan(host, port, result, INDEX_NULL, 0, interpret_null);
	if (scan_type & SCAN_ACK)
		tcp_scan(host, port, result, INDEX_ACK, TH_ACK, interpret_ack);
	if (scan_type & SCAN_UDP)
		udp_scan(host, port, result);
}
