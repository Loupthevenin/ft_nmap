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
	char	state[32];

	send_tcp(host->ip, port, flags);
	if (pcap_wait_response(host->pcap_handle, port, IPPROTO_TCP, state,
			sizeof(state)))
		res->scan_results[scan_index] = strdup(interpret(state));
	else
		res->scan_results[scan_index] = strdup(interpret("Filtered"));
}

static void	udp_scan(t_host *host, int port, t_result *res)
{
	char	state[32];

	send_udp(host->ip, port);
	if (pcap_wait_response(host->pcap_handle, port, IPPROTO_UDP, state,
			sizeof(state)))
		res->scan_results[INDEX_UDP] = strdup(state);
	else
		res->scan_results[INDEX_UDP] = strdup("Open|Filtered");
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
