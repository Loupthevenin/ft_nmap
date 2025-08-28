#include "../includes/ft_nmap.h"

static void	packet_handler(unsigned char *user, const struct pcap_pkthdr *h,
		const unsigned char *bytes)
{
	(void)user;
	(void)h;
	(void)bytes;
	// TODO: le SNIFFEUR;
}

void	*thread_listener(void *arg)
{
	t_listener_arg		*larg;
	t_config			*config;
	pcap_t				*handle;
	char				errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program	fp;

	larg = (t_listener_arg *)arg;
	config = larg->config;
	// TODO: changer DEFAULT_IFACE par une fonction get_interface;
	handle = pcap_open_live(DEFAULT_IFACE, BUFSIZ, 1, 1000, errbuf);
	if (!handle)
	{
		free(larg);
		return (NULL);
	}
	pthread_mutex_lock(&larg->handle_mutex);
	larg->handle = handle;
	pthread_mutex_unlock(&larg->handle_mutex);
	if (build_filter(handle, NULL, config->local_ip, &fp) == -1)
	{
		pcap_close(handle);
		free(larg);
		return (NULL);
	}
	pcap_loop(handle, -1, packet_handler, (unsigned char *)config);
	pcap_freecode(&fp);
	pcap_close(handle);
	free(larg);
	return (NULL);
}
