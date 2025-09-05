#include "../includes/ft_nmap.h"

unsigned short	cksum(unsigned short *buf, int n)
{
	long			sum;
	unsigned short	oddbyte;

	sum = 0;
	while (n > 1)
	{
		sum += *buf++;
		n -= 2;
	}
	if (n == 1)
	{
		oddbyte = 0;
		*((unsigned char *)&oddbyte) = *(unsigned char *)buf;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
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
	serv.sin_addr.s_addr = inet_addr("8.8.8.8");
	// n’importe quelle IP externe
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

int	get_datalink_offset(pcap_t *handle)
{
	int	dl_type;

	dl_type = pcap_datalink(handle);
	switch (dl_type)
	{
	case DLT_EN10MB:
		return (14);
	case DLT_NULL:
	case DLT_LOOP:
		return (4);
	case DLT_RAW:
		return (0);
	case DLT_LINUX_SLL:
		return (16);
	default:
		fprintf(stderr, "Unsupported datalink type: %d\n", dl_type);
		return (-1);
	}
}

const char	*get_service_name(int port, const char *proto)
{
	struct servent	*se;

	se = getservbyport(htons(port), proto);
	if (se)
		return (se->s_name);
	return ("unknown");
}

size_t	ft_strlcat(char *dst, const char *src, size_t dstsize)
{
	size_t	i;
	size_t	len_src;
	size_t	len_dst;

	len_src = strlen(src);
	len_dst = strlen(dst);
	if (dstsize <= len_dst)
		return (len_src + dstsize);
	i = 0;
	while (src[i] != '\0' && (len_dst + i) < (dstsize - 1))
	{
		dst[len_dst + i] = src[i];
		i++;
	}
	dst[len_dst + i] = '\0';
	return (len_dst + len_src);
}

long	get_now_ms(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((tv.tv_sec * 1000L) + (tv.tv_usec / 1000L));
}

// Free
void	free_config(t_config *config)
{
	t_host		*host;
	t_result	*res;

	if (!config)
		return ;
	if (config->ports)
		free(config->ports);
	if (config->ports_list)
		free(config->ports_list);
	if (config->ip)
		free(config->ip);
	if (config->file)
		free(config->file);
	if (config->scan_type)
		free(config->scan_type);
	if (config->ips_list)
	{
		for (int i = 0; i < config->ips_count; i++)
			free(config->ips_list[i]);
		free(config->ips_list);
	}
	if (config->hosts)
	{
		for (int h = 0; h < config->hosts_count; h++)
		{
			host = &config->hosts[h];
			if (host->hostname)
				free(host->hostname);
			if (host->ip)
				free(host->ip);
			if (host->ports_list)
				free(host->ports_list);
			if (host->result)
			{
				for (int p = 0; p < host->ports_count; p++)
				{
					res = &host->result[p];
					if (res->service)
						free(res->service);
				}
				free(host->result);
			}
		}
		free(config->hosts);
	}
}
