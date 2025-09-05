#include "../includes/ft_nmap.h"

// Resolve hostname to IP address
int	resolve_hostname(const char *hostname, char **ip)
{
	struct addrinfo		hints;
	struct addrinfo		*res;
	struct addrinfo		*p;
	struct in_addr		addr;
	int					status;
	char				addrstr[INET_ADDRSTRLEN];
	struct sockaddr_in	*ipv4;

	// First check if it's already an IP address
	if (inet_aton(hostname, &addr))
	{
		*ip = strdup(hostname);
		return (*ip != NULL);
	}
	// Try to resolve hostname
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // IPv4 only
	hints.ai_socktype = SOCK_STREAM;
	if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0)
	{
		fprintf(stderr, "DNS resolution failed for %s: %s\n", hostname,
				gai_strerror(status));
		return (0);
	}
	for (p = res; p != NULL; p = p->ai_next)
	{
		ipv4 = (struct sockaddr_in *)p->ai_addr;
		if (inet_ntop(AF_INET, &(ipv4->sin_addr), addrstr, sizeof addrstr))
		{
			*ip = strdup(addrstr);
			freeaddrinfo(res);
			return (*ip != NULL);
		}
	}
	freeaddrinfo(res);
	return (0);
}

// Initialize config structure
static void	init_config(t_config *config)
{
	memset(config, 0, sizeof(t_config));
	// Legacy fields
	config->ip = NULL;
	config->ips_list = NULL;
	config->ips_count = 0;
	config->file = NULL;
	// New host-based fields
	config->hosts = NULL;
	config->hosts_count = 0;
	// Common fields
	config->ports = NULL;
	config->ports_list = NULL;
	config->ports_count = 0;
	config->speedup = 1;
	config->scans = 0;
	config->scan_type = NULL;
	config->show_help = 0;
	pthread_mutex_init(&config->result_mutex, NULL);
	pthread_mutex_init(&config->packet_time_mutex, NULL);
	pthread_mutex_init(&config->sport_mutex, NULL);
}

// Validate configuration (supports both legacy and new modes)
static int	validate_config(t_config *config)
{
	// Check if we have any targets (legacy or new format)
	if (!config->ip && !config->file && config->hosts_count == 0
		&& config->ips_count == 0)
	{
		fprintf(stderr, "Error: No targets specified. Use --ip, --file,"
						"or hostnames\n");
		return (-1);
	}
	if (config->speedup <= 0)
	{
		fprintf(stderr, "Error: --speedup must be a positive number\n");
		return (-1);
	}
	return (0);
}

// Check if argument format is valid
static int	is_valid_argument(const char *arg)
{
	return (strncmp(arg, "--", 2) == 0);
}

// Check if port is valid
static int	is_valid_port(const char *port)
{
	int	p;

	p = atoi(port);
	return (p > 0 && p <= 65535);
}

// Check if speedup value is valid
static int	is_valid_speedup(int speedup)
{
	return (speedup >= 1 && speedup <= 250);
}

// Check if file exists
static int	file_exists(const char *filename)
{
	FILE	*file;

	file = fopen(filename, "r");
	if (file)
	{
		fclose(file);
		return (1);
	}
	return (0);
}

// Parse ports from string (e.g., "80,443,1-1000")
static int	parse_ports(t_config *config, const char *ports_str)
{
	char	*copy;
	char	*token;
	int		*list;
	int		idx;
	char	*dash;
	int		start;
	int		end;

	if (!ports_str)
		return (0);
	config->ports = strdup(ports_str);
	if (!config->ports)
		return (0);
	list = malloc(sizeof(int) * 2000); // max size
	if (!list)
	{
		free(config->ports);
		return (0);
	}
	copy = strdup(ports_str);
	if (!copy)
	{
		free(list);
		free(config->ports);
		return (0);
	}
	token = strtok(copy, ",");
	idx = 0;
	while (token)
	{
		dash = strchr(token, '-');
		if (dash)
		{
			*dash = '\0';
			start = atoi(token);
			end = atoi(dash + 1);
			if (!is_valid_port(token) || !is_valid_port(dash + 1)
				|| start > end)
			{
				free(copy);
				free(list);
				return (0);
			}
			for (int i = start; i <= end; i++)
				list[idx++] = i;
		}
		else
		{
			if (!is_valid_port(token))
			{
				free(copy);
				free(list);
				return (0);
			}
			list[idx++] = atoi(token);
		}
		token = strtok(NULL, ",");
	}
	free(copy);
	if (config->ports)
		free(config->ports);
	config->ports = strdup(ports_str);
	config->ports_list = realloc(list, sizeof(int) * idx);
	config->ports_count = idx;
	return (1);
}

// Add a host to the hosts array (new method)
static int	add_host(t_config *config, const char *hostname)
{
	t_host	*new_hosts;
	t_host	*h;
	char	*ip;

	// Resolve hostname to IP
	if (!resolve_hostname(hostname, &ip))
	{
		fprintf(stderr, "Error: Cannot resolve hostname '%s'\n", hostname);
		return (0);
	}
	// Reallocate hosts array
	new_hosts = realloc(config->hosts, sizeof(t_host) * (config->hosts_count
				+ 1));
	if (!new_hosts)
	{
		free(ip);
		return (0);
	}
	config->hosts = new_hosts;
	// Initialize new host
	h = &config->hosts[config->hosts_count];
	memset(h, 0, sizeof(t_host));
	h->hostname = strdup(hostname);
	h->ip = ip;
	h->ports_list = NULL;
	h->ports_count = 0;
	h->result = NULL;
	if (!h->hostname)
	{
		free(ip);
		return (0);
	}
	config->hosts_count++;
	printf("Added host: %s -> %s\n", hostname, ip);
	return (1);
}

// Parse hosts from file (new method - stores in hosts array)
static int	parse_hosts_from_file(t_config *config, const char *filename)
{
	FILE	*file;
	char	line[256];
	int		count;

	count = 0;
	file = fopen(filename, "r");
	if (!file)
		return (0);
	while (fgets(line, sizeof(line), file))
	{
		line[strcspn(line, "\n")] = 0; // remove newline
		if (strlen(line) == 0)
			continue ; // skip empty lines
		if (add_host(config, line))
			count++;
	}
	fclose(file);
	printf("Parsed %d hosts from file '%s'\n", count, filename);
	return (count > 0);
}

// Add scan type to config
static int	add_scan_type(t_config *config, const char *scan)
{
	if (strcmp(scan, "SYN") == 0)
		config->scans |= SCAN_SYN;
	else if (strcmp(scan, "NULL") == 0)
		config->scans |= SCAN_NULL;
	else if (strcmp(scan, "ACK") == 0)
		config->scans |= SCAN_ACK;
	else if (strcmp(scan, "FIN") == 0)
		config->scans |= SCAN_FIN;
	else if (strcmp(scan, "XMAS") == 0)
		config->scans |= SCAN_XMAS;
	else if (strcmp(scan, "UDP") == 0)
		config->scans |= SCAN_UDP;
	else
	{
		fprintf(stderr, "Error: Invalid scan type '%s'. Must be one of: SYN,"
						"NULL, ACK, FIN, XMAS, UDP\n",
				scan);
		return (-1);
	}
	return (0);
}

// Main argument parser - supports both legacy and new modes
int	parse_args(t_config *config, int argc, char **argv)
{
	int		i;
	int		speedup;
	char	*resolve_ip;

	i = 1;
	init_config(config);
	if (argc < 2)
	{
		print_help();
		return (-1);
	}
	while (i < argc)
	{
		// Check for options vs hostnames
		if (is_valid_argument(argv[i]))
		{
			// This is an option
			if (strcmp(argv[i], "--help") == 0)
			{
				config->show_help = 1;
				return (0);
			}
			else if (strcmp(argv[i], "--ports") == 0)
			{
				if (i + 1 >= argc)
				{
					fprintf(stderr, "Error: --ports requires a value\n");
					return (-1);
				}
				if (!parse_ports(config, argv[i + 1]))
				{
					fprintf(stderr, "Error: Invalid port specification '%s'\n",
							argv[i + 1]);
					return (-1);
				}
				i += 2;
			}
			else if (strcmp(argv[i], "--ip") == 0)
			{
				if (i + 1 >= argc)
				{
					fprintf(stderr, "Error: --ip requires a value\n");
					return (-1);
				}
				resolve_ip = NULL;
				if (!resolve_hostname(argv[i + 1], &resolve_ip))
				{
					fprintf(stderr, "Error: Cannot resolve host '%s'\n", argv[i
							+ 1]);
					return (-1);
				}
				config->ip = resolve_ip;
				if (!config->ip)
				{
					fprintf(stderr, "Error: Memory allocation failed\n");
					return (-1);
				}
				i += 2;
			}
			else if (strcmp(argv[i], "--file") == 0)
			{
				if (i + 1 >= argc)
				{
					fprintf(stderr, "Error: --file requires a value\n");
					return (-1);
				}
				if (!file_exists(argv[i + 1]))
				{
					fprintf(stderr,
							"Error: File '%s' does not exist or is not readable\n",
							argv[i + 1]);
					return (-1);
				}
				config->file = strdup(argv[i + 1]);
				if (!config->file)
				{
					fprintf(stderr, "Error: Memory allocation failed\n");
					return (-1);
				}
				// Use new host-based method for --file
				if (!parse_hosts_from_file(config, argv[i + 1]))
				{
					fprintf(stderr,
							"Error: Failed to parse hosts from file '%s'\n",
							argv[i + 1]);
					return (-1);
				}
				i += 2;
			}
			else if (strcmp(argv[i], "--speedup") == 0)
			{
				if (i + 1 >= argc)
				{
					fprintf(stderr, "Error: --speedup requires a value\n");
					return (-1);
				}
				speedup = atoi(argv[i + 1]);
				if (!is_valid_speedup(speedup))
				{
					fprintf(stderr,
							"Error: --speedup must be between 1 and 250\n");
					return (-1);
				}
				config->speedup = speedup;
				i += 2;
			}
			else if (strcmp(argv[i], "--scan") == 0)
			{
				if (i + 1 >= argc)
				{
					fprintf(stderr, "Error: --scan requires a value\n");
					return (-1);
				}
				if (add_scan_type(config, argv[i + 1]) != 0)
					return (-1);
				i += 2;
			}
			else
			{
				fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
				return (-1);
			}
		}
		else
		{
			// This is a hostname/IP (new method)
			if (!add_host(config, argv[i]))
			{
				fprintf(stderr, "Error: Cannot add host '%s'\n", argv[i]);
				return (-1);
			}
			i++;
		}
	}
	if (!config->show_help)
	{
		if (validate_config(config) != 0)
			return (-1);
	}
	if (config->ports_count == 0)
		parse_ports(config, "1-1024");
	if (config->speedup == 0)
		config->speedup = 1;
	if (config->scans == 0)
		config->scans = SCAN_ALL;
	if (config->hosts_count == 0 && config->ip)
		add_host(config, config->ip);
	config->last_packet_time = get_now_ms();
	return (0);
}
