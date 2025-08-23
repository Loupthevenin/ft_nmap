#include "../includes/ft_nmap.h"

// Resolve hostname to IP address
int	resolve_hostname(const char *hostname, char **ip)
{
	struct hostent	*host_entry;
	struct in_addr	addr;

	// First check if it's already an IP address
	if (inet_aton(hostname, &addr))
	{
		*ip = strdup(hostname);
		return (*ip != NULL);
	}
	// Try to resolve hostname
	host_entry = gethostbyname(hostname);
	if (host_entry == NULL)
		return (0);
	*ip = strdup(inet_ntoa(*((struct in_addr *)host_entry->h_addr_list[0])));
	return (*ip != NULL);
}

// Initialize config structure
static void	init_config(t_config *config)
{
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
	config->iface = NULL;
	config->show_help = 0;
}

// Validate configuration (supports both legacy and new modes)
static int	validate_config(t_config *config)
{
	int	target_methods;

	// Check if we have any targets (legacy or new format)
	if (!config->ip && !config->file && config->hosts_count == 0
		&& config->ips_count == 0)
	{
		fprintf(stderr, "Error: No targets specified. Use --ip, --file,"
						"or hostnames\n");
		return (-1);
	}
	// Check for conflicting options
	target_methods = 0;
	if (config->ip)
		target_methods++;
	if (config->file)
		target_methods++;
	if (config->hosts_count > 0)
		target_methods++;
	if (target_methods > 1)
	{
		fprintf(stderr, "Error: Cannot mix --ip, --file,"
						"and hostname arguments\n");
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

// Check if IP is valid
static int	is_valid_ip(const char *ip)
{
	struct sockaddr_in	sa;

	return (inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0);
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
				free(config->ports);
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
				free(config->ports);
				return (0);
			}
			list[idx++] = atoi(token);
		}
		token = strtok(NULL, ",");
	}
	free(copy);
	config->ports_list = realloc(list, sizeof(int) * idx);
	config->ports_count = idx;
	return (1);
}

// Add a host to the hosts array (new method)
static int	add_host(t_config *config, const char *hostname)
{
	t_host	*new_hosts;
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
	config->hosts[config->hosts_count].hostname = strdup(hostname);
	config->hosts[config->hosts_count].ip = ip;
	config->hosts[config->hosts_count].ports_list = NULL;
	config->hosts[config->hosts_count].ports_count = 0;
	if (!config->hosts[config->hosts_count].hostname)
	{
		free(ip);
		return (0);
	}
	config->hosts_count++;
	printf("Added host: %s -> %s\n", hostname, ip);
	return (1);
}

// Parse IPs from file (legacy method - stores in ips_list)
char	**parse_ips_from_file(const char *filename, int *count)
{
	FILE	*file;
	char	**ips;
	char	line[INET_ADDRSTRLEN];
	int		i;
	char	**tmp;

	ips = NULL;
	i = 0;
	file = fopen(filename, "r");
	if (!file)
		return (NULL);
	while (fgets(line, sizeof(line), file))
	{
		line[strcspn(line, "\n")] = 0; // remove newline
		if (strlen(line) == 0)
			continue ; // skip empty lines
		if (is_valid_ip(line))
		{
			tmp = realloc(ips, sizeof(char *) * (i + 1));
			if (!tmp)
			{
				fclose(file);
				for (int j = 0; j < i; j++)
					free(ips[j]);
				free(ips);
				return (NULL);
			}
			ips = tmp;
			ips[i] = strdup(line);
			if (!ips[i])
			{
				fclose(file);
				for (int j = 0; j < i; j++)
					free(ips[j]);
				free(ips);
				return (NULL);
			}
			i++;
		}
		else
		{
			printf("Warning: Skipping invalid IP '%s' in file\n", line);
		}
	}
	fclose(file);
	*count = i;
	printf("Parsed %d IPs from file '%s'\n", i, filename);
	return (ips);
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
	int	i;
	int	speedup;

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
				if (!is_valid_ip(argv[i + 1]))
				{
					fprintf(stderr, "Error: Invalid IP address '%s'\n", argv[i
							+ 1]);
					return (-1);
				}
				config->ip = strdup(argv[i + 1]);
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
	return (0);
}
