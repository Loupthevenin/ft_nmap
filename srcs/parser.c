#include "../includes/ft_nmap.h"

// init
static void	init_config(t_config *config)
{
	config->show_help = 0;
	config->ports = NULL;
	config->ports_list = NULL;
	config->ports_count = 0;
	config->ip = NULL;
	config->file = NULL;
	config->speedup = 1;
	config->scan_type = NULL;
	config->scans = 0;
}

// Checker si --ip ou --file
static int	validate_config(t_config *config)
{
	if (!config->ip && !config->file)
	{
		fprintf(stderr, "Error: Either --ip or --file must be specified\n");
		return (-1);
	}
	if (config->ip && config->file)
	{
		fprintf(stderr, "Error: Cannot specify both --ip and --file\n");
		return (-1);
	}
	if (config->speedup <= 0)
	{
		fprintf(stderr, "Error: --speedup must be a positive number\n");
		return (-1);
	}
	return (0);
}

// Verifier si le port est valide
static int	is_valid_port(const char *port)
{
	int	p;

	p = atoi(port);
	return (p > 0 && p <= 65535);
}

// Verifier si l'argument est valide
static int	is_valid_argument(const char *arg)
{
	if (strncmp(arg, "--", 2) != 0)
		return (0);
	return (1);
}

// verifier si l'ip est valide
static int	is_valid_ip(const char *ip)
{
	struct sockaddr_in	sa;

	return (inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0);
}

// Verifier si la vitesse est valide
static int	is_valid_speedup(int speedup)
{
	return (speedup >= 1 && speedup <= 250);
}

// Verifier si le fichier existe
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

// Verifier si les ports sont valides
static int	parse_ports(t_config *config, const char *ports_str)
{
	char	*copy;
	char	*token;
	int		idx;
	char	*dash;
	int		start;
	int		end;

	if (!ports_str)
		return (0);
	config->ports = strdup(ports_str);
	if (!config->ports)
		return (0);
	int *list = malloc(sizeof(int) * 2000); // taille max raisonnable
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
	// réallocation à la taille exacte
	config->ports_list = realloc(list, sizeof(int) * idx);
	config->ports_count = idx;
	return (1);
}

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
		if (!is_valid_argument(argv[i]))
		{
			fprintf(stderr,
					"Error: Invalid argument format '%s'. Arguments must start with '--'\n",
					argv[i]);
			return (-1);
		}
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
			if (parse_ports(config, argv[i + 1]) == 0)
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
				fprintf(stderr, "Error: --speedup must be between 1 and 250\n");
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
	if (!config->show_help)
	{
		if (validate_config(config) != 0)
		{
			return (-1);
		}
	}
	if (config->scans == 0)
		config->scans = SCAN_ALL;
	return (0);
}
