#include "../includes/ft_nmap.h"

// Checker si --ip ou --file
int validate_config(t_config *config)
{
    if (!config->ip && !config->file) {
        fprintf(stderr, "Error: Either --ip or --file must be specified\n");
        return -1;
    }
    
    if (config->ip && config->file) {
        fprintf(stderr, "Error: Cannot specify both --ip and --file\n");
        return -1;
    }
    
    if (config->speedup <= 0) {
        fprintf(stderr, "Error: --speedup must be a positive number\n");
        return -1;
    }
    
    return 0;
}

// Verifier si le port est valide
int is_valid_port(const char *port)
{
    int p = atoi(port);
    return (p > 0 && p <= 65535);
}

// Verifier si l'argument est valide
int is_valid_argument(const char *arg)
{

    if (strncmp(arg, "--", 2) != 0)
        return (0);
    return (1);
}

// verifier si l'ip est valide
int is_valid_ip(const char *ip)
{
    struct sockaddr_in sa;
    return (inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0);
}

// Verifier si le scan est valide
int is_valid_scan_type(const char *type)
{
    const char *valid_types[] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP", NULL};
    int i = 0;
    
    while (valid_types[i]) {
        if (strcmp(type, valid_types[i]) == 0)
            return 1;
        i++;
    }
    return 0;
}

// Verifier si la vitesse est valide
int is_valid_speedup(int speedup)
{
    return (speedup >= 1 && speedup <= 250);
}

// Verifier si le fichier existe
int file_exists(const char *filename) 
{
    FILE *file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return 1;
    }
    return 0;
}

// Verifier si les ports sont valides
int validate_ports(const char *ports_str) 
{
    if (!ports_str) return 0;
    
    char *ports_copy = strdup(ports_str);
    if (!ports_copy) return 0;
    
    char *token = strtok(ports_copy, ",");
    while (token) {
        char *dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';
            if (!is_valid_port(token) || !is_valid_port(dash + 1)) {
                free(ports_copy);
                return 0;
            }
        } else {
            if (!is_valid_port(token)) {
                free(ports_copy);
                return 0;
            }
        }
        token = strtok(NULL, ",");
    }
    
    free(ports_copy);
    return 1;
}


// init
void init_config(t_config *config)
{
    config->show_help = 0;
    config->ports = NULL;
    config->ip = NULL;
    config->file = NULL;
    config->speedup = 1;
    config->scan_type = NULL;
}

// Free
void free_config(t_config *config)
{
    if (config->ports)
        free(config->ports);
    if (config->ip)
        free(config->ip);
    if (config->file)
        free(config->file);
    if (config->scan_type)
        free(config->scan_type);
}

int parse_args(t_config *config, int argc, char **argv)
{
    int i = 1;
    
    init_config(config);
    
    if (argc < 2) {
        print_help();
        return -1;
    }
    
    
    while (i < argc) {
        if (!is_valid_argument(argv[i])) {
            fprintf(stderr, "Error: Invalid argument format '%s'. Arguments must start with '--'\n", argv[i]);
            return -1;
        }
        
        if (strcmp(argv[i], "--help") == 0) {
            config->show_help = 1;
            print_help();
            return 0;
        }
        else if (strcmp(argv[i], "--ports") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --ports requires a value\n");
                return -1;
            }
            
            if (!validate_ports(argv[i + 1])) {
                fprintf(stderr, "Error: Invalid port specification '%s'\n", argv[i + 1]);
                return -1;
            }
            
            config->ports = strdup(argv[i + 1]);
            if (!config->ports) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                return -1;
            }
            i += 2;
        }
        else if (strcmp(argv[i], "--ip") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --ip requires a value\n");
                return -1;
            }
            
            if (!is_valid_ip(argv[i + 1])) {
                fprintf(stderr, "Error: Invalid IP address '%s'\n", argv[i + 1]);
                return -1;
            }
            
            config->ip = strdup(argv[i + 1]);
            if (!config->ip) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                return -1;
            }
            i += 2;
        }
        else if (strcmp(argv[i], "--file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --file requires a value\n");
                return -1;
            }
            
            if (!file_exists(argv[i + 1])) {
                fprintf(stderr, "Error: File '%s' does not exist or is not readable\n", argv[i + 1]);
                return -1;
            }
            
            config->file = strdup(argv[i + 1]);
            if (!config->file) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                return -1;
            }
            i += 2;
        }
        else if (strcmp(argv[i], "--speedup") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --speedup requires a value\n");
                return -1;
            }
            
            int speedup = atoi(argv[i + 1]);
            
            if (!is_valid_speedup(speedup)) {
                fprintf(stderr, "Error: --speedup must be between 1 and 250\n");
                return -1;
            }
            
            config->speedup = speedup;
            i += 2;
        }
        else if (strcmp(argv[i], "--scan") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --scan requires a value\n");
                return -1;
            }
            
            if (!is_valid_scan_type(argv[i + 1])) {
                fprintf(stderr, "Error: Invalid scan type '%s'. Must be one of: SYN, NULL, ACK, FIN, XMAS, UDP\n", argv[i + 1]);
                return -1;
            }
            
            config->scan_type = strdup(argv[i + 1]);
            if (!config->scan_type) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                return -1;
            }
            i += 2;
        }
        else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            return -1;
        }
    }
    
    if (!config->show_help) {
        if (validate_config(config) != 0) {
            return -1;
        }
    }
    
    return 0;
}