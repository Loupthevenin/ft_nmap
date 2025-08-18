#include "../includes/ft_nmap.h"

int main(int argc, char **argv)
{
    t_config config;
    
    if (parse_args(&config, argc, argv) == -1) {
        free_config(&config);
        return 1;
    }
    
    if (config.show_help) {
        print_help();
        free_config(&config);
        return 0;
    }
    
    print_config(&config);
    printf("\nStarting ft_nmap scan...\n");
    
    free_config(&config);
    return 0;
}
