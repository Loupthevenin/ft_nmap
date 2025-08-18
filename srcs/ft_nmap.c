#include "../includes/ft_nmap.h"



int	main(int argc, char **argv)
{
	t_config	config;
	int			ret;

	ret = parse_args(&config, argc, argv);
	(void)ret;
	return (0);
}
