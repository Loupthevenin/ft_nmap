#include "../includes/ft_nmap.h"

int	parse_args(t_config *config, int argc, char **argv)
{
	(void)argc;
	(void)argv;
	(void)config;
	return (0);
}

int	main(int argc, char **argv)
{
	t_config	config;
	int			ret;

	ret = parse_args(&config, argc, argv);
	(void)ret;
	return (0);
}
