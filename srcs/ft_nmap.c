#include "../includes/ft_nmap.h"

// static void	*thread_scan(void *arg)
// {
// 	t_thread_arg	*targ;

// 	targ = (t_thread_arg *)arg;
// 	scan_port(targ->config, targ->port);
// 	free(targ);
// 	return (NULL);
// }

// static void	run_scan(t_config *config)
// {
// 	int				i;
// 	pthread_t		*threads;
// 	int				active_threads;
// 	t_thread_arg	*targ;

// 	i = 0;
// 	active_threads = 0;
// 	threads = malloc(sizeof(pthread_t) * config->speedup);
// 	if (!threads)
// 		return ;
// 	while (i < config->ports_count)
// 	{
// 		targ = malloc(sizeof(t_thread_arg));
// 		targ->config = config;
// 		targ->port = config->ports_list[i];
// 		pthread_create(&threads[active_threads], NULL, thread_scan, targ);
// 		active_threads++;
// 		if (active_threads == config->speedup)
// 		{
// 			for (int j = 0; j < active_threads; j++)
// 				pthread_join(threads[j], NULL);
// 			active_threads = 0;
// 		}
// 		i++;
// 	}
// 	for (int j = 0; j < active_threads; j++)
// 		pthread_join(threads[j], NULL);
// 	free(threads);
// }

int	main(int argc, char **argv)
{
	t_config	config;

	if (parse_args(&config, argc, argv) == -1)
	{
		free_config(&config);
		return (1);
	}
	if (config.show_help)
	{
		print_help();
		free_config(&config);
		return (0);
	}
	print_config(&config);
	printf("\nStarting ft_nmap scan...\n");
//	run_scan(&config);
	free_config(&config);
	return (0);
}
