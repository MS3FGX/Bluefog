/*
 * 
 *  Bluefog - Create phantom Bluetooth devices
 * 
 *  Bluefog is a tool to create phantom Bluetooth devices. Can be used
 *  to confuse attackers or test Bluetooth detection systems.
 * 
 *  Written by Tom Nardi (MS3FGX@gmail.com), released under the GPLv2.
 *  For more information, see: www.digifail.com
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

// List of device names
#include "devicenames.h"

// MAC changing functions
#include "bdaddr.c"

#define VERSION	"0.0.1"
#define APPNAME "Bluefog"

// Sane defaults
#define MAX_THREADS	4
#define THREAD_DELAY 1
#define MAX_DELAY 300

// Data to pass to threads
struct thread_data
{
	int thread_id;
	unsigned long iterations;
	int change_addr;
	int verbose;
	int device;
	int delay;
};

char* random_name (void)
{	
	// Select random name from list within range
	return (device_name[((rand() % dev_max) + 1)] );	
}

// Generate random MAC address
// Adapted from "SpoofTooph" by JP Dunning (.ronin)
char* random_addr (void)
{	
	char addr_part[3] = {0};
	static char addr[21] = {0};
	int i = 0;
	addr[i++] = '0';
	addr[i++] = '0';
	addr[i++] = ':';
	
	while ( i < 18)
	{
		sprintf(addr_part, "%02x", (rand() % 254));	
		addr[i++] = addr_part[0];
		addr[i++] = addr_part[1];
		addr[i++] = ':';
	}

	sprintf(addr_part, "%02x", (rand() % 254));	
	addr[i++] = addr_part[0];
	addr[i++] = addr_part[1];
	
	return(addr);
}

struct thread_data thread_data_array[MAX_THREADS];

void *thread_spoof(void *threadarg)
{	
	// Define variables from struct
	int thread_id, change_addr, verbose, device, delay;
	unsigned long iterations;
	
	// Local use variables
	int bt_socket;
	unsigned long i;
	int verify_mac = 1;
		
	// Pull data out of struct
	struct thread_data *local_data;
	local_data = (struct thread_data *) threadarg;
	thread_id = local_data->thread_id;
	iterations = local_data->iterations;
	device = local_data->device;
	change_addr = local_data->change_addr;
	verbose = local_data->verbose;
	delay = local_data->delay;
	
	// MAC struct
	bdaddr_t bdaddr;
	bacpy(&bdaddr, BDADDR_ANY);
	struct hci_dev_info di;
	char addr_real[19] = {0};
	char addr_buff[19] = {0};	
	
	// Init device	
	if (verbose)
		printf("Initalizing hci%i on thread %i.\n", device, thread_id);

	bt_socket = hci_open_dev(device);
	if (bt_socket < 0)
	{
		printf("Failed to initalize hci%i on thread %i!\n", device, thread_id);
		exit(1); // TODO: Better shutdown
	}
		
	// Get MAC for reference
	if (!bacmp(&di.bdaddr, BDADDR_ANY))
	{
		if (hci_read_bd_addr(bt_socket, &bdaddr, 1000) < 0)
		{
			fprintf(stderr, "Can't read address for hci%d: %s (%d)\n", device, strerror(errno), errno);
			hci_close_dev(bt_socket);
		}
	}
	else
		bacpy(&bdaddr, &di.bdaddr);	

	// Real MAC stored to addr_real
	ba2str(&bdaddr, addr_real);
	
	for (i = 0; i < iterations; i++)
	{		
		// Verbose doesn't work here, have to buffer to something first
		
		// Always change name
		if (hci_write_local_name(bt_socket, random_name(), 2000) < 0)
			fprintf(stderr, "Can't change local name on hci%d: %s (%d)\n", device, strerror(errno), errno);

		if (verbose)
			printf("hci%d renamed to '%s'\n", device, random_name());
			
		// Attempt to change address
		if (change_addr)
		{
			// Assign random MAC
			cmd_bdaddr(device, random_addr());
				
			if (verbose)
					printf("hci%d addr changed to to '%s'\n", device, random_addr());	
		}
					
		// Wait
		if (i != (iterations - 1))
			sleep(delay);
			
		// Verify MAC actually changed
		if (verify_mac)
		{	
			if (!bacmp(&di.bdaddr, BDADDR_ANY))
			{
				if (hci_read_bd_addr(bt_socket, &bdaddr, 1000) < 0)
				{
					fprintf(stderr, "Can't read address for hci%d: %s (%d)\n", device, strerror(errno), errno);
					exit(1);
				}
			}
			else
				bacpy(&bdaddr, &di.bdaddr);	

			// Test MAC to addr_buff
			ba2str(&bdaddr, addr_buff);			
			
			if ((strcmp (addr_real, addr_buff) == 0))
			{
				printf("MAC on interface hci%i is not changing. Hardware is likely not compatible.\n", device);
				printf("Disabling MAC changing for this interface. See README for more info.\n");
				change_addr = 0;
			}
	
			// Only run once
			verify_mac = 0;
		}
	}
	
	// Close device
	hci_close_dev(bt_socket);

	if (verbose)
		printf("Thread %i done.\n", thread_id);
	
	// Leap home
	pthread_exit(NULL);
}

static void help(void)
{
	printf("%s (v%s) by MS3FGX\n", APPNAME, VERSION);
	printf("----------------------------------------------------------------\n");
	printf("Bluefog is a tool used to create phantom Bluetooth devices with\n"
		"a CSR Bluetooth adapter. Can be used to confuse attackers or test\n"
		"Bluetooth detection systems.\n");
	printf("\n");
	printf("For more information, see www.digifail.com\n");
	printf("\n");
	printf("Options:\n"
		"\t-a <stuff>      This does stuff.\n"
		"\t-b <stuff>      More stuff.\n"
		"\t-c <stuff>      More stuff.\n"
		"\n");
}

static struct option main_options[] = {
	{ "interface", 1, 0, 'i' },
	{ "threads", 1, 0, 't' },
	{ "delay", 1, 0, 'd' },
	{ "count", 1, 0, 'c' },
	{ "verbose", 0, 0, 'v' },
	{ "help", 0, 0, 'h' },
	{ 0, 0, 0, 0 }
};
 
int main(int argc, char *argv[])
{
	// Declare variables here
	int t, opt;
	
	// Thread ID
	pthread_t threads[MAX_THREADS];
	
	// Threads to run, default 1
	int numthreads = 1;
	
	// Delay between spoofs, default 10
	int delay = 10;

	// Default number of iterations
	unsigned long iterations = 1;
	
	// Default mode, verbosity, device ID
	int change_addr = 1;
	int verbose = 0;
	int device = -1;
	
	// MAC struct
	bdaddr_t bdaddr;
	bacpy(&bdaddr, BDADDR_ANY);
	char addr[19] = {0};

	while ((opt=getopt_long(argc, argv, "+t:d:c:i:hvm", main_options, NULL)) != EOF)
	{
		// Handle options
		switch (opt)
		{
		case 'i':
			if (!strncasecmp(optarg, "hci", 3))
				hci_devba(atoi(optarg + 3), &bdaddr);
			else
				str2ba(optarg, &bdaddr);
			break;		
		case 't':
			numthreads = atoi(optarg);		
			if (numthreads > MAX_THREADS || numthreads <= 0)
			{
				printf("Invalid number of threads. See README.\n");
				exit(1);
			}
			break;
		case 'd':
			delay = atoi(optarg);		
			if (delay > MAX_DELAY || delay <= 0)
			{
				printf("Invalid delay value. See README.\n");
				exit(1);
			}
			break;			
		case 'c':
			iterations = atoi(optarg);
			if (iterations <= 0)
			{
				printf("Parameter cannot be negative..\n");
				exit(1);
			}
			break;
		case 'v':
			verbose = 1;
			break;
		case 'm':
			change_addr = 1;
			break;
		case 'h':
			help();
			exit(0);
		default:
			printf("Unknown option. Use -h for help, or see README.\n");
			exit(0);
		}
	}
	
	// Check if we are running as root
	if(getuid() != 0)
	{
		printf("You need to be root to run Bluefog!\n");
		exit(1);
	}
	
	// Check to see if iterations is divisible by thread count
	if ( iterations % numthreads != 0 )
	{
		printf(
		"Iterations cannot be evenly distributed among the current number of"
		" threads.\nAdjust input variables and try again.\n");
		exit(1);
	}
		
	// Seed PRNG
	srand(time(NULL));
	
	// Boilerplate
	printf("%s (v%s) by MS3FGX\n", APPNAME, VERSION);
	printf("---------------------------\n");
		
	// Select hardware
	ba2str(&bdaddr, addr);
	if (!strcmp(addr, "00:00:00:00:00:00"))
	{
		printf("Bluetooth Interface: Automatic\n");
	}
	else
	{
		numthreads = 1;
		device = hci_devid(addr);		
		printf("Bluetooth Interface: hci%i\n", device);
	}

	printf("Available device names: %i\n", dev_max + 1);
	printf("Spoofing %lu devices on %i threads.\n", iterations, numthreads);
	printf("Fogging...\n");

	for( t = 0; t < numthreads; t++ )
	{
		// Thread ID number
		thread_data_array[t].thread_id = t;
		
		// Device number
		if (device == -1)
			thread_data_array[t].device = t;
		else
			thread_data_array[t].device = device;
			
		// Default information for all threads
		thread_data_array[t].iterations = iterations / numthreads;
		thread_data_array[t].change_addr = change_addr;
		thread_data_array[t].verbose = verbose;
		thread_data_array[t].delay = delay;
		
		// Start thread
		pthread_create(&threads[t], NULL, thread_spoof, (void *)
			&thread_data_array[t]);
			
		// Sleep for a second to stagger threads (needs experimentation)
		if (numthreads > 1)
			sleep (THREAD_DELAY);
	}
	
	// Wait for threads to complete
	for ( t = 0; t < numthreads; t++ )
		pthread_join(threads[t], NULL);
			
	// Close up
	printf("Done.\n");
	exit(0);
}
