/* 
 *  Bluefog - Create phantom Bluetooth devices
 * 
 *  Bluefog is a tool to create phantom Bluetooth devices. Can be used
 *  to confuse attackers or test Bluetooth detection systems.
 * 
 *  Written by Tom Nardi (MS3FGX@gmail.com), released under the GPLv2.
 *  For more information, see: www.digifail.com
 */

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
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

#define VERSION	"0.0.2"
#define APPNAME "Bluefog"

// Sane defaults
#define MAX_THREADS 6
#define THREAD_DELAY 1
#define MAX_DELAY 300
#define SHUTDOWN_WAIT 2
#define DEFAULT_CLASS "0x5a020c"

// Global variables
int verbose = 0;
int end_threads = 0;
int c_count = 0;

// Data to pass to threads
struct thread_data
{
	int thread_id;
	int change_addr;
	int change_class;
	char *static_name;
	int device;
	int delay;
};

struct thread_data thread_data_array[MAX_THREADS];

void shut_down(int sig)
{
	// Close up shop
	printf("\n");
	printf("Sending threads kill command\n");
	//end_threads = 1;
	printf("Count: %i\n", c_count);
	c_count++;
	//exit(sig);
}

char* get_localtime()
{
	// Time variables
	time_t rawtime;
	struct tm * timeinfo;
	static char time_string[20];
	
	// Find time and put it into time_string
	time (&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(time_string,20,"%D %T",timeinfo);
	
	// Send it back
	return(time_string);
}

// Open BT socket and return ID
int get_bt_socket (int device)
{
	int bt_socket;	
	bt_socket = hci_open_dev(device);
	if (bt_socket < 0)
	{
		printf("Failed to initalize hci%i!\n", device);
		exit(1); // TODO: Better shutdown
	}
	return(bt_socket);
}

// Write class info
int write_class (int bt_socket, int device, char *class)
{
	uint32_t cod = strtoul(class, NULL, 16);
	if (hci_write_class_of_dev(bt_socket, cod, 2000) < 0)
		fprintf(stderr,"Can't write local class of device on hci%d: %s (%d)\n", device, strerror(errno), errno);

	return(0);
}

// Select random name from list within range
char* random_name (void)
{	
	return (device_name[((rand() % dev_max) + 1)] );	
}

// Generate random MAC address
// Adapted from "SpoofTooph" by JP Dunning (.ronin)
char* random_addr (void)
{	
	char addr_part[3] = {0};
	static char addr[18] = {0};
	int i = 0;
	
	// Start off the MAC with 00:
	addr[i++] = '0';
	addr[i++] = '0';
	addr[i++] = ':';
	
	// Fill in the middle
	while ( i < 14)
	{
		sprintf(addr_part, "%02x", (rand() % 254));	
		addr[i++] = addr_part[0];
		addr[i++] = addr_part[1];
		addr[i++] = ':';
	}

	// Tack 2 more random characters to finish it
	sprintf(addr_part, "%02x", (rand() % 254));	
	addr[i++] = addr_part[0];
	addr[i++] = addr_part[1];
		
	return(addr);
}

void *thread_spoof(void *threadarg)
{		
	// Define variables from struct
	int thread_id, change_addr, device, delay, change_class;
	char *static_name;
	
	// Local use variables
	int bt_socket;

	// Pull data out of struct
	struct thread_data *local_data;
	local_data = (struct thread_data *) threadarg;
	thread_id = local_data->thread_id;
	device = local_data->device;
	change_addr = local_data->change_addr;
	delay = local_data->delay;
	change_class = local_data->change_class;
	static_name = local_data->static_name;
	
	// MAC struct
	bdaddr_t bdaddr;
	bacpy(&bdaddr, BDADDR_ANY);
	struct hci_dev_info di;
	char addr_ref[18] = {0};
	char addr_buff[18] = {0};
	
	// Buffers for verbose, ridiculous
	char *addr_buffer = {0};
	char *name_buffer = {0};
	
	// For discoverability
	struct hci_dev_req dr;
	dr.dev_id  = device;
	dr.dev_opt = SCAN_PAGE | SCAN_INQUIRY;
	
	// Device class
	char class[9] = {0};
		
	// Init device	
	if (verbose)
		printf("Initalizing hci%i on thread %i.\n", device, thread_id);

	// Get a socket
	bt_socket = get_bt_socket(device);
		
	// Get MAC for reference
	if (hci_read_bd_addr(bt_socket, &bdaddr, 1000) < 0)
	{
			fprintf(stderr, "Can't read address for hci%d: %s (%d)\n", device, strerror(errno), errno);
			hci_close_dev(bt_socket);
	}
	
	// Original MAC stored to addr_ref
	ba2str(&bdaddr, addr_ref);
	
	printf("Threads: %i\n", end_threads);
	while (end_threads != 1)
	{				
		// Attempt to change address first, since it probably requires reset
		if (change_addr)
		{
			addr_buffer = random_addr();
			if (cmd_bdaddr(device, bt_socket, addr_buffer) == 2)
			{
				// This type of device needs to be manually restarted
				hci_close_dev(bt_socket);
				sleep(SHUTDOWN_WAIT);
				bt_socket = get_bt_socket(device);
			}
		}
		
		// Always change name
		if (static_name != NULL)
			name_buffer = static_name;
		else
			name_buffer = random_name();
		
		if (hci_write_local_name(bt_socket, name_buffer, 2000) < 0)
			fprintf(stderr, "Can't change local name on hci%d: %s (%d)\n", device, strerror(errno), errno);
			
		// Change class
		if (change_class)
		{
			// Generate a random class
			int major = (rand() % 9);
			int minor = (rand() % 6);
	
			// Randomly add service flags
			int flag = 0;              
			if (rand() % 2) flag += 1;
			if (rand() % 2) flag += 2;
			if (rand() % 2) flag += 4;
			if (rand() % 2) flag += 8;
			if (rand() % 2) flag += 10;
			if (rand() % 2) flag += 20;
			if (rand() % 2) flag += 40;
			if (rand() % 2) flag += 80;

			// Put class into string
			sprintf(class, "0x%02x%02x%02x", flag, major, minor);		
			write_class(bt_socket, device, class);
		}
		else
		{
			strcpy(class, DEFAULT_CLASS);		
		}	write_class(bt_socket, device, class);

		// Make discoverable
		if (ioctl(bt_socket, HCISETSCAN, (unsigned long) &dr) < 0)
		{
			fprintf(stderr, "Can't set scan mode on hci%d: %s (%d)\n", device, strerror(errno), errno);
			exit(1);
		}

		// Print device if verbose
		if (verbose)
			printf("hci%i - Name: %s Class: %s MAC: %s\n", device, name_buffer, class, addr_buffer);
		
		// Wait
		sleep(delay);
							
		// Verify MAC actually changed
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
			
		if ((strcmp (addr_ref, addr_buff) == 0))
		{
			printf("MAC on interface hci%i is not changing. Hardware is likely not compatible.\n", device);
			printf("Disabling MAC changing for this interface. See README for more info.\n");
			change_addr = 0;
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
	printf("%s (v%s) by Tom Nardi \"MS3FGX\" (MS3FGX@gmail.com)\n", APPNAME, VERSION);
	printf("----------------------------------------------------------------\n");
	printf("Bluefog is a tool used to create phantom Bluetooth devices. It can\n"
		"be used to confuse attackers or test Bluetooth detection systems.\n");
	printf("\n");
	printf("At the moment, Bluefog has only been tested with CSR and Broadcom\n"
			"chipsets. Compatibility reports from other devices would be\n"
			"greatly appreciated\n");
	printf("\n");
	printf("For more information, see www.digifail.com\n");
	printf("\n");
	printf("Options:\n"
		"\t-i <interface>   Manually select device to use, default is automatic\n"
		"\t-t <threads>     Set this to match how many Bluetooth adapters you have\n"
		"\t-n <name>        Sets a static device name instead of random\n"
		"\t-d <seconds>     How many seconds to wait between spoofs, default 30\n"
		"\t-m               Toggle randomization of MAC address, default is enabled\n"
		"\t-c               Toggle randomization of class info, default disabled\n"
		"\t-v               Toggle verbose messages, default disabled\n"
		"\n");
}

static struct option main_options[] = {
	{ "interface", 1, 0, 'i' },
	{ "threads", 1, 0, 't' },
	{ "name", 1, 0, 'n' },
	{ "delay", 1, 0, 'd' },
	{ "class", 1, 0, 'c' },
	{ "mac", 0, 0, 'm' },
	{ "verbose", 0, 0, 'v' },
	{ "help", 0, 0, 'h' },
	{ 0, 0, 0, 0 }
};
 
int main(int argc, char *argv[])
{
	// Handle signals
	signal(SIGINT,shut_down);
	//signal(SIGHUP,shut_down);
	//signal(SIGTERM,shut_down);
	//signal(SIGQUIT,shut_down);
	
	// General variables
	int t, opt;
		
	// Thread ID
	pthread_t threads[MAX_THREADS];
		
	// MAC struct
	bdaddr_t bdaddr;
	bacpy(&bdaddr, BDADDR_ANY);
	char addr[19] = {0};
	
	// Options
	int numthreads = 1;
	int delay = 30;
	int change_addr = 1;
	int change_class = 1;
	int device = -1;	
	char *static_name = NULL;

	// Process options
	while ((opt=getopt_long(argc, argv, "+t:d:i:n:mchv", main_options, NULL)) != EOF)
	{
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
			if (delay > MAX_DELAY || delay <= 4)
			{
				printf("Invalid delay value. See README.\n");
				exit(1);
			}
			break;			
		case 'c':
			change_class = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'm':
			change_addr = 0;
			break;
		case 'n':
			static_name = strdup(optarg);			
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
			
	// Seed PRNG
	srand(time(NULL));
	
	// Boilerplate
	printf("%s (v%s) by MS3FGX\n", APPNAME, VERSION);
	printf("---------------------------\n");
				
	// Select hardware
	printf("Bluetooth Interface: ");
	ba2str(&bdaddr, addr);
	if (!strcmp(addr, "00:00:00:00:00:00"))
	{
		printf("Auto\n");
	}
	else
	{
		numthreads = 1;
		device = hci_devid(addr);		
		printf("hci%i\n", device);
	}

	// Static or random names
	printf("Device Name: ");
	if (static_name == NULL)
	{
		printf("Randomized\n");
		
		// Number of names loaded
		printf("Available Names: %i\n", dev_max - 1);
	}
	else
		printf("Static (%s)\n", static_name);
	
	// Static or random addr
	printf("MAC Address: ");
	if (change_class)
		printf("Randomized\n");
	else
		printf("Default\n");	

	// Static or random class
	printf("Device Class: ");
	if (change_class)
		printf("Randomized\n");
	else
		printf("Static (%s)\n", DEFAULT_CLASS);

	printf("Fogging started at [%s] on %i threads.\n", get_localtime(), numthreads);
	printf("Hit Ctrl+C to end.\n");	

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
		thread_data_array[t].change_addr = change_addr;
		thread_data_array[t].change_class = change_class;
		thread_data_array[t].static_name = static_name;
		thread_data_array[t].delay = delay;
		
		// Start thread
		pthread_create(&threads[t], NULL, thread_spoof, (void *)
			&thread_data_array[t]);
			
		// Sleep for a second to stagger threads (needs experimentation)
		if (numthreads > 1)
			sleep (delay / numthreads);
	}
	
	// Wait for threads to complete
	for ( t = 0; t < numthreads; t++ )
		pthread_join(threads[t], NULL);
			
	// Close up
	printf("Done.\n");
	exit(0);
}
