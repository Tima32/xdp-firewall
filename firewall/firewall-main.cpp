#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <sys/wait.h>
#include <string.h>
#include "ArgumentParser.hpp"
#include "common_defines.h"

using namespace std;

static string dev;

static void PrintHelp()
{
	static constexpr auto str =
		"Usage: xdp-firewall [options]\n"
		"	--dev / -d [dev name] The device to which the filter will be applied."
		"	--block [protocol]\n"
		"	--filter [protocol] [ip-src] [ip-dst] [port-src] [port-dst]\n"
		"	--range [protocol] [ip-src-begin] [ip-src-end] [ip-dst-begin] [ip-dst-end]\n"
		"		[port-src-begin] [port-src-end] [port-dst-begin] [port-dst-end]\n";

	cout << str << endl;
}

bool GetDevice(ArgumentParser& ap)
{
	try
	{
		dev = ap.get<string>("--dev", "");
		dev = ap.get<string>("-d", dev);
		if (dev.size() == 0)
		{
			cout << "Err: You must specify the name of the network device." << endl;
			return false;
		}
		return true;
	}
	catch (const std::exception &e)
	{
		std::cerr << e.what() << '\n';
		return false;
	}
}
static bool LoadProgKern()
{
	// -d enp4s0 --filename ./kern/xdp_prog_kern.o -S

	const char* argv[] = {"./xdp_loader", "-d", "", "--filename", "./kern/xdp_prog_kern.o", "-S",(char *)0};
	argv[2] = dev.c_str();

	int status;
	pid_t pid;
	
	fflush(NULL);
	status = posix_spawn(&pid, "./xdp_loader", NULL, NULL, (char*const*)argv, environ);
	if (status == 0)
	{
		printf("Child id: %i\n", pid);
		fflush(NULL);
		if (waitpid(pid, &status, 0) != -1)
		{
			printf("Child exited with status %d\n", status);
			if (status != 0 && WEXITSTATUS(status) != EXIT_FAIL_XDP_LOADED)
			{
				cout << "<PosixSpawn>Error: Loader rturn code " << WEXITSTATUS(status) << endl;
				return false;
			}
		}
		else
		{
			perror("waitpid");
			return false;
		}
	}
	else
	{
		printf("posix_spawn: %s\n", strerror(status));
		return false;
	}
	return true;
}
static bool UnloadProgKern()
{
	// -d enp4s0 --filename ./kern/xdp_prog_kern.o -S

	const char* argv[] = {"./xdp_loader", "-d", "", "--filename", "./kern/xdp_prog_kern.o", "-S", "-U",(char *)0};
	argv[2] = dev.c_str();

	int status;
	pid_t pid;
	
	fflush(NULL);
	status = posix_spawn(&pid, "./xdp_loader", NULL, NULL, (char*const*)argv, environ);
	if (status == 0)
	{
		printf("Child id: %i\n", pid);
		fflush(NULL);
		if (waitpid(pid, &status, 0) != -1)
		{
			printf("Child exited with status %d\n", status);
			if (status != 0 && WEXITSTATUS(status) != EXIT_FAIL_XDP_LOADED)
			{
				cout << "<PosixSpawn>Error: Loader rturn code " << WEXITSTATUS(status) << endl;
				return false;
			}
		}
		else
		{
			perror("waitpid");
			return false;
		}
	}
	else
	{
		printf("posix_spawn: %s\n", strerror(status));
		return false;
	}
	return true;
}

static void CommandStart(ArgumentParser& ap)
{
	if (ap.size() < 3)
	{
		cout << "Error: The network device name was not specified." << endl;
		exit(-1);
	}

	dev = ap[2];

	if (!LoadProgKern())
	{
		cout << "<CommandStart>Error: Failed to start bootloader." << endl;
	}
}
static void CommandStop(ArgumentParser& ap)
{
	if (ap.size() < 3)
	{
		cout << "Error: The network device name was not specified." << endl;
		exit(-1);
	}

	dev = ap[2];
	
	if (!UnloadProgKern())
	{
		cout << "<CommandStart>Error: Failed to start bootloader." << endl;
	}
}
extern void CommandAdd(ArgumentParser& ap);
extern void CommandClear(ArgumentParser& ap);

int main(int argc, const char **argv)
{	
	ArgumentParser ap(argc, argv);

	// Help
	auto help_pos = ap.find("--help");
	if (help_pos != ArgumentParser::not_found || argc < 2)
	{
		PrintHelp();
		return 0;
	}

	if (ap[1] == "start")
	{
		CommandStart(ap);
		return 0;
	}

	if (ap[1] == "stop")
	{
		CommandStop(ap);
		return 0;
	}

	if (ap[1] == "add")
	{
		CommandAdd(ap);
		return 0;
	}

	if (ap[1] == "del")
	{
		return 0;
	}

	if (ap[1] == "clear")
	{
		CommandClear(ap);
		return 0;
	}

	//Filters::InitFiltersArray();

	return 0;
}
