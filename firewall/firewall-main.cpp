#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <sys/wait.h>
#include <string.h>
#include "ArgumentParser.hpp"
#include "firewall-filters.hpp"
#include "common_defines.h"

using namespace std;

static string dev;

enum class ParseArgsStatus
{
	OK,
	ERR,
	EXIT,
};
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
static ParseArgsStatus ParseArgs(int argc, const char **argv)
{
	ArgumentParser ap(argc, argv);

	// Help
	auto help_pos = ap.find("--help");
	if (help_pos != ArgumentParser::not_found || argc == 1)
	{
		PrintHelp();
		return ParseArgsStatus::EXIT;
	}	

	// Device
	try
	{
		dev = ap.get<string>("--dev", "");
		dev = ap.get<string>("-d", dev);
		if (dev.size() == 0)
		{
			cout << "Err: You must specify the name of the network device." << endl;
			return ParseArgsStatus::ERR;
		}
	}
	catch (const std::exception &e)
	{
		std::cerr << e.what() << '\n';
		return ParseArgsStatus::ERR;
	}

	// Start
	try
	{
		dev = ap.get<string>("--start", "");
		dev = ap.get<string>("-s", dev);
		if (dev.size() == 0)
		{
			cout << "Err: You must specify the name of the network device." << endl;
			return ParseArgsStatus::ERR;
		}
	}
	catch (const std::exception &e)
	{
		std::cerr << e.what() << '\n';
		return ParseArgsStatus::ERR;
	}

	// Filters
	if (!Filters::ParseArgs(argc, argv))
	{
		return ParseArgsStatus::ERR;
	}

	return ParseArgsStatus::OK;
}
static bool GetDevice(ArgumentParser& ap)
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

void CommandStart(ArgumentParser& ap)
{
	if (!GetDevice(ap))
		exit(-1);

	if (!LoadProgKern())
	{
		cout << "<CommandStart>Error: Failed to start bootloader." << endl;
	}
}
void CommandStop(ArgumentParser& ap)
{
	if (!GetDevice(ap))
		exit(-1);
	
	if (!UnloadProgKern())
	{
		cout << "<CommandStart>Error: Failed to start bootloader." << endl;
	}
}

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
		return 0;
	}

	if (ap[1] == "del")
	{
		return 0;
	}

	if (ap[1] == "clear")
	{
		return 0;
	}

	//Filters::InitFiltersArray();

	return 0;
}
