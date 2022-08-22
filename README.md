# XDP firewall

A stateless firewall that attaches to the [XDP](https://www.iovisor.org/technology/xdp) hook for fast packet processing. This firewall is designed to read filter rules from the command line and filter incoming packets. Both only IPv4. Supported protocols include TCP, UDP, and ICMP at the moment. With that said, the program comes with accepted and blocked packet statistics.


# Filtration commands

Usage: xdp-firewall [command] ...
* `*start` [device name] Enable filtering for the specified network device.
* `stop` [device name] Disaable filtering for the specified network device.
* `add` [device name] [command arguments add] Adds a new filter.
* `clear` [device name] Clears the list of arguments.

Each of the arguments to the add command is optional, but there must be at least one.
Argument list for the add command:
* `--proto` [name] Set the protocol name. Supported ICMP, TCP, UDP.
* `--ip_src` [ip] Set the source ip.
* `--ip_dst` [ip] Set the destination ip.
* `--port_src` [port] Set the source port.
* `--port_dst` [port] Set the destination port.

# Examples

* Start filtering:
```
sudo xdp-firewall start enp4s0
```
* Blocking ICMP:
```
sudo xdp-firewall add enp4s0 --proto icmp
```
* Blocking TCP traffic only from 192.168.0.5.
```
sudo xdp-firewall add enp4s0 --proto tcp --ip_src 192.168.0.5
```

# Statistics output
```
sudo ./xdp_stats --dev device_name
```


# Build
## Packages on Debian/Ubuntu
On Debian and Ubuntu installations, install the dependencies like this:
```
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
```
To install the ‘perf’ utility, run this on Debian:
```
sudo apt install linux-perf
```
or this on Ubuntu:
```
sudo apt install linux-tools-$(uname -r)
```
Build:
```
make
```