## Author Information

**Author:** Denys Chernenko  
**Login:** xchern08  
**Date Created:** 19.10.2024  

## Program Description

This program is designed to parse DNS packets and supports the following types of records: A, AAAA, MX, SOA, SRV, NS, and CNAME. It includes the following features and functionalities:

- **Output Information**: Displays information about packets, such as source IP, destination IP, domain names, DNS packet ID, etc.
- **Write Domain Names to File**: With the `-d` parameter and the name of the file, the program will write every unique domain name to the specified file.
- **Write Domain Names with Their IPs to File**: With the `-t` parameter, the program will write each unique domain name along with its IP address to the specified file.
- **Additional Note**: The program supports both verbose and non-verbose output formats. If the program encounters a packet with an unhandled record type, it will print `UNKNOWN TYPE`. If the packet does not contain a UDP header, it will simply skip it. The program supports the following record types: A, AAAA, MX, SOA, SRV, NS, and CNAME, and works only with packets that include a UDP header.

    Additionally, for the `-d` and `-t` parameters, if the specified file does not exist, the program will create it. If the file already exists, it will be overwritten with new information. *(See `manual.pdf` for more details.)*
- **Extensions**: The program supports the `-h` parameter, which provides a help message describing the parameters and shows examples of usage. When the `-h` parameter is provided, the program will execute and output only the help, than end the program.


## Usage Examples
First, run the `make` command to ensure everything works correctly. This will create the `dns-monitor` executable, which you can then use to try all the usage examples described below.



### Example 1: Monitor DNS Queries on an Interface

To monitor DNS queries on a specific network interface (here is `eth0`) in non verbose mode, run the following command:

```bash
./dns-monitor -i eth0
```

Or same command but monitor DNS queries with a verbose mode turned of
```bash
./dns-monitor -i eth0 -v
```
### Example 2: Monitor DNS Queries on an Interface with loggin domain names

To log the domain names found in DNS messages to a file named domains.txt, use:
```bash
./dns-monitor -i eth0 -d output.txt
```
After running command, output.txt will look like that:
```
some.domain.name
www.example.com
```

### Example 3: Monitor DNS Queries on an Interface with loggin domain names and IP adresses related to them

To log translations of domain names to IP addresses in a file named output.txt, run:

```bash
./dns-monitor -i eth0 -t output.txt
```

After running command, output.txt will look like that:

```
some.domain.ua 1.1.1.1
some.domain.com 1.1.2.2
```


### Example 4: Monitor DNS Queries within a PCAP File

All features described previously work the same when a PCAP file is provided instead of an interface. However, the program will execute until all packets in the provided PCAP file have been processed.

Verbose output with provided pcap file
```bash
./dns-monitor -p some_pcap_file.pcap -v
```

Verbose output with logging domain names with provided pcap file
```bash
./dns-monitor -p some_pcap_file_2.pcap -v -d output.txt
```

Non verbose output with logging domain names and their related IP adresses with provided pcap file
```bash
./dns-monitor -p some_pcap_file_3.pcap -t output.txt
```

### Example 5: Help Parameter Provided

The program will display a help message and immediately terminate. The help message contains examples of usage and detailed descriptions of each parameter.

```bash
./dns-monitor -h
```

## List of All Files

```

Makefile
README.md
manual.pdf

dns-monitor.c
dns-monitor.h

arguments-parse.c
arguments-parse.h

packet-capture.c
packet-capture.h

domain-file-handle.c
domain-file-handle.h
```
