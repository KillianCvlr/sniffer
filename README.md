# Sniffer Project
A C-coded sniffer using the pcap library for the "Service Réseau" course at 
Télécom Physique Strasbourg. Made by Killian Cavalier.
Catches network packets thanks to the pcap librairy and analyses them with
my personal code or the headers provided by the net/netinet librairies.
Prints in color with the ansi_color librairy under public domain,
wich is suported in most Shell terminal. 

## Strucutre

The project is divided in the src and include directories (object and bin only used during the compilation).
In each of this directories you should find the project files and their headers.
See the "include/protols" and "include/protols" directories for the different protocols implmented.

## Usage
In order to compile the binary, you should use the Makefile (simply type "make")

```c
Usage : sudo ./bin/sniffer <options>

Available options : 
	 -i <device> : Device to listen on
	 -o <file> : File to open (.pcap)
	 -f <filter> : Filter used during sniffing
	 -v <1|2|3> : Verbosity of the output
                    (1 = concise, 2 = synthetic, 3 = complete)
	 -n <integer> : Number of packet to analyse

```

The output printed is colored according to the layer of the encapsulation of the packet.
### Default settings
Without options setted by the user, the program listens on the standard
device and lists the ones available. It will stop working only if Ctrl+c is 
pressed by the user.
Verbosity is set to 3 by default which provide a complete analysis of the packages.

### Verbosity level
Here are the main features of the verbosity level :
- **Verbosity Level 1** : One line per packet catched. 
Prints the packet's id (= number of packet captured before) 
and parse TCP flags and most of the applicative protocols options
- **Verbosity Level 2** : No more than 3 lines per protocol.
- **Verbosity Level 3** : Complete analysis, prints every info available
concerning the packet.

## Implementation
The sniffer supports the following protocols :
- **Ethernet** : Complete analysis
- **Ipv4 & Ipv6** : Complete analysis
- **ICMP & ICMPv6** : Complete analysis
- **ARP** : Complete analysis
- **UDP** : Complete analysis
- **TCP** : Anlyses deeply the header but do not parse the options
- **HTTP** : Print the packet's content without parsing
- **DNS** : Analyses the header but do not print the queries and responses
- **BOOTP & DHCP** : Complete analysis and parsage of the DHCP flags
- **IMAP** : Synthesises the options and print the packet's content if needed
- **POP3** : Prints the packet's content
- **FTP** : Prints the packet's content
- **SMTP** : Prints the packet's content
- **TELNET** : Supports the diversity of TELNET flags, making them readable.
- ***DATA*** : When not supported, protocols are simply printed as *DATA (source_port - destination_port)*

### MAIN
The main function is situated in sniffer.c
