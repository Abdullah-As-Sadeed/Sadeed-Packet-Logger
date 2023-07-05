# Sadeed-Packet-Logger
Detects TCP (Transmission Control Protocol) and UDP (User Datagram Protocol) packets and logs their source and destination. Works on Linux.

## Compilation
### Installing Dependencies
On Fedora,
```
sudo dnf install libpcap-devel
```

On Ubuntu and its derivatives,
```
sudo apt install libpcap-dev
```

### Compiling
Use GCC (the GNU Compiler Collection) and remember to link against the Packet Capture (PCAP) library.
```
gcc ./Sadeed_Packet_Logger.cpp -o ./Sadeed_Packet_Logger -lpcap
```

## Usage
Give the name of the target network interface as an argument.
```
sudo ./Sadeed_Packet_Logger wlo1
```

A text file named **Packet_Logs.txt** will be generated in the directory in which the program is running. So, make sure the program or the current user has sufficient permission to do so. The file will contain the log also.
