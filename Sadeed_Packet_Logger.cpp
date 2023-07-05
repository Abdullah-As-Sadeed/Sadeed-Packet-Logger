/* By Abdullah As-Sadeed */

/*
gcc ./Sadeed_Packet_Logger.cpp -o ./Sadeed_Packet_Logger -lpcap
*/

#include "csignal"
#include "iostream"
#include "netinet/if_ether.h"
#include "netinet/ip.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "pcap.h"
#include "stdio.h"
#include "string.h"

#define TERMINAL_TITLE_START "\033]0;"
#define TERMINAL_TITLE_END "\007"

#define TERMINAL_BOLD_START "\033[1m"
#define TERMINAL_BOLD_END "\033[0m"

#define TERMINAL_ANSI_COLOR_RED "\x1b[31m"
#define TERMINAL_ANSI_COLOR_GREEN "\x1b[32m"
#define TERMINAL_ANSI_COLOR_YELLOW "\x1b[33m"
#define TERMINAL_ANSI_COLOR_RESET "\x1b[0m"

#define MAXIMUM_PACKET_SIZE 65535

#define LOG_FILE "Packets_Log.txt"

struct Packet_Information
{
    char source_ip[INET_ADDRSTRLEN];
    char destination_ip[INET_ADDRSTRLEN];
    char domain_name[NI_MAXHOST];
    char protocol[10];
    int source_port;
    int destination_port;
};

void Process_Packet(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet_data)
{
    struct ether_header *ether_header = (struct ether_header *)packet_data;

    /* Skip non-IP packets */
    if (ntohs(ether_header->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    struct ip *ip_header = (struct ip *)(packet_data + sizeof(struct ether_header));

    if (ip_header->ip_p != IPPROTO_TCP && ip_header->ip_p != IPPROTO_UDP)
    {
        return;
    }

    struct Packet_Information packet_information;

    inet_ntop(AF_INET, &(ip_header->ip_src), packet_information.source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), packet_information.destination_ip, INET_ADDRSTRLEN);

    struct hostent *host;
    host = gethostbyaddr(&(ip_header->ip_dst), sizeof(struct in_addr), AF_INET);

    if (host != NULL)
    {
        strncpy(packet_information.domain_name, host->h_name, NI_MAXHOST);
    }
    else
    {
        strncpy(packet_information.domain_name, "Not Available", NI_MAXHOST);
    }

    if (ip_header->ip_p == IPPROTO_TCP)
    {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet_data + sizeof(struct ether_header) + sizeof(struct ip));

        strncpy(packet_information.protocol, "TCP", 10);

        packet_information.source_port = ntohs(tcp_header->th_sport);
        packet_information.destination_port = ntohs(tcp_header->th_dport);
    }
    else if (ip_header->ip_p == IPPROTO_UDP)
    {
        struct udphdr *udp_header = (struct udphdr *)(packet_data + sizeof(struct ether_header) + sizeof(struct ip));

        strncpy(packet_information.protocol, "UDP", 10);

        packet_information.source_port = ntohs(udp_header->uh_sport);
        packet_information.destination_port = ntohs(udp_header->uh_dport);
    }

    printf(TERMINAL_BOLD_START "Source IP: " TERMINAL_BOLD_END "%s\n", packet_information.source_ip);
    printf(TERMINAL_BOLD_START "Destination IP: " TERMINAL_BOLD_END "%s\n", packet_information.destination_ip);
    printf(TERMINAL_BOLD_START "Domain Name: " TERMINAL_BOLD_END "%s\n", packet_information.domain_name);
    printf(TERMINAL_BOLD_START "Protocol: " TERMINAL_BOLD_END "%s\n", packet_information.protocol);
    printf(TERMINAL_BOLD_START "Source Port: " TERMINAL_BOLD_END "%d\n", packet_information.source_port);
    printf(TERMINAL_BOLD_START "Destination Port: " TERMINAL_BOLD_END "%d\n", packet_information.destination_port);
    printf(TERMINAL_ANSI_COLOR_GREEN "----------------------------------------\n" TERMINAL_ANSI_COLOR_RESET);

    FILE *log_file = (FILE *)user;
    fprintf(log_file, "Source IP: %s\n", packet_information.source_ip);
    fprintf(log_file, "Destination IP: %s\n", packet_information.destination_ip);
    fprintf(log_file, "Domain Name: %s\n", packet_information.domain_name);
    fprintf(log_file, "Protocol: %s\n", packet_information.protocol);
    fprintf(log_file, "Source Port: %d\n", packet_information.source_port);
    fprintf(log_file, "Destination Port: %d\n", packet_information.destination_port);
    fprintf(log_file, "----------------------------------------\n");
}

void Handle_Signal(int signal)
{
    if (signal == SIGINT)
    {
        printf(TERMINAL_ANSI_COLOR_RED "\n\nYou interrupted me by SIGINT signal.\n" TERMINAL_ANSI_COLOR_RESET);
        printf(TERMINAL_ANSI_COLOR_GREEN "The log is saved as '%s'.\n" TERMINAL_ANSI_COLOR_RESET, LOG_FILE);
        exit(signal);
    }
}

int main(int argument_count, char *argument_values[])
{

    signal(SIGINT, Handle_Signal);

    printf(TERMINAL_TITLE_START "Sadeed Packet Logger" TERMINAL_TITLE_END);

    if (argument_count != 2)
    {
        printf(TERMINAL_ANSI_COLOR_YELLOW "Usage: %s <interface>\n" TERMINAL_ANSI_COLOR_RESET, argument_values[0]);
        return 1;
    }

    char *interface = argument_values[1];

    printf(TERMINAL_TITLE_START "Sadeed Packet Logger: listenting to %s" TERMINAL_TITLE_END, interface);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr packet_header;
    const u_char *packet_data;

    handle = pcap_open_live(interface, MAXIMUM_PACKET_SIZE, 1, 1000, errbuf);

    if (handle == NULL)
    {
        printf(TERMINAL_ANSI_COLOR_RED "Error opening device: %s\n" TERMINAL_ANSI_COLOR_RESET, errbuf);
        return 1;
    }

    struct bpf_program filter_pointer;
    char filter_expression[] = "tcp or udp";

    if (pcap_compile(handle, &filter_pointer, filter_expression, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf(TERMINAL_ANSI_COLOR_RED "Error compiling filter: %s\n" TERMINAL_ANSI_COLOR_RESET, pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &filter_pointer) == -1)
    {
        printf(TERMINAL_ANSI_COLOR_RED "Error setting filter: %s\n" TERMINAL_ANSI_COLOR_RESET, pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    FILE *log_file = fopen(LOG_FILE, "w");
    if (log_file == NULL)
    {
        printf(TERMINAL_ANSI_COLOR_RED "Error opening log file.\n" TERMINAL_ANSI_COLOR_RESET);
        pcap_close(handle);
        return 1;
    }

    printf(TERMINAL_ANSI_COLOR_GREEN "----------------------------------------\n" TERMINAL_ANSI_COLOR_RESET);

    /* Start capturing packets */
    pcap_loop(handle, -1, Process_Packet, (u_char *)log_file);

    printf(TERMINAL_ANSI_COLOR_GREEN "----------------------------------------\n" TERMINAL_ANSI_COLOR_RESET);

    pcap_close(handle);
    fclose(log_file);

    return 0;
}
