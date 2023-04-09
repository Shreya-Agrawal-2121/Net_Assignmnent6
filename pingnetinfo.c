/*
    Raw TCP packets
*/
#include <stdio.h>      //for printf
#include <string.h>     //memset
#include <sys/socket.h> //for socket ofcourse
#include <stdlib.h>     //for exit(0);
#include <errno.h>      //For errno - the error number	//Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header
#include <arpa/inet.h>  // inet_addr
#include <unistd.h>     // sleep()
#include <linux/tcp.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fcntl.h>
#include <netdb.h>
#define TIMEOUT 1000000
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        *(unsigned char *)(&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        perror("Insufficient arguments given\n");
        exit(1);
    }
    struct hostent *h = gethostbyname(argv[1]);
    if (h == NULL)
    {
        perror("Could not resolve host name");
        exit(1);
    }
    int n = atoi(argv[2]);
    int T = atoi(argv[3]);
    struct sockaddr_in dest_addr, source_addr;
    dest_addr.sin_family = AF_INET;
    struct in_addr ipaddr = *(struct in_addr *)h->h_addr_list[0];
    dest_addr.sin_addr = ipaddr;
    dest_addr.sin_port = htons(32164);
    source_addr.sin_family = AF_INET;
    source_addr.sin_port = htons(20000);
    source_addr.sin_addr.s_addr = INADDR_ANY;
    int sock_icmp;
    if ((sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("ICMP socket creation failed\n");
        exit(1);
    }
    int one = 1, ttl = 1;
    if (setsockopt(sock_icmp, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("Set options for ICMP socket failed\n");
        exit(1);
    }
    /*
    if (bind(sock_icmp, (struct sockaddr *)&source_addr, sizeof(source_addr)) < 0)
    {
        perror("Bind for ICMP socket failed\n");
        exit(1);
    }*/
    struct sockaddr_in source_now;
    source_now.sin_addr.s_addr = source_addr.sin_addr.s_addr;
    source_now.sin_family = AF_INET;
    source_now.sin_port = htons(20000);
    printf("Dest IP: %s\n", inet_ntoa(dest_addr.sin_addr));
    int dest_link_found = 0;
    int msg = 0;
    while (1)
    {
        int done = 0, timeout = 0;
        struct timeval tv_out;
        tv_out.tv_sec = 0;
        tv_out.tv_usec = TIMEOUT;
        setsockopt(sock_icmp, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_out, sizeof(tv_out));
        struct sockaddr_in from_arr[5];
        int last_idx = 0;
        int is_dest = 0;
        struct sockaddr_in from_addr,nth_hop_addr;
        int from_len = sizeof(from_addr);
        int all_same = 0;
        while (!all_same)
        {
            is_dest = 0;
            all_same = 1;
            for (int i = 0; i < 5; i++)
            {
                struct timeval tout;
                tout.tv_usec = TIMEOUT;
                tout.tv_sec = 0;
                struct iphdr *iph;
                struct icmphdr *icmph;
                char datagram[4096] = "\0", *data;
                iph = (struct iphdr *)datagram;
                icmph = (struct icmphdr *)(datagram + sizeof(struct iphdr));
                iph->ihl = 5;
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
                iph->check = 0;
                iph->daddr = dest_addr.sin_addr.s_addr;
                iph->saddr = source_addr.sin_addr.s_addr;
                iph->ttl = ttl;
                iph->frag_off = 0;
                iph->id = 10000;
                iph->tos = 0;
                iph->version = 4;
                iph->protocol = IPPROTO_ICMP;
                iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));
                icmph->type = ICMP_ECHO;
                icmph->un.echo.id = getpid();
                icmph->un.echo.sequence = msg++;
                icmph->code = 0;
                icmph->checksum = csum((unsigned short *)(datagram + sizeof(struct iphdr)), sizeof(struct icmphdr));
                if (sendto(sock_icmp, datagram, sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
                {
                    perror("Send failed\n");
                    exit(1);
                }

                char buf[4096];
                recvfrom(sock_icmp, buf, sizeof(buf), 0, (struct sockaddr *)&from_addr, &from_len);
                struct iphdr *recv_iph;
                recv_iph = (struct iphdr *)buf;
                if (recv_iph->protocol == IPPROTO_ICMP)
                {
                    icmph = (struct icmphdr *)(buf + sizeof(struct iphdr));
                    if (icmph->type == ICMP_TIME_EXCEEDED && icmph->code == ICMP_EXC_TTL)
                    {
                        if(i == 0)
                            nth_hop_addr = from_addr;
                        else if(from_addr.sin_addr.s_addr != nth_hop_addr.sin_addr.s_addr){
                            all_same = 0;
                        }
                        //from_arr[last_idx++] = from_addr;
                    }
                    else if (icmph->type == ICMP_ECHOREPLY && recv_iph->saddr == dest_addr.sin_addr.s_addr)
                    {
                        //from_arr[last_idx++] = from_addr;
                        if(i == 0)
                            nth_hop_addr = from_addr;
                        else if(from_addr.sin_addr.s_addr != nth_hop_addr.sin_addr.s_addr){
                            all_same = 0;
                        }
                        is_dest = 1;
                    }
                    else
                    {
                    }
                }
            }
        }
        from_addr = nth_hop_addr;
            if (is_dest)
            {
                printf("Destination reached at hop %d with ip %s\n", ttl, inet_ntoa(from_addr.sin_addr));
               
                exit(0);
            }
            else
            {
                printf("Node reached at hop %d with ip %s\n", ttl, inet_ntoa(from_addr.sin_addr));
                
            }
        
        tv_out.tv_sec = T;
        tv_out.tv_usec = 0;

        setsockopt(sock_icmp, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_out, sizeof(tv_out));
        for (int sz = 0; sz < 1; sz++)
        {
            for (int i = 0; i < n; i++)
            {
                char datagram[4096] = "\0";
                struct iphdr *ping_iph;
                struct icmphdr *ping_icmph;
                ping_iph = (struct iphdr *)datagram;
                ping_icmph = (struct icmphdr *)(datagram + sizeof(struct iphdr));
                ping_iph->ihl = 5;
                ping_iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sz);
                ping_iph->check = 0;
                ping_iph->daddr = from_addr.sin_addr.s_addr;
                ping_iph->saddr = source_addr.sin_addr.s_addr;
                ping_iph->ttl = ttl;
                ping_iph->frag_off = 0;
                ping_iph->id = 10000;
                ping_iph->tos = 0;
                ping_iph->version = 4;
                ping_iph->protocol = IPPROTO_ICMP;
                ping_iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));
                ping_icmph->type = ICMP_ECHO;
                ping_icmph->un.echo.id = getpid();
                ping_icmph->un.echo.sequence = msg++;
                ping_icmph->code = 0;
                ping_icmph->checksum = csum((unsigned short *)(datagram + sizeof(struct iphdr)), sizeof(struct icmphdr));
                char *data;
                data = (char *)(datagram + sizeof(struct iphdr) + sizeof(struct icmphdr));
                if (sz == 0)
                {
                    strcpy(data, "\0");
                }
                else
                {
                    char buf[sz];
                    strcpy(buf, "\0");
                    for (int idx = 0; idx < sz; idx++)
                        buf[idx] = rand() % 26 + 'a';
                    strcpy(data, buf);
                }
                struct timeval curr_time, recv_time;
                gettimeofday(&curr_time, NULL);
                char recv_buf[4096];
                sendto(sock_icmp, datagram, sizeof(struct iphdr) + sizeof(struct icmphdr) + sz, 0, (struct sockaddr *)&from_addr, sizeof(from_addr));
                struct sockaddr_in from_addr_ping;
                int fromlen = sizeof(from_addr_ping);
                recvfrom(sock_icmp, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from_addr_ping, &fromlen);
                struct iphdr *ping_recv_iph;
                struct icmphdr *ping_recv_icmph;
                ping_recv_iph = (struct iphdr *)recv_buf;
                ping_recv_icmph = (struct icmphdr *)(recv_buf + sizeof(struct iphdr));
                if (ping_recv_iph->protocol == IPPROTO_ICMP)
                {
                    if (ping_recv_icmph->type == ICMP_ECHOREPLY && ping_recv_iph->saddr == from_addr.sin_addr.s_addr)
                    {
                        gettimeofday(&recv_time, NULL);
                        printf("Echo reply received on IP: %s\n", inet_ntoa(from_addr.sin_addr));
                    }
                }
            }
        }

        ttl++;
    }
    return 0;
}