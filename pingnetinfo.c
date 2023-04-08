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
        perror("Set options for UDP socket failed\n");
        exit(1);
    }
    if (bind(sock_icmp, (struct sockaddr *)&source_addr, sizeof(source_addr)) < 0)
    {
        perror("Bind for UDP socket failed\n");
        exit(1);
    }

   // if (bind(sock_icmp, (struct sockaddr *)&source_addr, sizeof(source_addr)) < 0)
    //{
       // perror("Bind for ICMP socket failed\n");
       // exit(1);
    //}
    int msg = 0;
    while (1)
    {
        int done = 0, timeout = 0;
        for (int i = 0; i < 5; i++)
        {
            struct timeval tout;
            tout.tv_usec = TIMEOUT;
            tout.tv_sec = 0;
            struct iphdr *iph;
            struct icmphdr *icmph;
            struct udphdr *udph;
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
            icmph->checksum = csum((unsigned short *)(datagram + sizeof(struct iphdr)),sizeof(struct icmphdr));
            if (sendto(sock_icmp, datagram, sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
            {
                perror("Send failed\n");
                exit(1);
            }
            //while (1)
            //{
                fd_set fd;
                FD_ZERO(&fd);
                FD_SET(sock_icmp, &fd);
                int ret = select(sock_icmp + 1, &fd, NULL, NULL, &tout);
                if (FD_ISSET(sock_icmp, &fd))
                {
                    struct sockaddr_in from_addr;
                    int from_len = sizeof(from_addr);
                    char buf[4096];
                    recvfrom(sock_icmp, buf, sizeof(buf), 0, (struct sockaddr *)&from_addr, &from_len);
                    struct iphdr *recv_iph;
                    recv_iph = (struct iphdr *)buf;
                    if (recv_iph->protocol == IPPROTO_ICMP)
                    {
                        icmph = (struct icmphdr *)(buf + sizeof(struct iphdr));
                        if (icmph->type == ICMP_TIME_EXCEEDED && icmph->code == ICMP_EXC_TTL)
                        {
                            printf("Node reached at hop %d with ip %s\n", ttl, inet_ntoa(from_addr.sin_addr));
                            done = 1;
                            //break;
                        }
                        else if (icmph->type == ICMP_ECHOREPLY && recv_iph->saddr == dest_addr.sin_addr.s_addr)
                        {
                            printf("Destination with ip %s reached at hop %d\n", inet_ntoa(from_addr.sin_addr), ttl);
                            done = 1;
                            close(sock_icmp);
                            exit(0);
                        }
                        else{
                           // break;
                        }
                    }
                    
                   
                }
               
                
            //}
            if (done == 1)
            {
                break;
            }
        }
        ttl++;
    }
    return 0;
}