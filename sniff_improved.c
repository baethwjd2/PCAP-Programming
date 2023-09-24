#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"


// MAC 주소를 출력하는 함수
void print_mac(u_char *mac){
  for (int i = 0; i < 6; i++) {
    printf("%02x", mac[i]);
    if (i < 5) {
        printf(":");
    }
  }
}

 
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  // Ethernet 헤더 추출
  struct ethheader *eth = (struct ethheader *)packet;

  // Ethernet 프레임의 출발지 MAC 주소 출력
  printf("[Ehternet] Source MAC: ");
  print_mac(eth->ether_shost); printf("\n");

  // Ethernet 프레임의 도착지 MAC 주소 출력
  printf("[Ehternet] Destination MAC: ");
  print_mac(eth->ether_dhost); printf("\n");

  if (ntohs(eth->ether_type) == 0x0800) { // IP 패킷인지 확인 (0x0800은 IP의 type)
    // IP 헤더 추출
    struct ipheader * ip = (struct ipheader *)
                            (packet + sizeof(struct ethheader)); 


    // IP 패킷의 출발지, 도착지 IP 주소 출력
    printf("[IP] Source IP: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("[IP] Destination IP: %s\n", inet_ntoa(ip->iph_destip));    

    // TCP, UDP, ICMP  분류
    switch(ip->iph_protocol) {

      // TCP 세그먼트                                 
      case IPPROTO_TCP:
        // TCP 헤더 추출
        struct tcpheader* tcp = (struct tcpheader *)
                                  (packet + sizeof(struct ethheader) + sizeof(struct ipheader)); 
        
        // TCP 세그먼트의 출발, 도착 포트 출력 
        printf("[TCP] Source Port: %d\n", tcp->tcp_sport);
        printf("[TCP] Destination Port: %d\n", tcp->tcp_dport);

        // 메세지 출력 
        printf("[Message]\n");
        char *msg = (char *)(tcp + sizeof(struct tcpheader));
        for(int i=0;i<16;i++){
          printf("%02x ", msg[i]);
        }
        printf("\n");

        printf("----------Protocol: TCP----------\n\n");
        return;

      // UDP 세그먼트
      case IPPROTO_UDP:
        printf("----------Protocol: UDP----------\n\n");
        return;

      // ICMP 패킷
      case IPPROTO_ICMP:
        printf("----------Protocol: ICMP----------\n\n");
        return;
      
      default:
        printf("----------Protocol: others----------\n\n");
        return;
    } 
  }
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // 1단계: pcap 세션 생성 (NIC 이름: eth0)
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  // 2단계: BFP(Berkeley Packet Filter)를 컴파일
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }

  // 3단계: 패킷 캡처
  pcap_loop(handle, -1, got_packet, NULL);

  // pcap 세션 종료
  pcap_close(handle);  
  return 0;
}