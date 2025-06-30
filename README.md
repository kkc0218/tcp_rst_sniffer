# tcp_rst_sniffer

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <unistd.h>

#define ETHERNET_SIZE 14
#define BLOCKED_IP "66.254.114.41"  // 차단할 서버 IP (예: pornhub CDN 중 하나)
#define BLOCKED_PORT 443           // HTTPS 포트
#define RST_REPEAT_COUNT 5
#define RST_DELAY_US 3000

libnet_t *libnet_ctx;

void send_rst_pair(const char *src_ip, const char *dst_ip,
                   uint16_t src_port, uint16_t dst_port,
                   uint32_t seq, uint32_t ack) {
    for (int i = 0; i < RST_REPEAT_COUNT; i++) {
        libnet_clear_packet(libnet_ctx);

        // [1] Client → Server 방향 RST
        libnet_build_tcp(
            src_port, dst_port, seq, 0,
            TH_RST | TH_ACK, 32767, 0, 0,
            LIBNET_TCP_H, NULL, 0,
            libnet_ctx, 0
        );
        libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_TCP_H,
            0, libnet_get_prand(LIBNET_PRu16),
            0, 64, IPPROTO_TCP, 0,
            libnet_name2addr4(libnet_ctx, src_ip, LIBNET_RESOLVE),
            libnet_name2addr4(libnet_ctx, dst_ip, LIBNET_RESOLVE),
            NULL, 0, libnet_ctx, 0
        );
        libnet_write(libnet_ctx);
        usleep(RST_DELAY_US);

        libnet_clear_packet(libnet_ctx);

        // [2] Server → Client 방향 RST (역방향도 끊기)
        libnet_build_tcp(
            dst_port, src_port, ack, 0,
            TH_RST | TH_ACK, 32767, 0, 0,
            LIBNET_TCP_H, NULL, 0,
            libnet_ctx, 0
        );
        libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_TCP_H,
            0, libnet_get_prand(LIBNET_PRu16),
            0, 64, IPPROTO_TCP, 0,
            libnet_name2addr4(libnet_ctx, dst_ip, LIBNET_RESOLVE),
            libnet_name2addr4(libnet_ctx, src_ip, LIBNET_RESOLVE),
            NULL, 0, libnet_ctx, 0
        );
        libnet_write(libnet_ctx);
        usleep(RST_DELAY_US);
    }

    printf("[TCP-RST] %s:%d ↔ %s:%d blocked (SEQ=%u)\n",
           src_ip, src_port, dst_ip, dst_port, seq);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ip *ip = (struct ip *)(packet + ETHERNET_SIZE);
    if (ip->ip_p != IPPROTO_TCP) return;

    int ip_header_len = ip->ip_hl * 4;
    const struct tcphdr *tcp = (struct tcphdr *)(packet + ETHERNET_SIZE + ip_header_len);

    if (!(tcp->th_flags & TH_SYN)) return;  // SYN이 아닌 경우 무시

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->ip_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->ip_dst, dst_ip, sizeof(dst_ip));

    uint16_t sport = ntohs(tcp->th_sport);
    uint16_t dport = ntohs(tcp->th_dport);
    uint32_t seq = ntohl(tcp->th_seq);
    uint32_t ack = seq + 1;

    // 대상 IP/PORT만 차단
    if (strcmp(dst_ip, BLOCKED_IP) == 0 && dport == BLOCKED_PORT) {
        send_rst_pair(src_ip, dst_ip, sport, dport, seq, ack);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("en0", BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    char libnet_errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ctx = libnet_init(LIBNET_RAW4, NULL, libnet_errbuf);
    if (!libnet_ctx) {
        fprintf(stderr, "libnet_init failed: %s\n", libnet_errbuf);
        return 2;
    }

    printf("[+] SYN-level TCP blocker started for %s:%d\n", BLOCKED_IP, BLOCKED_PORT);
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    libnet_destroy(libnet_ctx);
    return 0;
}
