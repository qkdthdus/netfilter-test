#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>     // struct iphdr 정의
#include <netinet/tcp.h>    // struct tcphdr 정의
#include <libnetfilter_queue/libnetfilter_queue.h>

char *malicious_host = NULL;

static u_int32_t process_packet(struct nfq_data *tb) {
    unsigned char *data;
    int len = nfq_get_payload(tb, &data);
    if (len <= 0) {
        printf("FAIL: No payload\n");
        return 0;
    }

    struct iphdr *iph = (struct iphdr *)data;
    if (iph->protocol != IPPROTO_TCP) {
        printf("FAIL: Not TCP\n");
        return 0;
    }

    int ip_header_len = iph->ihl * 4;
    if (ip_header_len < 20 || ip_header_len > len) {
        printf("FAIL: Invalid IP header length\n");
        return 0;
    }

    struct tcphdr *tcph = (struct tcphdr *)(data + ip_header_len);
    int tcp_header_len = tcph->doff * 4;
    if (tcp_header_len < 20 || ip_header_len + tcp_header_len > len) {
        printf("FAIL: Invalid TCP header length\n");
        return 0;
    }

    int http_payload_len = len - ip_header_len - tcp_header_len;
    if (http_payload_len <= 0) {
        printf("FAIL: No HTTP payload\n");
        return 0;
    }

    char *http_payload = (char *)(data + ip_header_len + tcp_header_len);
    char *host_pos = strcasestr(http_payload, "Host: ");
    if (!host_pos) {
        printf("FAIL: No Host header\n");
        return 0;
    }

    host_pos += 6; // "Host: " 길이
    char *end = strstr(host_pos, "\r\n");
    if (!end) {
        printf("FAIL: Host header no CRLF\n");
        return 0;
    }

    int host_len = end - host_pos;
    if (host_len <= 0 || host_len >= 256) {
        printf("FAIL: Invalid Host length\n");
        return 0;
    }

    char host[256] = {0};
    strncpy(host, host_pos, host_len);
    host[host_len] = '\0';

    if (strcmp(host, malicious_host) == 0) {
        printf("SUCCESS: Block malicious host: %s\n", host);
        struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
        return ph ? ntohl(ph->packet_id) : 0;
    }

    printf("SUCCESS: Host not malicious: %s\n", host);
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    return ph ? ntohl(ph->packet_id) : 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg __attribute__((unused)),
              struct nfq_data *nfa, void *data __attribute__((unused))) {
    u_int32_t id = process_packet(nfa);
    if (id == 0) {
        printf("SUCCESS: Accepting packet (no drop)\n");
        return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, NULL);
    }

    printf("SUCCESS: Dropping packet with id: %u\n", id);
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "syntax : %s <host>\n", argv[0]);
        fprintf(stderr, "sample : %s test.gilgil.net\n", argv[0]);
        exit(1);
    }

    malicious_host = argv[1];
    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); exit(1); }

    if (nfq_unbind_pf(h, AF_INET) < 0) { perror("nfq_unbind_pf"); /* 무시 가능 */ }
    if (nfq_bind_pf(h, AF_INET) < 0) { perror("nfq_bind_pf"); exit(1); }

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) { perror("nfq_create_queue"); exit(1); }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode"); exit(1);
    }

    int fd = nfq_fd(h);
    char buf[4096] __attribute__ ((aligned));
    int rv;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
