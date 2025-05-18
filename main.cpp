#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

char *malicious_host = NULL;

static int host_compare(const char *host, const char *mal_host) {
    // host에 포트번호가 붙어 있을 수 있으니 ':' 앞까지 자름
    char host_only[256] = {0};
    const char *colon = strchr(host, ':');
    int len = colon ? (colon - host) : strlen(host);
    if (len >= sizeof(host_only)) return 0;
    strncpy(host_only, host, len);
    host_only[len] = '\0';

    // 대소문자 구분없이 완전 일치 비교
    return (strcasecmp(host_only, mal_host) == 0);
}

// Boyer-Moore 문자열 검색 알고리즘 (단순 버전)
int bm_search(const char* text, int text_len, const char* pattern) {
    int pat_len = strlen(pattern);
    if (pat_len == 0 || text_len < pat_len) return -1;

    int skip[256];
    for (int i = 0; i < 256; i++) skip[i] = pat_len;
    for (int i = 0; i < pat_len - 1; i++) skip[(unsigned char)pattern[i]] = pat_len - 1 - i;

    int i = 0;
    while (i <= text_len - pat_len) {
        int j = pat_len - 1;
        while (j >= 0 && pattern[j] == text[i + j]) j--;

        if (j < 0) return i;
        i += skip[(unsigned char)text[i + pat_len - 1]];
    }

    return -1;
}


int process_packet(unsigned char* data, int len) {
    struct iphdr* iph = (struct iphdr*)data;
    if (iph->protocol != IPPROTO_TCP) return NF_ACCEPT;

    int iphdr_len = iph->ihl * 4;
    struct tcphdr* tcph = (struct tcphdr*)(data + iphdr_len);
    int tcphdr_len = tcph->doff * 4;

    if (ntohs(tcph->dest) != 80) return NF_ACCEPT;

    unsigned char* payload = data + iphdr_len + tcphdr_len;
    int payload_len = len - iphdr_len - tcphdr_len;

    if (payload_len <= 0) return NF_ACCEPT;

    int pos = bm_search((char*)payload, payload_len, "Host: ");
    if (pos >= 0) {
        char* host_start = (char*)payload + pos + 6;
        char* host_end = strchr(host_start, '\r');
        if (host_end && (host_end - host_start) < 256) {
            char host[256] = {0};
            strncpy(host, host_start, host_end - host_start);
            host[host_end - host_start] = '\0';

            printf("[+] Host: %s\n", host);

            if (strcmp(host, "test.gilgil.net") == 0) {
                printf("[-] Blocked domain!\n");
                return NF_DROP;
            }
        }
    }

    return NF_ACCEPT;
}

static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
              struct nfq_data* nfa, void* data) {
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = 0;
    if (ph) id = ntohl(ph->packet_id);

    unsigned char* packet_data;
    int len = nfq_get_payload(nfa, &packet_data);
    if (len >= 0) {
        int verdict = process_packet(packet_data, len);
        return nfq_set_verdict(qh, id, verdict, 0, NULL);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
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

    if (nfq_unbind_pf(h, AF_INET) < 0) { perror("nfq_unbind_pf"); }
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
