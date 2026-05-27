/*
 * resolvtrace - Linux DNS Observability Tool
 * Logs to: systemd journald + /var/log/resolvtrace/resolvtrace.log
 * License: MIT
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define LOG_DIR      "/var/log/resolvtrace"
#define LOG_FILE     "/var/log/resolvtrace/resolvtrace.log"
#define MAX_LOG_SIZE (10 * 1024 * 1024)
#define VERSION      "1.0.0"
#define ETHER_HDR_LEN 14

static FILE *log_fp = NULL;

static void timestamp(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%S", t);
}

static int ensure_log_dir(void)
{
    struct stat st = {0};
    if (stat(LOG_DIR, &st) == -1) {
        if (mkdir(LOG_DIR, 0755) != 0) {
            fprintf(stderr, "[RESOLVTRACE] Failed to create log dir: %s\n", LOG_DIR);
            return -1;
        }
    }
    return 0;
}

static void maybe_rotate_log(void)
{
    if (!log_fp) return;
    long pos = ftell(log_fp);
    if (pos < 0 || pos < MAX_LOG_SIZE) return;
    fclose(log_fp);
    char rotated[256];
    snprintf(rotated, sizeof(rotated), "%s.1", LOG_FILE);
    rename(LOG_FILE, rotated);
    log_fp = fopen(LOG_FILE, "a");
}

static void dual_log(const char *msg)
{
    printf("%s\n", msg);
    fflush(stdout);
    if (log_fp) {
        fprintf(log_fp, "%s\n", msg);
        fflush(log_fp);
        maybe_rotate_log();
    }
}

static void parse_dns_name(const unsigned char *dns_payload,
                            int payload_len, char *out, size_t out_len)
{
    if (payload_len < 13) { strncpy(out, "(short packet)", out_len); return; }
    const unsigned char *p   = dns_payload + 12;
    const unsigned char *end = dns_payload + payload_len;
    size_t written = 0;
    int first = 1;
    while (p < end && *p != 0) {
        int label_len = *p++;
        if (label_len > 63 || p + label_len > end) break;
        if (!first && written + 1 < out_len) out[written++] = '.';
        first = 0;
        size_t copy = label_len;
        if (written + copy >= out_len) copy = out_len - written - 1;
        memcpy(out + written, p, copy);
        written += copy;
        p += label_len;
    }
    out[written] = '\0';
    if (written == 0) strncpy(out, "(unknown)", out_len);
}

void packet_handler(unsigned char *args __attribute__((unused)),
                    const struct pcap_pkthdr *header,
                    const unsigned char *packet)
{
    char ts[32];
    timestamp(ts, sizeof(ts));

    if (header->caplen < (unsigned)(ETHER_HDR_LEN + 20 + 8 + 12)) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "[RESOLVTRACE] %s | short packet len=%u (skipped)", ts, header->len);
        dual_log(msg);
        return;
    }

    const struct ip *ip_hdr = (const struct ip *)(packet + ETHER_HDR_LEN);
    int ip_hdr_len = ip_hdr->ip_hl * 4;

    char src_ip[INET_ADDRSTRLEN] = "?";
    char dst_ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));

    const unsigned char *udp_start = packet + ETHER_HDR_LEN + ip_hdr_len;
    const struct udphdr *udp_hdr   = (const struct udphdr *)udp_start;
    uint16_t src_port = ntohs(udp_hdr->uh_sport);
    uint16_t dst_port = ntohs(udp_hdr->uh_dport);

    const unsigned char *dns_payload = udp_start + 8;
    int dns_len = (int)header->caplen - ETHER_HDR_LEN - ip_hdr_len - 8;

    char domain[256] = "(parse error)";
    if (dns_len >= 12) parse_dns_name(dns_payload, dns_len, domain, sizeof(domain));

    const char *direction = (dst_port == 53) ? "QUERY" : "RESPONSE";

    char msg[512];
    snprintf(msg, sizeof(msg),
             "[RESOLVTRACE] %s | %-8s | %s:%u -> %s:%u | domain=%s | len=%u",
             ts, direction, src_ip, src_port, dst_ip, dst_port,
             domain[0] ? domain : "(empty)", header->len);
    dual_log(msg);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (ensure_log_dir() == 0) {
        log_fp = fopen(LOG_FILE, "a");
        if (!log_fp)
            fprintf(stderr, "[RESOLVTRACE] Warning: cannot open log file, journal only\n");
    }

    char ts[32];
    timestamp(ts, sizeof(ts));
    char banner[256];
    snprintf(banner, sizeof(banner),
             "[RESOLVTRACE] %s | version=%s | pid=%d | starting...",
             ts, VERSION, getpid());
    dual_log(banner);

    char *iface = "any";
    if (argc >= 2) {
        iface = argv[1];
    } else {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs)
            iface = alldevs->name;
    }

    char ifmsg[128];
    snprintf(ifmsg, sizeof(ifmsg), "[RESOLVTRACE] %s | interface=%s", ts, iface);
    dual_log(ifmsg);

    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "[RESOLVTRACE] pcap_open_live failed: %s\n", errbuf);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "udp port 53 or tcp port 53";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "[RESOLVTRACE] pcap_compile failed: %s\n", pcap_geterr(handle));
        pcap_close(handle); if (log_fp) fclose(log_fp); return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[RESOLVTRACE] pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_close(handle); if (log_fp) fclose(log_fp); return 1;
    }

    char readymsg[128];
    timestamp(ts, sizeof(ts));
    snprintf(readymsg, sizeof(readymsg),
             "[RESOLVTRACE] %s | status=ready | listening for DNS traffic...", ts);
    dual_log(readymsg);

    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    if (log_fp) fclose(log_fp);
    return 0;
}
