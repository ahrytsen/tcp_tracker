#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <unistd.h>

typedef struct connection_status_s {
    pthread_t tid;
    pthread_mutex_t mutex;
    uint32_t dst_ip;
    uint32_t src_ip;
    uint16_t retries;
    uint16_t dst_port;
    uint16_t src_port;
    u_char syn:1;
    u_char syn_ack:1;
    u_char ack:1;
    u_char success:1;
} connection_status_t;

void *client_ip_db[256];
void* connection_watcher(void* arg);

void print_tcp_connection_status(int success_fail_, const u_char *src_ip, u_int16_t src_port, const u_char *dst_ip, u_int16_t dst_port) {
    printf(success_fail_ ? "SUCCESS " : "FAILED ");
    printf("%hhu.%hhu.%hhu.%hhu:%hu -> ", src_ip[0], src_ip[1], src_ip[2], src_ip[3], src_port);
    printf("%hhu.%hhu.%hhu.%hhu:%hu\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], dst_port);
}

void clear_status(connection_status_t *status) {
    pthread_kill(status->tid, SIGKILL);
    pthread_mutex_unlock(&status->mutex);
    pthread_mutex_destroy(&status->mutex);
    memset(status, 0, sizeof(connection_status_t));
}

void init_status(connection_status_t *status) {
    memset(status, 0, sizeof(connection_status_t));
    if (pthread_mutex_init(&status->mutex, NULL) != 0) {
        fprintf(stderr, "mutex init failed: %s\n", strerror(errno));
        exit(1);
    }
    if (pthread_create(&status->tid, NULL, &connection_watcher, status) || pthread_detach(status->tid)) {
        printf("\nThread can't be created : %s", strerror(errno));
        exit(1);
    }
}

connection_status_t* add_ip_context(const u_char *ip_addr, u_int16_t port_id) {
    void **tmp = client_ip_db;
    for (int i = 0; i < 4; i++) {
        if (!tmp[ip_addr[i]]) {
            size_t size = i == 3 ? (sizeof(client_ip_db) * 256) : sizeof(client_ip_db);
            tmp[ip_addr[i]] = malloc(size);
            memset(tmp[ip_addr[i]], 0, size);
        }
        tmp = tmp[ip_addr[i]];
    }
    if (!tmp[port_id]) {
        tmp[port_id] = malloc(sizeof(connection_status_t));
        init_status(tmp[port_id]);
    }
    return tmp[port_id];
}

connection_status_t *get_ip_context(const u_char *ip_addr, u_int16_t port_id) {
    void **tmp = client_ip_db;
    for (int i = 0; i < 4; i++) {
        if (!tmp[ip_addr[i]]) return NULL;
        tmp = tmp[ip_addr[i]];
    }
    if (!tmp[port_id]) return NULL;
    return tmp[port_id];
}

void* connection_watcher(void* arg)
{
    connection_status_t *status = arg;
    sleep(3);
    pthread_mutex_lock(&status->mutex);
    if (!status->success) {
        print_tcp_connection_status(0, (u_char*)&status->src_ip, status->src_port, (u_char*)&status->dst_ip, status->dst_port); // FAIL
        pthread_mutex_unlock(&status->mutex);
        pthread_mutex_destroy(&status->mutex);
        memset(status, 0, sizeof(connection_status_t));
    }
    pthread_mutex_unlock(&status->mutex);

    return NULL;
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return;

    const u_char *ip_header;
    const u_char *tcp_header;

    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + 14;
    ip_header_length = ((*ip_header) & 0x0F) << 2;

    u_char ip_ver = *ip_header >> 4;
    if (4 != ip_ver) return;

    u_char protocol = *(ip_header + 9);
    if (IPPROTO_TCP != protocol) return;

    const u_char *src_ip = ip_header + 12;
    const u_char *dst_ip = ip_header + 16;

    tcp_header = ip_header + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 2;

    uint16_t src_port = ntohs(*((uint16_t*)tcp_header));
    uint16_t dst_port = ntohs(*((uint16_t*)(tcp_header + 2)));
    uint32_t seq_nbr = ntohl(*((uint32_t*)(tcp_header + 4)));
    uint32_t ack_nbr = ntohl(*((uint32_t*)(tcp_header + 8)));
    uint16_t tcp_flags = *(tcp_header + 13) | ((*(tcp_header + 12) & 1) << 8);


    connection_status_t *status = NULL;
    if ((0x02 & tcp_flags) && (0x10 & tcp_flags)) { // SYN_ACK
        status = get_ip_context(dst_ip, dst_port);
        if (!status) return;
        pthread_mutex_lock(&status->mutex);
        if (!status->syn || status->dst_ip != *((uint32_t*)src_ip) || status->dst_port != src_port) {
            pthread_mutex_unlock(&status->mutex);
            return;
        }
        status->syn_ack = 1;
        pthread_mutex_unlock(&status->mutex);
    } else if (0x02 & tcp_flags) { // SYN
        status = add_ip_context(src_ip, src_port);
        pthread_mutex_lock(&status->mutex);
        if (status->success) {
            clear_status(status);
            init_status(status);
            pthread_mutex_lock(&status->mutex);
        }
        if (status->syn) {
            if (status->dst_ip != *((uint32_t*)dst_ip) || status->dst_port != dst_port || status->retries >= 6) {
                print_tcp_connection_status(0, src_ip, src_port, (u_char*)&status->dst_ip, status->dst_port); // FAIL
                clear_status(status);
                return;
            } else {
                status->retries++;
            }
        } else {
            status->syn = 1;
            status->src_ip = *((uint32_t*)src_ip);
            status->src_port = src_port;
            status->dst_ip = *((uint32_t*)dst_ip);
            status->dst_port = dst_port;
        }
        pthread_mutex_unlock(&status->mutex);
    } else if (0x10 & tcp_flags) { // ACK
        status = get_ip_context(src_ip, src_port);
        if (!status) return;
        pthread_mutex_lock(&status->mutex);
        if (!status->syn || !status->syn_ack || status->success) {
            pthread_mutex_unlock(&status->mutex);
            return;
        }
        status->ack = 1;
        print_tcp_connection_status(1, src_ip, src_port, dst_ip, dst_port); // SUCCESS
        status->success = 1;
        pthread_mutex_unlock(&status->mutex);
    }

    return;
}

int main(int argc, char **argv) {
    if (2 != argc) {
        fprintf(stderr, "Incorect arguments\nUsage: %s <interface>\n", argv[0]);
        return 1;
    }
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_length = 1024;
    int total_packet_count = -1;
    u_char *my_arguments = NULL;

    if (!(handle = pcap_open_live(argv[1], snapshot_length, 0, 10000, error_buffer))) {
        fprintf(stderr, "%s: failed to open interface %s: %s\n", argv[0], argv[1], strerror(errno));
        return 1;
    }
    if (0 != pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments)) {
        fprintf(stderr, "%s: %s\n", argv[0], pcap_geterr(handle));
        return 1;
    }

    return 0;
}
