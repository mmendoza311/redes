/*-----------------------------------------------------------------------------
 * File:  sr_rip.c
 * Date:  Mon Sep 22 23:15:59 GMT-3 2025 
 * Authors: Santiago Freire
 * Contact: sfreire@fing.edu.uy
 *
 * Description:
 *
 * Data structures and methods for handling RIP protocol
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_rip.h"

#include "sr_utils.h"

static pthread_mutex_t rip_metadata_lock = PTHREAD_MUTEX_INITIALIZER;

/* Dirección MAC de multicast para los paquetes RIP */
uint8_t rip_multicast_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x09};

/* Función de validación de paquetes RIP */
int sr_rip_validate_packet(sr_rip_packet_t* packet, unsigned int len) {
    if (len < sizeof(sr_rip_packet_t)) {
        return 0;
    }

    if (packet->command != RIP_COMMAND_REQUEST && packet->command != RIP_COMMAND_RESPONSE) {
        return 0;
    }

    if (packet->version != RIP_VERSION) {
        return 0;
    }

    if (packet->zero != 0) {
        return 0;
    }

    unsigned int expected_len = sizeof(struct sr_rip_packet_t) +
                               ((len - sizeof(struct sr_rip_packet_t)) / sizeof(struct sr_rip_entry_t)) *
                               sizeof(struct sr_rip_entry_t);

    if (len != expected_len) {
        return 0;
    }

    return 1;
}

int sr_rip_update_route(struct sr_instance* sr,
                        const struct sr_rip_entry_t* rte,
                        uint32_t src_ip,
                        const char* in_ifname)
{
    /*
     * Procesa una entrada RIP recibida por una interfaz.
     *

     *  - Si la métrica anunciada es >= 16:
     *      - Si ya existe una ruta coincidente aprendida desde el mismo vecino, marca la ruta
     *        como inválida, pone métrica a INFINITY y fija el tiempo de garbage collection.
     *      - Si no, ignora el anuncio de infinito.
     *  - Calcula la nueva métrica sumando el coste del enlace de la interfaz; si resulta >=16,
     *    descarta la actualización.
     *  - Si la ruta no existe, inserta una nueva entrada en la tabla de enrutamiento.
     *  - Si la entrada existe pero está inválida, la revive actualizando métrica, gateway,
     *    learned_from, interfaz y timestamps.
     *  - Si la entrada fue aprendida del mismo vecino:
     *      - Actualiza métrica/gateway/timestamps si cambian; si no, solo refresca el timestamp.
     *  - Si la entrada viene de otro origen:
     *      - Reemplaza la ruta si la nueva métrica es mejor.
     *      - Si la métrica es igual y el next-hop coincide, refresca la entrada.
     *      - En caso contrario (peor métrica o diferente camino), ignora la actualización.
     *  - Actualiza campos relevantes: metric, gw, route_tag, learned_from, interface,
     *    last_updated, valid y garbage_collection_time según corresponda.
     *
     * Valores de retorno:
     *  - -1: entrada inválida o fallo al obtener la interfaz.
     *  -  1: la tabla de rutas fue modificada (inserción/actualización/eliminación).
     *  -  0: no se realizaron cambios.
     *
     */

    if (!sr || !rte || !in_ifname) return -1;

    struct sr_if* iface = sr_get_interface(sr, in_ifname);
    if (!iface) return -1;

    struct in_addr dest_addr;
    dest_addr.s_addr = rte->ip;
    struct in_addr mask_addr;
    mask_addr.s_addr = rte->mask;
    struct in_addr gw_addr;
    gw_addr.s_addr = src_ip;

    time_t now = time(NULL);
    uint8_t incoming_metric = ntohl(rte->metric);

    Debug("RIP: Processing entry - Dest: %s, Mask: %s, Metric: %u, Gateway: %s, Interface: %s",
          inet_ntoa(dest_addr), inet_ntoa(mask_addr), incoming_metric, inet_ntoa(*(struct in_addr*)&src_ip), in_ifname);

    if (incoming_metric >= INFINITY) {
        struct sr_rt* existing = sr->routing_table;
        while (existing) {
            if (existing->dest.s_addr == dest_addr.s_addr &&
                existing->mask.s_addr == mask_addr.s_addr &&
                existing->learned_from == src_ip) {
                existing->valid = 0;
                existing->metric = INFINITY;
                existing->garbage_collection_time = now;
                Debug("RIP: Route marked invalid (infinity from same neighbor)");
                return 1;
            }
            existing = existing->next;
        }
        return 0;
    }

    uint8_t new_metric = incoming_metric + (iface->cost ? iface->cost : 1);
    if (new_metric >= INFINITY) {
        return 0;
    }

    struct sr_rt* existing = sr->routing_table;
    while (existing) {
        if (existing->dest.s_addr == dest_addr.s_addr &&
            existing->mask.s_addr == mask_addr.s_addr) {
            if (existing->learned_from == src_ip) {
                if (existing->metric != new_metric) {
                    existing->metric = new_metric;
                    existing->gw.s_addr = src_ip;
                    existing->last_updated = now;
                    existing->route_tag = ntohs(rte->route_tag);
                    if (!existing->valid) {
                        existing->valid = 1;
                        existing->garbage_collection_time = 0;
                    }
                    Debug("RIP: Route updated (same neighbor, metric changed)");
                    return 1;
                } else {
                    existing->last_updated = now;
                    return 0;
                }
            } else {
                if (new_metric < existing->metric) {
                    existing->metric = new_metric;
                    existing->gw.s_addr = src_ip;
                    existing->learned_from = src_ip;
                    existing->last_updated = now;
                    existing->route_tag = ntohs(rte->route_tag);
                    strncpy(existing->interface, in_ifname, sr_IFACE_NAMELEN - 1);
                    existing->interface[sr_IFACE_NAMELEN - 1] = '\0';
                    if (!existing->valid) {
                        existing->valid = 1;
                        existing->garbage_collection_time = 0;
                    }
                    Debug("RIP: Route replaced (better metric from different neighbor)");
                    return 1;
                } else if (new_metric == existing->metric && existing->gw.s_addr == src_ip) {
                    existing->last_updated = now;
                    return 0;
                }
                return 0;
            }
        }
        existing = existing->next;
    }

    sr_add_rt_entry(sr,
                    dest_addr,
                    gw_addr,
                    mask_addr,
                    in_ifname,
                    new_metric,
                    ntohs(rte->route_tag),
                    src_ip,
                    now,
                    1,
                    0);
    Debug("RIP: New route added - Dest: %s, Mask: %s, Metric: %u, Gateway: %s, Interface: %s",
          inet_ntoa(dest_addr), inet_ntoa(mask_addr), new_metric, inet_ntoa(*(struct in_addr*)&src_ip), in_ifname);
    return 1;
}

void sr_handle_rip_packet(struct sr_instance* sr,
                          const uint8_t* packet,
                          unsigned int pkt_len,
                          unsigned int ip_off,
                          unsigned int rip_off,
                          unsigned int rip_len,
                          const char* in_ifname)
{
    if (!sr || !packet || !in_ifname) return;

    pthread_mutex_lock(&rip_metadata_lock);

    sr_rip_packet_t* rip_packet = (struct sr_rip_packet_t*)(packet + rip_off);
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + ip_off);

    if (!sr_rip_validate_packet(rip_packet, rip_len)) {
        Debug("RIP: Invalid RIP packet received");
        pthread_mutex_unlock(&rip_metadata_lock);
        return;
    }

    struct sr_if* iface = sr_get_interface(sr, in_ifname);
    if (!iface) {
        pthread_mutex_unlock(&rip_metadata_lock);
        return;
    }

    uint32_t src_ip = ip_hdr->ip_src;
    int table_changed = 0;

    if (rip_packet->command == RIP_COMMAND_REQUEST) {
        Debug("RIP: Request received on interface %s", in_ifname);
        pthread_mutex_unlock(&rip_metadata_lock);
        sr_rip_send_response(sr, iface, src_ip);
        return;
    } else if (rip_packet->command == RIP_COMMAND_RESPONSE) {
        Debug("RIP: Response received from %s", inet_ntoa(*(struct in_addr*)&src_ip));
        
        unsigned int num_entries = (rip_len - sizeof(sr_rip_packet_t)) / sizeof(sr_rip_entry_t);
        
        for (unsigned int i = 0; i < num_entries; i++) {
            sr_rip_entry_t* entry = &rip_packet->entries[i];
            
            int result = sr_rip_update_route(sr, entry, src_ip, in_ifname);
            if (result == 1) {
                table_changed = 1;
            }
        }
    } else {
        Debug("RIP: Invalid RIP command: %u", rip_packet->command);
        pthread_mutex_unlock(&rip_metadata_lock);
        return;
    }

    if (table_changed) {
    /* if (0) { */ /* DISABLED: Triggered Updates */
        Debug("RIP: Routing table changed, printing updated table:");
        print_routing_table(sr);
    }

    pthread_mutex_unlock(&rip_metadata_lock);
}

void sr_rip_send_response(struct sr_instance* sr, struct sr_if* interface, uint32_t ipDst) {
    if (!sr || !interface) return;

    struct sr_rt* rt_iter = sr->routing_table;
    int num_routes = 0;
    while (rt_iter) {
        num_routes++;
        rt_iter = rt_iter->next;
    }

    int entries_per_packet = 25;
    int num_packets = (num_routes + entries_per_packet - 1) / entries_per_packet;
    if (num_routes == 0) num_packets = 1;

    for (int packet_idx = 0; packet_idx < num_packets; packet_idx++) {
        int entries_in_packet = num_routes - (packet_idx * entries_per_packet);
        if (entries_in_packet > entries_per_packet) entries_in_packet = entries_per_packet;
        if (entries_in_packet < 0) entries_in_packet = 0;

        unsigned int rip_len = sizeof(sr_rip_packet_t) + entries_in_packet * sizeof(sr_rip_entry_t);
        unsigned int udp_len = sizeof(sr_udp_hdr_t) + rip_len;
        unsigned int ip_len = sizeof(sr_ip_hdr_t) + udp_len;
        unsigned int eth_len = sizeof(sr_ethernet_hdr_t) + ip_len;

        uint8_t* packet = malloc(eth_len);
        if (!packet) return;

        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
        memcpy(eth_hdr->ether_dhost, rip_multicast_mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        eth_hdr->ether_type = htons(ethertype_ip);

        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
        ip_hdr->ip_v = 4;
        ip_hdr->ip_hl = 5;
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(ip_len);
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = 1;
        ip_hdr->ip_p = ip_protocol_udp;
        ip_hdr->ip_src = interface->ip;
        ip_hdr->ip_dst = htonl(RIP_IP);
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        udp_hdr->src_port = htons(RIP_PORT);
        udp_hdr->dst_port = htons(RIP_PORT);
        udp_hdr->length = htons(udp_len);
        udp_hdr->checksum = 0;

        sr_rip_packet_t* rip_packet = (sr_rip_packet_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
        rip_packet->command = RIP_COMMAND_RESPONSE;
        rip_packet->version = RIP_VERSION;
        rip_packet->zero = 0;

        int entry_count = 0;
        rt_iter = sr->routing_table;
        int route_offset = packet_idx * entries_per_packet;
        int route_idx = 0;

        while (rt_iter && entry_count < entries_in_packet) {
            if (route_idx >= route_offset) {
                sr_rip_entry_t* rip_entry = &rip_packet->entries[entry_count];
                rip_entry->family_identifier = htons(2);
                rip_entry->route_tag = htons(rt_iter->route_tag);
                rip_entry->ip = rt_iter->dest.s_addr;
                rip_entry->mask = rt_iter->mask.s_addr;
                rip_entry->next_hop = 0;

                /* Split Horizon with Poisoned Reverse:
                   Si la ruta fue aprendida por RIP y viene por la misma interfaz,
                   enviarla pero marcarla como no alcanzable (métrica INFINITY) */
                if (!rt_iter->valid) {
                    /* Ruta inválida o expirada: marcar como no alcanzable */
                    rip_entry->metric = htonl(INFINITY);
                } else if (rt_iter->learned_from != htonl(0) && 
                           strcmp(rt_iter->interface, interface->name) == 0) {
                /* } else if (0) { */ /* DISABLED: Split Horizon */
                    /* Poisoned Reverse: ruta aprendida por RIP por esta interfaz
                       se envía con métrica INFINITY para prevenir bucles */
                    rip_entry->metric = htonl(INFINITY);
                } else {
                    /* Ruta válida que puede enviarse normalmente */
                    uint8_t metric = rt_iter->metric;
                    if (metric > INFINITY) metric = INFINITY;
                    if (metric < 1) metric = 1;
                    rip_entry->metric = htonl(metric);
                }

                entry_count++;
            }
            route_idx++;
            rt_iter = rt_iter->next;
        }

        uint8_t* rip_payload = (uint8_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
        udp_hdr->checksum = udp_cksum(ip_hdr, udp_hdr, rip_payload);

        sr_send_packet(sr, packet, eth_len, interface->name);
        free(packet);
    }
}

void* sr_rip_send_requests(void* arg) {
    sleep(3);
    struct sr_instance* sr = arg;
    struct sr_if* interface = sr->if_list;

    while (interface) {
        unsigned int rip_len = sizeof(sr_rip_packet_t) + sizeof(sr_rip_entry_t);
        unsigned int udp_len = sizeof(sr_udp_hdr_t) + rip_len;
        unsigned int ip_len = sizeof(sr_ip_hdr_t) + udp_len;
        unsigned int eth_len = sizeof(sr_ethernet_hdr_t) + ip_len;

        uint8_t* packet = malloc(eth_len);
        if (!packet) {
            interface = interface->next;
            continue;
        }

        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
        memcpy(eth_hdr->ether_dhost, rip_multicast_mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        eth_hdr->ether_type = htons(ethertype_ip);

        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
        ip_hdr->ip_v = 4;
        ip_hdr->ip_hl = 5;
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(ip_len);
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = 1;
        ip_hdr->ip_p = ip_protocol_udp;
        ip_hdr->ip_src = interface->ip;
        ip_hdr->ip_dst = htonl(RIP_IP);
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        udp_hdr->src_port = htons(RIP_PORT);
        udp_hdr->dst_port = htons(RIP_PORT);
        udp_hdr->length = htons(udp_len);
        udp_hdr->checksum = 0;

        sr_rip_packet_t* rip_packet = (sr_rip_packet_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
        rip_packet->command = RIP_COMMAND_REQUEST;
        rip_packet->version = RIP_VERSION;
        rip_packet->zero = 0;

        sr_rip_entry_t* rip_entry = &rip_packet->entries[0];
        rip_entry->family_identifier = 0;
        rip_entry->route_tag = 0;
        rip_entry->ip = 0;
        rip_entry->mask = 0;
        rip_entry->next_hop = 0;
        rip_entry->metric = htonl(INFINITY);

        uint8_t* rip_payload = (uint8_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
        udp_hdr->checksum = udp_cksum(ip_hdr, udp_hdr, rip_payload);

        sr_send_packet(sr, packet, eth_len, interface->name);
        free(packet);

        interface = interface->next;
    }

    return NULL;
}

void* sr_rip_periodic_advertisement(void* arg) {
    struct sr_instance* sr = arg;

    sleep(2);
    
    pthread_mutex_lock(&rip_metadata_lock);
    struct sr_if* int_temp = sr->if_list;
    while(int_temp != NULL)
    {
        struct in_addr ip;
        ip.s_addr = int_temp->ip;
        struct in_addr gw;
        gw.s_addr = 0x00000000;
        struct in_addr mask;
        mask.s_addr =  int_temp->mask;
        struct in_addr network;
        network.s_addr = ip.s_addr & mask.s_addr;
        uint8_t metric = int_temp->cost ? int_temp->cost : 1;

        struct sr_rt* it = sr->routing_table;
        while (it) {
            struct sr_rt* next = it->next;
            if (it->dest.s_addr == network.s_addr && it->mask.s_addr == mask.s_addr) {
                sr_del_rt_entry(&sr->routing_table, it);
            }
            it = next;
        }
        
        Debug("-> RIP: Adding the directly connected network [%s, ", inet_ntoa(network));
        Debug("%s] to the routing table\n", inet_ntoa(mask));
        sr_add_rt_entry(sr,
                        network,
                        gw,
                        mask,
                        int_temp->name,
                        metric,
                        0,
                        htonl(0),
                        time(NULL),
                        1,
                        0);
        int_temp = int_temp->next;
    }
    
    pthread_mutex_unlock(&rip_metadata_lock);
    Debug("\n-> RIP: Printing the forwarding table\n");
    print_routing_table(sr);

    sleep(RIP_ADVERT_INTERVAL_SEC);

    while (1) {
        pthread_mutex_lock(&rip_metadata_lock);
        
        struct sr_if* iface = sr->if_list;
        while (iface) {
            sr_rip_send_response(sr, iface, htonl(RIP_IP));
            iface = iface->next;
        }
        
        pthread_mutex_unlock(&rip_metadata_lock);
        
        sleep(RIP_ADVERT_INTERVAL_SEC);
    }

    return NULL;
}

void* sr_rip_timeout_manager(void* arg) {
    struct sr_instance* sr = arg;
    
    while (1) {
        sleep(1);
        pthread_mutex_lock(&rip_metadata_lock);

        time_t now = time(NULL);
        int table_changed = 0;

        struct sr_rt* rt = sr->routing_table;
        while (rt) {
            if (rt->learned_from != htonl(0)) {
                if (rt->valid && (now - rt->last_updated) >= RIP_TIMEOUT_SEC) {
                    rt->valid = 0;
                    rt->metric = INFINITY;
                    rt->garbage_collection_time = now;
                    Debug("RIP: Route to %s marked invalid (timeout)", inet_ntoa(rt->dest));
                    table_changed = 1;
                }
            }
            rt = rt->next;
        }

        if (table_changed) {
        /* if (0) { */ /* DISABLED: Triggered Updates */
            Debug("RIP: Routing table changed due to timeout, printing updated table:");
            print_routing_table(sr);
        }

        pthread_mutex_unlock(&rip_metadata_lock);
    }

    return NULL;
}

void* sr_rip_garbage_collection_manager(void* arg) {
    struct sr_instance* sr = arg;
    
    while (1) {
        sleep(1);
        pthread_mutex_lock(&rip_metadata_lock);

        time_t now = time(NULL);
        int table_changed = 0;

        struct sr_rt* rt = sr->routing_table;
        while (rt) {
            struct sr_rt* next = rt->next;
            
            if (!rt->valid && rt->garbage_collection_time > 0 &&
                (now >= rt->garbage_collection_time + RIP_GARBAGE_COLLECTION_SEC)) {
                Debug("RIP: Removing route to %s (garbage collection expired)", inet_ntoa(rt->dest));
                sr_del_rt_entry(&sr->routing_table, rt);
                table_changed = 1;
            }
            
            rt = next;
        }

        if (table_changed) {
        /* if (0) { */ /* DISABLED: Triggered Updates */
            Debug("RIP: Routing table changed due to garbage collection, printing updated table:");
            print_routing_table(sr);
        }

        pthread_mutex_unlock(&rip_metadata_lock);
    }

    return NULL;
}

int sr_rip_init(struct sr_instance* sr) {
    if(pthread_mutex_init(&sr->rip_subsys.lock, NULL) != 0) {
        printf("RIP: Error initializing mutex\n");
        return -1;
    }

    if(pthread_create(&sr->rip_subsys.thread, NULL, sr_rip_periodic_advertisement, sr) != 0) {
        printf("RIP: Error creating advertisement thread\n");
        pthread_mutex_destroy(&sr->rip_subsys.lock);
        return -1;
    }

    pthread_t timeout_thread;
    if(pthread_create(&timeout_thread, NULL, sr_rip_timeout_manager, sr) != 0) {
        printf("RIP: Error creating timeout thread\n");
        pthread_cancel(sr->rip_subsys.thread);
        pthread_mutex_destroy(&sr->rip_subsys.lock);
        return -1;
    }

    pthread_t garbage_collection_thread;
    if(pthread_create(&garbage_collection_thread, NULL, sr_rip_garbage_collection_manager, sr) != 0) {
        printf("RIP: Error creating garbage collection thread\n");
        pthread_cancel(sr->rip_subsys.thread);
        pthread_mutex_destroy(&sr->rip_subsys.lock);
        return -1;
    }

    pthread_t requests_thread;
    if(pthread_create(&requests_thread, NULL, sr_rip_send_requests, sr) != 0) {
        printf("RIP: Error creating requests thread\n");
        pthread_cancel(sr->rip_subsys.thread);
        pthread_mutex_destroy(&sr->rip_subsys.lock);
        return -1;
    }

    return 0;
}
