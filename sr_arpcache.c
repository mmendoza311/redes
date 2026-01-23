#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/*
	Envía una solicitud ARP.
*/
void sr_arp_request_send(struct sr_instance *sr, uint32_t ip, char* iface) {


  printf("$$$ -> Send ARP request.\n");

  /* 
  * COLOQUE AQÍ SU CÓDIGO
  * SUGERENCIAS: 
  * - Construya el cabezal Ethernet y agregue dirección de destino de broadcast
  * - Envíe la solicitud ARP desde la interfaz pasada por parámetro, correspondiente a la conectada a la subred de la IP cuya MAC se desea conocer
  * - Agregue la dirección de origen y el tipo de paquete
  * - Construya el cabezal ARP y envíe el paquete
  */
  
  /* Obtener la interfaz */
  struct sr_if *out_iface = sr_get_interface(sr, iface);
  if (!out_iface) {
      printf("Error: Interfaz %s no encontrada\n", iface);
      return;
  }

  int arpPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *arpPacket = malloc(arpPacketLen);
  
  sr_ethernet_hdr_t *ethHdr = (struct sr_ethernet_hdr *) arpPacket;
  memcpy(ethHdr->ether_dhost, (uint8_t[]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, ETHER_ADDR_LEN);
  memcpy(ethHdr->ether_shost, out_iface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  ethHdr->ether_type = htons(ethertype_arp);
  
  sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *) (arpPacket + sizeof(sr_ethernet_hdr_t));
  arpHdr->ar_hrd = htons(1);
  arpHdr->ar_pro = htons(2048);
  arpHdr->ar_hln = 6;
  arpHdr->ar_pln = 4;
  arpHdr->ar_op = htons(arp_op_request);
  memcpy(arpHdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  memcpy(arpHdr->ar_tha, (uint8_t[]){0, 0, 0, 0, 0, 0}, ETHER_ADDR_LEN);
  arpHdr->ar_sip = out_iface->ip;
  arpHdr->ar_tip = ip;
  
  /* Enviar el paquete */
  sr_send_packet(sr, arpPacket, arpPacketLen, iface);
  
  free(arpPacket);
  printf("$$$ -> Send ARP request processing complete.\n");
}

/*
  Para cada solicitud enviada, se verifica si se debe enviar otra solicitud o descartar la solicitud ARP.
  Si pasó más de un segundo desde que se envió la última solicitud, se envía otra, siempre y cuando no se haya enviado más de cinco veces.
  Si se envió más de 5 veces, se debe descartar la solicitud ARP y enviar un ICMP host unreachable.
  
  SUGERENCIAS:
  - la cola de solicitudes ARP se encuentra en sr->cache.requests, investigue la estructura y sus campos, junto a sus estructuras cuando corresponda
  - investigue el uso de tipos de datos de tiempo y sus funciones asociadas en C
  - no olvide actualizar los campos de la solicitud luego de reenviarla
*/
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t current_time = time(NULL);
    
    /* Si nunca se envió, enviar ahora */
    if (req->sent == 0) {
        req->sent = current_time;
        req->times_sent = 1;
        sr_arp_request_send(sr, req->ip, req->iface);
        printf("Enviando ARP request %u\n", req->times_sent);
    }
    /* Si pasó más de 1 segundo desde el último envío */
    else if (difftime(current_time, req->sent) >= 1.0) {
        /* Si se ha enviado menos de 5 veces, reenviar */
        if (req->times_sent < 5) {
            req->sent = current_time;
            req->times_sent++;
            sr_arp_request_send(sr, req->ip, req->iface);
            printf("Reenviando ARP request %u\n", req->times_sent);
        }
        /* Si ya se envió 5 veces, descartar y enviar ICMP */
        else {
            printf("ARP request fallido después de 5 intentos, enviando ICMP host unreachable\n");
            host_unreachable(sr, req);
            sr_arpreq_destroy(&(sr->cache), req);
        }
    }
}

/* Envía un mensaje ICMP host unreachable a los emisores de los paquetes esperando en la cola de una solicitud ARP */
void host_unreachable(struct sr_instance *sr, struct sr_arpreq *req) {
    struct sr_packet *pkt = req->packets;
    
    while (pkt != NULL) {
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt->buf + sizeof(sr_ethernet_hdr_t));
        sr_send_icmp_error_packet(3, 1, sr, ip_hdr->ip_src, pkt->buf);
        pkt = pkt->next;
    }
}

/* NO DEBERÍA TENER QUE MODIFICAR EL CÓDIGO A PARTIR DE AQUÍ. */

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    struct sr_arpreq *currReq = sr->cache.requests;
    struct sr_arpreq *nextReq;

    while (currReq != NULL)
    {
        nextReq = currReq->next;
        handle_arpreq(sr, currReq);
        currReq = nextReq;
    }
}

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        req->iface = iface;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

