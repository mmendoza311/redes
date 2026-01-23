/**********************************************************************
 * file:  sr_router.c
 *
 * Descripción:
 *
 * Este archivo contiene todas las funciones que interactúan directamente
 * con la tabla de enrutamiento, así como el método de entrada principal
 * para el enrutamiento.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* Forward declaration */
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface);

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req);

void sr_send_icmp_echo_reply(struct sr_instance *sr,
                             uint8_t *packet,
                             unsigned int len);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Inicializa el subsistema de enrutamiento
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    assert(sr);

    /* Inicializa la caché y el hilo de limpieza de la caché */
    sr_arpcache_init(&(sr->cache));

    /* Inicializa los atributos del hilo */
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    /* Hilo para gestionar el timeout del caché ARP */
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

} /* -- sr_init -- */

/* Envía un paquete ICMP de error */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{

  unsigned int icmp_len;
  unsigned int len;
  
  /* Determinar el tamaño de la estructura ICMP según el tipo */
  if (type == 3) {
      icmp_len = sizeof(sr_icmp_t3_hdr_t);
  } else {
      icmp_len = sizeof(sr_icmp_hdr_t);
  }
  
  len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len;
  uint8_t *packet = malloc(len);
  memset(packet, 0, len);
  
  /* Obtener el cabezal IP original */
  sr_ip_hdr_t *orig_ip_hdr = (sr_ip_hdr_t *)(ipPacket + sizeof(sr_ethernet_hdr_t));
  
  /* Encontrar la interfaz desde la cual enviar la respuesta */
  struct sr_if *iface = sr_get_interface_given_ip(sr, orig_ip_hdr->ip_dst);
  if (!iface) {
      free(packet);
      return;
  }
  
  /* Crear cabezal Ethernet */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ethernet_hdr_t *orig_eth = (sr_ethernet_hdr_t *)ipPacket;
  memcpy(eth_hdr->ether_dhost, orig_eth->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);
  
  /* Crear cabezal IP */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_id = htons(0);
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_src = iface->ip;
  ip_hdr->ip_dst = orig_ip_hdr->ip_src;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
  
  /* Crear cabezal ICMP según el tipo */
  if (type == 3) {
      /* Para tipo 3 (Destination Unreachable) usar sr_icmp_t3_hdr_t */
      sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      icmp_hdr->icmp_type = type;
      icmp_hdr->icmp_code = code;
      icmp_hdr->icmp_sum = 0;
      icmp_hdr->unused = 0;
      icmp_hdr->next_mtu = 0;
      
      /* Copiar los primeros 28 bytes del paquete original */
      memcpy(icmp_hdr->data, orig_ip_hdr, ICMP_DATA_SIZE);
      
      icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  } else {
      /* Para otros tipos (ej: 11 Time Exceeded) usar sr_icmp_hdr_t */
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      icmp_hdr->icmp_type = type;
      icmp_hdr->icmp_code = code;
      icmp_hdr->icmp_sum = 0;
      
      icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
  }
  
  /* Enviar el paquete ICMP */
  sr_send_packet(sr, packet, len, iface->name);
  free(packet);
  
  printf("ICMP error packet enviado (type=%u, code=%u)\n", type, code);
} /* -- sr_send_icmp_error_packet -- */

/* Envía un paquete ICMP Echo Reply (tipo 0) en respuesta a un Echo Request */
void sr_send_icmp_echo_reply(struct sr_instance *sr,
                             uint8_t *packet /* lent */,
                             unsigned int len)
{
  /* Obtener cabezales IP del request */
  sr_ip_hdr_t *orig_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  /* Encontrar la interfaz desde la cual enviar la respuesta */
  struct sr_if *iface = sr_get_interface_given_ip(sr, orig_ip_hdr->ip_dst);
  if (!iface) {
      return;
  }
  
  /* Crear el paquete de respuesta con el mismo tamaño */
  uint8_t *reply_packet = malloc(len);
  memcpy(reply_packet, packet, len);
  
  /* Obtener cabezales del paquete de respuesta */
  sr_ethernet_hdr_t *reply_eth = (sr_ethernet_hdr_t *)reply_packet;
  sr_ip_hdr_t *reply_ip = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *reply_icmp = (sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + reply_ip->ip_hl * 4);
  
  /* Actualizar cabezal Ethernet */
  sr_ethernet_hdr_t *orig_eth = (sr_ethernet_hdr_t *)packet;
  memcpy(reply_eth->ether_dhost, orig_eth->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
  
  /* Actualizar cabezal IP */
  reply_ip->ip_src = orig_ip_hdr->ip_dst;
  reply_ip->ip_dst = orig_ip_hdr->ip_src;
  reply_ip->ip_ttl = 64;
  reply_ip->ip_sum = 0;
  reply_ip->ip_sum = cksum(reply_ip, reply_ip->ip_hl * 4);
  
  /* Actualizar cabezal ICMP */
  reply_icmp->icmp_type = 0;  /* Echo Reply */
  reply_icmp->icmp_code = 0;
  reply_icmp->icmp_sum = 0;
  reply_icmp->icmp_sum = cksum(reply_icmp, len - sizeof(sr_ethernet_hdr_t) - (reply_ip->ip_hl * 4));
  
  /* Enviar la respuesta */
  sr_send_packet(sr, reply_packet, len, iface->name);
  free(reply_packet);
  
  printf("ICMP echo reply enviado\n");
} /* -- sr_send_icmp_echo_reply -- */

void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* 
  * COLOQUE ASÍ SU CÓDIGO
  * SUGERENCIAS: 
  * - Obtener el cabezal IP y direcciones 
  * - Verificar si el paquete es para una de mis interfaces o si hay una coincidencia en mi tabla de enrutamiento 
  * - Si no es para una de mis interfaces y no hay coincidencia en la tabla de enrutamiento, enviar ICMP net unreachable
  * - Sino, si es para mí, verificar si es un paquete ICMP echo request y responder con un echo reply 
  * - Sino, verificar TTL, ARP y reenviar si corresponde (puede necesitar una solicitud ARP y esperar la respuesta)
  * - No olvide imprimir los mensajes de depuración
  */

  /* Obtener el cabezal IP */
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ipDst = ipHdr->ip_dst;

  /* Verificar si el paquete es para una de mis interfaces */
  struct sr_if *iface = sr_get_interface_given_ip(sr, ipDst);
  if (iface != NULL) {
      printf("Paquete destinado a mí\n");
      
      /* Verificar si es un paquete ICMP echo request */
      if (ipHdr->ip_p == ip_protocol_icmp) {
          sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + ipHdr->ip_hl * 4);
          
          /* Si es echo request (tipo 8) */
          if (icmp_hdr->icmp_type == 8) {
              printf("ICMP echo request recibido, enviando echo reply\n");
              sr_send_icmp_echo_reply(sr, packet, len);
          } else {
              printf("ICMP type %u recibido (no es echo request)\n", icmp_hdr->icmp_type);
          }
      } else {
          printf("Paquete no ICMP dirigido a mí\n");
          sr_send_icmp_error_packet(3, 3, sr, ipHdr->ip_src, packet);
      }
      return;
  }

  /* El paquete no es para mí, buscar ruta en la tabla de enrutamiento */
  struct sr_rt *bestMatch = NULL;
  uint32_t longestPrefix = 0;
  struct sr_rt *route = sr->routing_table;
  
  while (route != NULL) {
      if ((ipDst & route->mask.s_addr) == (route->dest.s_addr & route->mask.s_addr)) {
          uint32_t prefixLen = __builtin_popcount(route->mask.s_addr);
          if (prefixLen > longestPrefix) {
              longestPrefix = prefixLen;
              bestMatch = route;
          }
      }
      route = route->next;
  }
  
  /* Si no hay ruta, enviar ICMP net unreachable */
  if (bestMatch == NULL) {
      printf("No hay ruta disponible, enviando ICMP net unreachable\n");
      sr_send_icmp_error_packet(3, 0, sr, ipHdr->ip_src, packet);
      return;
  }

  printf("Reenviando hacia: %s\n", bestMatch->interface);
  
  /* Verificar TTL */
  if (ipHdr->ip_ttl <= 1) {
      printf("TTL expirado, enviando ICMP time exceeded\n");
      sr_send_icmp_error_packet(11, 0, sr, ipHdr->ip_src, packet);
      return;
  }
  
  /* Decrementar TTL y recalcular checksum */
  ipHdr->ip_ttl--;
  ipHdr->ip_sum = 0;
  ipHdr->ip_sum = cksum(ipHdr, ipHdr->ip_hl * 4);

  /* Obtener IP del siguiente salto */
  uint32_t nextHopIP = bestMatch->gw.s_addr;
  if (nextHopIP == 0) {
      nextHopIP = ipDst;
  }

  /* Buscar MAC en caché ARP */
  struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), nextHopIP);

  if (arpEntry != NULL) {
      printf("MAC encontrada en caché\n");
      
      /* Actualizar direcciones MAC en el cabezal Ethernet */
      memcpy(eHdr->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
      struct sr_if *outIface = sr_get_interface(sr, bestMatch->interface);
      memcpy(eHdr->ether_shost, outIface->addr, ETHER_ADDR_LEN);
      
      /* Enviar paquete */
      print_hdrs(packet, len);
      sr_send_packet(sr, packet, len, bestMatch->interface);
      free(arpEntry);
      
      printf("Paquete reenviado correctamente\n");
  } else {
      printf("*** -> MAC not found in cache, requesting ARP for IP %u\n", ntohl(nextHopIP));
      
      /* Crear y enviar ARP request inmediatamente */
      struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), nextHopIP, packet, len, 
                          bestMatch->interface);
      
      /* Enviar el ARP request inmediatamente sin esperar al timeout */
      if (req != NULL) {
          handle_arpreq(sr, req);
      }
  }

}


/* Gestiona la llegada de un paquete ARP*/
void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* Imprimo el cabezal ARP */
  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  /* COLOQUE SU CÓDIGO AQUÍ
  
  SUGERENCIAS:
  - Verifique si se trata de un ARP request o ARP reply 
  - Si es una ARP request, antes de responder verifique si el mensaje consulta por la dirección MAC asociada a una dirección IP configurada en una interfaz del router
  - Si es una ARP reply, agregue el mapeo MAC->IP del emisor a la caché ARP y envíe los paquetes que hayan estado esperando por el ARP reply
  
  */

  /* Obtener cabezal ARP */
  sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  /* Imprimir información del ARP */
  char src_ip_str[INET_ADDRSTRLEN];
  char target_ip_str[INET_ADDRSTRLEN];
  struct in_addr src_ip_addr, target_ip_addr;
  src_ip_addr.s_addr = arpHdr->ar_sip;
  target_ip_addr.s_addr = arpHdr->ar_tip;
  inet_ntop(AF_INET, &src_ip_addr, src_ip_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &target_ip_addr, target_ip_str, INET_ADDRSTRLEN);
  
  /* Verificar si es ARP request */
  if (ntohs(arpHdr->ar_op) == arp_op_request) {
      printf("*** -> ARP request: Who has %s? Tell %s\n", target_ip_str, src_ip_str);
      
      /* Verificar si pregunta por una de mis interfaces */
      struct sr_if *iface = sr_get_interface_given_ip(sr, arpHdr->ar_tip);
      
      if (iface != NULL) {
          printf("*** -> ARP request is for me (interface %s)\n", iface->name);
          
          /* Crear respuesta ARP */
          uint8_t *arpReply = malloc(len);
          memcpy(arpReply, packet, len);
          
          sr_ethernet_hdr_t *replyEth = (sr_ethernet_hdr_t *)arpReply;
          sr_arp_hdr_t *replyArp = (sr_arp_hdr_t *)(arpReply + sizeof(sr_ethernet_hdr_t));
          
          /* Intercambiar direcciones MAC en Ethernet */
          memcpy(replyEth->ether_dhost, eHdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(replyEth->ether_shost, iface->addr, ETHER_ADDR_LEN);
          
          /* Crear ARP reply */
          replyArp->ar_op = htons(arp_op_reply);
          memcpy(replyArp->ar_sha, iface->addr, ETHER_ADDR_LEN);
          replyArp->ar_sip = iface->ip;
          memcpy(replyArp->ar_tha, arpHdr->ar_sha, ETHER_ADDR_LEN);
          replyArp->ar_tip = arpHdr->ar_sip;
          
          /* Enviar respuesta */
          sr_send_packet(sr, arpReply, len, interface);
          free(arpReply);
          
          printf("*** -> ARP reply sent\n");
      } else {
          printf("*** -> ARP request is NOT for any of my interfaces\n");
      }
  } 
  /* Si es ARP reply */
  else if (ntohs(arpHdr->ar_op) == arp_op_reply) {
      printf("*** -> ARP reply: %s is at ", src_ip_str);
      print_addr_eth(arpHdr->ar_sha);
      printf("\n");
      
      /* Insertar en caché ARP */
      struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), 
                                                  arpHdr->ar_sha, 
                                                  arpHdr->ar_sip);
      
      if (req != NULL) {
          /* Enviar paquetes pendientes */
          sr_arp_reply_send_pending_packets(sr, req, arpHdr->ar_sha, 
                                           eHdr->ether_dhost, 
                                           sr_get_interface(sr, req->iface));
          sr_arpreq_destroy(&(sr->cache), req);
      }
  }
}


/* 
* ***** A partir de aquí no debería tener que modificar nada ****
*/

/* Envía todos los paquetes IP pendientes de una solicitud ARP */
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface) {

  struct sr_packet *currPacket = arpReq->packets;
  sr_ethernet_hdr_t *ethHdr;
  uint8_t *copyPacket;

  while (currPacket != NULL) {
     ethHdr = (sr_ethernet_hdr_t *) currPacket->buf;
     memcpy(ethHdr->ether_shost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
     memcpy(ethHdr->ether_dhost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);

     copyPacket = malloc(sizeof(uint8_t) * currPacket->len);
     memcpy(copyPacket, ethHdr, sizeof(uint8_t) * currPacket->len);

     print_hdrs(copyPacket, currPacket->len);
     sr_send_packet(sr, copyPacket, currPacket->len, iface->name);
     free(copyPacket);
     currPacket = currPacket->next;
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d on interface %s\n", len, interface);

  /* Obtengo direcciones MAC origen y destino */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  printf("*** -> EtherType: 0x%04x\n", pktType);

  if (is_packet_valid(packet, len)) {
    if (pktType == ethertype_arp) {
      printf("*** -> Processing ARP packet\n");
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      printf("*** -> Processing IP packet\n");
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  } else {
    printf("*** -> Packet validation failed\n");
  }

  free(destAddr);
  free(srcAddr);
}/* end sr_ForwardPacket */
