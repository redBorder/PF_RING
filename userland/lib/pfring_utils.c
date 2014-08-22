/*
 *
 * (C) 2005-12 - Luca Deri <deri@ntop.org>
 *               Alfredo Cardigliano <cardigliano@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 */

#include "pfring.h"
#include "pfring_utils.h"

#include <linux/if.h>

#ifdef ENABLE_HW_TIMESTAMP
#include <linux/net_tstamp.h>
#endif

/* ******************************* */

int pfring_enable_hw_timestamp(pfring* ring, char *device_name, u_int8_t enable_rx, u_int8_t enable_tx) {
#ifdef ENABLE_HW_TIMESTAMP
  struct hwtstamp_config hwconfig;
  struct ifreq ifr;
  int rc, sock_fd;

  sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_fd <= 0)
    return(-1);

  memset(&hwconfig, 0, sizeof(hwconfig));

  hwconfig.rx_filter = (enable_rx ? HWTSTAMP_FILTER_ALL : HWTSTAMP_FILTER_NONE);
  hwconfig.tx_type   = (enable_tx ? HWTSTAMP_TX_ON      : HWTSTAMP_TX_OFF);

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device_name, sizeof(ifr.ifr_name)-1);
  ifr.ifr_data = (void *) &hwconfig;

  rc = ioctl(sock_fd, SIOCSHWTSTAMP, &ifr);

  if (rc < 0)
    rc = errno;
  else
    rc = 0;

  errno = 0;

#ifdef RING_DEBUG
  printf("pfring_enable_hw_timestamp(%s) returned %d\n", device_name, rc);
#endif

  close(sock_fd);

  return rc;
#else
  return(-1);
#endif
}

/* ******************************* */

static u_int32_t pfring_hash_pkt(struct pfring_pkthdr *hdr) {
  if (hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id == NO_TUNNEL_ID) {
    return
      hdr->extended_hdr.parsed_pkt.vlan_id +
      hdr->extended_hdr.parsed_pkt.l3_proto +
      hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[0] +
      hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[1] +
      hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[2] +
      hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[3] +
      hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[0] +
      hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[1] +
      hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[2] +
      hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[3] +
      hdr->extended_hdr.parsed_pkt.l4_src_port + 
      hdr->extended_hdr.parsed_pkt.l4_dst_port;
  } else {
    return
      hdr->extended_hdr.parsed_pkt.vlan_id +
      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto +
      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.s6_addr32[1] +
      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.s6_addr32[2] +
      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.s6_addr32[3] +
      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[0] +
      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[1] +
      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[2] +
      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[3] +
      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port +
      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port;
  }  
}

/* ******************************* */

static int __pfring_parse_tunneled_pkt(u_char *pkt, struct pfring_pkthdr *hdr, u_int16_t ip_version, u_int16_t tunnel_offset) {
  u_int32_t ip_len = 0;
  u_int16_t fragment_offset = 0;

  if(ip_version == 4 /* IPv4 */ ) {
    struct iphdr *tunneled_ip;

    if(hdr->caplen < (tunnel_offset+sizeof(struct iphdr)))
      return 0;

    tunneled_ip = (struct iphdr *) (&pkt[tunnel_offset]);

    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = tunneled_ip->protocol;
    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v4 = ntohl(tunneled_ip->saddr);
    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v4 = ntohl(tunneled_ip->daddr);

    fragment_offset = tunneled_ip->frag_off & htons(IP_OFFSET); /* fragment, but not the first */
    ip_len = tunneled_ip->ihl*4;
    tunnel_offset += ip_len;

  } else if(ip_version == 6 /* IPv6 */ ) {
    struct ipv6hdr *tunneled_ipv6;

    if(hdr->caplen < (tunnel_offset+sizeof(struct ipv6hdr))) 
      return 0;

    tunneled_ipv6 = (struct ipv6hdr *) (&pkt[tunnel_offset]);

    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = tunneled_ipv6->nexthdr;
    
    /* Values of IPv6 addresses are stored as network byte order */
    memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6, &tunneled_ipv6->saddr, sizeof(tunneled_ipv6->saddr));
    memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6, &tunneled_ipv6->daddr, sizeof(tunneled_ipv6->daddr));

    ip_len = sizeof(struct ipv6hdr);

    while(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_HOP
	  || hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_DEST
	  || hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_ROUTING
	  || hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_AUTH
	  || hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_ESP
	  || hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_FRAGMENT) {
      struct ipv6_opt_hdr *ipv6_opt;

      if(hdr->caplen < (tunnel_offset+ip_len+sizeof(struct ipv6_opt_hdr))) return 1;

      ipv6_opt = (struct ipv6_opt_hdr *)(&pkt[tunnel_offset+ip_len]);
      ip_len += sizeof(struct ipv6_opt_hdr), fragment_offset = 0;
      if(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_AUTH)
	/*
	  RFC4302 2.2. Payload Length: This 8-bit field specifies the
	  length of AH in 32-bit words (4-byte units), minus "2".
	*/
	ip_len += ipv6_opt->hdrlen * 4;
      else if(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto != NEXTHDR_FRAGMENT)
        ip_len += ipv6_opt->hdrlen;

      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = ipv6_opt->nexthdr;
    } /* while */

    tunnel_offset += ip_len;

  } else
    return 0;

  if (fragment_offset)
    return 1;

  if(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == IPPROTO_TCP) {
    struct tcphdr *tcp;

    if(hdr->caplen < tunnel_offset + sizeof(struct tcphdr))
      return 1;

    tcp = (struct tcphdr *)(&pkt[tunnel_offset]);

    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port = ntohs(tcp->source), 
    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port = ntohs(tcp->dest);
  } else if(hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == IPPROTO_UDP) {
    struct udphdr *udp;

    if(hdr->caplen < tunnel_offset + sizeof(struct udphdr)) 
      return 1;
    
    udp = (struct udphdr *)(&pkt[tunnel_offset]);

    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port = ntohs(udp->source), 
    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port = ntohs(udp->dest);
  }

  return 2;
}

/* ******************************* */

int pfring_parse_pkt(u_char *pkt, struct pfring_pkthdr *hdr, u_int8_t level /* L2..L4, 5 (tunnel) */, 
		     u_int8_t add_timestamp /* 0,1 */, u_int8_t add_hash /* 0,1 */) {
  struct ethhdr *eh = (struct ethhdr*) pkt;
  u_int32_t displ = 0, ip_len;
  u_int16_t analyzed = 0, fragment_offset = 0;

  hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = NO_TUNNEL_ID;

  /* Note: in order to optimize the computation, this function expects a zero-ed 
   * or partially parsed pkthdr */
  //memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
  //hdr->extended_hdr.parsed_header_len = 0;

  if (hdr->extended_hdr.parsed_pkt.offset.l3_offset != 0)
    goto L3;

  memcpy(&hdr->extended_hdr.parsed_pkt.dmac, eh->h_dest,   sizeof(eh->h_dest));
  memcpy(&hdr->extended_hdr.parsed_pkt.smac, eh->h_source, sizeof(eh->h_source));

  hdr->extended_hdr.parsed_pkt.eth_type = ntohs(eh->h_proto);
  hdr->extended_hdr.parsed_pkt.offset.eth_offset = 0;
  hdr->extended_hdr.parsed_pkt.offset.vlan_offset = 0;
  hdr->extended_hdr.parsed_pkt.vlan_id = 0; /* Any VLAN */

  if (hdr->extended_hdr.parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */) {
    struct eth_vlan_hdr *vh;
    hdr->extended_hdr.parsed_pkt.offset.vlan_offset = sizeof(struct ethhdr) - sizeof(struct eth_vlan_hdr);
    while (hdr->extended_hdr.parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */ ) {
      hdr->extended_hdr.parsed_pkt.offset.vlan_offset += sizeof(struct eth_vlan_hdr);
      vh = (struct eth_vlan_hdr *) &pkt[hdr->extended_hdr.parsed_pkt.offset.vlan_offset];
      hdr->extended_hdr.parsed_pkt.vlan_id = ntohs(vh->h_vlan_id) & 0x0fff;
      hdr->extended_hdr.parsed_pkt.eth_type = ntohs(vh->h_proto);
      displ += sizeof(struct eth_vlan_hdr);
    }
  }

  hdr->extended_hdr.parsed_pkt.offset.l3_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset + displ + sizeof(struct ethhdr);

 L3:

  analyzed = 2;

  if (level < 3)
    goto TIMESTAMP;

  if (hdr->extended_hdr.parsed_pkt.offset.l4_offset != 0)
    goto L4;

  if (hdr->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4 */) {
    struct iphdr *ip;

    hdr->extended_hdr.parsed_pkt.ip_version = 4;

    if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct iphdr))
      goto TIMESTAMP;

    ip = (struct iphdr *)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);

    hdr->extended_hdr.parsed_pkt.ipv4_src = ntohl(ip->saddr);
    hdr->extended_hdr.parsed_pkt.ipv4_dst = ntohl(ip->daddr);
    hdr->extended_hdr.parsed_pkt.l3_proto = ip->protocol;
    hdr->extended_hdr.parsed_pkt.ipv4_tos = ip->tos;
    fragment_offset = ip->frag_off & htons(IP_OFFSET); /* fragment, but not the first */
    ip_len  = ip->ihl*4;

  } else if(hdr->extended_hdr.parsed_pkt.eth_type == 0x86DD /* IPv6 */) {
    struct ipv6hdr *ipv6;

    hdr->extended_hdr.parsed_pkt.ip_version = 6;

    if(hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct ipv6hdr)) 
      goto TIMESTAMP;

    ipv6 = (struct ipv6hdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);
    ip_len = sizeof(struct ipv6hdr);

    /* Values of IPv6 addresses are stored as network byte order */
    memcpy(&hdr->extended_hdr.parsed_pkt.ipv6_src, &ipv6->saddr, sizeof(ipv6->saddr));
    memcpy(&hdr->extended_hdr.parsed_pkt.ipv6_dst, &ipv6->daddr, sizeof(ipv6->daddr));

    hdr->extended_hdr.parsed_pkt.l3_proto = ipv6->nexthdr;
    hdr->extended_hdr.parsed_pkt.ipv6_tos = ipv6->priority; /* IPv6 class of service */

    while(hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_HOP	   ||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_DEST	   ||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ROUTING ||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_AUTH	   ||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ESP	   ||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_FRAGMENT) {
      struct ipv6_opt_hdr *ipv6_opt;

      if(hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len + sizeof(struct ipv6_opt_hdr))
        goto TIMESTAMP;

      ipv6_opt = (struct ipv6_opt_hdr *)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len]);
      ip_len += sizeof(struct ipv6_opt_hdr);
      if(hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_AUTH)
	/*
	  RFC4302 2.2. Payload Length: This 8-bit field specifies the
	  length of AH in 32-bit words (4-byte units), minus "2".
	*/
        ip_len += ipv6_opt->hdrlen * 4;
      else if(hdr->extended_hdr.parsed_pkt.l3_proto != NEXTHDR_FRAGMENT)
        ip_len += ipv6_opt->hdrlen;

      hdr->extended_hdr.parsed_pkt.l3_proto = ipv6_opt->nexthdr;
    }
  } else {
    hdr->extended_hdr.parsed_pkt.l3_proto = 0;
    goto TIMESTAMP;
  }

  hdr->extended_hdr.parsed_pkt.offset.l4_offset = hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len;

 L4:

  analyzed = 3;

  if (level < 4 || fragment_offset)
    goto TIMESTAMP;

  if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) {
    struct tcphdr *tcp;

    if(hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct tcphdr)) 
      goto TIMESTAMP;

    tcp = (struct tcphdr *)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

    hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(tcp->source);
    hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(tcp->dest);
    hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + (tcp->doff * 4);
    hdr->extended_hdr.parsed_pkt.tcp.seq_num = ntohl(tcp->seq);
    hdr->extended_hdr.parsed_pkt.tcp.ack_num = ntohl(tcp->ack_seq);
    hdr->extended_hdr.parsed_pkt.tcp.flags = (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) +
      (tcp->rst * TH_RST_MULTIPLIER) + (tcp->psh * TH_PUSH_MULTIPLIER) +
      (tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);

    analyzed = 4;
  } else if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP) {
    struct udphdr *udp;

    if(hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr)) 
      goto TIMESTAMP;

    udp = (struct udphdr *)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

    hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(udp->source), hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(udp->dest);
    hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr);
    
    analyzed = 4;

    if (level < 5)
      goto TIMESTAMP;

    /* GTPv1 */
    if((hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_SIGNALING_PORT) || 
       (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_SIGNALING_PORT) || 
       (hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_U_DATA_PORT)    || 
       (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_U_DATA_PORT))  {
      struct gtp_v1_hdr *gtp;
      u_int16_t gtp_len;

      if(hdr->caplen < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+sizeof(struct gtp_v1_hdr)))
        goto TIMESTAMP;

      gtp = (struct gtp_v1_hdr *) (&pkt[hdr->extended_hdr.parsed_pkt.offset.payload_offset]);
      gtp_len = sizeof(struct gtp_v1_hdr);

      if(((gtp->flags & GTP_FLAGS_VERSION) >> GTP_FLAGS_VERSION_SHIFT) == GTP_VERSION_1) {
        struct iphdr *tunneled_ip;

	hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = ntohl(gtp->teid);

	if((hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_U_DATA_PORT) || 
	   (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_U_DATA_PORT)) {
	  if(gtp->flags & (GTP_FLAGS_EXTENSION | GTP_FLAGS_SEQ_NUM | GTP_FLAGS_NPDU_NUM)) {
	    struct gtp_v1_opt_hdr *gtpopt;

            if(hdr->caplen < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+gtp_len+sizeof(struct gtp_v1_opt_hdr)))
	      goto TIMESTAMP;
	      
	    gtpopt = (struct gtp_v1_opt_hdr *) (&pkt[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len]);
	    gtp_len += sizeof(struct gtp_v1_opt_hdr);

	    if((gtp->flags & GTP_FLAGS_EXTENSION) && gtpopt->next_ext_hdr) {
	      struct gtp_v1_ext_hdr *gtpext;
	      u_int8_t *next_ext_hdr;

	      do {
		if(hdr->caplen < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+gtp_len +1/* 8bit len field */)) goto TIMESTAMP;
		gtpext = (struct gtp_v1_ext_hdr *) (&pkt[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len]);
		gtp_len += (gtpext->len * GTP_EXT_HDR_LEN_UNIT_BYTES);
		if(gtpext->len == 0 || hdr->caplen < (hdr->extended_hdr.parsed_pkt.offset.payload_offset+gtp_len)) goto TIMESTAMP;
		next_ext_hdr = (u_int8_t *) (&pkt[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len - 1/* 8bit next_ext_hdr field*/]);
	      } while (*next_ext_hdr);
	    }
	  }

	  if(hdr->caplen < (hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len + sizeof(struct iphdr)))
	    goto TIMESTAMP;

	  tunneled_ip = (struct iphdr *) (&pkt[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len]);

          analyzed += __pfring_parse_tunneled_pkt(pkt, hdr, tunneled_ip->version, hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len);
        }
      }
    }
  } else if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_GRE /* 0x47 */) {
    struct gre_header *gre = (struct gre_header*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);
    int gre_offset;

    gre->flags_and_version = ntohs(gre->flags_and_version);
    gre->proto = ntohs(gre->proto);

    gre_offset = sizeof(struct gre_header);

    if((gre->flags_and_version & GRE_HEADER_VERSION) == 0) { 
      if(gre->flags_and_version & (GRE_HEADER_CHECKSUM | GRE_HEADER_ROUTING)) gre_offset += 4;
      if(gre->flags_and_version & GRE_HEADER_KEY) {
        u_int32_t *tunnel_id = (u_int32_t*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset+gre_offset]); 
        gre_offset += 4;
	hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = ntohl(*tunnel_id);
      }
      if(gre->flags_and_version & GRE_HEADER_SEQ_NUM)  gre_offset += 4;

      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + gre_offset;

      analyzed = 4;

      if (level < 5)
        goto TIMESTAMP;

      if (gre->proto == ETH_P_IP /* IPv4 */ || gre->proto == ETH_P_IPV6 /* IPv6 */)
        analyzed += __pfring_parse_tunneled_pkt(pkt, hdr, gre->proto == ETH_P_IP ? 4 : 6, hdr->extended_hdr.parsed_pkt.offset.payload_offset);

    } else { /* TODO handle other GRE versions */
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
    }
  } else {
    hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
    hdr->extended_hdr.parsed_pkt.l4_src_port = hdr->extended_hdr.parsed_pkt.l4_dst_port = 0;
  }

TIMESTAMP:

  if(add_timestamp && hdr->ts.tv_sec == 0)
    gettimeofday(&hdr->ts, NULL); /* TODO What about using clock_gettime(CLOCK_REALTIME, ts) ? */

  if (add_hash && hdr->extended_hdr.pkt_hash == 0)
    hdr->extended_hdr.pkt_hash = pfring_hash_pkt(hdr);

  return analyzed;
}

/* ****************************************************** */

static char *etheraddr2string(const u_char *ep, char *buf) {
  char *hex = "0123456789ABCDEF";
  u_int i, j;
  char *cp;

  cp = buf;
  if((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ****************************************************** */

static char *_intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  retStr = (char*)(cp+1);

  return(retStr);
}

/* ************************************ */

static char *intoa(unsigned int addr) {
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];
  return(_intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

static char *in6toa(struct in6_addr addr6) {
  static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];
  char *ret = (char*)inet_ntop(AF_INET6, &addr6, buf, sizeof(buf));
  
  if(ret == NULL) {
    //printf("Internal error (&buff[buff_used]r too short)");
    buf[0] = '\0';
  }
  
  return(ret);
}

/* ****************************************************** */

static char *proto2str(u_short proto) {
  static char protoName[8];

  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  case IPPROTO_GRE:  return("GRE");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return(protoName);
  }
}

/* ******************************* */

int pfring_print_parsed_pkt(char *buff, u_int buff_len, const u_char *p, const struct pfring_pkthdr *h) {
  char buf1[32], buf2[32];
  int buff_used = 0;

  buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
    "[%s -> %s] ",
    etheraddr2string(h->extended_hdr.parsed_pkt.smac, buf1),
    etheraddr2string(h->extended_hdr.parsed_pkt.dmac, buf2));    

  if(h->extended_hdr.parsed_pkt.offset.vlan_offset)
    buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
      "[vlan %u] ", h->extended_hdr.parsed_pkt.vlan_id);

  if (h->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/ || h->extended_hdr.parsed_pkt.eth_type == 0x86DD /* IPv6*/) {

    if(h->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/ ) {
      buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
        "[IPv4][%s:%d ", intoa(h->extended_hdr.parsed_pkt.ipv4_src), h->extended_hdr.parsed_pkt.l4_src_port);
      buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
        "-> %s:%d] ", intoa(h->extended_hdr.parsed_pkt.ipv4_dst), h->extended_hdr.parsed_pkt.l4_dst_port);
    } else {
      buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
        "[IPv6][%s:%d ",    in6toa(h->extended_hdr.parsed_pkt.ipv6_src), h->extended_hdr.parsed_pkt.l4_src_port);
      buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
        "-> %s:%d] ", in6toa(h->extended_hdr.parsed_pkt.ipv6_dst), h->extended_hdr.parsed_pkt.l4_dst_port);
    }

    buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
      "[l3_proto=%s]", proto2str(h->extended_hdr.parsed_pkt.l3_proto));

    if(h->extended_hdr.parsed_pkt.tunnel.tunnel_id != NO_TUNNEL_ID) {
      buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
        "[TEID=0x%08X][tunneled_proto=%s]", 
        h->extended_hdr.parsed_pkt.tunnel.tunnel_id,
        proto2str(h->extended_hdr.parsed_pkt.tunnel.tunneled_proto));

      if(h->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/ ) {
        buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
	  "[IPv4][%s:%d ",
          intoa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v4),
          h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port);
        buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
	  "-> %s:%d] ", 
          intoa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v4),
          h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port);
      } else {
        buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
	  "[IPv6][%s:%d ", 
          in6toa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6),
          h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port);
        buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
	  "-> %s:%d] ",
          in6toa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6),
          h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port);
      }	  
    }

    buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
      "[hash=%u][tos=%d][tcp_seq_num=%u]",
      h->extended_hdr.pkt_hash,
      h->extended_hdr.parsed_pkt.ipv4_tos, 
      h->extended_hdr.parsed_pkt.tcp.seq_num);
	
  } else if(h->extended_hdr.parsed_pkt.eth_type == 0x0806 /* ARP */) {
    buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[ARP]");
    if (buff_len >= h->extended_hdr.parsed_pkt.offset.l3_offset+30) {
      buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
        "[Sender=%s/%s]",
        etheraddr2string(&p[h->extended_hdr.parsed_pkt.offset.l3_offset+8], buf1),
        intoa(ntohl(*((u_int32_t *) &p[h->extended_hdr.parsed_pkt.offset.l3_offset+14]))));
      buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
        "[Target=%s/%s]", 
        etheraddr2string(&p[h->extended_hdr.parsed_pkt.offset.l3_offset+18], buf2),
        intoa(ntohl(*((u_int32_t *) &p[h->extended_hdr.parsed_pkt.offset.l3_offset+24]))));
    }
  } else {
    buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
      "[eth_type=0x%04X]", h->extended_hdr.parsed_pkt.eth_type);
  }

  buff_used += snprintf(&buff[buff_used], buff_len - buff_used, 
    " [caplen=%d][len=%d][parsed_header_len=%d][eth_offset=%d][l3_offset=%d][l4_offset=%d][payload_offset=%d]\n",
    h->caplen, h->len, h->extended_hdr.parsed_header_len,
    h->extended_hdr.parsed_pkt.offset.eth_offset,
    h->extended_hdr.parsed_pkt.offset.l3_offset,
    h->extended_hdr.parsed_pkt.offset.l4_offset,
    h->extended_hdr.parsed_pkt.offset.payload_offset);

  return buff_used;
}

/* ******************************* */

int pfring_print_pkt(char *buff, u_int buff_len, const u_char *p, u_int len, u_int caplen) {
  struct pfring_pkthdr hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.len = len, hdr.caplen = caplen;
  pfring_parse_pkt((u_char *) p, &hdr, 5, 0, 1);
  return pfring_print_parsed_pkt(buff, buff_len, p, &hdr);
}

/* ******************************* */

static int pfring_promisc(const char *device, int set_promisc) {
  int sock_fd, ret = 0;
  struct ifreq ifr;

  if(device == NULL) return(-3);

  sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(sock_fd <= 0) return(-1);

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  if(ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
    close(sock_fd);
    return(-2);
  }

  ret = ifr.ifr_flags & IFF_PROMISC;
  if(set_promisc) {
    if(ret == 0) ifr.ifr_flags |= IFF_PROMISC;
  } else {
    /* Remove promisc */
    if(ret != 0) ifr.ifr_flags &= ~IFF_PROMISC;
  }

  if(ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1)
    return(-1);

  close(sock_fd);
  return(ret);
}

/* ******************************* */

int pfring_set_if_promisc(const char *device, int set_promisc) {
  char name_copy[256], *elem;
  int ret = 0;
  
  snprintf(name_copy, sizeof(name_copy), "%s", device);
  elem = strtok(name_copy, ";,");

  while(elem != NULL) {
    char *at = strchr(elem, '@');

    if(at != NULL) at[0] = '\0';

    ret = pfring_promisc(elem, set_promisc);
    
    if(ret < 0) return(ret);

    elem = strtok(NULL, ";,");
  }

  return(ret);
}

/* *************************************** */

char* pfring_format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals) {
  u_int a1 = ((u_long)val / 1000000000) % 1000;
  u_int a = ((u_long)val / 1000000) % 1000;
  u_int b = ((u_long)val / 1000) % 1000;
  u_int c = (u_long)val % 1000;
  u_int d = (u_int)((val - (u_long)val)*100) % 100;  

  if(add_decimals) {
    if(val >= 1000000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u'%03u.%02d", a1, a, b, c, d);
    } else if(val >= 1000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u.%02d", a, b, c, d);
    } else if(val >= 100000) {
      snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
    } else if(val >= 1000) {
      snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
    } else
      snprintf(buf, buf_len, "%.2f", val);
  } else {
    if(val >= 1000000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u'%03u", a1, a, b, c);
    } else if(val >= 1000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u", a, b, c);
    } else if(val >= 100000) {
      snprintf(buf, buf_len, "%u'%03u", b, c);
    } else if(val >= 1000) {
      snprintf(buf, buf_len, "%u'%03u", b, c);
    } else
      snprintf(buf, buf_len, "%u", (unsigned int)val);
  }

  return(buf);
}

/* *************************************** */

int pfring_get_mtu_size(pfring* ring) {
  struct ifreq ifr;

  if(ring->device_name == NULL)
    return(0); /* Unknown for this device */

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ring->device_name, sizeof(ifr.ifr_name));
  
  if(ioctl(ring->fd, SIOCGIFMTU, &ifr) == -1)
    return(0); /* Unknown for this device */  
  else
    return(ifr.ifr_mtu);
}

/* *************************************** */

int pfring_parse_bpf_filter(char *filter_buffer, u_int caplen,
#ifdef BPF_RELEASE
                            struct bpf_program
#else
                            struct pfring_bpf_program
#endif
                            *filter) {
#ifdef ENABLE_BPF
  if (pcap_compile_nopcap(caplen,        /* snaplen_arg */
                          DLT_EN10MB,    /* linktype_arg */
                          filter,        /* program */
                          filter_buffer, /* const char *buf */
                          0,             /* optimize */
                          0              /* mask */
                          ) == -1)
    return PF_RING_ERROR_INVALID_ARGUMENT;

  if(filter->bf_insns == NULL)
    return PF_RING_ERROR_INVALID_ARGUMENT;

  return 0;
#else
  return PF_RING_ERROR_NOT_SUPPORTED;
#endif
}

/* *************************************** */

int32_t gmt_to_local(time_t t) {
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;

  if (t == 0)
    t = time(NULL);
  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
    (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/* ****************************************************** */

char* sysdig_event2name(u_int event_type) {
  static char unknown[32];

  switch(event_type) {
  case 0: return("GENERIC_E");
  case 1: return("GENERIC_X");
  case 2: return("SYSCALL_OPEN_E");
  case 3: return("SYSCALL_OPEN_X");
  case 4: return("SYSCALL_CLOSE_E");
  case 5: return("SYSCALL_CLOSE_X");
  case 6: return("SYSCALL_READ_E");
  case 7: return("SYSCALL_READ_X");
  case 8: return("SYSCALL_WRITE_E");
  case 9: return("SYSCALL_WRITE_X");
  case 10: return("SYSCALL_BRK_1_E");
  case 11: return("SYSCALL_BRK_1_X");
  case 12: return("SYSCALL_EXECVE_8_E");
  case 13: return("SYSCALL_EXECVE_8_X");
  case 14: return("CLONE_11_E");
  case 15: return("CLONE_11_X");
  case 16: return("PROCEXIT_E");
  case 17: return("PROCEXIT_X");
  case 18: return("SOCKET_SOCKET_E");
  case 19: return("SOCKET_SOCKET_X");
  case 20: return("SOCKET_BIND_E");
  case 21: return("SOCKET_BIND_X");
  case 22: return("SOCKET_CONNECT_E");
  case 23: return("SOCKET_CONNECT_X");
  case 24: return("SOCKET_LISTEN_E");
  case 25: return("SOCKET_LISTEN_X");
  case 26: return("SOCKET_ACCEPT_E");
  case 27: return("SOCKET_ACCEPT_X");
  case 28: return("SOCKET_SEND_E");
  case 29: return("SOCKET_SEND_X");
  case 30: return("SOCKET_SENDTO_E");
  case 31: return("SOCKET_SENDTO_X");
  case 32: return("SOCKET_RECV_E");
  case 33: return("SOCKET_RECV_X");
  case 34: return("SOCKET_RECVFROM_E");
  case 35: return("SOCKET_RECVFROM_X");
  case 36: return("SOCKET_SHUTDOWN_E");
  case 37: return("SOCKET_SHUTDOWN_X");
  case 38: return("SOCKET_GETSOCKNAME_E");
  case 39: return("SOCKET_GETSOCKNAME_X");
  case 40: return("SOCKET_GETPEERNAME_E");
  case 41: return("SOCKET_GETPEERNAME_X");
  case 42: return("SOCKET_SOCKETPAIR_E");
  case 43: return("SOCKET_SOCKETPAIR_X");
  case 44: return("SOCKET_SETSOCKOPT_E");
  case 45: return("SOCKET_SETSOCKOPT_X");
  case 46: return("SOCKET_GETSOCKOPT_E");
  case 47: return("SOCKET_GETSOCKOPT_X");
  case 48: return("SOCKET_SENDMSG_E");
  case 49: return("SOCKET_SENDMSG_X");
  case 50: return("SOCKET_SENDMMSG_E");
  case 51: return("SOCKET_SENDMMSG_X");
  case 52: return("SOCKET_RECVMSG_E");
  case 53: return("SOCKET_RECVMSG_X");
  case 54: return("SOCKET_RECVMMSG_E");
  case 55: return("SOCKET_RECVMMSG_X");
  case 56: return("SOCKET_ACCEPT4_E");
  case 57: return("SOCKET_ACCEPT4_X");
  case 58: return("SYSCALL_CREAT_E");
  case 59: return("SYSCALL_CREAT_X");
  case 60: return("SYSCALL_PIPE_E");
  case 61: return("SYSCALL_PIPE_X");
  case 62: return("SYSCALL_EVENTFD_E");
  case 63: return("SYSCALL_EVENTFD_X");
  case 64: return("SYSCALL_FUTEX_E");
  case 65: return("SYSCALL_FUTEX_X");
  case 66: return("SYSCALL_STAT_E");
  case 67: return("SYSCALL_STAT_X");
  case 68: return("SYSCALL_LSTAT_E");
  case 69: return("SYSCALL_LSTAT_X");
  case 70: return("SYSCALL_FSTAT_E");
  case 71: return("SYSCALL_FSTAT_X");
  case 72: return("SYSCALL_STAT64_E");
  case 73: return("SYSCALL_STAT64_X");
  case 74: return("SYSCALL_LSTAT64_E");
  case 75: return("SYSCALL_LSTAT64_X");
  case 76: return("SYSCALL_FSTAT64_E");
  case 77: return("SYSCALL_FSTAT64_X");
  case 78: return("SYSCALL_EPOLLWAIT_E");
  case 79: return("SYSCALL_EPOLLWAIT_X");
  case 80: return("SYSCALL_POLL_E");
  case 81: return("SYSCALL_POLL_X");
  case 82: return("SYSCALL_SELECT_E");
  case 83: return("SYSCALL_SELECT_X");
  case 84: return("SYSCALL_NEWSELECT_E");
  case 85: return("SYSCALL_NEWSELECT_X");
  case 86: return("SYSCALL_LSEEK_E");
  case 87: return("SYSCALL_LSEEK_X");
  case 88: return("SYSCALL_LLSEEK_E");
  case 89: return("SYSCALL_LLSEEK_X");
  case 90: return("SYSCALL_IOCTL_E");
  case 91: return("SYSCALL_IOCTL_X");
  case 92: return("SYSCALL_GETCWD_E");
  case 93: return("SYSCALL_GETCWD_X");
  case 94: return("SYSCALL_CHDIR_E");
  case 95: return("SYSCALL_CHDIR_X");
  case 96: return("SYSCALL_FCHDIR_E");
  case 97: return("SYSCALL_FCHDIR_X");
  case 98: return("SYSCALL_MKDIR_E");
  case 99: return("SYSCALL_MKDIR_X");
  case 100: return("SYSCALL_RMDIR_E");
  case 101: return("SYSCALL_RMDIR_X");
  case 102: return("SYSCALL_OPENAT_E");
  case 103: return("SYSCALL_OPENAT_X");
  case 104: return("SYSCALL_LINK_E");
  case 105: return("SYSCALL_LINK_X");
  case 106: return("SYSCALL_LINKAT_E");
  case 107: return("SYSCALL_LINKAT_X");
  case 108: return("SYSCALL_UNLINK_E");
  case 109: return("SYSCALL_UNLINK_X");
  case 110: return("SYSCALL_UNLINKAT_E");
  case 111: return("SYSCALL_UNLINKAT_X");
  case 112: return("SYSCALL_PREAD_E");
  case 113: return("SYSCALL_PREAD_X");
  case 114: return("SYSCALL_PWRITE_E");
  case 115: return("SYSCALL_PWRITE_X");
  case 116: return("SYSCALL_READV_E");
  case 117: return("SYSCALL_READV_X");
  case 118: return("SYSCALL_WRITEV_E");
  case 119: return("SYSCALL_WRITEV_X");
  case 120: return("SYSCALL_PREADV_E");
  case 121: return("SYSCALL_PREADV_X");
  case 122: return("SYSCALL_PWRITEV_E");
  case 123: return("SYSCALL_PWRITEV_X");
  case 124: return("SYSCALL_DUP_E");
  case 125: return("SYSCALL_DUP_X");
  case 126: return("SYSCALL_SIGNALFD_E");
  case 127: return("SYSCALL_SIGNALFD_X");
  case 128: return("SYSCALL_KILL_E");
  case 129: return("SYSCALL_KILL_X");
  case 130: return("SYSCALL_TKILL_E");
  case 131: return("SYSCALL_TKILL_X");
  case 132: return("SYSCALL_TGKILL_E");
  case 133: return("SYSCALL_TGKILL_X");
  case 134: return("SYSCALL_NANOSLEEP_E");
  case 135: return("SYSCALL_NANOSLEEP_X");
  case 136: return("SYSCALL_TIMERFD_CREATE_E");
  case 137: return("SYSCALL_TIMERFD_CREATE_X");
  case 138: return("SYSCALL_INOTIFY_INIT_E");
  case 139: return("SYSCALL_INOTIFY_INIT_X");
  case 140: return("SYSCALL_GETRLIMIT_E");
  case 141: return("SYSCALL_GETRLIMIT_X");
  case 142: return("SYSCALL_SETRLIMIT_E");
  case 143: return("SYSCALL_SETRLIMIT_X");
  case 144: return("SYSCALL_PRLIMIT_E");
  case 145: return("SYSCALL_PRLIMIT_X");
  case 146: return("SCHEDSWITCH_1_E");
  case 147: return("SCHEDSWITCH_1_X");
  case 148: return("DROP_E");
  case 149: return("DROP_X");
  case 150: return("SYSCALL_FCNTL_E");
  case 151: return("SYSCALL_FCNTL_X");
  case 152: return("SCHEDSWITCH_6_E");
  case 153: return("SCHEDSWITCH_6_X");
  case 154: return("SYSCALL_EXECVE_13_E");
  case 155: return("SYSCALL_EXECVE_13_X");
  case 156: return("CLONE_16_E");
  case 157: return("CLONE_16_X");
  case 158: return("SYSCALL_BRK_4_E");
  case 159: return("SYSCALL_BRK_4_X");
  case 160: return("SYSCALL_MMAP_E");
  case 161: return("SYSCALL_MMAP_X");
  case 162: return("SYSCALL_MMAP2_E");
  case 163: return("SYSCALL_MMAP2_X");
  case 164: return("SYSCALL_MUNMAP_E");
  case 165: return("SYSCALL_MUNMAP_X");
  case 166: return("SYSCALL_SPLICE_E");
  case 167: return("SYSCALL_SPLICE_X");
  default:
    snprintf(unknown, sizeof(unknown), "%u", event_type);
  }

  return("???"); /* NOTREACHED */
};
