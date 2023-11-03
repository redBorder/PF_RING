/*
 *
 * (C) 2016-23 - ntop.org
 *
 */

#ifndef _PFRING_MOD_FIBREBLAZE_H_
#define _PFRING_MOD_FIBREBLAZE_H_

#include "pfring.h"

int  pfring_fb_open(pfring *ring);
void pfring_fb_close(pfring *ring);
int  pfring_fb_stats(pfring *ring, pfring_stat *stats);
int  pfring_fb_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_fb_recv_chunk_pkt(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int pfring_fb_recv_chunk(pfring *ring, void **chunk, pfring_chunk_info *chunk_info, u_int8_t wait_for_incoming_chunk);
int  pfring_fb_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
int  pfring_fb_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_fb_set_poll_duration(pfring *ring, u_int duration);
int  pfring_fb_poll(pfring *ring, u_int wait_duration);
int  pfring_fb_set_direction(pfring *ring, packet_direction direction);
int  pfring_fb_enable_ring(pfring *ring);
int  pfring_fb_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_fb_get_bound_device_ifindex(pfring *ring, int *if_index);
int pfring_fb_get_bound_device_address(pfring *ring, u_char mac_address[6]);
u_int32_t pfring_fb_get_interface_speed(pfring *ring);
int pfring_fb_get_device_clock(pfring *ring, struct timespec *ts);
pfring_if_t *pfring_fb_findalldevs(); 

#endif /* _PFRING_MOD_FIBREBLAZE_H_ */
