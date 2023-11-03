/*
 *
 * (C) 2015-23 - ntop.org
 *
 *
 */

#ifndef _PFRING_MOD_MLX_H_
#define _PFRING_MOD_MLX_H_

#include "pfring.h"

int  pfring_mlx_open(pfring *ring);
void pfring_mlx_close(pfring *ring);
int  pfring_mlx_stats(pfring *ring, pfring_stat *stats);
int  pfring_mlx_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_mlx_recv_ll(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_mlx_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
void pfring_mlx_flush_tx_packets(pfring *ring);
int  pfring_mlx_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_mlx_set_poll_duration(pfring *ring, u_int duration);
int  pfring_mlx_poll(pfring *ring, u_int wait_duration);
int  pfring_mlx_poll_ll(pfring *ring, u_int wait_duration);
int  pfring_mlx_set_direction(pfring *ring, packet_direction direction);
int  pfring_mlx_enable_ring(pfring *ring);
int  pfring_mlx_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_mlx_get_bound_device_ifindex(pfring *ring, int *if_index);
int pfring_mlx_get_bound_device_address(pfring *ring, u_char mac_address[6]);
u_int32_t pfring_mlx_get_interface_speed(pfring *ring);
u_int8_t pfring_mlx_get_num_rx_channels(pfring *ring);
int pfring_mlx_remove_hw_rule(pfring *ring, u_int16_t rule_id);
int pfring_mlx_set_default_hw_action(pfring *ring, generic_default_action_type action);
int pfring_mlx_add_hw_rule(pfring *ring, hw_filtering_rule *rule);
int pfring_mlx_set_bpf_filter(pfring *ring, char *bpf);
pfring_if_t *pfring_mlx_findalldevs();

#endif /* _PFRING_MOD_MLX_H_ */
