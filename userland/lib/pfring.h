/*
 *
 * (C) 2005-11 - Luca Deri <deri@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _PFRING_MAIN_H_
#define _PFRING_MAIN_H_

#include "pfring_api.h"

int      pfring_main_open (pfring *ring);

void     pfring_main_close(pfring *ring);
int      pfring_main_stats(pfring *ring, pfring_stat *stats);
int      pfring_main_recv (pfring *ring, char* buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int      pfring_main_set_poll_watermark(pfring *ring, u_int16_t watermark);
int      pfring_main_set_poll_duration(pfring *ring, u_int duration);
int      pfring_main_add_hw_rule(pfring *ring, hw_filtering_rule *rule);
int      pfring_main_remove_hw_rule(pfring *ring, u_int16_t rule_id);
int      pfring_main_set_channel_id(pfring *ring, u_int32_t channel_id);
int      pfring_main_set_application_name(pfring *ring, char *name);
int      pfring_main_bind(pfring *ring, char *device_name);
int      pfring_main_send(pfring *ring, char *pkt, u_int pkt_len);
u_int8_t pfring_main_get_num_rx_channels(pfring *ring);
int      pfring_main_set_sampling_rate(pfring *ring, u_int32_t rate);
int      pfring_main_get_selectable_fd(pfring *ring);

#endif /* _PFRING_MAIN_H_ */
