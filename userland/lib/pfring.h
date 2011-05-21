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

#ifndef _PFRING_H_
#define _PFRING_H_

/* Test Only */
//#define USE_PCAP 

#include <sys/types.h>

#ifndef __USE_XOPEN2K
typedef volatile int pthread_spinlock_t;
extern int pthread_spin_init (pthread_spinlock_t *__lock,
			      int __pshared) __THROW;

/* Destroy the spinlock LOCK.  */
extern int pthread_spin_destroy (pthread_spinlock_t *__lock) __THROW;

/* Wait until spinlock LOCK is retrieved.  */
extern int pthread_spin_lock (pthread_spinlock_t *__lock) __THROW;

/* Release spinlock LOCK.  */
extern int pthread_spin_unlock (pthread_spinlock_t *__lock) __THROW;
#endif


#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>

#ifndef HAVE_PCAP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/sockios.h>
#endif

#ifdef USE_PCAP 
#include <pcap.h>
#endif

#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <linux/pf_ring.h>
#include <linux/if_ether.h>

#define MAX_CAPLEN             16384
#define PAGE_SIZE               4096

#define DEFAULT_POLL_DURATION   500

#define POLL_SLEEP_STEP           10 /* ns = 0.1 ms */
#define POLL_SLEEP_MIN          POLL_SLEEP_STEP
#define POLL_SLEEP_MAX          1000 /* ns */
#define POLL_QUEUE_MIN_LEN       500 /* # packets */

#ifndef max
#define max(a, b) (a > b ? a : b)
#endif


/* ********************************* */

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef SAFE_RING_MODE
  static char staticBucket[2048];
#endif

  typedef void (*pfringProcesssPacket)(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes);

  /* ********************************* */

  typedef struct {
    u_int8_t initialized;

    /* DNA (Direct NIC Access) */
    u_char dna_mapped_device;    
    u_int16_t num_pkts_before_dns_sync, dna_sync_watermark;
    u_int32_t tot_dna_read_pkts, rx_reg;
    dna_device dna_dev;    
    u_int32_t *rx_reg_ptr;
    dna_device_operation last_dna_operation;
    void *priv_data;
    
    /* All devices */
    char *buffer, *slots, *device_name;
    u_int16_t caplen, slot_header_len;
    u_int8_t kernel_packet_consumer, is_shutting_down;
    int fd;
    FlowSlotInfo *slots_info;
    u_int poll_sleep;
    u_int16_t poll_duration;
    u_int8_t clear_promisc, reentrant, break_recv_loop;
    u_long num_poll_calls;
    pthread_spinlock_t spinlock;

    struct sockaddr_ll sock_tx;
  } pfring;

  /* ********************************* */
  
#define MAX_NUM_BUNDLE_ELEMENTS 32
  
  typedef enum {
    pick_round_robin = 0,
    pick_fifo,
  } bundle_read_policy;

  typedef struct {
    bundle_read_policy policy;
    u_int16_t num_sockets, last_read_socket;
    pfring *sockets[MAX_NUM_BUNDLE_ELEMENTS];
  } pfring_bundle;

  /* ********************************* */

  typedef struct {
    u_int64_t recv, drop;
  } pfring_stat;

  /* ********************************* */

  void pfring_config(u_short cpu_percentage);
  int pfring_set_direction(pfring *ring, packet_direction direction);
  int pfring_set_cluster(pfring *ring, u_int clusterId, cluster_type the_type);
  int pfring_set_master_id(pfring *ring, u_int32_t master_id);
  int pfring_set_master(pfring *ring, pfring *master);
  int pfring_set_channel_id(pfring *ring, u_int32_t channel_id);
  int pfring_add_hw_rule(pfring *ring, hw_filtering_rule *rule);
  int pfring_remove_hw_rule(pfring *ring, u_int16_t rule_id);
  int pfring_set_application_name(pfring *ring, char *name);
  int pfring_remove_from_cluster(pfring *ring);
  int pfring_purge_idle_hash_rules(pfring *ring, u_int16_t inactivity_sec);  
  pfring* pfring_open(char *device_name, u_int8_t promisc, 
		      u_int32_t caplen, u_int8_t reentrant);
  pfring* pfring_open_consumer(char *device_name, u_int8_t promisc,
			       u_int32_t caplen, u_int8_t _reentrant,
			       u_int8_t consumer_plugin_id,
			       char* consumer_data, u_int consumer_data_len);
  int pfring_bind(pfring *ring, char *device_name);
  u_int8_t pfring_open_multichannel(char *device_name, u_int8_t promisc,
				    u_int32_t caplen, u_int8_t _reentrant,
				    pfring* ring[MAX_NUM_RX_CHANNELS]);
  pfring* pfring_open_dna(char *device_name,  u_int8_t promisc, u_int8_t reentrant);
  void pfring_close(pfring *ring);
  int  pfring_send(pfring *ring, char *pkt, u_int pkt_len);
  int pfring_stats(pfring *ring, pfring_stat *stats);
  int pfring_recv(pfring *ring, char* buffer, u_int buffer_len,
		  struct pfring_pkthdr *hdr,
		  u_int8_t wait_for_incoming_packet);
  void pfring_dna_recv_multiple(pfring *ring,
				pfringProcesssPacket looper,
				struct pfring_pkthdr *hdr,
				char *buffer, u_int buffer_len,
				u_int8_t wait_for_packet,
				void *user_data);
  int pfring_recv_batch(pfring *ring, char* buffer, u_int buffer_len,
			u_int32_t offset[], u_int num_offset,
			u_int8_t wait_for_incoming_packet);
  int pfring_loop(pfring *ring, pfringProcesssPacket looper, const u_char *user_bytes);
  void pfring_breakloop(pfring *);
  int pfring_get_filtering_rule_stats(pfring *ring, u_int16_t rule_id,
				      char* stats, u_int *stats_len);
  u_int8_t pfring_get_num_rx_channels(pfring *ring);
  u_int16_t pfring_get_ring_id(pfring *ring);
  u_int32_t pfring_get_num_queued_pkts(pfring *ring);
  u_int8_t pfring_get_packet_consumer_mode(pfring *ring);
  int pfring_set_virtual_device(pfring *ring, virtual_filtering_device_info *info);
  int pfring_set_packet_consumer_mode(pfring *ring, u_int8_t plugin_id,
				      char *plugin_data, u_int plugin_data_len);
  int pfring_get_hash_filtering_rule_stats(pfring *ring,
					   hash_filtering_rule* rule,
					   char* stats, u_int *stats_len);
  int pfring_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add);
  int pfring_handle_hash_filtering_rule(pfring *ring,
					hash_filtering_rule* rule_to_add,
					u_char add_rule);
  int pfring_enable_ring(pfring *ring);
  int pfring_disable_ring(pfring *ring);
  int pfring_remove_filtering_rule(pfring *ring, u_int16_t rule_id);
  int pfring_toggle_filtering_policy(pfring *ring, u_int8_t rules_default_accept_policy);
  int pfring_set_poll_watermark(pfring *ring, u_int16_t watermark);
  int pfring_enable_rss_rehash(pfring *ring);
  int pfring_poll(pfring *ring, u_int wait_duration);
  int pfring_version(pfring *ring, u_int32_t *version);
  int pfring_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */);
  int pfring_get_selectable_fd(pfring *ring);
  int pfring_get_bound_device_address(pfring *ring, u_char mac_address[6]);
  void pfring_set_poll_duration(pfring *ring, u_int duration);

  /* PF_RING Socket bundle */
  void init_pfring_bundle(pfring_bundle *bundle, bundle_read_policy p);
  int add_to_pfring_bundle(pfring_bundle *bundle, pfring *ring);
  int pfring_bundle_poll(pfring_bundle *bundle, u_int wait_duration);
  int pfring_bundle_read(pfring_bundle *bundle, 
			 char* buffer, u_int buffer_len,
			 struct pfring_pkthdr *hdr,
			 u_int8_t wait_for_incoming_packet);
  void pfring_bundle_close(pfring_bundle *bundle);  

#ifdef  __cplusplus
}
#endif

#endif /* _PFRING_H_ */
