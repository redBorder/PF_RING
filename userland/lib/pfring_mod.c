/*
 *
 * (C) 2005-11 - Luca Deri <deri@ntop.org>
 *               Alfredo Cardigliano <cardigliano@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 * This code includes contributions courtesy of
 * - Fedor Sakharov <fedor.sakharov@gmail.com>
 *
 */

#define __USE_XOPEN2K
#include <sys/types.h>
#include <pthread.h>

#ifdef ENABLE_HW_TIMESTAMP
#include <linux/net_tstamp.h>
#endif

#include "pfring.h"
#include "pfring_utils.h"
#include "pfring_mod.h"

// #define RING_DEBUG

#define MAX_NUM_LOOPS         1000
#define YIELD_MULTIPLIER        10

#define USE_MB

#define rmb()   asm volatile("lfence":::"memory")
#define wmb()   asm volatile("sfence" ::: "memory")

#define gcc_mb() __asm__ __volatile__("": : :"memory");


/* **************************************************** */
/*                  Static functions                    */
/* **************************************************** */

#if 0
unsigned long long rdtsc() {
  unsigned long long a;
  asm volatile("rdtsc":"=A" (a));
  return(a);
}
#endif

/* **************************************************** */

#ifdef ENABLE_HW_TIMESTAMP

int pfring_enable_hw_timestamp(pfring* ring, char *device_name) {
  struct hwtstamp_config hwconfig;
  struct ifreq ifr;
  int rc, sock_fd;

  sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(sock_fd <= 0) return(-1);

  memset(&hwconfig, 0, sizeof(hwconfig));

  /* Enable RX/disable TX timestamps */
  hwconfig.tx_type = HWTSTAMP_TX_OFF;
  hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;

  memset(&ifr, 0, sizeof(ifr));
  strcpy(ifr.ifr_name, device_name);
  ifr.ifr_data = (void *)&hwconfig;

  rc = ioctl(sock_fd, SIOCSHWTSTAMP, &ifr);
  if(rc < 0)
    rc = errno;
  else
    rc = 0;

#ifdef RING_DEBUG
  printf("pfring_enable_hw_timestamp(%s) returned %d\n",
	 device_name, rc);
#endif

  close(sock_fd);
  return(rc);
}

#endif

/* **************************************************** */

static u_int16_t pfring_get_slot_header_len(pfring *ring) {
  if(ring == NULL)
    return(1);
  else {
    u_int16_t hlen;
    socklen_t len = sizeof(hlen);
    int ret, rc = getsockopt(ring->fd, 0, SO_GET_PKT_HEADER_LEN, &hlen, &len);

    ret = (rc == 0) ? hlen : -1;

    return(ret);
  }
}

/* **************************************************** */

inline int pfring_there_is_pkt_available(pfring *ring) {
  return(ring->slots_info->tot_insert != ring->slots_info->tot_read);
}


/* **************************************************** */
/*     Functions part of the "specialized" subset       */
/* **************************************************** */

int pfring_mod_open(pfring *ring) {
  /* Setting pointers, we need these functions soon */
  ring->close = pfring_mod_close;
  ring->stats = pfring_mod_stats;
  ring->recv  = pfring_mod_recv;
  ring->set_poll_watermark = pfring_mod_set_poll_watermark;
  ring->set_poll_duration = pfring_mod_set_poll_duration;
  ring->add_hw_rule = pfring_mod_add_hw_rule;
  ring->remove_hw_rule = pfring_mod_remove_hw_rule;
  ring->set_channel_id = pfring_mod_set_channel_id;
  ring->set_application_name = pfring_mod_set_application_name;
  ring->bind = pfring_mod_bind;
  ring->send = pfring_mod_send;
  ring->get_num_rx_channels = pfring_mod_get_num_rx_channels;
  ring->set_sampling_rate = pfring_mod_set_sampling_rate;
  ring->get_selectable_fd = pfring_mod_get_selectable_fd;

  ring->poll_duration = DEFAULT_POLL_DURATION;
  ring->fd = socket(PF_RING, SOCK_RAW, htons(ETH_P_ALL));

  if(ring->fd < 0)
    return -1;

#ifdef RING_DEBUG
  printf("Open RING [fd=%d]\n", ring->fd);
#endif

  int rc;
  u_int memSlotsLen;

  if(ring->caplen > MAX_CAPLEN) ring->caplen = MAX_CAPLEN;
  setsockopt(ring->fd, 0, SO_RING_BUCKET_LEN, &ring->caplen, sizeof(ring->caplen));

  /* printf("channel_id=%d\n", channel_id); */

  if(!strcmp(ring->device_name, "none")) {
    /* No binding yet */
    rc = 0;
  } else /* "any" or "<interface name>" */
    rc = pfring_bind(ring, ring->device_name);

  if(rc < 0) {
     close(ring->fd);
     return -1;
  }

  ring->kernel_packet_consumer = 0;

  ring->buffer = (char *)mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
			      MAP_SHARED, ring->fd, 0);

  if(ring->buffer == MAP_FAILED) {
    printf("mmap() failed: try with a smaller snaplen\n");
    close(ring->fd);
    return -1;
  }

  ring->slots_info = (FlowSlotInfo *)ring->buffer;
  if(ring->slots_info->version != RING_FLOWSLOT_VERSION) {
    printf("Wrong RING version: "
	   "kernel is %i, libpfring was compiled with %i\n",
	   ring->slots_info->version, RING_FLOWSLOT_VERSION);
    close(ring->fd);
    return -1;
  }
  memSlotsLen = ring->slots_info->tot_mem;
  munmap(ring->buffer, PAGE_SIZE);

  ring->buffer = (char *)mmap(NULL, memSlotsLen,
			      PROT_READ|PROT_WRITE,
			      MAP_SHARED, ring->fd, 0);

  /* printf("mmap len %u\n", memSlotsLen); */

  if(ring->buffer == MAP_FAILED) {
    printf("mmap() failed");
    close(ring->fd);
    return -1;
   }

   ring->slots_info = (FlowSlotInfo *)ring->buffer;
   ring->slots = (char *)(ring->buffer+sizeof(FlowSlotInfo));

#ifdef RING_DEBUG
  printf("RING (%s): tot_mem=%u/max_slot_len=%u/"
	 "insert_off=%u/remove_off=%u/dropped=%lu\n", 
	 ring->device_name, ring->slots_info->tot_mem,
	 ring->slots_info->slot_len,   ring->slots_info->insert_off,
	 ring->slots_info->remove_off, ring->slots_info->tot_lost);
#endif

  if(ring->promisc) {
    if(set_if_promisc(ring->device_name, 1) == 0)
      ring->clear_promisc = 1;
  }

#ifdef ENABLE_HW_TIMESTAMP
  pfring_enable_hw_timestamp(ring, ring->device_name);
#endif

  ring->slot_header_len = pfring_get_slot_header_len(ring);
  if(ring->slot_header_len == (u_int16_t)-1) {
    printf("ring failure (pfring_get_slot_header_len)\n");
    return -1;
  }

  return 0;
}

/* **************************************************** */
   
pfring* pfring_open_consumer(char *device_name, u_int8_t promisc,
			     u_int32_t caplen, u_int8_t _reentrant,
			     u_int8_t consumer_plugin_id,
			     char* consumer_data, u_int consumer_data_len) {
  pfring *ring = pfring_open(device_name, promisc, caplen, _reentrant);
  
  if(ring) {
    if(consumer_plugin_id > 0) {
      int rc;

      ring->kernel_packet_consumer = consumer_plugin_id;
      rc = pfring_set_packet_consumer_mode(ring, consumer_plugin_id,
					   consumer_data, consumer_data_len);
      if(rc < 0) {
	pfring_close(ring);
	return(NULL);
      }
    }
  }

  return ring;
}

/* ******************************* */

int pfring_mod_add_hw_rule(pfring *ring, hw_filtering_rule *rule) {
  return(ring ? setsockopt(ring->fd, 0, SO_ADD_HW_FILTERING_RULE,
			   rule, sizeof(hw_filtering_rule)) : -1);
}

/* ******************************* */

int pfring_mod_remove_hw_rule(pfring *ring, u_int16_t rule_id) {
  return(ring ? setsockopt(ring->fd, 0, SO_DEL_HW_FILTERING_RULE, &rule_id, sizeof(rule_id)) : -1);
}

/* ******************************* */

int pfring_mod_set_channel_id(pfring *ring, u_int32_t channel_id) {
  return(ring ? setsockopt(ring->fd, 0, SO_SET_CHANNEL_ID,
			   &channel_id, sizeof(channel_id)): -1);
}

/* ******************************* */

int pfring_mod_set_application_name(pfring *ring, char *name) {
#if !defined(SO_SET_APPL_NAME)
  return(-1);
#else
  return(ring ? setsockopt(ring->fd, 0, SO_SET_APPL_NAME,
			   name, strlen(name)): -1);
#endif
}

/* **************************************************** */

int pfring_mod_bind(pfring *ring, char *device_name) {
  struct sockaddr sa;
  char *at;
  u_int32_t channel_id = RING_ANY_CHANNEL;
  int rc = 0;

  if((device_name == NULL) || (strcmp(device_name, "none") == 0))
    return(-1);

  at = strchr(device_name, '@');
  if(at != NULL) {
    char *tok, *pos = NULL;

    at[0] = '\0';

    /* Syntax
       ethX@1,5       channel 1 and 5
       ethX@1-5       channel 1,2...5
       ethX@1-3,5-7   channel 1,2,3,5,6,7
    */

    tok = strtok_r(&at[1], ",", &pos);
    channel_id = 0;

    while(tok != NULL) {
      char *dash = strchr(tok, '-');
      int32_t min_val, max_val, i;

      if(dash) {
	dash[0] = '\0';
	min_val = atoi(tok);
	max_val = atoi(&dash[1]);

      } else
	min_val = max_val = atoi(tok);

      for(i = min_val; i <= max_val; i++)
	channel_id |= 1 << i;

      tok = strtok_r(NULL, ",", &pos);
    }
  }

  /* Setup TX */
  ring->sock_tx.sll_family = PF_PACKET;
  ring->sock_tx.sll_protocol = htons(ETH_P_ALL);

  sa.sa_family = PF_RING;
  snprintf(sa.sa_data, sizeof(sa.sa_data), "%s", device_name);

  rc = bind(ring->fd, (struct sockaddr *)&sa, sizeof(sa));

  if(rc == 0) {
    rc = pfring_set_channel_id(ring, channel_id);

    if(rc != 0)
      printf("pfring_set_channel_id() failed: %d\n", rc);
  }

  return(rc);
}

/* **************************************************** */

void pfring_mod_close(pfring *ring) {
  if(ring->buffer != NULL) {
    munmap(ring->buffer, ring->slots_info->tot_mem);
  }

  if(ring->clear_promisc)
    set_if_promisc(ring->device_name, 0);

  close(ring->fd);
}

/* **************************************************** */

int  pfring_mod_send(pfring *ring, char *pkt, u_int pkt_len) {
  return(sendto(ring->fd, pkt, pkt_len, 0, (struct sockaddr *)&ring->sock_tx, sizeof(ring->sock_tx)));
}

/* **************************************************** */

int pfring_mod_set_poll_watermark(pfring *ring, u_int16_t watermark) {
  return(ring ? setsockopt(ring->fd, 0, SO_SET_POLL_WATERMARK,
			   &watermark, sizeof(watermark)): -1);
}

/* **************************************************** */

int pfring_mod_set_poll_duration(pfring *ring, u_int duration) {
  ring->poll_duration = duration;

  return duration;
}

/* **************************************************** */

u_int8_t pfring_mod_get_num_rx_channels(pfring *ring) {
  socklen_t len = sizeof(u_int32_t);
  u_int8_t num_rx_channels;
  int rc = getsockopt(ring->fd, 0, SO_GET_NUM_RX_CHANNELS, &num_rx_channels, &len);

  return((rc == 0) ? num_rx_channels : 1);
}

/* **************************************************** */

int pfring_mod_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */) {
  int rc;

  rc = ring ? setsockopt(ring->fd, 0, SO_SET_SAMPLING_RATE,
			 &rate, sizeof(rate)): -1;

  return(rc);
}

/* ******************************* */

int pfring_mod_stats(pfring *ring, pfring_stat *stats) {

  if((ring->slots_info != NULL) && (stats != NULL)) {
    rmb();
    stats->recv = ring->slots_info->tot_read;
    stats->drop = ring->slots_info->tot_lost;
    return(0);
  } else
    return(-1);
}

/* **************************************************** */

int pfring_mod_recv(pfring *ring, u_char** buffer, u_int buffer_len,
		    struct pfring_pkthdr *hdr,
		    u_int8_t wait_for_incoming_packet) {

  if(ring->is_shutting_down) return(-1);

  int rc = 0;

  if(ring->buffer == NULL) return(-1);

  ring->break_recv_loop = 0;

  do_pfring_recv:
    if(ring->break_recv_loop)
      return(0);

    if(ring->reentrant)
      pthread_spin_lock(&ring->spinlock);

    //rmb();

    if(pfring_there_is_pkt_available(ring)) {
      char *bucket = &ring->slots[ring->slots_info->remove_off];
      u_int32_t next_off, real_slot_len, insert_off, bktLen;

      memcpy(hdr, bucket, ring->slot_header_len);

      if(ring->slot_header_len != sizeof(struct pfring_pkthdr))
	bktLen = hdr->caplen;
      else
	bktLen = hdr->caplen+hdr->extended_hdr.parsed_header_len;

      real_slot_len = ring->slot_header_len + bktLen;
      insert_off = ring->slots_info->insert_off;
      if(bktLen > buffer_len) bktLen = buffer_len;

      if(buffer_len == 0)
	*buffer = (u_char*)&bucket[ring->slot_header_len];
      else
	memcpy(*buffer, &bucket[ring->slot_header_len], bktLen);            

      next_off = ring->slots_info->remove_off + real_slot_len;
      if((next_off + ring->slots_info->slot_len) > (ring->slots_info->tot_mem - sizeof(FlowSlotInfo))) {
        next_off = 0;
      }

#ifdef USE_MB
      /* This prevents the compiler from reordering instructions.
       * http://en.wikipedia.org/wiki/Memory_ordering#Compiler_memory_barrier */
      gcc_mb();
#endif

      ring->slots_info->tot_read++;
      ring->slots_info->remove_off = next_off;

      /* Ugly safety check */
      if((ring->slots_info->tot_insert == ring->slots_info->tot_read)
	 && (ring->slots_info->remove_off > ring->slots_info->insert_off)) {
	ring->slots_info->remove_off = ring->slots_info->insert_off;
      }

      if(ring->reentrant) pthread_spin_unlock(&ring->spinlock);
      return(1);
    }

    /* Nothing to do: we need to wait */
    if(ring->reentrant) pthread_spin_unlock(&ring->spinlock);

    if(wait_for_incoming_packet) {
      rc = pfring_poll(ring, ring->poll_duration);

      if((rc == -1) && (errno != EINTR))
	return(-1);
      else
	goto do_pfring_recv;
    }

  return(-1); /* Not reached */
}

/* ******************************* */

int pfring_mod_get_selectable_fd(pfring *ring) {
  if (!ring)
    return -1;

  return(ring->fd);
}


/* **************************************************** */
/*   Functions part of the "PF_RING-specific" subset    */
/* **************************************************** */

int pfring_set_direction(pfring *ring, packet_direction direction) {
  if (!ring)
    return -1;

  return(ring ? setsockopt(ring->fd, 0, SO_SET_PACKET_DIRECTION,
			   &direction, sizeof(direction)): -1);
}

/* ******************************* */

int pfring_set_master_id(pfring *ring, u_int32_t master_id) {
  if (!ring)
    return -1;

  return(ring ? setsockopt(ring->fd, 0, SO_SET_MASTER_RING,
			   &master_id, sizeof(master_id)): -1);
}

/* ******************************* */

int pfring_set_master(pfring *ring, pfring *master) {
  if (!ring)
    return -1;

  int id = pfring_get_ring_id(master);

  if(id != -1)
    return(pfring_set_master_id(ring, id));
  else
    return(id);
}

/* ******************************* */

int pfring_set_cluster(pfring *ring, u_int clusterId, cluster_type the_type) {
  if (!ring)
    return -1;

  struct add_to_cluster cluster;

  cluster.clusterId = clusterId, cluster.the_type = the_type;

  return(ring ? setsockopt(ring->fd, 0, SO_ADD_TO_CLUSTER,
		 	   &cluster, sizeof(cluster)): -1);
}


/* ******************************* */

int pfring_remove_from_cluster(pfring *ring) {
  if (!ring)
    return -1;

  return(ring ? setsockopt(ring->fd, 0, SO_REMOVE_FROM_CLUSTER,
			   NULL, 0) : -1);
}

/* ******************************* */

int pfring_purge_idle_hash_rules(pfring *ring, u_int16_t inactivity_sec) {
  if (!ring)
    return -1;

  return(ring ? setsockopt(ring->fd, 0, SO_PURGE_IDLE_HASH_RULES,
			   &inactivity_sec, sizeof(inactivity_sec)) : -1);
}

/* **************************************************** */

u_int8_t pfring_open_multichannel(char *device_name, u_int8_t promisc,
				  u_int32_t caplen, u_int8_t _reentrant,
				  pfring* ring[MAX_NUM_RX_CHANNELS]) {
  u_int8_t num_channels, i, num = 0;
  char *at;
  char base_device_name[32];

  snprintf(base_device_name, sizeof(base_device_name), "%s", device_name);
  at = strchr(base_device_name, '@');
  if(at != NULL)
    at[0] = '\0';

  /* Count how many RX channel the specified device supports */
  ring[0] = pfring_open(base_device_name, promisc, caplen, _reentrant);

  if(ring[0] == NULL)
    return(0);
  else
    num_channels = pfring_get_num_rx_channels(ring[0]);

  pfring_close(ring[0]);

  /* Now do the real job */
  for(i=0; i<num_channels; i++) {
    char dev[32];

    snprintf(dev, sizeof(dev), "%s@%d", base_device_name, i);
    ring[i] = pfring_open(dev, promisc, caplen, _reentrant);

    if(ring[i] == NULL)
      return(num);
    else
      num++;
  }

  return(num);
}


/* **************************************************** */

int pfring_toggle_filtering_policy(pfring *ring,
				   u_int8_t rules_default_accept_policy) {
  if (!ring)
    return -1;

  return(ring ? setsockopt(ring->fd, 0, SO_TOGGLE_FILTER_POLICY,
			   &rules_default_accept_policy,
			   sizeof(rules_default_accept_policy)): -1);
}

/* **************************************************** */

int pfring_enable_rss_rehash(pfring *ring) {
  if (!ring)
    return -1;

  char dummy;
  return(setsockopt(ring->fd, 0, SO_REHASH_RSS_PACKET, &dummy, sizeof(dummy)));
}

/* **************************************************** */

int pfring_poll(pfring *ring, u_int wait_duration) {
  if (!ring)
    return -1;

  struct pollfd pfd;
  int rc;

  /* Sleep when nothing is happening */
  pfd.fd      = ring->fd;
  pfd.events  = POLLIN /* | POLLERR */;
  pfd.revents = 0;
  errno       = 0;

  rc = poll(&pfd, 1, wait_duration);
  ring->num_poll_calls++;

  return(rc);
}

/* **************************************************** */

int pfring_version(pfring *ring, u_int32_t *version) {
  if (!ring)
    return -1;

  socklen_t len = sizeof(u_int32_t);
  return(getsockopt(ring->fd, 0, SO_GET_RING_VERSION, version, &len));
}

/* **************************************************** */

u_int32_t pfring_get_num_queued_pkts(pfring *ring) {
  if (!ring)
    return 0;

  socklen_t len = sizeof(u_int32_t);
  u_int32_t num_queued_pkts;
  int rc = getsockopt(ring->fd, 0, SO_GET_NUM_QUEUED_PKTS, &num_queued_pkts, &len);

  return((rc == 0) ? num_queued_pkts : 0);
}

/* **************************************************** */

u_int16_t pfring_get_ring_id(pfring *ring) {
  if (!ring)
    return 1;

  u_int32_t id;
  socklen_t len = sizeof(id);
  int ret, rc = getsockopt(ring->fd, 0, SO_GET_RING_ID, &id, &len);

  ret = (rc == 0) ? id : -1;

  return(ret);
}

/* **************************************************** */

int pfring_get_filtering_rule_stats(pfring *ring, u_int16_t rule_id,
				    char* stats, u_int *stats_len) {
  if (!ring)
    return -1;

  if(*stats_len < sizeof(u_int16_t))
    return(-1);
  else {
    memcpy(stats, &rule_id, sizeof(u_int16_t));
    return(getsockopt(ring->fd, 0,
		      SO_GET_FILTERING_RULE_STATS,
		      stats, stats_len));
  }
}

/* **************************************************** */

int pfring_get_hash_filtering_rule_stats(pfring *ring,
					 hash_filtering_rule* rule,
					 char* stats, u_int *stats_len) {
  if (!ring)
    return -1;

  char buffer[2048];
  int rc;
  u_int len;

  memcpy(buffer, rule, sizeof(hash_filtering_rule));
  len = sizeof(buffer);
  rc = getsockopt(ring->fd, 0,
		  SO_GET_HASH_FILTERING_RULE_STATS,
		  buffer, &len);
  if(rc < 0)
    return(rc);
  else {
    *stats_len = min_val(*stats_len, rc);
    memcpy(stats, buffer, *stats_len);
    return(0);
  }
}

/* **************************************************** */

int pfring_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add) {
  if (!ring)
    return -1;

  int rc;

  if(rule_to_add) return(-1);

  /* Sanitize entry */
  if(rule_to_add->core_fields.port_low > rule_to_add->core_fields.port_high)
    rule_to_add->core_fields.port_low = rule_to_add->core_fields.port_high;
  if(rule_to_add->core_fields.host4_low > rule_to_add->core_fields.host4_high)
    rule_to_add->core_fields.host4_low = rule_to_add->core_fields.host4_high;

  if(rule_to_add->balance_id > rule_to_add->balance_pool)
    rule_to_add->balance_id = 0;

  rc = setsockopt(ring->fd, 0, SO_ADD_FILTERING_RULE,
		  rule_to_add, sizeof(filtering_rule));

  return(rc);
}

/* **************************************************** */

int pfring_enable_ring(pfring *ring) {
  if (!ring)
    return -1;

  char dummy;
  return(setsockopt(ring->fd, 0, SO_ACTIVATE_RING, &dummy, sizeof(dummy)));
}

/* **************************************************** */

int pfring_disable_ring(pfring *ring) {
  if (!ring)
    return -1;

  char dummy;
  return(setsockopt(ring->fd, 0, SO_DEACTIVATE_RING, &dummy, sizeof(dummy)));
}

/* **************************************************** */

int pfring_remove_filtering_rule(pfring *ring, u_int16_t rule_id) {
  if (!ring)
    return -1;

  int rc;

  rc = ring ? setsockopt(ring->fd, 0, SO_REMOVE_FILTERING_RULE,
			 &rule_id, sizeof(rule_id)): -1;

  return(rc);
}

/* **************************************************** */

int pfring_handle_hash_filtering_rule(pfring *ring,
				      hash_filtering_rule* rule_to_add,
				      u_char add_rule) {
  if (!ring)
    return -1;

  int rc;

  if(!rule_to_add) return(-1);

  rc = setsockopt(ring->fd, 0, add_rule ? SO_ADD_FILTERING_RULE : SO_REMOVE_FILTERING_RULE,
		  rule_to_add, sizeof(hash_filtering_rule));

  return(rc);
}

/* ******************************* */

u_int8_t pfring_get_packet_consumer_mode(pfring *ring) {
  if (!ring)
    return -1;

  u_int8_t id;
  socklen_t len = sizeof(id);
  int ret, rc = getsockopt(ring->fd, 0, SO_GET_PACKET_CONSUMER_MODE, &id, &len);

  ret = (rc == 0) ? id : -1;

  return(ret);
}

/* **************************************************** */

int pfring_set_packet_consumer_mode(pfring *ring, u_int8_t plugin_id,
				    char *plugin_data, u_int plugin_data_len) {
  if (!ring)
    return -1;

  char buffer[4096];

  if(plugin_data_len > (sizeof(buffer)-1)) return(-2);

  memcpy(buffer, &plugin_id, 1);

  if(plugin_data_len > 0)
    memcpy(&buffer[1], plugin_data, plugin_data_len);

  return(setsockopt(ring->fd, 0, SO_SET_PACKET_CONSUMER_MODE,
		    buffer, plugin_data_len+1));
}

/* **************************************************** */

int pfring_set_virtual_device(pfring *ring, virtual_filtering_device_info *info) {
  if (!ring)
    return -1;

  return(setsockopt(ring->fd, 0, SO_SET_VIRTUAL_FILTERING_DEVICE,
		    (char*)info, sizeof(virtual_filtering_device_info)));
}

/* **************************************************** */

int pfring_loopback_test(pfring *ring, char *buffer, u_int buffer_len, u_int test_len) {
  if (!ring)
    return -1;

  socklen_t len;
  
  if(ring == NULL) return(-1);
  
  if(test_len > buffer_len) test_len = buffer_len;
  len = test_len;

  return(getsockopt(ring->fd, 0, SO_GET_LOOPBACK_TEST, (char*)buffer, &len));
}

/* *********************************** */

int pfring_get_bound_device_address(pfring *ring, u_char mac_address[6]) {
  if (!ring)
    return -1;

  socklen_t len = 6;
  return(getsockopt(ring->fd, 0, SO_GET_BOUND_DEVICE_ADDRESS, mac_address, &len));
}

/* *********************************** */

void init_pfring_bundle(pfring_bundle *bundle, bundle_read_policy p) {
  memset(bundle, 0, sizeof(pfring_bundle));
  bundle->policy = p;
}

/* *********************************** */

int add_to_pfring_bundle(pfring_bundle *bundle, pfring *ring) {
  if(bundle->num_sockets >= (MAX_NUM_BUNDLE_ELEMENTS-1))
    return(-1);

  pfring_enable_ring(ring);
  bundle->sockets[bundle->num_sockets++] = ring;

  return(0);
}

/* *********************************** */

/* Returns the first bundle socket with something to read */
int pfring_bundle_poll(pfring_bundle *bundle, u_int wait_duration) {
  int i, rc;
  struct pollfd pfd[MAX_NUM_BUNDLE_ELEMENTS];

  for(i=0; i<bundle->num_sockets; i++) {
    pfd[i].fd = bundle->sockets[i]->fd;
    pfd[i].events  = POLLIN /* | POLLERR */;
    pfd[i].revents = 0;
  }

  errno = 0;
  rc = poll(pfd, bundle->num_sockets, wait_duration);

  if(rc > 0) {
    for(i=0; i<bundle->num_sockets; i++)
      if(pfd[i].revents != 0)
	return(i);
  } else if(rc == 0)
    return(-1);

  return(-2); /* Default */
}

/* *********************************** */

inline int is_before(struct timeval *ts_a,  struct timeval *ts_b) {
  if(ts_a->tv_sec < ts_b->tv_sec)
    return(1);
  else if(ts_a->tv_sec == ts_b->tv_sec) {
    if(ts_a->tv_usec < ts_b->tv_usec)
      return(1);
  }

  return(0);
}

/* *********************************** */

int pfring_bundle_read(pfring_bundle *bundle,
		       u_char** buffer, u_int buffer_len,
		       struct pfring_pkthdr *hdr,
		       u_int8_t wait_for_incoming_packet) {
  u_int i, sock_id = 0, num_found, rc;
  struct timeval ts = { 0 };

 redo_pfring_bundle_read:

  switch(bundle->policy) {
  case pick_round_robin:
    for(i=0; i<bundle->num_sockets; i++) {
      bundle->last_read_socket = (bundle->last_read_socket + 1) % bundle->num_sockets;

      if(pfring_there_is_pkt_available(bundle->sockets[bundle->last_read_socket])) {
	return(pfring_recv(bundle->sockets[bundle->last_read_socket], buffer,
			   buffer_len, hdr, wait_for_incoming_packet));
      }
    }
    break;

  case pick_fifo:
    num_found = 0;

    for(i=0; i<bundle->num_sockets; i++) {
      pfring *ring = bundle->sockets[i];

      if(pfring_there_is_pkt_available(ring)) {
	struct pfring_pkthdr *header = (struct pfring_pkthdr*)&ring->slots[ring->slots_info->remove_off];

	if((num_found == 0) || is_before(&header->ts, &ts)) {
	  memcpy(&ts, &header->ts, sizeof(struct timeval));
	  num_found++, sock_id = i;
	}
      }
    }

    if(num_found > 0) {
      return(pfring_recv(bundle->sockets[sock_id], buffer,
			 buffer_len, hdr, wait_for_incoming_packet));
    }
    break;
  }

  if(wait_for_incoming_packet) {
    rc = pfring_bundle_poll(bundle, bundle->sockets[0]->poll_duration);

    if(rc > 0) {
      goto redo_pfring_bundle_read;
    } else
      return(rc);
  }

  return(0);
}

/* *********************************** */

/* Returns the first bundle socket with something to read */
void pfring_bundle_close(pfring_bundle *bundle) {
  int i;

  for(i=0; i<bundle->num_sockets; i++)
    pfring_close(bundle->sockets[i]);
}

/* *********************************** */

