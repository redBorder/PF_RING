/*
** Copyright (C) 2012 ntop.org
**
** Authors:
**          Alfredo Cardigliano <cardigliano@ntop.org>
**          Luca Deri <deri@ntop.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sysinfo.h> /* get_nprocs(void) */
#include <unistd.h>
#include <signal.h>

#include "pfring.h"
#include "sfbpf.h"
#include "daq_api.h"

#define DAQ_PF_RING_DNA_VERSION 10

#define DAQ_PF_RING_MAX_NUM_DEVICES 128
#define DAQ_PF_RING_PASSIVE_DEV_IDX  0

#define DAQ_PF_RING_BEST_EFFORT_BOOST

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
#define DAQ_PF_RING_BEST_EFFORT_BOOST_MIN_NUM_SLOTS 4096

typedef struct _pfring_queue_slothdr
{
  u_int32_t caplen;
  u_int32_t pktlen;
  int device_index;
  struct timeval ts;
  void *user;
  u_char pkt_buffer[];
} Pfring_Queue_SlotHdr_t;

typedef struct _pfring_queue 
{
  u_char *buffer;
  u_int64_t buffer_len;
  u_int64_t insert_off;
  u_int64_t remove_off;
  u_int32_t tot_read;
  u_int32_t tot_insert;
  u_int32_t max_slot_len;
  u_int32_t min_num_slots;
} Pfring_Queue_t;
#endif

typedef struct _pfring_context
{
  DAQ_Mode mode;
  char *devices[DAQ_PF_RING_MAX_NUM_DEVICES];
  int ifindexes[DAQ_PF_RING_MAX_NUM_DEVICES];
  pfring *ring_handles[DAQ_PF_RING_MAX_NUM_DEVICES];
  int num_devices;
  int snaplen;
#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  Pfring_Queue_t *q;
#endif
  char *filter_string;
  char errbuf[1024];
  u_char *pkt_buffer;
  u_int breakloop;
  int promisc_flag;
  int timeout;
  DAQ_Analysis_Func_t analysis_func;
  uint32_t netmask;
  DAQ_Stats_t stats;
  int ids_bridge;
  u_int bindcpu;
  uint64_t base_recv[DAQ_PF_RING_MAX_NUM_DEVICES];
  uint64_t base_drop[DAQ_PF_RING_MAX_NUM_DEVICES];
  DAQ_State state;
} Pfring_Context_t;

static void pfring_daq_reset_stats(void *handle);
static int pfring_daq_set_filter(void *handle, const char *filter);

static int pfring_daq_open(Pfring_Context_t *context, int id) {
  uint32_t default_net = 0xFFFFFF00;
  char *device = context->devices[id];
  pfring *ring_handle;

  if(!device) {
    DPE(context->errbuf, "%s", "PF_RING a device must be specified");
    return -1;
  }

  if(device) {
    context->pkt_buffer = NULL;

    ring_handle = pfring_open(device, context->snaplen,
                              PF_RING_DNA_SYMMETRIC_RSS |
                              PF_RING_TIMESTAMP | /* force sw timestamp */
			      (context->promisc_flag ? PF_RING_PROMISC : 0));

    if(!ring_handle) {
      DPE(context->errbuf, "pfring_open(): unable to open device '%s'. Please use -i <device>", device);
      return -1;
    }
  }

  pfring_get_bound_device_ifindex(ring_handle, &context->ifindexes[id]);

  if (context->mode == DAQ_MODE_INLINE || (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge)) {
    /* Default mode: recv_and_send_mode */
    pfring_set_direction(ring_handle, rx_only_direction);
  } else if (context->mode == DAQ_MODE_PASSIVE) {
    /* Default direction: rx_and_tx_direction */
    pfring_set_socket_mode(ring_handle, recv_only_mode);
  }

  context->netmask = htonl(default_net);

  context->ring_handles[id] = ring_handle;
  return(0);
}

static int update_hw_stats(Pfring_Context_t *context) {
  pfring_stat ps;
  int i;

  for (i = 0; i < context->num_devices; i++)
    if (context->ring_handles[i] == NULL)
      /* daq stopped - using last available stats */
      return DAQ_SUCCESS;

  context->stats.hw_packets_received = 0;
  context->stats.hw_packets_dropped = 0;

  for (i = 0; i < context->num_devices; i++) {
    memset(&ps, 0, sizeof(pfring_stat));

    if(pfring_stats(context->ring_handles[i], &ps) < 0) {
      DPE(context->errbuf, "%s: pfring_stats error [ring_idx = %d]", __FUNCTION__, i);
      return DAQ_ERROR;
    }

    context->stats.hw_packets_received += (ps.recv - context->base_recv[i]);
    context->stats.hw_packets_dropped  += (ps.drop - context->base_drop[i]);
  }

  return DAQ_SUCCESS;
}

static sighandler_t default_sig_reload_handler = NULL;
static u_int8_t pfring_daq_reload_requested = 0;

static void pfring_daq_sig_reload(int sig) {
  if(default_sig_reload_handler != NULL)
    default_sig_reload_handler(sig);

  pfring_daq_reload_requested = 1;
}

static void pfring_daq_reload(Pfring_Context_t *context) {
  pfring_daq_reload_requested = 0;

  /* Reload actions (e.g. purge filtering rules) */
}

static int pfring_daq_initialize(const DAQ_Config_t *config,
				 void **ctxt_ptr, char *errbuf, size_t len) {
  Pfring_Context_t *context;
  DAQ_Dict* entry;
  u_int numCPU = get_nprocs();
  int i;

  context = calloc(1, sizeof(Pfring_Context_t));
  if(!context) {
    snprintf(errbuf, len, "%s: Couldn't allocate memory for the new PF_RING context!", __FUNCTION__);
    return DAQ_ERROR_NOMEM;
  }

  context->mode = config->mode;
  context->snaplen = config->snaplen;
  context->promisc_flag =(config->flags & DAQ_CFG_PROMISC);
  context->timeout = (config->timeout > 0) ? (int) config->timeout : -1;
  context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX] = strdup(config->name);
  context->num_devices = 1;
  context->ids_bridge = 0;

  if(!context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX]) {
    snprintf(errbuf, len, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
    free(context);
    return DAQ_ERROR_NOMEM;
  }

  for(entry = config->values; entry; entry = entry->next) {
    if(!entry->value || !*entry->value) {
      snprintf(errbuf, len,
	       "%s: variable needs value(%s)\n", __FUNCTION__, entry->key);
      return DAQ_ERROR;
    } else if(!strcmp(entry->key, "bindcpu")) {
      char* end = entry->value;
      context->bindcpu =(int)strtol(entry->value, &end, 0);
      if(*end
	 || (context->bindcpu >= numCPU)) {
	snprintf(errbuf, len, "%s: bad bindcpu(%s)\n",
		 __FUNCTION__, entry->value);
	return DAQ_ERROR;
      } else {
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET((int)context->bindcpu, &mask);
	if(sched_setaffinity(0, sizeof(mask), &mask) < 0) {
	  snprintf(errbuf, len, "%s:failed to set bindcpu(%u) on pid %i\n",
		   __FUNCTION__, context->bindcpu, getpid());
	  return DAQ_ERROR;
	}
      }
    } else if(!strcmp(entry->key, "timeout")) {
      char* end = entry->value;
      context->timeout = (int) strtol(entry->value, &end, 0);
      if(*end || (context->timeout < 0)) {
	snprintf(errbuf, len, "%s: bad timeout(%s)\n",
		 __FUNCTION__, entry->value);
	return DAQ_ERROR;
      }
    } else if(!strcmp(entry->key, "idsbridge")) {
      if (context->mode == DAQ_MODE_PASSIVE) {
        char* end = entry->value;
        context->ids_bridge = (int) strtol(entry->value, &end, 0);
	if(*end || (context->ids_bridge < 0) || (context->ids_bridge > 2)) {
	  snprintf(errbuf, len, "%s: bad ids bridge mode(%s)\n",
	    __FUNCTION__, entry->value);
	  return DAQ_ERROR;
	}
      } else {
        snprintf(errbuf, len, "%s: idsbridge is for passive mode only\n",
		 __FUNCTION__);
        return DAQ_ERROR;
      }
    } else {
      snprintf(errbuf, len,
	       "%s: unsupported variable(%s=%s)\n",
	       __FUNCTION__, entry->key, entry->value);
      return DAQ_ERROR;
    }
  }

  if(context->mode == DAQ_MODE_READ_FILE) {
    snprintf(errbuf, len, "%s: function not supported on PF_RING", __FUNCTION__);
    free(context);
    return DAQ_ERROR;
  } else if(context->mode == DAQ_MODE_INLINE || (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge)) {
    /* dnaX:dnaY;dnaZ:dnaJ */
    char *twins, *twins_pos = NULL;
    context->num_devices = 0;

    twins = strtok_r(context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX], ",", &twins_pos);
    while(twins != NULL) {
      char *dev, *dev_pos = NULL;
      int last_twin = 0;

      dev = strtok_r(twins, ":", &dev_pos);
      while(dev != NULL) {
        last_twin = context->num_devices;

	context->devices[context->num_devices++] = dev;

        dev = strtok_r(NULL, ":", &dev_pos);
      }

      if (context->num_devices & 0x1) {
        snprintf(errbuf, len, "%s: Wrong format: %s requires pairs of devices",
	         __FUNCTION__, context->mode == DAQ_MODE_INLINE ? "inline mode" : "ids bridge");
        free(context);
        return DAQ_ERROR;
      }

      if (last_twin > 0) /* new dev pair */
        printf("%s <-> %s\n", context->devices[last_twin - 1], context->devices[last_twin]);

      twins = strtok_r(NULL, ",", &twins_pos);
    }
  } else if(context->mode == DAQ_MODE_PASSIVE) {
    /* dnaX,dnaY */
    char *dev, *dev_pos = NULL;
    context->num_devices = 0;

    dev = strtok_r(context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX], ",", &dev_pos);
    while(dev != NULL) {
      context->devices[context->num_devices++] = dev;
      dev = strtok_r(NULL, ",", &dev_pos);
    }
  }

  /* catching the SIGRELOAD signal, replacing the default snort handler */
  if ((default_sig_reload_handler = signal(SIGHUP, pfring_daq_sig_reload)) == SIG_ERR)
    default_sig_reload_handler = NULL;

  for (i = 0; i < context->num_devices; i++) {
    if(context->ring_handles[i] == NULL) {
      if (pfring_daq_open(context, i) == -1)
        return DAQ_ERROR;
    }
  }

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  if (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge == 2) {
    context->q = (Pfring_Queue_t *) calloc(1, sizeof(Pfring_Queue_t));
    if(!context->q) {
      snprintf(errbuf, len, "%s: Couldn't allocate memory for the new PF_RING context!", __FUNCTION__);
      return DAQ_ERROR_NOMEM;
    }

    context->q->min_num_slots = DAQ_PF_RING_BEST_EFFORT_BOOST_MIN_NUM_SLOTS;
    context->q->max_slot_len = sizeof(Pfring_Queue_SlotHdr_t) + context->snaplen;
    context->q->buffer_len = context->q->min_num_slots * context->q->max_slot_len;

    context->q->buffer = (u_char *) malloc(context->q->buffer_len);
    if(!context->q->buffer) {
      snprintf(errbuf, len, "%s: Couldn't allocate memory for best-effort IDS bridge support (queue)!", __FUNCTION__);
      return DAQ_ERROR_NOMEM;
    }
  }
#endif

  context->state = DAQ_STATE_INITIALIZED;

  *ctxt_ptr = context;
  return DAQ_SUCCESS;
}

static int pfring_daq_set_filter(void *handle, const char *filter) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

  DPE(context->errbuf, "%s: BPF filters not supported with DNA!", __FUNCTION__);
  return DAQ_ERROR;
}

static int pfring_daq_start(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(context->filter_string) {
    if(pfring_daq_set_filter(context, context->filter_string))
      return DAQ_ERROR;
  }

  pfring_daq_reset_stats(context);
  context->state = DAQ_STATE_STARTED;

  return DAQ_SUCCESS;
}

static int pfring_daq_send_packet(Pfring_Context_t *context, pfring *send_ring, u_int pkt_len)
{
  int rc;

  if(send_ring == NULL)
    return(DAQ_SUCCESS);

  rc = pfring_send(send_ring, (char *) context->pkt_buffer, pkt_len, 1 /* flush packet */);

  if (rc < 0) {
    DPE(context->errbuf, "%s", "pfring_send() error");
    return DAQ_ERROR;
  }

  context->stats.packets_injected++;

  return(DAQ_SUCCESS);
}

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST

static inline int pfring_daq_queue_check_room(Pfring_Queue_t *q) {
  if (q->insert_off == q->remove_off) {
    if ((q->tot_insert - q->tot_read) >= q->min_num_slots)
      return 0;
  } else {
    if (q->insert_off < q->remove_off) {
      if ((q->remove_off - q->insert_off) < q->max_slot_len)
	return 0;
    } else {
      if ((q->buffer_len - q->insert_off) < q->max_slot_len && q->remove_off == 0)
	return 0;
    }
  }

  return 1;
}

static inline int pfring_daq_queue_next_slot_offset(Pfring_Queue_t *q, 
  u_int32_t off) {
  Pfring_Queue_SlotHdr_t *qhdr = (Pfring_Queue_SlotHdr_t *) &q->buffer[off];
  u_int32_t real_slot_size;

  real_slot_size = sizeof(Pfring_Queue_SlotHdr_t) + qhdr->caplen;

  if((off + real_slot_size + q->max_slot_len) > q->buffer_len)
    return 0;

  return (off + real_slot_size);
}

#define min(_a, _b) ((_a) < (_b) ? (_a) : (_b))

static inline void pfring_daq_enqueue(Pfring_Queue_t *q,
  struct pfring_pkthdr *phdr, u_char* pkt_buffer, u_int32_t ifindex, void *user) {

  if (pfring_daq_queue_check_room(q)) {
    Pfring_Queue_SlotHdr_t *qhdr = (Pfring_Queue_SlotHdr_t *) &q->buffer[q->insert_off];

    qhdr->caplen = min(phdr->caplen, q->max_slot_len - sizeof(Pfring_Queue_SlotHdr_t));
    qhdr->pktlen = phdr->len;
    qhdr->ts = phdr->ts;
    qhdr->device_index = ifindex;

    memcpy(qhdr->pkt_buffer, pkt_buffer, qhdr->caplen);

    q->insert_off = pfring_daq_queue_next_slot_offset(q, q->insert_off);
    q->tot_insert++;
  }
}

static inline int pfring_daq_queue_check_packet(Pfring_Queue_t *q) {
  return q->tot_insert != q->tot_read;
}

static inline Pfring_Queue_SlotHdr_t *pfring_daq_dequeue(Pfring_Queue_t *q) { 
  Pfring_Queue_SlotHdr_t *qhdr = (Pfring_Queue_SlotHdr_t *) &q->buffer[q->remove_off];
  q->remove_off = pfring_daq_queue_next_slot_offset(q, q->remove_off);
  q->tot_read++;
  return qhdr;
}

static inline void pfring_daq_process(Pfring_Context_t *context, Pfring_Queue_SlotHdr_t *qhdr) {
  DAQ_PktHdr_t hdr;
  DAQ_Verdict verdict;

  hdr.caplen = qhdr->caplen;
  hdr.pktlen = qhdr->pktlen;
  hdr.ts = qhdr->ts;
#if (DAQ_API_VERSION >= 0x00010002)
  hdr.ingress_index = qhdr->device_index;
  hdr.egress_index = -1;
  hdr.ingress_group = -1;
  hdr.egress_group = -1;
#else
  hdr.device_index = qhdr->device_index;
#endif
  hdr.flags = 0;

  context->stats.packets_received++;

  verdict = context->analysis_func(qhdr->user, &hdr, qhdr->pkt_buffer);

  if(verdict >= MAX_DAQ_VERDICT)
    verdict = DAQ_VERDICT_PASS;

  switch(verdict) {
    case DAQ_VERDICT_BLACKLIST: /* Block the packet and block all future packets in the same flow systemwide. */
      /* TODO handle hw filters */
      break;
    case DAQ_VERDICT_WHITELIST: /* Pass the packet and fastpath all future packets in the same flow systemwide. */
    case DAQ_VERDICT_IGNORE:    /* Pass the packet and fastpath all future packets in the same flow for this application. */
    case DAQ_VERDICT_PASS:      /* Pass the packet */
    case DAQ_VERDICT_REPLACE:   /* Pass a packet that has been modified in-place.(No resizing allowed!) */
    case DAQ_VERDICT_BLOCK:     /* Block the packet. */
      /* Nothing to do really */
      break;
    case MAX_DAQ_VERDICT:
      /* No way we can reach this point */
      break;
  }

  context->stats.verdicts[verdict]++;
}

static inline int pfring_daq_in_packets(Pfring_Context_t *context, u_int32_t *rx_ring_idx) {
  int i;
  
  for (i = 0; i < context->num_devices; i++) {
    *rx_ring_idx = ((*rx_ring_idx) + 1) % context->num_devices;
    if (context->ring_handles[*rx_ring_idx]->is_pkt_available(context->ring_handles[*rx_ring_idx]) > 0) 
      return 1;
  }

  return 0;
}

static int pfring_daq_acquire_best_effort(void *handle, int cnt, DAQ_Analysis_Func_t callback,
#if (DAQ_API_VERSION >= 0x00010002)
                              DAQ_Meta_Func_t metaback,
#endif
			      void *user) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int ret = 0, i, rc, poll_duration = 0, c = 0;
  u_int32_t rx_ring_idx = context->num_devices - 1, rx_ring_idx_clone;
  struct pollfd pfd[DAQ_PF_RING_MAX_NUM_DEVICES];
  struct pfring_pkthdr phdr;

  context->analysis_func = callback;
  context->breakloop = 0;

  for (i = 0; i < context->num_devices; i++) {
    pfring_enable_ring(context->ring_handles[i]);
    pfd[i].fd = pfring_get_selectable_fd(context->ring_handles[i]);
  }

  while((!context->breakloop) && ((cnt <= 0) || (c < cnt))) {

    memset(&phdr, 0, sizeof(phdr));

    if(pfring_daq_reload_requested)
      pfring_daq_reload(context);

    while(pfring_daq_in_packets(context, &rx_ring_idx) && !context->breakloop) {

      pfring_recv(context->ring_handles[rx_ring_idx], &context->pkt_buffer, 0, &phdr, 0);
#if 0
      if(!pfring_daq_in_packets(context, &rx_ring_idx)) { /* optimization (?): no enqueue */
        pfring_daq_process(..);
        c++;
      } else
#endif
      /* enqueueing pkt (and don't care of no room available) */
      pfring_daq_enqueue(context->q, &phdr, context->pkt_buffer, context->ifindexes[rx_ring_idx], user);

      pfring_daq_send_packet(context, context->ring_handles[rx_ring_idx ^ 0x1], phdr.caplen);
    }

    rx_ring_idx_clone = rx_ring_idx;
    while(!(ret = pfring_daq_in_packets(context, &rx_ring_idx_clone)) && pfring_daq_queue_check_packet(context->q) && !context->breakloop) {
      /* no incoming pkts, queued pkts available -> processing enqueued pkts */
      Pfring_Queue_SlotHdr_t *qhdr = pfring_daq_dequeue(context->q); 
      pfring_daq_process(context, qhdr);
      c++;
    }

    if(!ret) {
      /* no packet to read: poll */

      for (i = 0; i < context->num_devices; i++) {
        pfring_sync_indexes_with_kernel(context->ring_handles[i]);
        pfd[i].events = POLLIN;
	pfd[i].revents = 0;
      }

      errno = 0;
      rc = poll(pfd, context->num_devices, poll_duration < context->timeout ? poll_duration += 10 : poll_duration);

      if(rc < 0) {
	if(errno == EINTR)
	  break;

	DPE(context->errbuf, "%s: Poll failed: %s(%d)", __FUNCTION__, strerror(errno), errno);
	return DAQ_ERROR;
      } else if (rc > 0) poll_duration = 0;
    }
  }

  return 0;
}

#endif

static int pfring_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback,
#if (DAQ_API_VERSION >= 0x00010002)
                              DAQ_Meta_Func_t metaback,
#endif
			      void *user) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int ret = 0, i, rc, poll_duration = 0, rx_ring_idx = context->num_devices - 1, c = 0;
  struct pollfd pfd[DAQ_PF_RING_MAX_NUM_DEVICES];

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  if (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge == 2)
    return pfring_daq_acquire_best_effort(handle, cnt, callback, 
#if (DAQ_API_VERSION >= 0x00010002)
      metaback,
#endif 
      user);
#endif

  context->analysis_func = callback;
  context->breakloop = 0;

  for (i = 0; i < context->num_devices; i++) {
    pfring_enable_ring(context->ring_handles[i]);
    pfd[i].fd = pfring_get_selectable_fd(context->ring_handles[i]);
  }

  while((!context->breakloop) && ((cnt <= 0) || (c < cnt))) {
    struct pfring_pkthdr phdr;
    DAQ_PktHdr_t hdr;
    DAQ_Verdict verdict;

    memset(&phdr, 0, sizeof(phdr));

    if(pfring_daq_reload_requested)
      pfring_daq_reload(context);

    for (i = 0; i < context->num_devices; i++) {
      rx_ring_idx = (rx_ring_idx + 1) % context->num_devices;

      ret = pfring_recv(context->ring_handles[rx_ring_idx], &context->pkt_buffer, 0, &phdr, 0 /* Dont't wait */);

      if (ret > 0) break;
    }

    if(ret <= 0) {
      /* No packet to read: let's poll */

      for (i = 0; i < context->num_devices; i++) {
        pfring_sync_indexes_with_kernel(context->ring_handles[i]);
        pfd[i].events = POLLIN;
	pfd[i].revents = 0;
      }

      errno = 0;
      rc = poll(pfd, context->num_devices, poll_duration < context->timeout ? poll_duration += 10 : poll_duration);

      if(rc < 0) {
	if(errno == EINTR)
	  break;

	DPE(context->errbuf, "%s: Poll failed: %s(%d)", __FUNCTION__, strerror(errno), errno);
	return DAQ_ERROR;
      } else if (rc > 0) poll_duration = 0;
    } else {
      hdr.caplen = phdr.caplen;
      hdr.pktlen = phdr.len;
      hdr.ts = phdr.ts;
#if (DAQ_API_VERSION >= 0x00010002)
      hdr.ingress_index = context->ifindexes[rx_ring_idx];
      hdr.egress_index = -1;
      hdr.ingress_group = -1;
      hdr.egress_group = -1;
#else
      hdr.device_index = context->ifindexes[rx_ring_idx];
#endif
      hdr.flags = 0;

      context->stats.packets_received++;

      verdict = context->analysis_func(user, &hdr, (u_char *) context->pkt_buffer);

      if(verdict >= MAX_DAQ_VERDICT)
	verdict = DAQ_VERDICT_PASS;

      if (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge) { /* always forward the packet */

        pfring_daq_send_packet(context, context->ring_handles[rx_ring_idx ^ 0x1], hdr.caplen);

      } else if (context->mode == DAQ_MODE_INLINE) {
        /* parsing eth_type to forward ARP */
        struct ethhdr *eh = (struct ethhdr *) context->pkt_buffer;
        phdr.extended_hdr.parsed_pkt.eth_type = ntohs(eh->h_proto);
        phdr.extended_hdr.parsed_pkt.offset.vlan_offset = 0;
        if (phdr.extended_hdr.parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */) {
          struct eth_vlan_hdr *vh;
          phdr.extended_hdr.parsed_pkt.offset.vlan_offset = sizeof(struct ethhdr) - sizeof(struct eth_vlan_hdr);
          while (phdr.extended_hdr.parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */ ) {
            phdr.extended_hdr.parsed_pkt.offset.vlan_offset += sizeof(struct eth_vlan_hdr);
            vh = (struct eth_vlan_hdr *) &context->pkt_buffer[phdr.extended_hdr.parsed_pkt.offset.vlan_offset];
            phdr.extended_hdr.parsed_pkt.eth_type = ntohs(vh->h_proto);
          }
        }

        if (phdr.extended_hdr.parsed_pkt.eth_type == 0x0806 /* ARP */ )
          verdict = DAQ_VERDICT_PASS;
      }

      switch(verdict) {
      case DAQ_VERDICT_BLACKLIST: /* Block the packet and block all future packets in the same flow systemwide. */
        /* TODO handle hw filters */
	break;
      case DAQ_VERDICT_WHITELIST: /* Pass the packet and fastpath all future packets in the same flow systemwide. */
      case DAQ_VERDICT_IGNORE:    /* Pass the packet and fastpath all future packets in the same flow for this application. */
      case DAQ_VERDICT_PASS:      /* Pass the packet */
      case DAQ_VERDICT_REPLACE:   /* Pass a packet that has been modified in-place.(No resizing allowed!) */
        if (context->mode == DAQ_MODE_INLINE)
	  pfring_daq_send_packet(context, context->ring_handles[rx_ring_idx ^ 0x1], hdr.caplen);
	break;
      case DAQ_VERDICT_BLOCK:     /* Block the packet. */
	/* Nothing to do really */
	break;
      case MAX_DAQ_VERDICT:
	/* No way we can reach this point */
	break;
      }

      context->stats.verdicts[verdict]++;
      c++;
    }
  }

  return 0;
}

static int pfring_daq_inject(void *handle, const DAQ_PktHdr_t *hdr,
			     const uint8_t *packet_data, uint32_t len, int reverse) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int i, tx_ring_idx = DAQ_PF_RING_PASSIVE_DEV_IDX;

  if (context->mode == DAQ_MODE_INLINE) { /* looking for the device idx */
    for (i = 0; i < context->num_devices; i++)
#if (DAQ_API_VERSION >= 0x00010002)
      if (context->ifindexes[i] == hdr->ingress_index) {
#else
      if (context->ifindexes[i] == hdr->device_index) {
#endif
        tx_ring_idx = i ^ 0x1;
        break;
      }
  }

  if(pfring_send(context->ring_handles[tx_ring_idx],
		 (char *) packet_data, len, 1 /* flush packet */) < 0) {
    DPE(context->errbuf, "%s", "pfring_send() error");
    return DAQ_ERROR;
  }

  context->stats.packets_injected++;
  return DAQ_SUCCESS;
}

static int pfring_daq_breakloop(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(!context->ring_handles[DAQ_PF_RING_PASSIVE_DEV_IDX])
    return DAQ_ERROR;

  context->breakloop = 1;

  return DAQ_SUCCESS;
}

static int pfring_daq_stop(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;
  int i;

  update_hw_stats(context);

  for (i = 0; i < context->num_devices; i++) {
    if(context->ring_handles[i]) {
      /* Store the hardware stats for post-stop stat calls. */
      pfring_close(context->ring_handles[i]);
      context->ring_handles[i] = NULL;
    }
  }

  context->state = DAQ_STATE_STOPPED;

  return DAQ_SUCCESS;
}

static void pfring_daq_shutdown(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;
  int i;

  for (i = 0; i < context->num_devices; i++)
    if(context->ring_handles[i])
      pfring_close(context->ring_handles[i]);

  if(context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX])
    free(context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX]);

  if(context->filter_string)
    free(context->filter_string);

  free(context);
}

static DAQ_State pfring_daq_check_status(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  return context->state;
}

static int pfring_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  update_hw_stats(context);

  memcpy(stats, &context->stats, sizeof(DAQ_Stats_t));

  return DAQ_SUCCESS;
}

static void pfring_daq_reset_stats(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;
  pfring_stat ps;
  int i;

  memset(&context->stats, 0, sizeof(DAQ_Stats_t));
  memset(&ps, 0, sizeof(pfring_stat));

  for (i = 0; i < context->num_devices; i++)
    if(context->ring_handles[i]
       && pfring_stats(context->ring_handles[i], &ps) == 0) {
      context->base_recv[i] = ps.recv;
      context->base_drop[i] = ps.drop;
    }
}

static int pfring_daq_get_snaplen(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(!context->ring_handles[DAQ_PF_RING_PASSIVE_DEV_IDX])
    return DAQ_ERROR;
  else
    return context->snaplen;
}

static uint32_t pfring_daq_get_capabilities(void *handle) {
  return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
    DAQ_CAPA_INJECT_RAW | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BPF;
}

static int pfring_daq_get_datalink_type(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(!context)
    return DAQ_ERROR;
  else
    return DLT_EN10MB;
}

static const char *pfring_daq_get_errbuf(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  return context->errbuf;
}

static void pfring_daq_set_errbuf(void *handle, const char *string) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if(!string)
    return;

  DPE(context->errbuf, "%s", string);
}

static int pfring_daq_get_device_index(void *handle, const char *device) {
  return DAQ_ERROR_NOTSUP;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
  const DAQ_Module_t pfring_daq_module_data =
#endif
  {
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_PF_RING_DNA_VERSION,
    .name = "pfring_dna",
    .type = DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    .initialize = pfring_daq_initialize,
    .set_filter = pfring_daq_set_filter,
    .start = pfring_daq_start,
    .acquire = pfring_daq_acquire,
    .inject = pfring_daq_inject,
    .breakloop = pfring_daq_breakloop,
    .stop = pfring_daq_stop,
    .shutdown = pfring_daq_shutdown,
    .check_status = pfring_daq_check_status,
    .get_stats = pfring_daq_get_stats,
    .reset_stats = pfring_daq_reset_stats,
    .get_snaplen = pfring_daq_get_snaplen,
    .get_capabilities = pfring_daq_get_capabilities,
    .get_datalink_type = pfring_daq_get_datalink_type,
    .get_errbuf = pfring_daq_get_errbuf,
    .set_errbuf = pfring_daq_set_errbuf,
    .get_device_index = pfring_daq_get_device_index
  };
