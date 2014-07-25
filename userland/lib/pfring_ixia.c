/*
 *
 * (C) 2011-14 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 */

/* ********************************* */

struct ixia {
	u_int8_t type;
	u_int8_t timestamp_len;
	u_int32_t sec;
	u_int32_t nsec;
	u_int8_t trailer_len;
	u_int16_t signature;
	u_int16_t fcs;
}__attribute__((__packed__));

static u_int ixia_trailer_offset = 4;
static u_int ixia_signature_offset = 8;

#define IXIA_SIGNATURE 0x12af /*0xaf12*/

/* ********************************* */

void ixia_add_timestamp(u_char* buffer, u_int32_t buffer_len, struct pfring_pkthdr *hdr) {
  struct ixia* trailer;
  u_int16_t* ixia_signature;
	
  ixia_signature = (u_int16_t*)(buffer + buffer_len - ixia_signature_offset);
  
  if ( (*ixia_signature) == IXIA_SIGNATURE){
    trailer = (struct ixia*) (buffer + ixia_trailer_offset);
    hdr->ts.tv_sec = ntohl(trailer->sec);
    hdr->ts.tv_usec = (ntohl(trailer->nsec)/1000);
  }
}

