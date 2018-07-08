/* ----------------------------------------------------------------------------
 *
 * Copyright (C) 2018 - Emanuele Faranda
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>

/* For capabilities / permissions */
#include <sys/types.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <pwd.h>
#include <unistd.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define NF_MAX_QUEUE_LEN 1024
#define PACKET_BUFSIZE 70000
#define REWRITE_ME_MAGIC 0xF00DBEEF

struct proxy_data {
  u_int32_t orig_ip;
  u_int16_t orig_port;
} __attribute__((packed));


/* ******************************************************* */

// from DHCPd
static inline u_int16_t in_cksum(const char *buf, size_t nbytes, u_int32_t sum) {
  u_int16_t i;

  /* Checksum all the pairs of bytes first... */
  for (i = 0; i < (nbytes & ~1U); i += 2) {
    sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  /* If there's a single byte left over, checksum it, too.   Network
     byte order is big-endian, so the remaining byte is the high byte. */
  if(i < nbytes) {
    sum += buf [i] << 8;
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  return sum;
}

static inline u_int16_t wrapsum(u_int32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

static u_int16_t ip_checksum(const void *buf, size_t hdr_len) {
  return wrapsum(in_cksum(buf, hdr_len, 0));
}

/* ******************************************************* */

// from http://minirighi.sourceforge.net/html/tcp_8c-source.html
static u_int16_t tcp_checksum(const void *buff, size_t len, u_int32_t src_addr, u_int32_t dest_addr) {
  const uint16_t *buf=buff;
  uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
  uint32_t sum;
  size_t length=len;

  // Calculate the sum
  sum = 0;
  while (len > 1) {
    sum += *buf++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }

  if ( len & 1 )
    // Add the padding if the packet lenght is odd
    sum += *((uint8_t *)buf);

  // Add the pseudo-header
  sum += *(ip_src++);
  sum += *ip_src;
  sum += *(ip_dst++);
  sum += *ip_dst;
  sum += htons(IPPROTO_TCP);
  sum += htons(length);

  // Add the carries
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  // Return the one's complement of sum
  return ( (uint16_t)(~sum)  );
}

/* ******************************************************* */

static int netfilter_callback(struct nfq_q_handle *nfhandle, struct nfgenmsg *nfmsg,
      struct nfq_data *nfdata, void *userdata) {
  struct nfqnl_msg_packet_hdr *ph;
  u_char *payload = NULL;
  int payload_len = 0;
  int id;

  ph = nfq_get_msg_packet_hdr(nfdata);
  id = ntohl(ph->packet_id);

  if((payload_len = nfq_get_payload(nfdata, &payload)) > 0) {
    struct iphdr *ip = (struct iphdr *) payload;

    if((ip->version == 4) && (ip->protocol == IPPROTO_TCP)) {
      u_int8_t iphdr_size = ip->ihl * 4;
      struct tcphdr *tcp = (struct tcphdr*) &payload[iphdr_size];
      u_int8_t tcphdr_size = tcp->doff * 4;
      u_int16_t data_len = ntohs(ip->tot_len) - iphdr_size - tcphdr_size;

      if(data_len >= sizeof(struct proxy_data)) {
        struct proxy_data *data = (struct proxy_data*) (((u_char*)tcp) + tcphdr_size);

        if(ntohl(data->orig_ip) == REWRITE_ME_MAGIC) {
          /* Write original client information */
          data->orig_ip = ip->saddr;
          data->orig_port = tcp->source;

          /* Recalculate checksums */
          tcp->check = 0;
          tcp->check = tcp_checksum(tcp, payload_len-iphdr_size, ip->saddr, ip->daddr);
          ip->check = 0;
          ip->check = ip_checksum(payload, iphdr_size);
        }
      }
    }
  } else
    payload_len = 0;

  return nfq_set_verdict(nfhandle, id, NF_ACCEPT, payload_len, payload);
}

/* ******************************************************* */

static int drop_privs() {
  const cap_value_t cap_values[] = {
    CAP_NET_RAW,      /* Use RAW and PACKET sockets */
    CAP_NET_ADMIN     /* Perform various network-related operations */
  };
  const int num_cap = sizeof(cap_values) / sizeof(cap_value_t);
  const char *username = "anonymous";
  struct passwd *pw = getpwnam(username);

  if(!pw) {
    fprintf(stderr, "Cannot find user %s\n", username);
    return -1;
  }

  /* Prepare capabilities */
  cap_t caps = cap_get_proc();
  cap_set_flag(caps, CAP_PERMITTED, num_cap, cap_values, CAP_SET);
  cap_set_flag(caps, CAP_EFFECTIVE, num_cap, cap_values, CAP_SET);

  if(cap_set_proc(caps) == 0) {
    if(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
      fprintf(stderr, "Cannot retain capabilities\n");
      cap_free(caps);
      return -2;
    }
  } else {
    fprintf(stderr, "Could not set capabilities\n");
    cap_free(caps);
    return -3;
  }

  if((setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0)) {
    fprintf(stderr, "Cannot drop privileges\n");
    return -4;
  }

  /* Acquire capabilities */
  if(cap_set_proc(caps) != 0) {
    fprintf(stderr, "Could not acquire capabilities\n");
    cap_free(caps);
    return -5;
  }

  cap_free(caps);

  return 0;
}

/* ******************************************************* */

int main() {
  struct nfq_handle *nfHandle;
  struct nfq_q_handle *queueHandle;
  const uint16_t queueId = 0;

  if((nfHandle = nfq_open()) == NULL) {
    fprintf(stderr, "nfq_open error\n");
    return -1;
  }

  if(nfq_unbind_pf(nfHandle, AF_INET) < 0) {
    fprintf(stderr, "nfq_unbind_pf error\n");
    return -1;
  }

  if(nfq_bind_pf(nfHandle, AF_INET) < 0) {
    fprintf(stderr, "nfq_bind_pf error\n");
    return -1;
  }

  void *userdata = NULL;
  if((queueHandle = nfq_create_queue(nfHandle, queueId, &netfilter_callback, &userdata)) == NULL) {
    fprintf(stderr, "nfq_create_queue: cannot create nfqueue #%u\n", queueId);
    return -1;
  } else
    printf("Successfully created nfqueue #%u\n", queueId);

  if(nfq_set_mode(queueHandle, NFQNL_COPY_PACKET, 0XFFFF) < 0) {
    fprintf(stderr, "nfq_set_mode NFQNL_COPY_PACKET error\n");
    return -1;
  }

  if(nfq_set_queue_maxlen(queueHandle, NF_MAX_QUEUE_LEN) < 0) {
    fprintf(stderr, "nfq_set_queue_maxlen NF_MAX_QUEUE_LEN error\n");
    return -1;
  }

  int fd = nfq_fd(nfHandle);
  char *buf = (char *) malloc(PACKET_BUFSIZE);

  if(!buf) {
    fprintf(stderr, "malloc failed\n");
    return -1;
  }

  int priv_rv;

  if((priv_rv = drop_privs()) != 0) {
    if(priv_rv == -5) {
      fprintf(stderr, "FATAL: privileges error\n");
      return -1;
    }

    fprintf(stderr, "WARNING: privileges not dropped!\n");
  }  

  /*****/

  while(1) {
    int len = recv(fd, buf, PACKET_BUFSIZE, 0);

    if(len >= 0) {
      int rc = nfq_handle_packet(nfHandle, buf, len);

      if(rc != 0)
        fprintf(stderr, "nfq_handle_packet returned error: rc=%d, errno=%d", rc, errno);
    } else
      fprintf(stderr, "NFQUEUE recv returned error: len=%d, errno=%d", len, errno);
  }

  /*****/

  free(buf);
  nfq_destroy_queue(queueHandle);
  nfq_close(nfHandle);

  printf("Destroyed nfqueue #%u\n", queueId);
  return 0;
}
