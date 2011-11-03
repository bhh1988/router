/*-----------------------------------------------------------------------------
 * File: sr_vns_comm.c
 * Date: Spring 2002
 * Authors: Guido Apanzeller, Vikram Vijayaraghaven, Martin Casado
 * Contact: casado@stanford.edu
 *
 * Based on many generations of sr clients including the original c client
 * and bert.
 *
 * 2003-Dec-03 09:00:52 AM :
 *   - bug sending packets read from client to sr_log_packet.  Packet was
 *     sent in network byte order ... expected host byte order.
 *     Reported by Matt Holliman & Sam Small. /mc
 *
 * 2004-Jan-29 19:09:28
 *   - added check to handle signal interrupts on recv (for use with
 *     alarm(..) for timeouts.  Fixes are based on patch by
 *     Abhyudaya Chodisetti <sravanth@stanford.edu> /mc
 *
 * 2004-Jan-31 13:27:54
 *    - William Chan (chanman@stanford.edu) submitted patch for UMR on
 *      sr_dump_packet(..)
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "sr_dumper.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

#include "sha1.h"
#include "vnscommand.h"

#define AUTH_KEY_LEN 64
#define SHA1_LEN 20

static void sr_log_packet(struct sr_instance* , uint8_t* , int );
static int  sr_arp_req_not_for_us(struct sr_instance* sr,
                                  uint8_t * packet /* lent */,
                                  unsigned int len,
                                  char* interface  /* lent */);
int sr_read_from_server_expect(struct sr_instance* sr /* borrowed */, int expected_cmd);

/*-----------------------------------------------------------------------------
 * Method: sr_session_closed_help(..)
 *
 * Provide debugging hints if VNS closes session
 *
 *----------------------------------------------------------------------------*/
static void sr_session_closed_help()
{
  fprintf(stdout, " `~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~\n");
  fprintf(stdout, " Make sure you are using the right topology \n");
  fprintf(stdout, "      ./sr -t <topoid> \n");
  fprintf(stdout, "                       \n");
  fprintf(stdout, " You can also check that another router isn't already \n");
  fprintf(stdout, " on your topology at: http://vns-2.stanford.edu/summary \n");
  fprintf(stdout, " `~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~\n");
}

/*-----------------------------------------------------------------------------
 * Method: sr_connect_to_server()
 * Scope: Global
 *
 * Connect to the virtual server
 *
 * RETURN VALUES:
 *
 *  0 on success
 *  something other than zero on error
 *
 *---------------------------------------------------------------------------*/

int sr_connect_to_server(struct sr_instance* sr,unsigned short port,
                         char* server)
{
  struct hostent *hp;
  char buf[576];
  uint32_t buf_len;
  c_open *command = (c_open *)buf;
  c_open_template *ot = (c_open_template *)buf;

  /* REQUIRES */
  assert(sr);
  assert(server);

  /* purify UMR be gone ! */
  memset(buf, 0, 576);

  /* zero out server address struct */
  memset(&(sr->sr_addr),0,sizeof(struct sockaddr_in));

  sr->sr_addr.sin_family = AF_INET;
  sr->sr_addr.sin_port = htons(port);

  /* grab hosts address from domain name */
  if ((hp = gethostbyname(server))==0) {
    perror("gethostbyname:sr_client.c::sr_connect_to_server(..)");
    return -1;
  }

  /* set server address */
  memcpy(&(sr->sr_addr.sin_addr),hp->h_addr,hp->h_length);

  /* create socket */
  if ((sr->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket(..):sr_client.c::sr_connect_to_server(..)");
    return -1;
  }

  /* attempt to connect to the server */
  if (connect(sr->sockfd,
              (struct sockaddr *)&(sr->sr_addr),
              sizeof(sr->sr_addr)) < 0) {
    perror("connect(..):sr_client.c::sr_connect_to_server(..)");
    close(sr->sockfd);
    return -1;
  }

  /* wait for authentication to be completed (server sends the first message) */
  if (sr_read_from_server_expect(sr, VNS_AUTH_REQUEST)!= 1 ||
      sr_read_from_server_expect(sr, VNS_AUTH_STATUS) != 1) {
    return -1; /* failed to receive expected message */
  }

  if (strlen(sr->template) > 0) {
    /* send VNS_OPEN_TEMPLATE message to server */
    ot->mLen = htonl(sizeof(c_open_template));
    ot->mType = htonl(VNS_OPEN_TEMPLATE);
    strncpy(ot->templateName, sr->template, 30);
    strncpy(ot->mVirtualHostID, sr->host, IDSIZE);

    int filters = 0;
    struct vns_filter *filter = sr->filter_list;
    for (; filter != NULL; filter = filter->next, ++filters) {
      ot->srcFilters[filters].ip = (uint32_t)(filter->addr.s_addr);
      ot->srcFilters[filters].num_masked_bits = filter->mask_bits;
    }
    buf_len = sizeof(c_open_template) + filters * sizeof(c_src_filter);
    ot->mLen = htonl(buf_len);
  }
  else {
    /* send sr_OPEN message to server */
    command->mLen   = htonl(sizeof(c_open));
    command->mType  = htonl(VNSOPEN);
    command->topoID = htons(sr->topo_id);
    strncpy( command->mVirtualHostID, sr->host,  IDSIZE);
    strncpy( command->mUID, sr->user, IDSIZE);

    buf_len = sizeof(command);
  }

  if (send(sr->sockfd, buf, buf_len, 0) != buf_len)
  {
    perror("send(..):sr_client.c::sr_connect_to_server()");
    return -1;
  }

  if (strlen(sr->template) > 0 &&
      sr_read_from_server_expect(sr, VNS_RTABLE) != 1) {
    return -1; /* needed to get the rtable */
  }

  return 0;
} /* -- sr_connect_to_server -- */

/*-----------------------------------------------------------------------------
 * Method: sr_handle_hwinfo(..)
 * scope: global
 *
 *
 * Read, from the server, the hardware information for the reserved host.
 *
 *---------------------------------------------------------------------------*/

int sr_handle_hwinfo(struct sr_instance* sr, c_hwinfo* hwinfo)
{
  int num_entries;
  int i = 0;

  /* REQUIRES */
  assert(sr);
  assert(hwinfo);

  num_entries = (ntohl(hwinfo->mLen) - (2*sizeof(uint32_t)))/sizeof(c_hw_entry);

  /* Debug("Received Hardware Info with %d entries\n",num_entries); */

  for ( i=0; i<num_entries; i++ ) {
    switch ( ntohl(hwinfo->mHWInfo[i].mKey)) {
      case HWFIXEDIP:
        /*Debug("Fixed IP: %s\n",inet_ntoa(
                    *((struct in_addr*)(hwinfo->mHWInfo[i].value))));*/
        break;
      case HWINTERFACE:
        /*Debug("INTERFACE: %s\n",hwinfo->mHWInfo[i].value);*/
        sr_add_interface(sr,hwinfo->mHWInfo[i].value);
        break;
      case HWSPEED:
        /* Debug("Speed: %d\n",
                ntohl(*((unsigned int*)hwinfo->mHWInfo[i].value))); */
        break;
      case HWSUBNET:
        /* Debug("Subnet: %s\n",inet_ntoa(
                    *((struct in_addr*)(hwinfo->mHWInfo[i].value)))); */
        break;
      case HWMASK:
        /* Debug("Mask: %s\n",inet_ntoa(
                    *((struct in_addr*)(hwinfo->mHWInfo[i].value)))); */
        break;
      case HWETHIP:
        /*Debug("IP: %s\n",inet_ntoa(
                    *((struct in_addr*)(hwinfo->mHWInfo[i].value))));*/
        sr_set_ether_ip(sr,*((uint32_t*)hwinfo->mHWInfo[i].value));
        break;
      case HWETHER:
        /*Debug("\tHardware Address: ");
        DebugMAC(hwinfo->mHWInfo[i].value);
        Debug("\n"); */
        sr_set_ether_addr(sr,(unsigned char*)hwinfo->mHWInfo[i].value);
        break;
      default:
        printf (" %d \n",ntohl(hwinfo->mHWInfo[i].mKey));
    } /* -- switch -- */
  } /* -- for -- */

  printf("Router interfaces:\n");
  sr_print_if_list(sr);

  return num_entries;
} /* -- sr_handle_hwinfo -- */

int sr_handle_rtable(struct sr_instance* sr, c_rtable* rtable) {
  char fn[7+IDSIZE+1];
  FILE* fp;

  strcpy(fn, "rtable.");
  strcat(fn, rtable->mVirtualHostID);
  fp = fopen(fn, "w");
  if (fp) {
    fwrite(rtable->rtable, ntohl(rtable->mLen) - 8 - IDSIZE, 1, fp);
    fclose(fp);
    return 1;
  }
  else {
      perror("unable to write new rtable file");
      return 0; /* failed */
  }
}

int sr_handle_auth_request(struct sr_instance* sr, c_auth_request* req) {
  char auth_key[AUTH_KEY_LEN+1];
  FILE* fp;
  SHA1Context sha1;
  c_auth_reply* ar;
  char* buf;
  int len, len_username, i, ret;

  /* read in the user's auth key */
  fp = fopen("auth_key", "r");
  if (fp) {
    if (fgets(auth_key, AUTH_KEY_LEN+1, fp) != auth_key) {
      fclose(fp);
      return 0;
    }
    fclose(fp);

    /* compute the salted SHA1 of password from auth_key */
    SHA1Reset(&sha1);
    SHA1Input(&sha1, req->salt, ntohl(req->mLen) - sizeof(*req));
    SHA1Input(&sha1, (unsigned char*)auth_key, AUTH_KEY_LEN);
    if (!SHA1Result(&sha1)) {
        fprintf(stderr, "SHA1 result could not be computed\n");
        return 0;
    }

    /* build the auth reply packet and then send it */
    len_username = strlen(sr->user);
    len = sizeof(c_auth_reply) + len_username + SHA1_LEN;
    buf = (char*)malloc(len);
    if (!buf) {
      perror("malloc failed");
      return 0;
    }
    ar = (c_auth_reply*)buf;
    ar->mLen = htonl(len);
    ar->mType = htonl(VNS_AUTH_REPLY);
    ar->usernameLen = htonl(len_username);
    strcpy(ar->username, sr->user);
    for (i=0; i<5; i++) {
      sha1.Message_Digest[i] = htonl(sha1.Message_Digest[i]);
    }
    memcpy(ar->username + len_username, sha1.Message_Digest, SHA1_LEN);

    if (send(sr->sockfd, buf, len, 0) != len) {
      perror("send(..):sr_client.c::sr_handle_auth_request()");
      ret = 0;
    } else {
      ret = 1;
    }
    free(buf);
    return ret;
  }
  else {
    perror("unable to read credentials from 'auth_key' file");
    return 0; /* failed */
  }
}

int sr_handle_auth_status(struct sr_instance* sr, c_auth_status* status) {
  if (status->auth_ok)
    printf("successfully authenticated as %s\n", sr->user);
  else
    fprintf(stderr, "Authentication failed as %s: %s\n", sr->user, status->msg);
  return status->auth_ok;
}

struct vns_filter *
sr_filter_matching_src(struct sr_instance *sr, struct in_addr *src) {

  /* Run the packet src through our filters */
  struct vns_filter *filter = sr->filter_list;

  for (; filter != NULL; filter = filter->next) { /* -- cidr masking -- */
    if ((filter->addr.s_addr & filter->mask.s_addr) ==
        (src->s_addr & filter->mask.s_addr)) {
      return filter; /* Filter match! */
    }
  }
  return NULL; /* no match */
}

char *sr_filter_interface(struct sr_instance* sr,
                          uint8_t * packet /* lent */,
                          unsigned int len,
                          char* interface  /* lent */)
{
  if (sr->filter_list == NULL)
    return interface; /* -- filters not in use -- */

  char *str_addr = NULL;
  struct in_addr *src_addr = NULL;
  struct vns_filter *filter = NULL;

  struct sr_ethernet_hdr *e_hdr;
  struct sr_ip_hdr *ip_hdr;
  struct sr_arp_hdr *arp_hdr;

  e_hdr = (struct sr_ethernet_hdr *)packet;
  ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));

  if (ntohs(e_hdr->ether_type) == ethertype_ip)
    src_addr = (struct in_addr *)&(ip_hdr->ip_src);
  else if (ntohs(e_hdr->ether_type) == ethertype_arp)
    /* src_addr = (struct in_addr *)&(arp_hdr->ar_sip); */
    return interface; /* -- dont filter ARP -- */

  if (src_addr == NULL) {
    fprintf(stderr, "unknown ethernet type %d\n", ntohs(e_hdr->ether_type));
    return NULL;
  }

  str_addr = inet_ntoa(*src_addr);
  printf("SRC IP: %s\n", str_addr);

  filter = sr_filter_matching_src(sr, src_addr);
  if (filter == NULL) {
    fprintf(stderr, "Filtered packet from %s (dropped).\n", str_addr);
    return NULL; /* -- no match. drop. -- */
  }

  /* -- keep -- */
  if (filter->interface[0] != '\0') { /* -- mapping match! -- */
    fprintf(stderr, "Injecting packet from %s directly into %s,"
      " (instead of %s). \n", str_addr, filter->interface, interface);
    return filter->interface;
  }

  return interface;
}

/*-----------------------------------------------------------------------------
 * Method: sr_read_from_server(..)
 * Scope: global
 *
 * Houses main while loop for communicating with the virtual router server.
 *
 *---------------------------------------------------------------------------*/

int sr_read_from_server(struct sr_instance* sr /* borrowed */) {
  return sr_read_from_server_expect(sr, 0);

}


int sr_read_data_from_socket(int sockfd, uint8_t* buf, size_t len) {
  /* attempt to read the size of the incoming packet */
  int ret = 0;
  int bytes_read = 0;
  while( bytes_read < len) {
    do {
      /* -- just in case SIGALRM breaks recv -- */
      errno = 0; /* -- hacky glibc workaround -- */
      if ((ret = recv(sockfd, buf + bytes_read, len - bytes_read, 0)) == -1) {
        if ( errno == EINTR ) {
          continue;
        }
        perror("recv(..):sr_client.c::sr_read_data_from_sock");
        return -1;
      }
      bytes_read += ret;
    } while ( errno == EINTR); /* be mindful of signals */
  }
  return 0;
}


int sr_read_incoming_packet(struct sr_instance* sr, uint8_t* buf, uint32_t len,
  char *interface)
{

  /* -- check if it is an ARP to another router if so drop   -- */
  if (sr_arp_req_not_for_us(sr, buf, len, interface))
    return -1;

  /* print_hdrs(buf, len); */

  /* -- apply filters, if any -- */
  interface = sr_filter_interface(sr, buf, len, interface);
  if (interface == NULL)
    return -1;

  /* -- log packet -- */
  sr_log_packet(sr, buf, len);

  /* -- pass to router, student's code should take over here -- */
  printf("Received packet on interface %s \n", interface);
  sr_handlepacket(sr, buf, len, interface);

  return 0;
}


int sr_read_from_server_expect(struct sr_instance* sr /* borrowed */,
                               int expected_cmd)
{
  int ret, command;
  uint32_t len = 0;
  uint8_t *buf = NULL;
  c_packet_header *pkt = NULL;

  /* REQUIRES */
  assert(sr);

  /*---------------------------------------------------------------------------
    Read a command from the server
    -------------------------------------------------------------------------*/

  if ((ret = sr_read_data_from_socket(sr->sockfd, ((uint8_t*)&len), 4)) != 0) {
    fprintf(stderr,"Error: failed reading command length \n");
    close(sr->sockfd);
    return -1;
  }

  len = ntohl(len);

  if ( len > 10000 || len < 0 ) {
    fprintf(stderr,"Error: command length to large %d\n",len);
    close(sr->sockfd);
    return -1;
  }

  if ((buf = malloc(len)) == 0) {
    fprintf(stderr,"Error: out of memory (sr_read_from_server)\n");
    return -1;
  }

  pkt = (c_packet_header *)buf;
  /* set first field of command since we've already read it */
  pkt->mLen = htonl(len);

  if ((ret = sr_read_data_from_socket(sr->sockfd, buf + 4, len - 4)) != 0) {
    fprintf(stderr,"Error: failed reading command body\n");
    close(sr->sockfd);
    return -1;
  }

  /* My entry for most unreadable line of code - guido */
  /* ... you win - mc                                  */
  /* command = *(((int *)buf)+1) = ntohl(*(((int *)buf)+1)); */
  /* !! this sets bad example. just cast the buffer. -juan   */
  command = ntohl(pkt->mType);

  /* make sure the command is what we expected if we were expecting something */
  if (expected_cmd && command != expected_cmd && command != VNSCLOSE) {
    /* VNSCLOSE is always ok */
    fprintf(stderr, "Error: expected command %d, got %d\n", expected_cmd,
      command);
    return -1;
  }

  ret = 1;

  switch (command) {
      /* -------------        VNSPACKET     -------------------- */
    case VNSPACKET:
      sr_read_incoming_packet(sr,
                              buf + sizeof(c_packet_header),
                              len - sizeof(c_packet_header),
                              (char *)buf + sizeof(c_base));
      break;

      /* -------------        VNSCLOSE      -------------------- */
    case VNSCLOSE:
      fprintf(stderr,"VNS server closed session.\n");
      fprintf(stderr,"Reason: %s\n",((c_close*)buf)->mErrorMessage);
      sr_session_closed_help();

      ret = 0;
      break;

      /* -------------        VNSBANNER      -------------------- */
    case VNSBANNER:
      fprintf(stderr,"%s",((c_banner*)buf)->mBannerMessage);
      break;

      /* -------------     VNSHWINFO     -------------------- */
    case VNSHWINFO:
      sr_handle_hwinfo(sr,(c_hwinfo*)buf);
      if (sr_verify_routing_table(sr) != 0) {
        fprintf(stderr,"Routing table not consistent with hardware\n");
        return -1;
      }
      printf(" <-- Ready to process packets --> \n");
      break;

      /* ---------------- VNS_RTABLE ---------------- */
    case VNS_RTABLE:
      if (!sr_handle_rtable(sr, (c_rtable*)buf))
        ret = -1;
      break;

      /* ------------- VNS_AUTH_REQUEST ------------- */
    case VNS_AUTH_REQUEST:
      if (!sr_handle_auth_request(sr, (c_auth_request*)buf))
        ret = -1;
      break;

      /* ------------- VNS_AUTH_STATUS -------------- */
    case VNS_AUTH_STATUS:
      if (!sr_handle_auth_status(sr, (c_auth_status*)buf))
        ret = -1;
      break;

    default:
      Debug("unknown command: %d\n", command);
      break;

  }/* -- switch -- */

  fflush(stdout);

  if (buf) {
    free(buf);
  }
  return ret;
}/* -- sr_read_from_server -- */

/*-----------------------------------------------------------------------------
 * Method: sr_ether_addrs_match_interface(..)
 * Scope: Local
 *
 * Make sure ethernet addresses are sane so we don't muck uo the system.
 *
 *----------------------------------------------------------------------------*/

static int
sr_ether_addrs_match_interface( struct sr_instance* sr, /* borrowed */
                                uint8_t* buf, /* borrowed */
                                const char* name /* borrowed */ )
{
  struct sr_ethernet_hdr* ether_hdr = 0;
  struct sr_if* iface = 0;

  /* -- REQUIRES -- */
  assert(sr);
  assert(buf);
  assert(name);

  ether_hdr = (struct sr_ethernet_hdr*)buf;
  iface = sr_get_interface(sr, name);

  if ( iface == 0 ) {
    fprintf( stderr, "** Error, interface %s, does not exist\n", name);
    return 0;
  }

  if ( memcmp( ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN) != 0 ) {
    fprintf( stderr, "** Error, source address does not match interface\n");
    return 0;
  }

  /* TODO */
  /* Check destination, hardware address.  If it is private (i.e. destined
   * to a virtual interface) ensure it is going to the correct topology
   * Note: This check should really be done server side ...
   */

  return 1;

} /* -- sr_ether_addrs_match_interface -- */

/*-----------------------------------------------------------------------------
 * Method: sr_send_packet(..)
 * Scope: Global
 *
 * Send a packet (ethernet header included!) of length 'len' to the server
 * to be injected onto the wire.
 *
 *---------------------------------------------------------------------------*/

int sr_send_packet(struct sr_instance* sr /* borrowed */,
                         uint8_t* buf /* borrowed */ ,
                         unsigned int len,
                         const char* iface /* borrowed */)
{
  c_packet_header *sr_pkt;
  unsigned int total_len =  len + (sizeof(c_packet_header));

  /* REQUIRES */
  assert(sr);
  assert(buf);
  assert(iface);

  /* don't waste my time ... */
  if ( len < sizeof(struct sr_ethernet_hdr) ) {
    fprintf(stderr , "** Error: packet is way too short (%d bytes)**\n", len);
    return -1;
  }

  /* Create packet */
  sr_pkt = (c_packet_header *)malloc(len + sizeof(c_packet_header));
  assert(sr_pkt);
  sr_pkt->mLen  = htonl(total_len);
  sr_pkt->mType = htonl(VNSPACKET);
  strncpy(sr_pkt->mInterfaceName,iface,16);
  memcpy(((uint8_t*)sr_pkt) + sizeof(c_packet_header), buf,len);

  /* -- log packet -- */
  sr_log_packet(sr,buf,len);

  if ( ! sr_ether_addrs_match_interface( sr, buf, iface) ) {
    fprintf( stderr, "*** Error: problem with ethernet header, check log\n");
    free ( sr_pkt );
    return -1;
  }

  if ( write(sr->sockfd, sr_pkt, total_len) < total_len ) {
    fprintf(stderr, "Error writing packet\n");
    free(sr_pkt);
    return -1;
  }

  free(sr_pkt);

  return 0;
} /* -- sr_send_packet -- */

/*-----------------------------------------------------------------------------
 * Method: sr_log_packet()
 * Scope: Local
 *
 *---------------------------------------------------------------------------*/

void sr_log_packet(struct sr_instance* sr, uint8_t* buf, int len )
{
  struct pcap_pkthdr h;
  int size;

  /* REQUIRES */
  assert(sr);

  if (!sr->logfile)
    return;

  size = min(PACKET_DUMP_SIZE, len);

  gettimeofday(&h.ts, 0);
  h.caplen = size;
  h.len = (size < PACKET_DUMP_SIZE) ? size : PACKET_DUMP_SIZE;

  sr_dump(sr->logfile, &h, buf);
  fflush(sr->logfile);
} /* -- sr_log_packet -- */

/*-----------------------------------------------------------------------------
 * Method: sr_arp_req_not_for_us()
 * Scope: Local
 *
 *---------------------------------------------------------------------------*/

int  sr_arp_req_not_for_us(struct sr_instance* sr,
                           uint8_t * packet /* lent */,
                           unsigned int len,
                           char* interface  /* lent */)
{
  struct sr_if* iface = sr_get_interface(sr, interface);
  struct sr_ethernet_hdr* e_hdr = 0;
  struct sr_arp_hdr*      a_hdr = 0;

  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr) ) {
    return 0;
  }

  assert(iface);

  e_hdr = (struct sr_ethernet_hdr*)packet;
  a_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

  if ((e_hdr->ether_type == htons(ethertype_arp)) &&
      (a_hdr->ar_op   == htons(arp_op_request))   &&
      (a_hdr->ar_tip  != iface->ip ) ) {
    return 1;
  }

  return 0;
} /* -- sr_arp_req_not_for_us -- */
