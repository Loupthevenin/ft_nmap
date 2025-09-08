#include "../includes/ft_nmap.h"

static int create_ip_packet(char *buff, const char *src_ip, const char *dst_ip,
                            int proto, size_t payload_len) {
  struct ip *iph;

  iph = (struct ip *)buff;
  memset(buff, 0, 4096);
  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_ttl = 64;
  iph->ip_p = proto;
  iph->ip_len = htons(sizeof(struct ip) + payload_len);
  iph->ip_src.s_addr = inet_addr(src_ip);
  iph->ip_dst.s_addr = inet_addr(dst_ip);
  // Checksum
  iph->ip_id = htons(rand() % 65535);
  iph->ip_off = 0;
  iph->ip_sum = 0; // mettre Ã 0 avant le calcul
  iph->ip_sum = cksum((unsigned short *)buff, sizeof(struct ip));
  return (sizeof(struct ip));
}

int create_tcp_packet(char *buff, const char *src_ip, const char *dst_ip,
                      int sport, int dport, int flags) {
  struct tcphdr *tcph;
  size_t ip_size;
  int options_len;
  int payload_len;
  t_pseudo_tcp pseudo_header;

  options_len = 0;
  payload_len = 0;
  ip_size = create_ip_packet(buff, src_ip, dst_ip, IPPROTO_TCP,
                             sizeof(struct tcphdr));
  tcph = (struct tcphdr *)(buff + ip_size);
  // TCP header
  tcph->source = htons(sport);
  tcph->dest = htons(dport);
  tcph->seq = htonl(rand());
  tcph->ack_seq = 0;
  tcph->doff = (sizeof(struct tcphdr) + options_len) / 4;
  tcph->window = htons(14600);
  // Flags
  tcph->fin = (flags & TH_FIN) ? 1 : 0;
  tcph->syn = (flags & TH_SYN) ? 1 : 0;
  tcph->rst = (flags & TH_RST) ? 1 : 0;
  tcph->psh = (flags & TH_PUSH) ? 1 : 0;
  tcph->ack = (flags & TH_ACK) ? 1 : 0;
  tcph->urg = (flags & TH_URG) ? 1 : 0;
  tcph->urg_ptr = 0;
  tcph->check = 0;
  // pseudo-header
  pseudo_header.src_addr = inet_addr(src_ip);
  pseudo_header.dst_addr = inet_addr(dst_ip);
  pseudo_header.zero = 0;
  pseudo_header.protocol = IPPROTO_TCP;
  pseudo_header.tcp_length = htons(sizeof(struct tcphdr) + payload_len);
  // Calcul checksum TCP
  char tmp[sizeof(t_pseudo_tcp) + sizeof(struct tcphdr) + payload_len];
  memcpy(tmp, &pseudo_header, sizeof(t_pseudo_tcp));
  memcpy(tmp + sizeof(t_pseudo_tcp), tcph, sizeof(struct tcphdr) + payload_len);
  tcph->check = cksum((unsigned short *)tmp, sizeof(tmp));

  return (ip_size + sizeof(struct tcphdr) + options_len + payload_len);
}
