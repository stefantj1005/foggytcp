#include <deque>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <algorithm>

#include "foggy_function.h"
#include "foggy_backend.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

#define DEBUG_PRINT 1
#define debug_printf(fmt, ...) \
  do { if (DEBUG_PRINT) fprintf(stdout, fmt, ##__VA_ARGS__); } while (0)

#define DUP_ACK_THRESHOLD 3

// Helper structure for out-of-order receive buffering
struct recv_buffer_slot {
  uint8_t *msg;
  uint32_t seq;
  uint16_t len;
};

std::vector<recv_buffer_slot> recv_buffer;

void handle_timeout(foggy_socket_t *sock) {
  debug_printf("Timeout occurred! Reducing CWND and retransmitting\n");

  // Set SSTHRESH to max(cwnd/2, 2*MSS)
  sock->window.ssthresh = MAX(sock->window.congestion_window / 2, 2 * MSS);
  sock->window.congestion_window = MSS; // Restart with one MSS
  sock->window.reno_state = RENO_SLOW_START;
  sock->window.dup_ack_count = 0;

  // Retransmit the first unACKed packet
  for (auto& slot : sock->send_window) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t seq = get_seq(hdr);
    if (!has_been_acked(sock, seq)) {
      debug_printf("Timeout retransmit packet %d\n", seq);
      sendto(sock->socket, slot.msg, get_plen(hdr), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      break;
    }
  }
}

void handle_new_ack(foggy_socket_t *sock, uint32_t ack) {
  debug_printf("New ACK %d received, state: %d, CWND: %d, SSTHRESH: %d\n",
               ack, sock->window.reno_state, sock->window.congestion_window, sock->window.ssthresh);

  if (sock->window.reno_state == RENO_FAST_RECOVERY) {
    debug_printf("Exiting fast recovery\n");
    sock->window.congestion_window = sock->window.ssthresh;
    sock->window.reno_state = RENO_CONGESTION_AVOIDANCE;
    sock->window.dup_ack_count = 0;
    return;
  }

  switch (sock->window.reno_state) {
    case RENO_SLOW_START:
      sock->window.congestion_window += MSS;
      debug_printf("Slow start: CWND increased to %d\n", sock->window.congestion_window);
      if (sock->window.congestion_window >= sock->window.ssthresh) {
        sock->window.reno_state = RENO_CONGESTION_AVOIDANCE;
        debug_printf("Transition to congestion avoidance\n");
      }
      break;

    case RENO_CONGESTION_AVOIDANCE:
      sock->window.congestion_window += (MSS * MSS) / sock->window.congestion_window;
      debug_printf("Congestion avoidance: CWND increased to %d\n", sock->window.congestion_window);
      break;

    default:
      break;
  }
}

void handle_fast_retransmit(foggy_socket_t *sock, uint32_t ack) {
  debug_printf("Entering fast retransmit\n");

  for (auto& slot : sock->send_window) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t seq = get_seq(hdr);
    if (!has_been_acked(sock, seq)) {
      sendto(sock->socket, slot.msg, get_plen(hdr), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));

      sock->window.ssthresh = MAX(sock->window.congestion_window / 2, 2 * MSS);
      sock->window.congestion_window = sock->window.ssthresh + 3 * MSS;
      sock->window.reno_state = RENO_FAST_RECOVERY;

      debug_printf("Fast recovery: SSTHRESH=%d, CWND=%d\n",
                   sock->window.ssthresh, sock->window.congestion_window);
      break;
    }
  }
}

void add_receive_window(foggy_socket_t *sock, uint8_t *pkt) {
  foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)pkt;
  uint32_t seq = get_seq(hdr);
  uint16_t len = get_payload_len(pkt);

  for (auto& slot : recv_buffer) {
    if (slot.seq == seq) return; // already buffered
  }

  recv_buffer_slot slot;
  slot.seq = seq;
  slot.len = len;
  slot.msg = (uint8_t *)malloc(get_plen(hdr));
  memcpy(slot.msg, pkt, get_plen(hdr));
  recv_buffer.push_back(slot);
}

void process_receive_window(foggy_socket_t *sock) {
  bool updated = true;
  while (updated) {
    updated = false;
    for (auto it = recv_buffer.begin(); it != recv_buffer.end(); ++it) {
      foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)it->msg;
      if (get_seq(hdr) == sock->window.next_seq_expected) {
        uint16_t len = get_payload_len(it->msg);
        sock->received_buf = (uint8_t *)realloc(sock->received_buf, sock->received_len + len);
        memcpy(sock->received_buf + sock->received_len, get_payload(it->msg), len);
        sock->received_len += len;
        sock->window.next_seq_expected += len;
        free(it->msg);
        recv_buffer.erase(it);
        updated = true;
        break;
      }
    }
  }
}

void on_recv_pkt(foggy_socket_t *sock, uint8_t *pkt) {
  foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);
  uint16_t new_rwnd = get_advertised_window(hdr);

  if (new_rwnd != sock->window.advertised_window) {
    sock->window.advertised_window = new_rwnd;
  }

  if (flags == ACK_FLAG_MASK) {
    uint32_t ack = get_ack(hdr);
    if (ack == sock->window.last_ack_received) {
      sock->window.dup_ack_count++;
      if (sock->window.dup_ack_count == DUP_ACK_THRESHOLD &&
          sock->window.reno_state != RENO_FAST_RECOVERY) {
        handle_fast_retransmit(sock, ack);
      } else if (sock->window.dup_ack_count > DUP_ACK_THRESHOLD &&
                 sock->window.reno_state == RENO_FAST_RECOVERY) {
        sock->window.congestion_window += MSS;
      }
    } else if (after(ack, sock->window.last_ack_received)) {
      sock->window.last_ack_received = ack;
      sock->window.dup_ack_count = 0;
      handle_new_ack(sock, ack);
      receive_send_window(sock);
    }
    transmit_send_window(sock);
  }

  if (get_payload_len(pkt) > 0) {
    add_receive_window(sock, pkt);
    process_receive_window(sock);

    uint8_t *ack_pkt = create_packet(
        sock->my_port, ntohs(sock->conn.sin_port),
        sock->window.last_byte_sent, sock->window.next_seq_expected,
        sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t), ACK_FLAG_MASK,
        MAX(MAX_NETWORK_BUFFER - (uint32_t)sock->received_len, MSS), 0,
        NULL, NULL, 0);
    sendto(sock->socket, ack_pkt, sizeof(foggy_tcp_header_t), 0,
           (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
    free(ack_pkt);
  }

  if (flags != ACK_FLAG_MASK) {
    transmit_send_window(sock);
  }
}

void send_pkts(foggy_socket_t *sock, uint8_t *data, int buf_len) {
  if (sock->window.ssthresh == 0) {
    sock->window.ssthresh = 65535;
  }

  receive_send_window(sock);

  uint8_t *ptr = data;

  while (buf_len > 0) {
    uint16_t len = MIN(buf_len, MSS);
    uint32_t cwnd = sock->window.congestion_window;
    uint32_t rwnd = sock->window.advertised_window;

    uint32_t in_flight = 0;
    for (auto& slot : sock->send_window) {
      if (slot.is_sent && !has_been_acked(sock, get_seq((foggy_tcp_header_t*)slot.msg))) {
        in_flight += get_payload_len(slot.msg);
      }
    }

    uint32_t avail = MIN(cwnd, rwnd);
    if (in_flight + len > avail) break;

    send_window_slot_t slot;
    slot.is_sent = 0;
    slot.is_rtt_sample = 0;
    slot.msg = create_packet(sock->my_port, ntohs(sock->conn.sin_port),
                             sock->window.last_byte_sent,
                             sock->window.next_seq_expected,
                             sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t) + len,
                             ACK_FLAG_MASK,
                             MAX(MAX_NETWORK_BUFFER - sock->received_len, MSS), 0,
                             NULL, ptr, len);
    sock->send_window.push_back(slot);

    sock->window.last_byte_sent += len;
    ptr += len;
    buf_len -= len;
  }

  transmit_send_window(sock);
}

void transmit_send_window(foggy_socket_t *sock) {
  if (sock->send_window.empty()) return;

  uint32_t cwnd = sock->window.congestion_window;
  uint32_t rwnd = sock->window.advertised_window;
  uint32_t avail = MIN(cwnd, rwnd);

  uint32_t in_flight = 0;
  for (auto& slot : sock->send_window) {
    if (slot.is_sent && !has_been_acked(sock, get_seq((foggy_tcp_header_t*)slot.msg))) {
      in_flight += get_payload_len(slot.msg);
    }
  }

  for (auto& slot : sock->send_window) {
    if (!slot.is_sent) {
      uint32_t len = get_payload_len(slot.msg);
      if (in_flight + len <= avail) {
        sendto(sock->socket, slot.msg, get_plen((foggy_tcp_header_t*)slot.msg), 0,
               (struct sockaddr*)&(sock->conn), sizeof(sock->conn));
        slot.is_sent = 1;
        in_flight += len;
      } else {
        break;
      }
    }
  }
}

void receive_send_window(foggy_socket_t *sock) {
  while (!sock->send_window.empty()) {
    send_window_slot_t slot = sock->send_window.front();
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    if (!has_been_acked(sock, get_seq(hdr))) break;
    sock->send_window.pop_front();
    free(slot.msg);
  }
}