#include <deque>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <cstdint>

#include "foggy_function.h"
#include "foggy_backend.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

#define DEBUG_PRINT 1
#define debug_printf(fmt, ...)                            \
  do {                                                    \
    if (DEBUG_PRINT) fprintf(stdout, fmt, ##__VA_ARGS__); \
  } while (0)

// TCP Reno constants
#define DUP_ACK_THRESHOLD 3

// If your codebase defines PSH, you may want PSH|ACK for data packets.
// Keeping ACK_FLAG_MASK as you had for compatibility.
// #define DATA_FLAGS (ACK_FLAG_MASK | PSH_FLAG_MASK)
#define DATA_FLAGS ACK_FLAG_MASK

// Helper to get payload length from a send_window slot message consistently
static inline uint16_t slot_payload_len(const send_window_slot_t& slot) {
  // get_payload_len likely expects a uint8_t* pkt
  return get_payload_len(slot.msg);
}

/**
 * Handle new ACK - update congestion control state
 */
void handle_new_ack(foggy_socket_t *sock, uint32_t ack) {
  debug_printf("New ACK %u received, current state: %d, CWND: %u, SSTHRESH: %u\n", 
               ack, sock->window.reno_state, sock->window.congestion_window, sock->window.ssthresh);
  
  // If in fast recovery and we get a new ACK that advances, exit fast recovery
  if (sock->window.reno_state == RENO_FAST_RECOVERY) {
    debug_printf("Exiting fast recovery on new ACK\n");
    sock->window.congestion_window = sock->window.ssthresh;
    sock->window.reno_state = RENO_CONGESTION_AVOIDANCE;
    sock->window.dup_ack_count = 0;
    return;
  }
  
  // Normal congestion window updates
  switch (sock->window.reno_state) {
    case RENO_SLOW_START: {
      // Slow start: increase CWND by 1 MSS per ACK
      uint32_t prev = sock->window.congestion_window;
      sock->window.congestion_window += MSS;
      debug_printf("Slow start: CWND increased from %u to %u\n", 
                   prev, sock->window.congestion_window);
      
      // Transition to congestion avoidance when cwnd >= ssthresh
      if (sock->window.congestion_window >= sock->window.ssthresh) {
        sock->window.reno_state = RENO_CONGESTION_AVOIDANCE;
        debug_printf("Transition to congestion avoidance, CWND=%u >= SSTHRESH=%u\n",
                     sock->window.congestion_window, sock->window.ssthresh);
      }
      break;
    }
    case RENO_CONGESTION_AVOIDANCE: {
      // Congestion avoidance: cwnd += MSS*MSS / cwnd per ACK (at least 1 when cwnd < MSS)
      uint32_t cwnd = sock->window.congestion_window;
      if (cwnd < MSS) cwnd = MSS; // guard against zero increment
      uint32_t inc = (MSS * MSS) / cwnd;
      if (inc == 0) inc = 1; // make progress even with rounding
      sock->window.congestion_window += inc;
      debug_printf("Congestion avoidance: CWND increased by %u to %u\n", inc, sock->window.congestion_window);
      break;
    }
    case RENO_FAST_RECOVERY:
      // handled above
      break;
  }
}

/**
 * Handle fast retransmit on 3 duplicate ACKs
 */
void handle_fast_retransmit(foggy_socket_t *sock, uint32_t ack) {
  debug_printf("Fast retransmit triggered with ACK %u\n", ack);
  
  // Find and retransmit the first unACKed packet
  for (auto& slot : sock->send_window) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t packet_seq = get_seq(hdr);
    
    // Retransmit the oldest unACKed packet (first one we find)
    if (!has_been_acked(sock, packet_seq)) {
      debug_printf("Fast retransmit packet %u\n", packet_seq);
      sendto(sock->socket, slot.msg, get_plen(hdr), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      
      // TCP Reno fast recovery: ssthresh = max(cwnd/2, 2*MSS), cwnd = ssthresh + 3*MSS
      sock->window.ssthresh = MAX(sock->window.congestion_window / 2, 2 * MSS);
      sock->window.congestion_window = sock->window.ssthresh + 3 * MSS;
      sock->window.reno_state = RENO_FAST_RECOVERY;
      debug_printf("Enter fast recovery: SSTHRESH=%u, CWND=%u\n", 
                   sock->window.ssthresh, sock->window.congestion_window);
      break;
    }
  }
}

/**
 * Updates the socket information to represent the newly received packet.
 */
void on_recv_pkt(foggy_socket_t *sock, uint8_t *pkt) {
  debug_printf("Received packet\n");
  foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);

  // ALWAYS update advertised window from EVERY packet
  uint16_t new_advertised_window = get_advertised_window(hdr);
  if (new_advertised_window != sock->window.advertised_window) {
    debug_printf("Advertised window changed: %u -> %u\n", 
                 sock->window.advertised_window, new_advertised_window);
    sock->window.advertised_window = new_advertised_window;
  }

  if (flags & ACK_FLAG_MASK) {
    uint32_t ack = get_ack(hdr);
    debug_printf("Receive ACK %u, last_ack=%u, dup_count=%u, state=%d\n", 
                 ack, sock->window.last_ack_received, sock->window.dup_ack_count, sock->window.reno_state);

    // Handle duplicate ACKs for fast retransmit
    if (ack == sock->window.last_ack_received) {
      sock->window.dup_ack_count++;
      debug_printf("Duplicate ACK %u, count: %u\n", ack, sock->window.dup_ack_count);
      
      // Fast retransmit on 3 duplicate ACKs
      if (sock->window.dup_ack_count == DUP_ACK_THRESHOLD && sock->window.reno_state != RENO_FAST_RECOVERY) {
        debug_printf("3 duplicate ACKs detected, entering fast recovery\n");
        handle_fast_retransmit(sock, ack);
      } else if (sock->window.dup_ack_count > DUP_ACK_THRESHOLD && 
                 sock->window.reno_state == RENO_FAST_RECOVERY) {
        // In fast recovery, each additional duplicate ACK increases congestion window by MSS
        sock->window.congestion_window += MSS;
        debug_printf("Fast recovery: CWND increased to %u (extra dup ACK)\n", sock->window.congestion_window);
      }
    } else if (after(ack, sock->window.last_ack_received)) {
      // New ACK received: advances right edge of ACKed data
      debug_printf("New ACK advances: updating last_ack from %u to %u\n", 
                   sock->window.last_ack_received, ack);
      
      // Update last_ack_received BEFORE calling handle_new_ack
      sock->window.last_ack_received = ack;
      sock->window.dup_ack_count = 0;

      // If we are in fast recovery and this ACK advances, we will exit in handle_new_ack
      handle_new_ack(sock, ack);
      
      // Clean up ACKed packets and send more data
      receive_send_window(sock);
    }
    
    // ALWAYS try to send more data after processing any ACK
    transmit_send_window(sock);
  } 
  
  // Handle data packets (with payload)
  if (get_payload_len(pkt) > 0) {
    uint32_t seq = get_seq(hdr);
    uint16_t pay = get_payload_len(pkt);
    debug_printf("Received data packet %u %u\n", seq, seq + pay);
    
    // Add the packet to receive window and process receive window
    add_receive_window(sock, pkt);
    process_receive_window(sock);
    
    // Send ACK for the data packet
    debug_printf("Sending ACK packet %u\n", sock->window.next_seq_expected);

    // The window field in ACK: how much room we can accept
    uint32_t rwnd_space = MAX_NETWORK_BUFFER > sock->received_len
                            ? (MAX_NETWORK_BUFFER - (uint32_t)sock->received_len)
                            : 0;
    uint16_t rwnd_advert = (uint16_t)MIN(rwnd_space, (uint32_t)0xFFFF);

    uint8_t *ack_pkt = create_packet(
        sock->my_port, ntohs(sock->conn.sin_port),
        sock->window.last_byte_sent, sock->window.next_seq_expected,
        sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t), ACK_FLAG_MASK,
        rwnd_advert, 0,
        NULL, NULL, 0);
    sendto(sock->socket, ack_pkt, sizeof(foggy_tcp_header_t), 0,
           (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
    free(ack_pkt);
  }
}

/**
 * Send packets with flow and congestion control
 */
void send_pkts(foggy_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *data_offset = data;
  
  // First, process any ACKs we've received to free up window space
  receive_send_window(sock);
  
  if (buf_len > 0) {
    while (buf_len > 0) {
      uint16_t payload_len = (uint16_t)MIN(buf_len, (int)MSS);

      // Calculate effective window (congestion- and flow-control)
      uint32_t effective_window = MIN(sock->window.congestion_window, 
                                      sock->window.advertised_window);
      // If receiver window is zero, we cannot send (no zero-window probe in this code).
      if (effective_window == 0) {
        debug_printf("Effective window is zero, cannot send more data now\n");
        break;
      }
      
      // Calculate bytes in flight (sum of unsacked, sent payloads)
      uint32_t bytes_in_flight = 0;
      for (const auto& s : sock->send_window) {
        if (s.is_sent && !has_been_acked(sock, get_seq((foggy_tcp_header_t*)s.msg))) {
          bytes_in_flight += slot_payload_len(s);
        }
      }
      
      // Check if we have window space available
      if (bytes_in_flight >= effective_window) {
        debug_printf("Window full: in_flight=%u, effective_window=%u, cannot send more data\n",
                     bytes_in_flight, effective_window);
        break;
      }
      
      uint32_t available_space = effective_window - bytes_in_flight;
      if ((uint32_t)payload_len > available_space) {
        debug_printf("Not enough space: need %u, have %u available\n", (uint32_t)payload_len, available_space);
        break;
      }

      // Compute advertised receive window we should place in outgoing packet
      uint32_t rwnd_space = MAX_NETWORK_BUFFER > sock->received_len
                              ? (MAX_NETWORK_BUFFER - (uint32_t)sock->received_len)
                              : 0;
      uint16_t rwnd_advert = (uint16_t)MIN(rwnd_space, (uint32_t)0xFFFF);

      // Create and add packet to send window
      send_window_slot_t slot;
      slot.is_sent = 0;
      slot.is_rtt_sample = 0;
      slot.msg = create_packet( 
          sock->my_port, ntohs(sock->conn.sin_port),
          sock->window.last_byte_sent, sock->window.next_seq_expected,
          sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t) + payload_len,
          DATA_FLAGS,
          rwnd_advert, 0,
          NULL,
          data_offset, payload_len);
      sock->send_window.push_back(slot);

      buf_len -= payload_len;
      data_offset += payload_len;
      sock->window.last_byte_sent += payload_len;
      
      debug_printf("Queued packet %u len=%u, CWND=%u, RWND=%u, new_in_flight_est=%u\n", 
                   sock->window.last_byte_sent - payload_len,
                   payload_len,
                   sock->window.congestion_window, sock->window.advertised_window,
                   bytes_in_flight + payload_len);
    }
  }
  
  // Transmit any new packets we just added
  transmit_send_window(sock);
}

// KEEP ALL YOUR EXISTING FUNCTIONS EXACTLY AS THEY WERE:
void add_receive_window(foggy_socket_t *sock, uint8_t *pkt) {
  foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)pkt;
  receive_window_slot_t *cur_slot = &(sock->receive_window[0]);
  if (cur_slot->is_used == 0) {
    cur_slot->is_used = 1;
    cur_slot->msg = (uint8_t*) malloc(get_plen(hdr));
    memcpy(cur_slot->msg, pkt, get_plen(hdr));
  }
}

void process_receive_window(foggy_socket_t *sock) {
  receive_window_slot_t *cur_slot = &(sock->receive_window[0]);
  if (cur_slot->is_used != 0) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)cur_slot->msg;
    if (get_seq(hdr) != sock->window.next_seq_expected) return;
    uint16_t payload_len = get_payload_len(cur_slot->msg);
    sock->window.next_seq_expected += payload_len;
    sock->received_buf = (uint8_t*)
        realloc(sock->received_buf, sock->received_len + payload_len);
    memcpy(sock->received_buf + sock->received_len, get_payload(cur_slot->msg),
           payload_len);
    sock->received_len += payload_len;
    cur_slot->is_used = 0;
    free(cur_slot->msg);
    cur_slot->msg = NULL;
  }
}

void transmit_send_window(foggy_socket_t *sock) {
  if (sock->send_window.empty()) return;

  uint32_t effective_window = MIN(sock->window.congestion_window, 
                                  sock->window.advertised_window);

  // Calculate bytes in flight for transmission decisions
  uint32_t bytes_in_flight = 0;
  for (const auto& s : sock->send_window) {
    if (s.is_sent && !has_been_acked(sock, get_seq((foggy_tcp_header_t*)s.msg))) {
      bytes_in_flight += slot_payload_len(s);
    }
  }
  
  debug_printf("Transmit: CWND=%u, RWND=%u, effective=%u, in_flight=%u\n",
               sock->window.congestion_window, sock->window.advertised_window,
               effective_window, bytes_in_flight);

  for (auto& slot : sock->send_window) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t packet_seq = get_seq(hdr);
    
    if (!slot.is_sent) {
      uint16_t plen = slot_payload_len(slot);
      // Check if we have window space for this packet
      if (bytes_in_flight + plen <= effective_window) {
        debug_printf("Sending packet %u len=%u\n", packet_seq, plen);
        slot.is_sent = 1;
        sendto(sock->socket, slot.msg, get_plen(hdr), 0,
               (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        bytes_in_flight += plen;
      } else {
        debug_printf("Window full, cannot send packet %u\n", packet_seq);
        break;
      }
    }
  }
}

void receive_send_window(foggy_socket_t *sock) {
  while (!sock->send_window.empty()) {
    send_window_slot_t slot = sock->send_window.front();
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;

    if (!has_been_acked(sock, get_seq(hdr))) {
      break;
    }
    
    debug_printf("Removing ACKed packet %u\n", get_seq(hdr));
    sock->send_window.pop_front();
    free(slot.msg);
  }
}