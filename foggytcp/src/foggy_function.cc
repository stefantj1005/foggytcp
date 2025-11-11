#include <deque>
#include <cstdlib>
#include <cstring>
#include <cstdio>

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

/**
 * Handle new ACK - update congestion control state
 */
void handle_new_ack(foggy_socket_t *sock, uint32_t ack) {
  debug_printf("New ACK %d received, current state: %d, CWND: %d, SSTHRESH: %d\n", 
               ack, sock->window.reno_state, sock->window.congestion_window, sock->window.ssthresh);
  
  // If in fast recovery and we get a new ACK beyond recovery point, exit fast recovery
  if (sock->window.reno_state == RENO_FAST_RECOVERY) {
    debug_printf("Exiting fast recovery on new ACK\n");
    sock->window.congestion_window = sock->window.ssthresh;
    sock->window.reno_state = RENO_CONGESTION_AVOIDANCE;
    return;
  }
  
  // Normal congestion window updates
  switch (sock->window.reno_state) {
    case RENO_SLOW_START:
      // Slow start: increase CWND by 1 MSS per ACK
      sock->window.congestion_window += MSS;
      debug_printf("Slow start: CWND increased to %d\n", sock->window.congestion_window);
      
      // Check if we should transition to congestion avoidance
      if (sock->window.congestion_window >= sock->window.ssthresh) {
        sock->window.reno_state = RENO_CONGESTION_AVOIDANCE;
        debug_printf("Transition to congestion avoidance, CWND=%d >= SSTHRESH=%d\n",
                     sock->window.congestion_window, sock->window.ssthresh);
      }
      break;
      
    case RENO_CONGESTION_AVOIDANCE:
      // Congestion avoidance: increase CWND by (MSS * MSS) / CWND per ACK
      // This gives roughly MSS increase per RTT
      sock->window.congestion_window += MAX((MSS * MSS) / sock->window.congestion_window, 1);
      debug_printf("Congestion avoidance: CWND increased to %d\n", sock->window.congestion_window);
      break;
      
    case RENO_FAST_RECOVERY:
      // Should be handled above
      break;
  }
}

/**
 * Handle fast retransmit on 3 duplicate ACKs
 */
void handle_fast_retransmit(foggy_socket_t *sock, uint32_t ack) {
  debug_printf("Fast retransmit triggered with ACK %d\n", ack);
  
  // Find the first unACKed packet and retransmit it
  for (auto& slot : sock->send_window) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t packet_seq = get_seq(hdr);
    
    // Retransmit the oldest unACKed packet (first one we find)
    if (!has_been_acked(sock, packet_seq)) {
      debug_printf("Fast retransmit packet seq=%d\n", packet_seq);
      sendto(sock->socket, slot.msg, get_plen(hdr), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      
      // TCP Reno: Set ssthresh to max(cwnd/2, 2*MSS) and cwnd to ssthresh + 3*MSS
      sock->window.ssthresh = MAX(sock->window.congestion_window / 2, 2 * MSS);
      sock->window.congestion_window = sock->window.ssthresh + 3 * MSS;
      sock->window.reno_state = RENO_FAST_RECOVERY;
      
      debug_printf("Fast recovery: SSTHRESH=%d, CWND=%d\n", 
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
    debug_printf("Advertised window changed: %d -> %d\n", 
                 sock->window.advertised_window, new_advertised_window);
    sock->window.advertised_window = new_advertised_window;
  }

  if (flags == ACK_FLAG_MASK) {
    uint32_t ack = get_ack(hdr);
    debug_printf("Receive ACK %d, last_ack=%d, dup_count=%d, state=%d\n", 
                 ack, sock->window.last_ack_received, sock->window.dup_ack_count, sock->window.reno_state);

    // Handle duplicate ACKs for fast retransmit
    if (ack == sock->window.last_ack_received) {
      sock->window.dup_ack_count++;
      debug_printf("Duplicate ACK %d, count: %d\n", ack, sock->window.dup_ack_count);
      
      // Fast retransmit on 3 duplicate ACKs (only if not already in fast recovery)
      if (sock->window.dup_ack_count == DUP_ACK_THRESHOLD && 
          sock->window.reno_state != RENO_FAST_RECOVERY) {
        debug_printf("3 duplicate ACKs detected, entering fast recovery\n");
        handle_fast_retransmit(sock, ack);
      } else if (sock->window.dup_ack_count > DUP_ACK_THRESHOLD && 
                 sock->window.reno_state == RENO_FAST_RECOVERY) {
        // In fast recovery, each additional duplicate ACK increases congestion window
        sock->window.congestion_window += MSS;
        debug_printf("Fast recovery: additional dup ACK, CWND increased to %d\n", 
                     sock->window.congestion_window);
      }
    } else if (after(ack, sock->window.last_ack_received)) {
      // New ACK received
      debug_printf("New ACK received, updating last_ack from %d to %d\n", 
                   sock->window.last_ack_received, ack);
      
      // Reset duplicate ACK count
      sock->window.dup_ack_count = 0;
      
      // Update last_ack_received BEFORE calling handle_new_ack
      sock->window.last_ack_received = ack;
      
      handle_new_ack(sock, ack);
      
      // Clean up ACKed packets
      receive_send_window(sock);
    }
    
    // ALWAYS try to send more data after processing any ACK
    transmit_send_window(sock);
  } 
  
  // Handle data packets (with payload)
  if (get_payload_len(pkt) > 0) {
    debug_printf("Received data packet seq=%d, len=%d\n", get_seq(hdr), get_payload_len(pkt));
    
    // Add the packet to receive window
    add_receive_window(sock, pkt);
    
    // Process receive window to deliver in-order data
    process_receive_window(sock);
    
    // Send ACK for the data packet with updated advertised window
    debug_printf("Sending ACK for seq=%d\n", sock->window.next_seq_expected);

    uint32_t available_space = MAX_NETWORK_BUFFER > sock->received_len ? 
                               MAX_NETWORK_BUFFER - sock->received_len : 0;
    uint16_t adv_window = MAX(available_space, MSS);
    
    uint8_t *ack_pkt = create_packet(
        sock->my_port, ntohs(sock->conn.sin_port),
        sock->window.last_byte_sent, sock->window.next_seq_expected,
        sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t), ACK_FLAG_MASK,
        adv_window, 0, NULL, NULL, 0);
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
    while (buf_len != 0) {
      uint16_t payload_len = MIN(buf_len, (int)MSS);

      // Calculate available window space considering both congestion and flow control
      uint32_t effective_window = MIN(sock->window.congestion_window, 
                                     sock->window.advertised_window);
      
      // Calculate bytes in flight
      uint32_t bytes_in_flight = 0;
      for (const auto& slot : sock->send_window) {
        foggy_tcp_header_t *slot_hdr = (foggy_tcp_header_t*)slot.msg;
        uint32_t slot_seq = get_seq(slot_hdr);
        if (slot.is_sent && !has_been_acked(sock, slot_seq)) {
          bytes_in_flight += get_payload_len(slot.msg);
        }
      }
      
      // Check if we have window space available
      if (bytes_in_flight >= effective_window) {
        debug_printf("Window full: in_flight=%d, effective_window=%d, cannot send more data\n",
                     bytes_in_flight, effective_window);
        break;
      }
      
      uint32_t available_space = effective_window - bytes_in_flight;
      if (payload_len > available_space) {
        debug_printf("Not enough space: need %d, have %d available\n", payload_len, available_space);
        break;
      }

      // Create and add packet to send window
      send_window_slot_t slot;
      slot.is_sent = 0;
      slot.is_rtt_sample = 0;
      
      // Calculate advertised window for this packet
      uint32_t available_recv_space = MAX_NETWORK_BUFFER > sock->received_len ? 
                                      MAX_NETWORK_BUFFER - sock->received_len : 0;
      uint16_t adv_window = MAX(available_recv_space, MSS);
      
      slot.msg = create_packet( 
          sock->my_port, ntohs(sock->conn.sin_port),
          sock->window.last_byte_sent, sock->window.next_seq_expected,
          sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t) + payload_len,
          ACK_FLAG_MASK, adv_window, 0, NULL,
          data_offset, payload_len);
      sock->send_window.push_back(slot);

      buf_len -= payload_len;
      data_offset += payload_len;
      sock->window.last_byte_sent += payload_len;
      
      debug_printf("Added packet seq=%d (len=%d) to send window, CWND=%d, RWND=%d, in_flight=%d\n", 
                   sock->window.last_byte_sent - payload_len, payload_len,
                   sock->window.congestion_window, sock->window.advertised_window,
                   bytes_in_flight);
    }
  }
  
  // Transmit any new packets we just added
  transmit_send_window(sock);
}

void add_receive_window(foggy_socket_t *sock, uint8_t *pkt) {
  foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)pkt;
  uint32_t seq = get_seq(hdr);
  uint16_t payload_len = get_payload_len(pkt);
  
  // Check if this is the next expected packet
  if (seq == sock->window.next_seq_expected) {
    // In-order packet - put it in slot 0
    receive_window_slot_t *cur_slot = &(sock->receive_window[0]);
    if (cur_slot->is_used == 0) {
      cur_slot->is_used = 1;
      cur_slot->msg = (uint8_t*) malloc(get_plen(hdr));
      memcpy(cur_slot->msg, pkt, get_plen(hdr));
      debug_printf("Added in-order packet seq=%d to receive window slot 0\n", seq);
    }
  } else if (after(seq, sock->window.next_seq_expected)) {
    // Out-of-order packet - try to store it in other slots
    debug_printf("Out-of-order packet seq=%d (expected %d)\n", seq, sock->window.next_seq_expected);
    
    // Look for an empty slot or update existing slot
    for (int i = 1; i < WINDOW_SIZE; i++) {
      receive_window_slot_t *slot = &(sock->receive_window[i]);
      
      if (!slot->is_used) {
        // Found empty slot
        slot->is_used = 1;
        slot->msg = (uint8_t*) malloc(get_plen(hdr));
        memcpy(slot->msg, pkt, get_plen(hdr));
        debug_printf("Stored out-of-order packet seq=%d in slot %d\n", seq, i);
        break;
      } else {
        // Check if this is a duplicate
        foggy_tcp_header_t *slot_hdr = (foggy_tcp_header_t *)slot->msg;
        if (get_seq(slot_hdr) == seq) {
          debug_printf("Duplicate out-of-order packet seq=%d ignored\n", seq);
          break;
        }
      }
    }
  }
}

void process_receive_window(foggy_socket_t *sock) {
  // Process slot 0 if it has the next expected packet
  receive_window_slot_t *cur_slot = &(sock->receive_window[0]);
  
  while (cur_slot->is_used != 0) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)cur_slot->msg;
    uint32_t seq = get_seq(hdr);
    
    if (seq != sock->window.next_seq_expected) {
      debug_printf("Slot 0 packet seq=%d doesn't match expected %d\n", 
                   seq, sock->window.next_seq_expected);
      break;
    }
    
    uint16_t payload_len = get_payload_len(cur_slot->msg);
    debug_printf("Processing in-order packet seq=%d, len=%d\n", seq, payload_len);
    
    sock->window.next_seq_expected += payload_len;
    sock->received_buf = (uint8_t*)
        realloc(sock->received_buf, sock->received_len + payload_len);
    memcpy(sock->received_buf + sock->received_len, get_payload(cur_slot->msg),
           payload_len);
    sock->received_len += payload_len;
    
    cur_slot->is_used = 0;
    free(cur_slot->msg);
    cur_slot->msg = NULL;
    
    // Check if any out-of-order packet is now in order
    int found = 0;
    for (int i = 1; i < WINDOW_SIZE; i++) {
      receive_window_slot_t *slot = &(sock->receive_window[i]);
      if (slot->is_used) {
        foggy_tcp_header_t *slot_hdr = (foggy_tcp_header_t *)slot->msg;
        if (get_seq(slot_hdr) == sock->window.next_seq_expected) {
          // Move this packet to slot 0
          cur_slot->is_used = 1;
          cur_slot->msg = slot->msg;
          slot->is_used = 0;
          slot->msg = NULL;
          debug_printf("Moved out-of-order packet seq=%d from slot %d to slot 0\n", 
                       get_seq(slot_hdr), i);
          found = 1;
          break;
        }
      }
    }
    
    if (!found) break;
  }
}

void transmit_send_window(foggy_socket_t *sock) {
  if (sock->send_window.empty()) return;

  uint32_t effective_window = MIN(sock->window.congestion_window, 
                                 sock->window.advertised_window);

  // Calculate bytes in flight for transmission decisions
  uint32_t bytes_in_flight = 0;
  for (const auto& slot : sock->send_window) {
    foggy_tcp_header_t *slot_hdr = (foggy_tcp_header_t*)slot.msg;
    uint32_t slot_seq = get_seq(slot_hdr);
    if (slot.is_sent && !has_been_acked(sock, slot_seq)) {
      bytes_in_flight += get_payload_len(slot.msg);
    }
  }
  
  debug_printf("Transmit: CWND=%d, RWND=%d, effective=%d, in_flight=%d\n",
               sock->window.congestion_window, sock->window.advertised_window,
               effective_window, bytes_in_flight);

  for (auto& slot : sock->send_window) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t packet_seq = get_seq(hdr);
    
    if (!slot.is_sent) {
      uint16_t pkt_payload_len = get_payload_len(slot.msg);
      
      // Check if we have window space for this packet
      if (bytes_in_flight + pkt_payload_len <= effective_window) {
        debug_printf("Sending packet seq=%d, len=%d\n", packet_seq, pkt_payload_len);
        slot.is_sent = 1;
        sendto(sock->socket, slot.msg, get_plen(hdr), 0,
               (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        bytes_in_flight += pkt_payload_len;
      } else {
        debug_printf("Window full, cannot send packet seq=%d (need %d, have %d available)\n", 
                     packet_seq, pkt_payload_len, effective_window - bytes_in_flight);
        break;
      }
    }
  }
}

void receive_send_window(foggy_socket_t *sock) {
  while (!sock->send_window.empty()) {
    send_window_slot_t slot = sock->send_window.front();
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t seq = get_seq(hdr);

    if (!has_been_acked(sock, seq)) {
      break;
    }
    
    debug_printf("Removing ACKed packet seq=%d\n", seq);
    sock->send_window.pop_front();
    free(slot.msg);
  }
}