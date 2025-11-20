/* Copyright (C) 2024 Hong Kong University of Science and Technology

This repository is used for the Computer Networks (ELEC 3120) 
course taught at Hong Kong University of Science and Technology. 

No part of the project may be copied and/or distributed without 
the express permission of the course staff. Everyone is prohibited 
from releasing their forks in any public places. */

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


/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void on_recv_pkt(foggy_socket_t *sock, uint8_t *pkt) {
  debug_printf("Received packet\n");
  foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);
  
  // Track advertised window changes
  uint32_t old_adv_window = sock->window.advertised_window;
  uint32_t new_adv_window = get_advertised_window(hdr);
  if (old_adv_window != new_adv_window) {
    printf("Advertised window changed: %u -> %u\n", old_adv_window, new_adv_window);
  }

  // Check for ACK flag using bitwise AND
  if (flags & ACK_FLAG_MASK) {
    uint32_t ack = get_ack(hdr);
    uint32_t last_ack = sock->window.last_ack_received;
    uint32_t dup_count = sock->window.dup_ack_count;
    
    printf("Receive ACK %u, last_ack=%u, dup_count=%u, state=%d, CWND=%u, ssthresh=%u\n", 
           ack, last_ack, dup_count, sock->window.reno_state, 
           sock->window.congestion_window, sock->window.ssthresh);

    sock->window.advertised_window = new_adv_window;

    if (after(ack, sock->window.last_ack_received)) {
      // NEW ACK received - advance the window
      uint32_t bytes_acked = ack - sock->window.last_ack_received;
      sock->window.last_ack_received = ack;
      sock->window.dup_ack_count = 0;
      
      // TCP Reno CWND updates based on state
      if (sock->window.reno_state == RENO_SLOW_START) {
        // Slow start: CWND += MSS for each ACK (exponential growth)
        sock->window.congestion_window += MSS;
        printf("SLOW_START: CWND increased to %u\n", sock->window.congestion_window);
        
        // Transition to congestion avoidance when CWND >= ssthresh
        if (sock->window.congestion_window >= sock->window.ssthresh) {
          sock->window.reno_state = RENO_CONGESTION_AVOIDANCE;
          printf("Transition to CONGESTION_AVOIDANCE\n");
        }
      } else if (sock->window.reno_state == RENO_CONGESTION_AVOIDANCE) {
        // Congestion avoidance: CWND += MSS * MSS / CWND (linear growth)
        sock->window.congestion_window += (MSS * MSS) / sock->window.congestion_window;
        if ((MSS * MSS) % sock->window.congestion_window != 0) {
          sock->window.congestion_window++; // Round up
        }
        printf("CONGESTION_AVOIDANCE: CWND increased to %u\n", sock->window.congestion_window);
      } else if (sock->window.reno_state == RENO_FAST_RECOVERY) {
        // Exit fast recovery on new ACK
        sock->window.congestion_window = sock->window.ssthresh;
        sock->window.reno_state = RENO_CONGESTION_AVOIDANCE;
        printf("Exit FAST_RECOVERY: CWND=%u, state=CONGESTION_AVOIDANCE\n", 
               sock->window.congestion_window);
      }
    } else if (ack == sock->window.last_ack_received) {
      // DUPLICATE ACK
      sock->window.dup_ack_count++;
      printf("Duplicate ACK %u, count: %u\n", ack, sock->window.dup_ack_count);
      
      // Fast retransmit on 3rd duplicate ACK
      if (sock->window.dup_ack_count == 3) {
        printf("\n*** FAST RETRANSMIT triggered on 3 dup ACKs ***\n");
        
        // Update ssthresh = CWND / 2 (but at least 2*MSS)
        sock->window.ssthresh = MAX(sock->window.congestion_window / 2, 2 * MSS);
        
        // Set CWND = ssthresh + 3*MSS
        sock->window.congestion_window = sock->window.ssthresh + 3 * MSS;
        
        // Enter fast recovery
        sock->window.reno_state = RENO_FAST_RECOVERY;
        
        printf("Fast retransmit: ssthresh=%u, CWND=%u, state=FAST_RECOVERY\n",
               sock->window.ssthresh, sock->window.congestion_window);
        
        // Retransmit the first unacked packet
        if (!sock->send_window.empty()) {
          send_window_slot_t& slot = sock->send_window.front();
          foggy_tcp_header_t *retx_hdr = (foggy_tcp_header_t *)slot.msg;
          uint16_t payload_len = get_payload_len(slot.msg);
          
          printf("Retransmitting packet seq=%u, len=%u\n", 
                 get_seq(retx_hdr), payload_len);
          
          sendto(sock->socket, slot.msg, get_plen(retx_hdr), 0,
                 (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
          slot.is_sent = 1;
        }
      } else if (sock->window.dup_ack_count > 3 && 
                 sock->window.reno_state == RENO_FAST_RECOVERY) {
        // Inflate CWND by 1 MSS for each additional dup ACK in fast recovery
        sock->window.congestion_window += MSS;
        printf("FAST_RECOVERY: inflate CWND to %u (dup_ack=%u)\n", 
               sock->window.congestion_window, sock->window.dup_ack_count);
      }
    }
  }

  // Check for FIN flag
  if (flags & FIN_FLAG_MASK) {
    printf("Received FIN packet, flags=%u\n", flags);
    printf("Setting dying flag due to FIN\n");
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {}
    sock->dying = 1;
    pthread_mutex_unlock(&(sock->death_lock));
  }

  // Handle data packets
  if (get_payload_len(pkt) > 0) {
    debug_printf("Received data packet %d %d\n", get_seq(hdr),
                 get_seq(hdr) + get_payload_len(pkt));

    sock->window.advertised_window = new_adv_window;
    // Add the packet to receive window and process receive window
    add_receive_window(sock, pkt);
    process_receive_window(sock);
    // Send ACK
    debug_printf("Sending ACK packet %d\n", sock->window.next_seq_expected);

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
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void send_pkts(foggy_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *data_offset = data;
  transmit_send_window(sock);

  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN(buf_len, (int)MSS);

      send_window_slot_t slot;
      slot.is_sent = 0;
      slot.msg = create_packet(
          sock->my_port, ntohs(sock->conn.sin_port),
          sock->window.last_byte_sent, sock->window.next_seq_expected,
          sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t) + payload_len,
          ACK_FLAG_MASK,
          MAX(MAX_NETWORK_BUFFER - (uint32_t)sock->received_len, MSS), 0, NULL,
          data_offset, payload_len);
      sock->send_window.push_back(slot);

      buf_len -= payload_len;
      data_offset += payload_len;
      sock->window.last_byte_sent += payload_len;
    }
  }
  receive_send_window(sock);
}


void add_receive_window(foggy_socket_t *sock, uint8_t *pkt) {
  foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)pkt;
  uint32_t seq = get_seq(hdr);
  uint16_t payload_len = get_payload_len(pkt);

  // Calculate slot index based on sequence number offset from next_seq_expected
  int32_t offset = seq - sock->window.next_seq_expected;
  
  // Discard duplicate or old packets
  if (offset < 0) {
    debug_printf("Discarding old packet seq=%u (expected=%u)\n", 
                 seq, sock->window.next_seq_expected);
    return;
  }
  
  // Calculate which slot to use - slot 0 always has next expected
  int slot_index = offset / MSS;
  
  if (slot_index >= RECEIVE_WINDOW_SLOT_SIZE) {
    debug_printf("Packet seq=%u beyond receive window, discarding\n", seq);
    return;
  }
  
  receive_window_slot_t *cur_slot = &(sock->receive_window[slot_index]);
  
  // If slot already used, check if it's a duplicate
  if (cur_slot->is_used) {
    foggy_tcp_header_t *existing_hdr = (foggy_tcp_header_t *)cur_slot->msg;
    if (get_seq(existing_hdr) == seq) {
      debug_printf("Discarding duplicate packet seq=%u\n", seq);
      return;
    }
    // Shouldn't happen with correct offset calculation
    debug_printf("WARNING: Slot %d collision! existing_seq=%u, new_seq=%u\n",
                 slot_index, get_seq(existing_hdr), seq);
    return;
  }
  
  // Buffer the packet
  cur_slot->is_used = 1;
  cur_slot->msg = (uint8_t*) malloc(get_plen(hdr));
  memcpy(cur_slot->msg, pkt, get_plen(hdr));
  debug_printf("Buffered packet seq=%u in slot %d (expected=%u)\n", 
               seq, slot_index, sock->window.next_seq_expected);
}

void process_receive_window(foggy_socket_t *sock) {
  // Process consecutive in-order packets starting from slot 0
  // Slot 0 always contains next_seq_expected (if present)
  while (1) {
    receive_window_slot_t *cur_slot = &(sock->receive_window[0]);
    
    if (!cur_slot->is_used) {
      break; // No packet in slot 0
    }
    
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)cur_slot->msg;
    uint32_t seq = get_seq(hdr);
    
    // Verify this is the expected packet
    if (seq != sock->window.next_seq_expected) {
      debug_printf("ERROR: Slot 0 has seq=%u but expected=%u\n",
                   seq, sock->window.next_seq_expected);
      break;
    }
    
    // Process this packet
    uint16_t payload_len = get_payload_len(cur_slot->msg);
    sock->window.next_seq_expected += payload_len;
    
    // Copy to received_buf
    sock->received_buf = (uint8_t*)
        realloc(sock->received_buf, sock->received_len + payload_len);
    memcpy(sock->received_buf + sock->received_len, get_payload(cur_slot->msg),
           payload_len);
    sock->received_len += payload_len;
    
    debug_printf("Processed packet seq=%u, new next_seq_expected=%u\n",
                 seq, sock->window.next_seq_expected);
    
    // Free the slot
    free(cur_slot->msg);
    cur_slot->is_used = 0;
    cur_slot->msg = NULL;
    
    // Shift all slots down by one (slot 1 becomes slot 0, etc.)
    for (int i = 0; i < RECEIVE_WINDOW_SLOT_SIZE - 1; i++) {
      sock->receive_window[i] = sock->receive_window[i + 1];
    }
    // Clear the last slot
    sock->receive_window[RECEIVE_WINDOW_SLOT_SIZE - 1].is_used = 0;
    sock->receive_window[RECEIVE_WINDOW_SLOT_SIZE - 1].msg = NULL;
  }
}

void transmit_send_window(foggy_socket_t *sock) {
  if (sock->send_window.empty()) return;

  struct timespec current_time;
  clock_gettime(CLOCK_MONOTONIC, &current_time);

  // Send packets up to the effective window (min of CWND and RWND)
  uint32_t cwnd = sock->window.congestion_window;
  uint32_t rwnd = sock->window.advertised_window;
  uint32_t effective_window = (cwnd < rwnd) ? cwnd : rwnd;
  
  // Calculate bytes in flight
  uint32_t in_flight = 0;
  for (const auto& slot : sock->send_window) {
    if (slot.is_sent) {
      in_flight += get_payload_len(slot.msg);
    }
  }
  
  // Check for timeout retransmissions (RTO = 1000ms = 1 second)
  const long RTO_MS = 1000;
  bool timeout_occurred = false;
  
  for (auto& slot : sock->send_window) {
    if (slot.is_sent) {
      long elapsed_ms = (current_time.tv_sec - slot.send_time.tv_sec) * 1000 +
                        (current_time.tv_nsec - slot.send_time.tv_nsec) / 1000000;
      
      if (elapsed_ms > RTO_MS) {
        // Timeout - retransmit this packet
        foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
        uint16_t payload_len = get_payload_len(slot.msg);
        
        printf("\n*** TIMEOUT RETRANSMIT: seq=%u, elapsed=%ldms ***\n", 
               get_seq(hdr), elapsed_ms);
        
        // On timeout, reduce CWND (like Reno does on timeout)
        // But only if we haven't already reduced it recently
        if (!timeout_occurred) {
          sock->window.ssthresh = MAX(sock->window.congestion_window / 2, 2 * MSS);
          sock->window.congestion_window = MSS;  // Reset to 1 MSS
          sock->window.reno_state = RENO_SLOW_START;
          sock->window.dup_ack_count = 0;  // Reset dup ACK counter
          timeout_occurred = true;
          
          printf("Timeout: ssthresh=%u, CWND=%u, state=SLOW_START\n",
                 sock->window.ssthresh, sock->window.congestion_window);
        }
        
        sendto(sock->socket, slot.msg, get_plen(hdr), 0,
               (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        clock_gettime(CLOCK_MONOTONIC, &slot.send_time);
        
        // Only retransmit first unacked packet on timeout
        break;
      }
    }
  }
  
  // Send unsent packets while within window
  for (auto& slot : sock->send_window) {
    if (!slot.is_sent) {
      foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
      uint16_t payload_len = get_payload_len(slot.msg);
      
      if (in_flight + payload_len <= effective_window) {
        debug_printf("Sending packet %d %d\n", get_seq(hdr),
                     get_seq(hdr) + payload_len);
        slot.is_sent = 1;
        clock_gettime(CLOCK_MONOTONIC, &slot.send_time);
        sendto(sock->socket, slot.msg, get_plen(hdr), 0,
               (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        in_flight += payload_len;
      } else {
        break;  // Window is full
      }
    }
  }
}

void receive_send_window(foggy_socket_t *sock) {
  // Pop out the packets that have been ACKed
  while (1) {
    if (sock->send_window.empty()) break;

    send_window_slot_t slot = sock->send_window.front();
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;

    if (slot.is_sent == 0) {
      break;
    }
    if (has_been_acked(sock, get_seq(hdr)) == 0) {
      break;
    }
    sock->send_window.pop_front();
    free(slot.msg);
  }
}
//theo