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

  switch (flags) {
    case ACK_FLAG_MASK: {
      uint32_t ack = get_ack(hdr);
      printf("Receive ACK %d\n", ack);

      // Extract advertised window from ACK packet
      sock->window.advertised_window = get_advertised_window(hdr);

      // Handle congestion control for new ACKs
      if (after(ack, sock->window.last_ack_received)) {
        // New ACK - handle congestion window update
        handle_congestion_window(sock, pkt);
        sock->window.last_ack_received = ack;
        sock->window.dup_ack_count = 0; // Reset duplicate ACK counter
      } else if (ack == sock->window.last_ack_received) {
        // Duplicate ACK
        sock->window.dup_ack_count++;
        if (sock->window.dup_ack_count == 3) {
          // Triple duplicate ACK - trigger fast retransmit
          handle_fast_retransmit(sock);
        }
      }
      break;
    }

    default: {
      if (get_payload_len(pkt) > 0) {
        debug_printf("Received data packet %d %d\n", get_seq(hdr),
                     get_seq(hdr) + get_payload_len(pkt));
        
        // Add the packet to receive window and process receive window
        add_receive_window(sock, pkt);
        process_receive_window(sock);
        
        // Send ACK with updated advertised window
        debug_printf("Sending ACK packet %d\n", sock->window.next_seq_expected);

        uint8_t *ack_pkt = create_packet(
            sock->my_port, ntohs(sock->conn.sin_port),
            sock->window.last_byte_sent, sock->window.next_seq_expected,
            sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t), ACK_FLAG_MASK,
            sock->window.advertised_window, 0,  // Use the calculated advertised window from process_receive_window
            NULL, NULL, 0);
        sendto(sock->socket, ack_pkt, sizeof(foggy_tcp_header_t), 0,
               (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        free(ack_pkt);
      }
      break;
    }
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
  
  // First, process any ACKs we've received to free up window space
  receive_send_window(sock);
  
  // If we have data to send, break it into packets and add to send window
  if (buf_len > 0) {
    while (buf_len != 0) {
      // Calculate how much data we can send based on window limits
      uint32_t effective_window = MIN(sock->window.congestion_window, 
                                      sock->window.advertised_window);
      uint32_t bytes_in_flight = sock->window.last_byte_sent - sock->window.last_ack_received;
      
      // If window is full, stop creating new packets
      if (bytes_in_flight >= effective_window) {
        break;
      }
      
      uint16_t payload_len = MIN(buf_len, (int)MSS);
      
      // Create packet and add to send window
      send_window_slot_t slot;
      slot.is_sent = 0;
      slot.is_rtt_sample = 0;  // You might want to set this for some packets for RTT measurement
      slot.msg = create_packet(
          sock->my_port, ntohs(sock->conn.sin_port),
          sock->window.last_byte_sent, sock->window.next_seq_expected,
          sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t) + payload_len,
          ACK_FLAG_MASK,
          MAX(MAX_NETWORK_BUFFER - (uint32_t)sock->received_len, MSS), 0, NULL,
          data_offset, payload_len);
      
      sock->send_window.push_back(slot);

      // Update counters
      buf_len -= payload_len;
      data_offset += payload_len;
      sock->window.last_byte_sent += payload_len;
      
      // For RTT measurement, you might want to record send_time here
      // clock_gettime(CLOCK_MONOTONIC, &slot.send_time);
    }
  }
  
  // Now transmit as many packets as the window allows
  transmit_send_window(sock);
}


void add_receive_window(foggy_socket_t *sock, uint8_t *pkt) {
  foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)pkt;
  uint32_t seq_num = get_seq(hdr);
  
  // Check if packet is within our window
  uint32_t window_start = sock->window.next_seq_expected;
  uint32_t window_end = sock->window.next_seq_expected + MAX_NETWORK_BUFFER;
  
  // If packet is outside our window, discard it
  if (before(seq_num, window_start) || after(seq_num, window_end)) {
    debug_printf("Packet %d outside receive window [%d, %d]\n", 
                 seq_num, window_start, window_end);
    return;
  }
  
  // Calculate slot index based on sequence number
  uint32_t slot_index = (seq_num - window_start) / MSS;
  if (slot_index >= RECEIVE_WINDOW_SLOT_SIZE) {
    debug_printf("No available slot for packet %d\n", seq_num);
    return;
  }
  
  receive_window_slot_t *slot = &sock->receive_window[slot_index];
  
  // If slot is empty, store the packet
  if (!slot->is_used) {
    slot->is_used = 1;
    slot->msg = (uint8_t*) malloc(get_plen(hdr));
    memcpy(slot->msg, pkt, get_plen(hdr));
    debug_printf("Stored packet %d in slot %d\n", seq_num, slot_index);
  } else {
    debug_printf("Slot %d already occupied, discarding duplicate packet %d\n", 
                 slot_index, seq_num);
  }
}

void process_receive_window(foggy_socket_t *sock) {
  bool processed_any;
  
  do {
    processed_any = false;
    
    // Process all consecutive packets starting from next_seq_expected
    for (int i = 0; i < RECEIVE_WINDOW_SLOT_SIZE; i++) {
      receive_window_slot_t *slot = &sock->receive_window[i];
      
      if (slot->is_used) {
        foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot->msg;
        uint32_t seq_num = get_seq(hdr);
        
        // If this is exactly the next packet we expect
        if (seq_num == sock->window.next_seq_expected) {
          uint16_t payload_len = get_payload_len(slot->msg);
          
          debug_printf("Processing packet %d, payload %d bytes\n", 
                       seq_num, payload_len);
          
          // Copy payload to receive buffer
          sock->received_buf = (uint8_t*)realloc(sock->received_buf, 
                                                 sock->received_len + payload_len);
          memcpy(sock->received_buf + sock->received_len, 
                 get_payload(slot->msg), payload_len);
          sock->received_len += payload_len;
          
          // Update next expected sequence number
          sock->window.next_seq_expected += payload_len;
          
          // Free the slot
          free(slot->msg);
          slot->msg = NULL;
          slot->is_used = 0;
          
          processed_any = true;
          debug_printf("Advanced window to %d\n", sock->window.next_seq_expected);
          
          // Break to restart from the beginning since window moved
          break;
        } else if (after(seq_num, sock->window.next_seq_expected)) {
          // Found a gap, stop processing until we get the missing packet
          break;
        }
        // If before next_seq_expected, it's a duplicate - ignore and continue
      } else {
        // Empty slot found - if this is where we expect data, we have a gap
        uint32_t expected_seq_for_slot = sock->window.next_seq_expected + (i * MSS);
        if (before(expected_seq_for_slot, sock->window.next_seq_expected + MAX_NETWORK_BUFFER)) {
          // We have a gap, stop processing
          break;
        }
      }
    }
  } while (processed_any); // Continue while we're successfully moving the window
  
  // Update advertised window based on available buffer space
  uint32_t used_buffer = sock->received_len;
  uint32_t available_buffer = MAX_NETWORK_BUFFER - used_buffer;
  sock->window.advertised_window = available_buffer;
  
  debug_printf("Receive window: used=%d, available=%d, next_expected=%d\n",
               used_buffer, available_buffer, sock->window.next_seq_expected);
}

void transmit_send_window(foggy_socket_t *sock) {
  if (sock->send_window.empty()) return;

  // Calculate effective window and available space
  uint32_t effective_window = MIN(sock->window.congestion_window, sock->window.advertised_window);
  uint32_t bytes_in_flight = sock->window.last_byte_sent - sock->window.last_ack_received;
  uint32_t available_window = (effective_window > bytes_in_flight) ? 
                              (effective_window - bytes_in_flight) : 0;
  
  // Send as many unsent packets as the window allows
  for (auto& slot : sock->send_window) {
    if (available_window <= 0) break;
    
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t packet_size = get_payload_len(slot.msg);
    
    if (!slot.is_sent && packet_size <= available_window) {
      // Send this packet
      debug_printf("Sending packet %d %d\n", get_seq(hdr),
                   get_seq(hdr) + packet_size);
      slot.is_sent = 1;
      sendto(sock->socket, slot.msg, get_plen(hdr), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      available_window -= packet_size;
    }
  }
}

void receive_send_window(foggy_socket_t *sock) {
  // Pop out the packets that have been ACKed
  while (!sock->send_window.empty()) {
    send_window_slot_t slot = sock->send_window.front();
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;

    if (!has_been_acked(sock, get_seq(hdr))) {
      break;  // Stop at first non-ACKed packet
    }
    
    sock->send_window.pop_front();
    free(slot.msg);
  }
}
/*
// Congestion control placeholder functions - you need to implement these
void handle_congestion_window(foggy_socket_t *sock, uint8_t *pkt) {
  // TODO: Implement TCP Reno congestion control
  // Update cwnd based on current state (slow start, congestion avoidance)
  // This function is called when a new ACK is received
}

void handle_fast_retransmit(foggy_socket_t *sock) {
  // TODO: Implement fast retransmit
  // This function is called when 3 duplicate ACKs are received
  // Should retransmit the lost packet and adjust congestion control state
}
*/