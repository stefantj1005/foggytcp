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
#define INITIAL_SSTHRESH 10000  // Start with a reasonable ssthresh

/**
 * Handle new ACK - update congestion control state
 */
void handle_new_ack(foggy_socket_t *sock, uint32_t ack) {
  debug_printf("New ACK %d received, current state: %d, CWND: %d, SSTHRESH: %d\n", 
               ack, sock->window.reno_state, sock->window.congestion_window, sock->window.ssthresh);
  
  // If in fast recovery and we get a new ACK, exit fast recovery
  if (sock->window.reno_state == RENO_FAST_RECOVERY) {
    debug_printf("Exiting fast recovery on new ACK\n");
    sock->window.congestion_window = sock->window.ssthresh;
    sock->window.reno_state = RENO_CONGESTION_AVOIDANCE;
    sock->window.dup_ack_count = 0;
    return;
  }
  
  // Normal congestion window updates
  switch (sock->window.reno_state) {
    case RENO_SLOW_START:
      // Slow start: increase CWND by 1 MSS per ACK
      sock->window.congestion_window += MSS;
      debug_printf("Slow start: CWND increased from %d to %d\n", 
                   sock->window.congestion_window - MSS, sock->window.congestion_window);
      
      // Check if we should transition to congestion avoidance
      if (sock->window.congestion_window >= sock->window.ssthresh) {
        sock->window.reno_state = RENO_CONGESTION_AVOIDANCE;
        debug_printf("Transition to congestion avoidance, CWND=%d >= SSTHRESH=%d\n",
                     sock->window.congestion_window, sock->window.ssthresh);
      }
      break;
      
    case RENO_CONGESTION_AVOIDANCE:
      // Congestion avoidance: increase CWND by (MSS * MSS) / CWND per ACK
      sock->window.congestion_window += (MSS * MSS) / sock->window.congestion_window;
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
  
  // FIXED: Proper congestion control response to loss
  sock->window.ssthresh = MAX(sock->window.congestion_window / 2, 2 * MSS);
  // FIXED: Set cwnd to ssthresh (NOT ssthresh + 3*MSS) - this is the key fix!
  sock->window.congestion_window = sock->window.ssthresh;
  sock->window.reno_state = RENO_FAST_RECOVERY;
  
  debug_printf("CONGESTION: SSTHRESH=%d, CWND=%d (reduced due to loss)\n", 
               sock->window.ssthresh, sock->window.congestion_window);
  
  // Find and retransmit the first unACKed packet
  for (auto& slot : sock->send_window) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t packet_seq = get_seq(hdr);
    
    if (!has_been_acked(sock, packet_seq)) {
      debug_printf("Fast retransmit packet %d\n", packet_seq);
      sendto(sock->socket, slot.msg, get_plen(hdr), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
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

  // Initialize ssthresh if not set
  if (sock->window.ssthresh == 0) {
    sock->window.ssthresh = INITIAL_SSTHRESH;
  }

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
      
      // Fast retransmit on 3 duplicate ACKs
      if (sock->window.dup_ack_count == DUP_ACK_THRESHOLD && sock->window.reno_state != RENO_FAST_RECOVERY) {
        debug_printf("3 duplicate ACKs detected, entering fast recovery\n");
        handle_fast_retransmit(sock, ack);
      } else if (sock->window.dup_ack_count > DUP_ACK_THRESHOLD && 
                 sock->window.reno_state == RENO_FAST_RECOVERY) {
        // In fast recovery, each additional duplicate ACK increases congestion window
        sock->window.congestion_window += MSS;
        debug_printf("Fast recovery: CWND increased to %d\n", sock->window.congestion_window);
      }
    } else if (after(ack, sock->window.last_ack_received)) {
      // New ACK received
      debug_printf("New ACK received, updating last_ack from %d to %d\n", 
                   sock->window.last_ack_received, ack);
      
      // Update last_ack_received BEFORE calling handle_new_ack
      sock->window.last_ack_received = ack;
      sock->window.dup_ack_count = 0;
      
      handle_new_ack(sock, ack);
      
      // Clean up ACKed packets and send more data
      receive_send_window(sock);
    }
    
    // ALWAYS try to send more data after processing any ACK
    transmit_send_window(sock);
  } 
  
  // Handle data packets (with payload)
  if (get_payload_len(pkt) > 0) {
    debug_printf("Received data packet %d %d\n", get_seq(hdr),
                 get_seq(hdr) + get_payload_len(pkt));
    
    // Add the packet to receive window and process receive window
    add_receive_window(sock, pkt);
    process_receive_window(sock);
    
    // Send ACK for the data packet
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

// ... REST OF YOUR FUNCTIONS REMAIN EXACTLY THE SAME ...
// (send_pkts, add_receive_window, process_receive_window, transmit_send_window, receive_send_window)