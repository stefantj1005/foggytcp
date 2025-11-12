#include <deque>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <sys/time.h>

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
#define INITIAL_RTO_MS 1000
#define MIN_RTO_MS 200
#define MAX_RTO_MS 60000
#define RTO_ALPHA 0.125
#define RTO_BETA 0.25

// Extended send window slot with timeout tracking
struct send_window_slot_extended_t {
  uint8_t is_sent;
  uint8_t is_rtt_sample;
  uint8_t *msg;
  struct timeval send_time;
  int retransmit_count;
};

// Buffer for data that couldn't be sent due to window constraints
struct pending_data_t {
  uint8_t *data;
  size_t len;
  size_t offset;
};

static pending_data_t pending_buffer = {NULL, 0, 0};
static std::deque<send_window_slot_extended_t> extended_send_window;
static int current_rto_ms = INITIAL_RTO_MS;
static int srtt_ms = 0;
static int rttvar_ms = 0;
static bool rtt_initialized = false;

/**
 * Get current time in milliseconds
 */
static long get_time_ms(struct timeval *tv) {
  return tv->tv_sec * 1000 + tv->tv_usec / 1000;
}

/**
 * Update RTO based on RTT sample
 */
static void update_rto(int rtt_ms) {
  if (!rtt_initialized) {
    srtt_ms = rtt_ms;
    rttvar_ms = rtt_ms / 2;
    rtt_initialized = true;
  } else {
    rttvar_ms = (int)((1 - RTO_BETA) * rttvar_ms + RTO_BETA * abs(srtt_ms - rtt_ms));
    srtt_ms = (int)((1 - RTO_ALPHA) * srtt_ms + RTO_ALPHA * rtt_ms);
  }
  
  current_rto_ms = srtt_ms + MAX(1, 4 * rttvar_ms);
  current_rto_ms = MAX(MIN_RTO_MS, MIN(current_rto_ms, MAX_RTO_MS));
  
  debug_printf("RTT sample: %d ms, SRTT: %d ms, RTTVAR: %d ms, RTO: %d ms\n",
               rtt_ms, srtt_ms, rttvar_ms, current_rto_ms);
}

/**
 * Handle new ACK - update congestion control state
 */
void handle_new_ack(foggy_socket_t *sock, uint32_t ack) {
  debug_printf("New ACK %d received, current state: %d, CWND: %d, SSTHRESH: %d\n", 
               ack, sock->window.reno_state, sock->window.congestion_window, sock->window.ssthresh);
  
  // Calculate RTT for packets being ACKed
  struct timeval now;
  gettimeofday(&now, NULL);
  
  for (auto& slot : extended_send_window) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t packet_seq = get_seq(hdr);
    uint32_t packet_end = packet_seq + get_payload_len(slot.msg);
    
    // If this packet is being ACKed and we can use it for RTT sample
    if (slot.is_rtt_sample && slot.retransmit_count == 0 && 
        after(ack, packet_seq) && !after(ack, packet_end)) {
      long rtt_ms = get_time_ms(&now) - get_time_ms(&slot.send_time);
      if (rtt_ms > 0) {
        update_rto((int)rtt_ms);
      }
      slot.is_rtt_sample = 0;  // Only use once
      break;
    }
  }
  
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
      sock->window.congestion_window += (MSS * MSS) / sock->window.congestion_window;
      debug_printf("Congestion avoidance: CWND increased to %d\n", sock->window.congestion_window);
      break;
      
    case RENO_FAST_RECOVERY:
      // Should be handled above
      break;
  }
}

/**
 * Handle timeout - retransmit and reset congestion control
 */
void handle_timeout(foggy_socket_t *sock, send_window_slot_extended_t &slot) {
  foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
  uint32_t packet_seq = get_seq(hdr);
  
  debug_printf("TIMEOUT on packet %d (retransmit #%d)\n", packet_seq, slot.retransmit_count + 1);
  
  // Retransmit the packet
  sendto(sock->socket, slot.msg, get_plen(hdr), 0,
         (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
  
  // Update timestamp and retransmit count
  gettimeofday(&slot.send_time, NULL);
  slot.retransmit_count++;
  slot.is_rtt_sample = 0;  // Can't use retransmitted packets for RTT
  
  // On timeout, reset congestion control to slow start
  sock->window.ssthresh = MAX(sock->window.congestion_window / 2, 2 * MSS);
  sock->window.congestion_window = MSS;
  sock->window.reno_state = RENO_SLOW_START;
  sock->window.dup_ack_count = 0;
  
  // Exponential backoff on RTO
  current_rto_ms = MIN(current_rto_ms * 2, MAX_RTO_MS);
  
  debug_printf("Timeout recovery: SSTHRESH=%d, CWND=%d, RTO=%d ms\n", 
               sock->window.ssthresh, sock->window.congestion_window, current_rto_ms);
}

/**
 * Check for timeouts and retransmit if necessary
 */
void check_timeouts(foggy_socket_t *sock) {
  struct timeval now;
  gettimeofday(&now, NULL);
  long now_ms = get_time_ms(&now);
  
  for (auto& slot : extended_send_window) {
    if (slot.is_sent && !has_been_acked(sock, get_seq((foggy_tcp_header_t*)slot.msg))) {
      long elapsed_ms = now_ms - get_time_ms(&slot.send_time);
      
      if (elapsed_ms > current_rto_ms) {
        handle_timeout(sock, slot);
        // Only handle one timeout per check to avoid overwhelming the network
        break;
      }
    }
  }
}

/**
 * Handle fast retransmit on 3 duplicate ACKs
 */
void handle_fast_retransmit(foggy_socket_t *sock, uint32_t ack) {
  debug_printf("Fast retransmit triggered with ACK %d\n", ack);
  
  // Find the first unACKed packet and retransmit it
  for (auto& slot : extended_send_window) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t packet_seq = get_seq(hdr);
    
    // Retransmit the oldest unACKed packet (first one we find)
    if (!has_been_acked(sock, packet_seq)) {
      debug_printf("Fast retransmit packet %d\n", packet_seq);
      sendto(sock->socket, slot.msg, get_plen(hdr), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      
      // Update timestamp but don't use for RTT
      gettimeofday(&slot.send_time, NULL);
      slot.retransmit_count++;
      slot.is_rtt_sample = 0;
      
      // CORRECT TCP RENO: Set ssthresh to max(cwnd/2, 2*MSS) and cwnd to ssthresh + 3*MSS
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
    
    // Check for timeouts
    check_timeouts(sock);
    
    // ALWAYS try to send more data after processing any ACK
    transmit_send_window(sock);
    
    // Try to send pending buffered data if window opened up
    if (pending_buffer.data != NULL && pending_buffer.offset < pending_buffer.len) {
      debug_printf("Attempting to send pending buffered data\n");
      size_t remaining = pending_buffer.len - pending_buffer.offset;
      send_pkts(sock, pending_buffer.data + pending_buffer.offset, remaining);
    }
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
      for (const auto& slot : extended_send_window) {
        if (slot.is_sent && !has_been_acked(sock, get_seq((foggy_tcp_header_t*)slot.msg))) {
          bytes_in_flight += get_payload_len(slot.msg);
        }
      }
      
      // Check if we have window space available
      if (bytes_in_flight >= effective_window) {
        debug_printf("Window full: in_flight=%d, effective_window=%d, buffering remaining data\n",
                     bytes_in_flight, effective_window);
        
        // Buffer the remaining data for later transmission
        size_t remaining = buf_len;
        if (pending_buffer.data == NULL) {
          pending_buffer.data = (uint8_t*)malloc(remaining);
          pending_buffer.len = remaining;
          pending_buffer.offset = 0;
          memcpy(pending_buffer.data, data_offset, remaining);
        } else {
          // Append to existing buffer
          size_t old_len = pending_buffer.len;
          pending_buffer.data = (uint8_t*)realloc(pending_buffer.data, old_len + remaining);
          memcpy(pending_buffer.data + old_len, data_offset, remaining);
          pending_buffer.len = old_len + remaining;
        }
        
        debug_printf("Buffered %zu bytes of pending data\n", remaining);
        break;
      }
      
      uint32_t available_space = effective_window - bytes_in_flight;
      if (payload_len > available_space) {
        debug_printf("Not enough space: need %d, have %d available, buffering data\n", 
                     payload_len, available_space);
        
        // Buffer this data
        size_t remaining = buf_len;
        if (pending_buffer.data == NULL) {
          pending_buffer.data = (uint8_t*)malloc(remaining);
          pending_buffer.len = remaining;
          pending_buffer.offset = 0;
          memcpy(pending_buffer.data, data_offset, remaining);
        } else {
          size_t old_len = pending_buffer.len;
          pending_buffer.data = (uint8_t*)realloc(pending_buffer.data, old_len + remaining);
          memcpy(pending_buffer.data + old_len, data_offset, remaining);
          pending_buffer.len = old_len + remaining;
        }
        break;
      }

      // Create and add packet to send window
      send_window_slot_extended_t slot;
      slot.is_sent = 0;
      slot.is_rtt_sample = 1;  // Mark for RTT sampling
      slot.retransmit_count = 0;
      gettimeofday(&slot.send_time, NULL);
      slot.msg = create_packet( 
          sock->my_port, ntohs(sock->conn.sin_port),
          sock->window.last_byte_sent, sock->window.next_seq_expected,
          sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t) + payload_len,
          ACK_FLAG_MASK,
          MAX(MAX_NETWORK_BUFFER - (uint32_t)sock->received_len, MSS), 0, NULL,
          data_offset, payload_len);
      extended_send_window.push_back(slot);

      buf_len -= payload_len;
      data_offset += payload_len;
      sock->window.last_byte_sent += payload_len;
      
      // Update pending buffer offset if we're sending from it
      if (pending_buffer.data != NULL && data >= pending_buffer.data && 
          data < pending_buffer.data + pending_buffer.len) {
        pending_buffer.offset += payload_len;
        
        // Free buffer if we've sent everything
        if (pending_buffer.offset >= pending_buffer.len) {
          free(pending_buffer.data);
          pending_buffer.data = NULL;
          pending_buffer.len = 0;
          pending_buffer.offset = 0;
        }
      }
      
      debug_printf("Added packet %d to send window, CWND=%d, RWND=%d, in_flight=%d\n", 
                   sock->window.last_byte_sent - payload_len,
                   sock->window.congestion_window, sock->window.advertised_window,
                   bytes_in_flight + payload_len);
    }
  }
  
  // Transmit any new packets we just added
  transmit_send_window(sock);
}

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
  if (extended_send_window.empty()) return;

  uint32_t effective_window = MIN(sock->window.congestion_window, 
                                 sock->window.advertised_window);

  // Calculate bytes in flight for transmission decisions
  uint32_t bytes_in_flight = 0;
  for (const auto& slot : extended_send_window) {
    if (slot.is_sent && !has_been_acked(sock, get_seq((foggy_tcp_header_t*)slot.msg))) {
      bytes_in_flight += get_payload_len(slot.msg);
    }
  }
  
  debug_printf("Transmit: CWND=%d, RWND=%d, effective=%d, in_flight=%d\n",
               sock->window.congestion_window, sock->window.advertised_window,
               effective_window, bytes_in_flight);

  for (auto& slot : extended_send_window) {
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;
    uint32_t packet_seq = get_seq(hdr);
    
    if (!slot.is_sent) {
      // Check if we have window space for this packet
      if (bytes_in_flight + get_payload_len(slot.msg) <= effective_window) {
        debug_printf("Sending packet %d\n", packet_seq);
        slot.is_sent = 1;
        gettimeofday(&slot.send_time, NULL);
        sendto(sock->socket, slot.msg, get_plen(hdr), 0,
               (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        bytes_in_flight += get_payload_len(slot.msg);
      } else {
        debug_printf("Window full, cannot send packet %d\n", packet_seq);
        break;
      }
    }
  }
}

void receive_send_window(foggy_socket_t *sock) {
  while (!extended_send_window.empty()) {
    send_window_slot_extended_t slot = extended_send_window.front();
    foggy_tcp_header_t *hdr = (foggy_tcp_header_t *)slot.msg;

    if (!has_been_acked(sock, get_seq(hdr))) {
      break;
    }
    
    debug_printf("Removing ACKed packet %d\n", get_seq(hdr));
    extended_send_window.pop_front();
    free(slot.msg);
  }
}