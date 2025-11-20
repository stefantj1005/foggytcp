/* Copyright (C) 2024 Hong Kong University of Science and Technology

This repository is used for the Computer Networks (ELEC 3120) 
course taught at Hong Kong University of Science and Technology. 

No part of the project may be copied and/or distributed without 
the express permission of the course staff. Everyone is prohibited 
from releasing their forks in any public places. */
 
 /*
 * This file implements the high-level API for foggy-TCP sockets.
 */

#include "foggy_tcp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <iostream>

#include "foggy_backend.h"

#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

/* CP3 ------------------------------------------------ */
static uint64_t now_ms() {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000ULL + t.tv_nsec / 1000000ULL;
}
/* ---------------------------------------------------- */

void* foggy_socket(const foggy_socket_type_t socket_type,
               const char *server_port, const char *server_ip) {
  foggy_socket_t* sock = new foggy_socket_t;
  int sockfd, optval;
  socklen_t len;
  struct sockaddr_in conn, my_addr;
  len = sizeof(my_addr);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("ERROR opening socket");
    return NULL;
  }
  sock->socket = sockfd;
  sock->received_buf = NULL;
  sock->received_len = 0;
  pthread_mutex_init(&(sock->recv_lock), NULL);

  sock->sending_buf = NULL;
  sock->sending_len = 0;
  pthread_mutex_init(&(sock->send_lock), NULL);

  sock->type = socket_type;
  sock->dying = 0;
  pthread_mutex_init(&(sock->death_lock), NULL);

  sock->window.last_byte_sent = 0;
  sock->window.last_ack_received = 0;
  sock->window.dup_ack_count = 0;
  sock->window.next_seq_expected = 0;
  sock->window.ssthresh = WINDOW_INITIAL_SSTHRESH;
  sock->window.advertised_window = WINDOW_INITIAL_ADVERTISED;
  sock->window.congestion_window = WINDOW_INITIAL_WINDOW_SIZE;
  sock->window.reno_state = RENO_SLOW_START;
  pthread_mutex_init(&(sock->window.ack_lock), NULL);

  for (int i = 0; i < RECEIVE_WINDOW_SLOT_SIZE; ++i) {
    sock->receive_window[i].is_used = 0;
    sock->receive_window[i].msg = NULL;
  }

  if (pthread_cond_init(&sock->wait_cond, NULL) != 0) {
    perror("ERROR condition variable not set\n");
    return NULL;
  }

  /* CP3 ------------------------------------------------ */
  sock->outstanding = 0;
  clock_gettime(CLOCK_MONOTONIC, &sock->last_send_time);
  /* ---------------------------------------------------- */

  uint16_t portno = (uint16_t)atoi(server_port);
  switch (socket_type) {
    case TCP_INITIATOR:
      if (server_ip == NULL) {
        perror("ERROR server_ip NULL");
        return NULL;
      }
      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = inet_addr(server_ip);
      conn.sin_port = htons(portno);
      sock->conn = conn;

      my_addr.sin_family = AF_INET;
      my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      my_addr.sin_port = 0;
      if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0) {
        perror("ERROR on binding");
        return NULL;
      }
      break;

    case TCP_LISTENER:
      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = inet_addr(server_ip);
      conn.sin_port = htons(portno);

      optval = 1;
      setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
                 sizeof(int));
      if (bind(sockfd, (struct sockaddr *)&conn, sizeof(conn)) < 0) {
        perror("ERROR on binding");
        return NULL;
      }
      sock->conn = conn;
      break;

    default:
      perror("Unknown Flag");
      return NULL;
  }
  getsockname(sockfd, (struct sockaddr *)&my_addr, &len);
  sock->my_port = ntohs(my_addr.sin_port);
  /* Log socket info for debugging to a workspace file so we can inspect from the VM */
  {
    FILE *f = fopen("/vagrant/foggytcp/debug.log", "a");
    if (f) {
      char addr_str[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(sock->conn.sin_addr), addr_str, sizeof(addr_str));
      fprintf(f, "foggy_socket: type=%d conn=%s:%d my_port=%d\n", sock->type,
              addr_str, ntohs(sock->conn.sin_port), sock->my_port);
      fclose(f);
    }
  }

  {
    int rc = pthread_create(&(sock->thread_id), NULL, begin_backend, (void *)sock);
    /* Log thread creation result */
    FILE *f = fopen("/vagrant/foggytcp/debug.log", "a");
    if (f) {
      if (rc == 0)
        fprintf(f, "foggy_socket: backend thread created successfully for sock=%p\n", (void*)sock);
      else
        fprintf(f, "foggy_socket: backend pthread_create failed rc=%d for sock=%p\n", rc, (void*)sock);
      fclose(f);
    }
  }
  return (void*)sock;
}

int foggy_close(void *in_sock) {
  struct foggy_socket_t *sock = (struct foggy_socket_t *)in_sock;
  
  const char* role = (sock->type == TCP_INITIATOR) ? "CLIENT" : "SERVER";
  
  // Wait for all data to be sent and ACKed before closing
  std::cerr << role << " foggy_close: Waiting for data to be transmitted...\n";
  
  // Add initial state check
  int initial_sending_len = 0;
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {}
  initial_sending_len = sock->sending_len;
  pthread_mutex_unlock(&(sock->send_lock));
  std::cerr << role << " foggy_close: Initial state - sending_len=" << initial_sending_len 
            << ", send_window.size=" << sock->send_window.size() << "\n";
  
  // For TCP_LISTENER (server), skip waiting if no initial data
  bool skip_wait = (sock->type == TCP_LISTENER && initial_sending_len == 0 && sock->send_window.empty());
  if (skip_wait) {
    std::cerr << role << " foggy_close: No data to send (receiver)\n";
  }
  
  int wait_count = 0;
  bool had_data = false;
  
  if (!skip_wait) {
  
  while (wait_count < 30000) {  // 30000 * 10ms = 300 seconds = 5 minutes for large files
    int sending_len = 0;
    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {}
    sending_len = sock->sending_len;
    pthread_mutex_unlock(&(sock->send_lock));
    
    bool send_window_empty = sock->send_window.empty();
    
    // Track if we ever had data to send
    if (sending_len > 0 || !send_window_empty) {
      had_data = true;
    }
    
    // Exit if we had data AND both buffers are now empty
    if (had_data && sending_len == 0 && send_window_empty) {
      std::cerr << role << " foggy_close: All data transmitted and ACKed\n";
      break;
    }
    
    // If no data after initial wait, exit (receiver side with no data to send)
    if (!had_data && wait_count > 5) {
      std::cerr << role << " foggy_close: No data to send (wait_count=" << wait_count << ")\n";
      break;
    }
    
    if (sending_len > 0 || !send_window_empty) {
      std::cerr << role << " foggy_close: sending_len=" << sending_len 
                << ", send_window.size=" << sock->send_window.size() << "\n";
    }
    
    usleep(10000); // 10ms
    wait_count++;
  }
  
  if (wait_count >= 30000) {
    std::cerr << role << " foggy_close: WARNING - timeout waiting for data to be sent (had_data=" 
              << had_data << ")\n";
  }
  } // end if (!skip_wait)
  
  // Send a FIN packet to signal connection close
  std::cerr << role << " foggy_close: Sending FIN packet (my_port=" << sock->my_port 
            << ", dst_port=" << ntohs(sock->conn.sin_port) << ")\n";
  uint32_t adv_win = MAX_NETWORK_BUFFER - (uint32_t)sock->received_len;
  if (adv_win < MSS) adv_win = MSS;
  uint8_t *fin_pkt = create_packet(
      sock->my_port, ntohs(sock->conn.sin_port),
      sock->window.last_byte_sent, sock->window.next_seq_expected,
      sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t), FIN_FLAG_MASK | ACK_FLAG_MASK,
      adv_win, 0,
      NULL, NULL, 0);
  if (fin_pkt == NULL) {
    std::cerr << role << " foggy_close: ERROR - create_packet returned NULL!\n";
  } else {
    int sendto_result = sendto(sock->socket, fin_pkt, sizeof(foggy_tcp_header_t), 0,
           (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
    std::cerr << role << " foggy_close: FIN sendto result=" << sendto_result << " errno=" << errno << "\n";
    free(fin_pkt);
  }
  
  while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
  }
  sock->dying = 1;
  pthread_mutex_unlock(&(sock->death_lock));

  pthread_join(sock->thread_id, NULL);

  if (sock != NULL) {
    if (sock->received_buf != NULL) {
      free(sock->received_buf);
    }
    if (sock->sending_buf != NULL) {
      free(sock->sending_buf);
    }
  } else {
    perror("ERROR null socket\n");
    return EXIT_ERROR;
  }
  return close(sock->socket);
}

int foggy_read(void* in_sock, void *buf, int length) {
  struct foggy_socket_t *sock = (struct foggy_socket_t *)in_sock;  
  uint8_t *new_buf;
  int read_len = 0;

  if (length < 0) {
    perror("ERROR negative length");
    return EXIT_ERROR;
  }

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }

  // Wait for data or EOF signal
  while (sock->received_len == 0) {
    pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
  }
  
  // Check for EOF signal (-1)
  if (sock->received_len == -1) {
    pthread_mutex_unlock(&(sock->recv_lock));
    return 0;  // Return 0 to signal EOF
  }
  
  if (sock->received_len > 0) {
    if (sock->received_len > length)
      read_len = length;
    else
      read_len = sock->received_len;

    memcpy(buf, sock->received_buf, read_len);
    if (read_len < sock->received_len) {
      new_buf = (uint8_t*) malloc(sock->received_len - read_len);
      memcpy(new_buf, sock->received_buf + read_len,
              sock->received_len - read_len);
      free(sock->received_buf);
      sock->received_len -= read_len;
      sock->received_buf = new_buf;
    } else {
      free(sock->received_buf);
      sock->received_buf = NULL;
      sock->received_len = 0;
    }
    
    // Send window update ACK after reading data to free up receive buffer
    uint32_t new_adv_window = MAX(MAX_NETWORK_BUFFER - (uint32_t)sock->received_len, MSS);
    uint8_t *win_update_pkt = create_packet(
        sock->my_port, ntohs(sock->conn.sin_port),
        sock->window.last_byte_sent, sock->window.next_seq_expected,
        sizeof(foggy_tcp_header_t), sizeof(foggy_tcp_header_t), ACK_FLAG_MASK,
        new_adv_window, 0,
        NULL, NULL, 0);
    if (win_update_pkt != NULL) {
      sendto(sock->socket, win_update_pkt, sizeof(foggy_tcp_header_t), 0,
             (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      free(win_update_pkt);
    }
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return read_len;
}

int foggy_write(void *in_sock, const void *buf, int length) {
  struct foggy_socket_t *sock = (struct foggy_socket_t *)in_sock;
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
  if (sock->sending_buf == NULL)
    sock->sending_buf = (uint8_t*) malloc(length);
  else
    sock->sending_buf = (uint8_t*) realloc(sock->sending_buf, length + sock->sending_len);
  memcpy(sock->sending_buf + sock->sending_len, buf, length);
  sock->sending_len += length;

  /* Also append a persistent log entry so we can see when data is queued */
  {
    FILE *f = fopen("/vagrant/foggytcp/debug.log", "a");
    if (f) {
      fprintf(f, "foggy_write: queued %d bytes, total queued=%d\n", length, sock->sending_len);
      fclose(f);
    }
  }

  pthread_mutex_unlock(&(sock->send_lock));
  return EXIT_SUCCESS;
}