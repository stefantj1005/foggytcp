/* Copyright (C) 2024 Hong Kong University of Science and Technology

This repository is used for the Computer Networks (ELEC 3120) 
course taught at Hong Kong University of Science and Technology. 

No part of the project may be copied and/or distributed without 
the express permission of the course staff. Everyone is prohibited 
from releasing their forks in any public places. */
 
/* This file defines the API for the Foggy TCP implementation.
 */

#ifndef FOGGY_TCP_H_
#define FOGGY_TCP_H_

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <deque>

#include "foggy_packet.h"
#include "grading.h"

using namespace std;

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

#define RECEIVE_WINDOW_SLOT_SIZE 64

typedef enum {
  RENO_SLOW_START = 0,
  RENO_CONGESTION_AVOIDANCE = 1,
  RENO_FAST_RECOVERY = 2,
} reno_state_t;

typedef struct {
  int is_sent;
  uint8_t* msg;
  int is_rtt_sample;
  struct timespec send_time;
  time_t timeout_interval;
} send_window_slot_t;

typedef struct {
  uint8_t* msg;
  int is_used;
} receive_window_slot_t;

typedef enum {
  TCP_INITIATOR = 0,
  TCP_LISTENER = 1,
} foggy_socket_type_t;

typedef struct {
  uint32_t last_byte_sent;
  uint32_t last_ack_received;
  uint32_t dup_ack_count;
  uint32_t next_seq_expected;
  uint32_t ssthresh;
  uint32_t advertised_window;
  uint32_t congestion_window;
  reno_state_t reno_state;
  pthread_mutex_t ack_lock;
} window_t;

/**
 * This structure holds the state of a socket. You may modify this structure as
 * you see fit to include any additional state you need for your implementation.
 */
struct foggy_socket_t {
  int socket;
  pthread_t thread_id;
  uint16_t my_port;
  struct sockaddr_in conn;
  uint8_t* received_buf;
  int received_len;
  pthread_mutex_t recv_lock;
  pthread_cond_t wait_cond;
  uint8_t* sending_buf;
  int sending_len;
  foggy_socket_type_t type;
  pthread_mutex_t send_lock;
  int dying;
  pthread_mutex_t death_lock;
  window_t window;

  deque<send_window_slot_t> send_window;
  receive_window_slot_t receive_window[RECEIVE_WINDOW_SLOT_SIZE];

  /* CP3 ------------------------------------------------ */
  uint32_t outstanding;          // bytes in flight
  struct timespec last_send_time; // most recent tx time
  /* ---------------------------------------------------- */
};

/*
 * DO NOT CHANGE THE DECLARATIONS BELOW
 */

typedef enum {
  NO_FLAG = 0,
  NO_WAIT,
  TIMEOUT,
} foggy_read_mode_t;

void* foggy_socket(const foggy_socket_type_t socket_type,
               const char* port, const char* server_ip);

int foggy_close(void* sock);

int foggy_read(void* sock, void* buf, const int length);

int foggy_write(void* sock, const void* buf, int length);

#endif  // FOGGY_TCP_H_

//theo