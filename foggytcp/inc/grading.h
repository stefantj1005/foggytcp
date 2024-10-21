/* Copyright (C) 2024 Hong Kong University of Science and Technology

This repository is used for the Computer Networks (ELEC 3120) 
course taught at Hong Kong University of Science and Technology. 

No part of the project may be copied and/or distributed without 
the express permission of the course staff. Everyone is prohibited 
from releasing their forks in any public places. */
 
 /* This files defines constants used for grading. Do NOT modify this file as
 * any changes will be overwritten by the autograder.
 */

#ifndef PROJECT_1_ELEC3120_INC_GRADING_H_
#define PROJECT_1_ELEC3120_INC_GRADING_H_

/*
 * DO NOT CHANGE THIS FILE
 * This contains the variables for your TCP implementation
 * and we will replace this file during the autolab testing with new variables.
 */

// packet lengths
#define MAX_LEN 1400

// window variables
#define WINDOW_INITIAL_WINDOW_SIZE MSS
#define WINDOW_INITIAL_SSTHRESH (MSS * 64)
#define WINDOW_INITIAL_RTT 3000  // ms
#define WINDOW_INITIAL_ADVERTISED MSS

// Max TCP Buffer
#define MAX_NETWORK_BUFFER 65535  // (2^16 - 1) bytes

#endif  // PROJECT_1_ELEC3120_INC_GRADING_H_
