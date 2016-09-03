/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_H_
#define RR_H_

/**
 * rr tracees can write data to a special fd that they want verified across
 * record/replay.  When it's written in recording, rr saves the data.  During
 * replay, the data are checked against the recorded data.  This fd is obtained
 * by calling SYS_rrcall_open_magic_save_fd with no arguments.
 *
 * Tracees using this interface should take care that the buffers
 * storing the data are either not racy, or are synchronized by the
 * tracee.
 *
 * To simplify things, we make this a valid fd opened to /dev/null during
 * recording.
 *
 * Tracees may close this fd, or dup() something over it, etc. If that happens,
 * it will lose its magical properties.
 */
#define SYS_rrcall_open_magic_save_fd 447

#endif /* RR_H_ */
