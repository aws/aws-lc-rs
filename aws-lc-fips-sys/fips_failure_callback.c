// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// Built only with the `fips-failure-callback` feature, which also compiles
// AWS-LC with AWSLC_FIPS_FAILURE_CALLBACK. AWS-LC then calls
// AWS_LC_fips_failure_callback (weakly referenced) on a FIPS self-test or
// pairwise consistency test failure instead of aborting the process. This
// definition latches the failure and keeps the first message so that the
// application can query it and stop using the module.
//
// It is linked with +whole-archive: a weak reference does not make the linker
// extract an archive member, so the definition would otherwise be dropped and
// AWS-LC would abort.

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

enum {
  FAILURE_STATE_NONE = 0,
  FAILURE_STATE_RECORDING = 1,
  FAILURE_STATE_RECORDED = 2,
};

// 16 KiB
#define FAILURE_MESSAGE_CAPACITY 16384

static atomic_int g_failure_state = FAILURE_STATE_NONE;
static char g_failure_message[FAILURE_MESSAGE_CAPACITY];

void AWS_LC_fips_failure_callback(const char *message) {
  int expected = FAILURE_STATE_NONE;
  if (atomic_compare_exchange_strong(&g_failure_state, &expected,
                                     FAILURE_STATE_RECORDING)) {
    // The last byte stays zero, so the copy is always NUL-terminated.
    strncpy(g_failure_message, message != NULL ? message : "(null)",
            FAILURE_MESSAGE_CAPACITY - 1);
    atomic_store(&g_failure_state, FAILURE_STATE_RECORDED);
  }
  fprintf(stderr, "AWS-LC FIPS failure caused by:\n%s\n",
          message != NULL ? message : "(null)");
  fflush(stderr);
}

int aws_lc_fips_sys_failure_detected(void) {
  return atomic_load(&g_failure_state) != FAILURE_STATE_NONE;
}

const char *aws_lc_fips_sys_failure_message(void) {
  if (atomic_load(&g_failure_state) != FAILURE_STATE_RECORDED) {
    return NULL;
  }
  return g_failure_message;
}
