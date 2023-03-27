// Copyright (c) 2022, Google Inc.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include "rust_wrapper.h"


int ERR_GET_LIB_RUST(uint32_t packed_error) {
  return ERR_GET_LIB(packed_error);
}

int ERR_GET_REASON_RUST(uint32_t packed_error) {
  return ERR_GET_REASON(packed_error);
}

int ERR_GET_FUNC_RUST(uint32_t packed_error) {
  return ERR_GET_FUNC(packed_error);
}
