#pragma once

#include "sign_psbt.h"
#include "bitvector.h"
#include "dispatcher.h"

// Validate the entire invocation before any nonce or signature is yielded.
bool anti_exfil_preflight(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]);
