#include "anti_exfil_preflight.h"

#include <string.h>

#include "anti_exfil.h"
#include "amount_from_psbt.h"
#include "crypto.h"
#include "secp256k1.h"
#include "get_merkleized_map.h"
#include "get_merkleized_map_value.h"
#include "psbt.h"
#include "psbt_fields.h"
#include "sw.h"

typedef struct {
    uint8_t fields;
    uint8_t pubkey[32];
    bool invalid;
    bool signed_or_finalized;
    bool unsupported;
} fields_t;

static void keys_callback(dispatcher_context_t *dc,
                          void *state,
                          const merkleized_map_commitment_t *map,
                          int index,
                          buffer_t *data) {
    (void) dc;
    (void) map;
    (void) index;
    fields_t *fields = state;
    const uint8_t *key = data->ptr + data->offset;
    size_t len = data->size - data->offset;
    uint8_t subtype, pubkey[32];
    anti_exfil_key_status_t status = anti_exfil_parse_key(key, len, &subtype, pubkey);
    if (status == ANTI_EXFIL_KEY_INVALID) fields->invalid = true;
    if (status == ANTI_EXFIL_KEY_VALID) {
        if (fields->fields != 0 && memcmp(fields->pubkey, pubkey, 32) != 0) {
            fields->invalid = true;
        }
        fields->fields |= 1u << subtype;
        memcpy(fields->pubkey, pubkey, 32);
    }
    if (len > 0) {
        switch (key[0]) {
            case PSBT_IN_TAP_KEY_SIG:
            case PSBT_IN_TAP_SCRIPT_SIG:
            case PSBT_IN_FINAL_SCRIPTSIG:
            case PSBT_IN_FINAL_SCRIPTWITNESS:
                fields->signed_or_finalized = true;
                break;
            case PSBT_IN_REDEEM_SCRIPT:
            case PSBT_IN_WITNESS_SCRIPT:
            case PSBT_IN_TAP_LEAF_SCRIPT:
            case PSBT_IN_MUSIG2_PUB_NONCE:
            case PSBT_IN_MUSIG2_PARTIAL_SIG:
                fields->unsupported = true;
                break;
        }
    }
}

static bool validate_target(dispatcher_context_t *dc,
                            const merkleized_map_commitment_t *map,
                            const fields_t *fields) {
    uint64_t amount;
    uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    size_t script_len;
    uint32_t sighash = SIGHASH_DEFAULT;
    psbt_field_status_t status = psbt_get_input_sighash_type(dc, map, &sighash);
    if (status == PSBT_FIELD_ERROR ||
        (status == PSBT_FIELD_PRESENT && sighash != SIGHASH_DEFAULT && sighash != SIGHASH_ALL) ||
        get_amount_scriptpubkey_from_psbt_witness(dc, map, &amount, script, &script_len) < 0 ||
        script_len != 34 || script[0] != 0x51 || script[1] != 0x20 ||
        memcmp(script + 2, fields->pubkey, 32) != 0) {
        return false;
    }

    uint8_t key[37] = {0xfc, 2, 'a', 'e', 0};
    memcpy(key + 5, fields->pubkey, 32);
    uint8_t commitment[32], nonce[33], entropy[32];
    if (call_get_merkleized_map_value(dc, map, key, sizeof(key), commitment, 32) != 32) {
        return false;
    }
    if (fields->fields == 7) {
        key[4] = 1;
        if (call_get_merkleized_map_value(dc, map, key, sizeof(key), nonce, 33) != 33) return false;
        key[4] = 2;
        if (call_get_merkleized_map_value(dc, map, key, sizeof(key), entropy, 32) != 32)
            return false;
        // Reject malformed points, scalars and openings during preflight as well.
        uint8_t point[65], computed_commitment[32];
        if ((nonce[0] != 2 && nonce[0] != 3) || crypto_get_uncompressed_pubkey(nonce, point) < 0 ||
            is_array_all_zeros(entropy, 32) || memcmp(entropy, secp256k1_n, 32) >= 0) {
            return false;
        }
        static const uint8_t host_tag[] = "BIP-EXFIL/host";
        crypto_tr_tagged_hash(host_tag,
                              sizeof(host_tag) - 1,
                              entropy,
                              32,
                              NULL,
                              0,
                              computed_commitment);
        if (memcmp(commitment, computed_commitment, 32) != 0) return false;
    }
    return true;
}

bool anti_exfil_preflight(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    // Ordinary preprocessing has already enumerated every key in every map.
    if (!st->has_anti_exfil_fields) return true;

    fields_t fields = {0};
    if (call_check_merkleized_map_sorted_with_callback(dc,
                                                       &st->global_map,
                                                       &fields,
                                                       keys_callback) < 0 ||
        fields.invalid || fields.fields != 0)
        goto invalid;

    for (unsigned int i = 0; i < st->n_outputs; i++) {
        merkleized_map_commitment_t map;
        memset(&fields, 0, sizeof(fields));
        if (call_get_merkleized_map_with_callback(dc,
                                                  &fields,
                                                  st->outputs_root,
                                                  st->n_outputs,
                                                  i,
                                                  keys_callback,
                                                  &map) < 0 ||
            fields.invalid || fields.fields != 0)
            goto invalid;
    }

    for (unsigned int i = 0; i < st->n_inputs; i++) {
        merkleized_map_commitment_t map;
        memset(&fields, 0, sizeof(fields));
        if (call_get_merkleized_map_with_callback(dc,
                                                  &fields,
                                                  st->inputs_root,
                                                  st->n_inputs,
                                                  i,
                                                  keys_callback,
                                                  &map) < 0 ||
            fields.invalid)
            goto invalid;
        if (fields.fields == 0) continue;
        if ((fields.fields != 1 && fields.fields != 7) || fields.signed_or_finalized ||
            fields.unsupported || !bitvector_get(internal_inputs, i) || st->protocol_version < 1 ||
            st->account.policy_map->type != TOKEN_TR ||
            ((policy_node_tr_t *) st->account.policy_map)->key->type != KEY_EXPRESSION_NORMAL ||
            (st->anti_exfil_round != 0 && st->anti_exfil_round != fields.fields) ||
            !validate_target(dc, &map, &fields))
            goto invalid;
        st->anti_exfil_round = fields.fields;
        bitvector_set(st->anti_exfil_inputs, i, 1);
    }
    if (st->anti_exfil_round != 0) {
        bool has_keypath = false;
        // The invocation signs only its protected key path; leaf/MuSig keys are
        // never allowed to produce an unprotected receipt in the same call.
        for (size_t i = 0; i < st->account.n_internal_key_expressions; i++) {
            keyexpr_info_t *key = &st->account.internal_key_expressions[i];
            if (key->is_tapscript || key->key_expression_ptr->type != KEY_EXPRESSION_NORMAL) {
                key->to_sign = false;
            } else if (key->to_sign) {
                has_keypath = true;
            }
        }
        if (!has_keypath) goto invalid;
    }
    return true;
invalid:
    SEND_SW(dc, SW_INCORRECT_DATA);
    return false;
}
