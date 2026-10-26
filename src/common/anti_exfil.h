#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Recognize the identifier before checking canonical encoding. A malformed ae key
// must never silently fall back to ordinary signing.
typedef enum {
    ANTI_EXFIL_KEY_NONE,
    ANTI_EXFIL_KEY_INVALID,
    ANTI_EXFIL_KEY_VALID,
} anti_exfil_key_status_t;

anti_exfil_key_status_t anti_exfil_parse_key(const uint8_t *key,
                                             size_t key_len,
                                             uint8_t *subtype,
                                             uint8_t pubkey[static 32]);

// Includes malformed keys whose decoded identifier is ae.
bool anti_exfil_is_key(const uint8_t *key, size_t key_len);
