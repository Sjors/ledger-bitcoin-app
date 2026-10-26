#include "anti_exfil.h"

#include <string.h>

static bool read_compact_size(const uint8_t *key, size_t len, size_t *pos, uint64_t *value) {
    if (*pos >= len) return false;
    uint8_t first = key[(*pos)++];
    if (first < 0xfd) {
        *value = first;
        return true;
    }
    size_t n = first == 0xfd ? 2 : (first == 0xfe ? 4 : 8);
    if (len - *pos < n) return false;
    *value = 0;
    for (size_t i = 0; i < n; i++) *value |= (uint64_t) key[(*pos)++] << (8 * i);
    return true;
}

anti_exfil_key_status_t anti_exfil_parse_key(const uint8_t *key,
                                             size_t key_len,
                                             uint8_t *subtype,
                                             uint8_t pubkey[static 32]) {
    size_t pos = 0;
    uint64_t type, identifier_len, field;
    if (!read_compact_size(key, key_len, &pos, &type) || type != 0xfc ||
        !read_compact_size(key, key_len, &pos, &identifier_len) || identifier_len != 2 ||
        key_len - pos < 2 || memcmp(key + pos, "ae", 2) != 0) {
        return ANTI_EXFIL_KEY_NONE;
    }
    // All supported encodings are one byte. This also rejects noncanonical
    // CompactSize encodings of the proprietary type or identifier length.
    bool canonical = pos == 2;
    pos += 2;
    if (!read_compact_size(key, key_len, &pos, &field) || !canonical || pos != 5 || field > 2 ||
        key_len - pos != 32) {
        return ANTI_EXFIL_KEY_INVALID;
    }
    *subtype = (uint8_t) field;
    memcpy(pubkey, key + pos, 32);
    return ANTI_EXFIL_KEY_VALID;
}

bool anti_exfil_is_key(const uint8_t *key, size_t key_len) {
    uint8_t subtype, pubkey[32];
    return anti_exfil_parse_key(key, key_len, &subtype, pubkey) != ANTI_EXFIL_KEY_NONE;
}
