#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "anti_exfil.h"

static void test_namespace(void **state) {
    (void) state;
    uint8_t key[48] = {0xfc, 2, 'a', 'e', 0};
    uint8_t subtype, pubkey[32];
    memset(key + 5, 0x55, 32);
    for (uint8_t i = 0; i < 3; i++) {
        key[4] = i;
        assert_int_equal(anti_exfil_parse_key(key, 37, &subtype, pubkey), ANTI_EXFIL_KEY_VALID);
        assert_true(anti_exfil_is_key(key, 37));
        assert_int_equal(subtype, i);
        assert_memory_equal(pubkey, key + 5, 32);
    }
    key[4] = 3;
    assert_int_equal(anti_exfil_parse_key(key, 37, &subtype, pubkey), ANTI_EXFIL_KEY_INVALID);
    assert_true(anti_exfil_is_key(key, 37));
    key[4] = 0;
    for (size_t len = 4; len < 37; len++) {
        assert_int_equal(anti_exfil_parse_key(key, len, &subtype, pubkey), ANTI_EXFIL_KEY_INVALID);
    }
    assert_int_equal(anti_exfil_parse_key(key, 38, &subtype, pubkey), ANTI_EXFIL_KEY_INVALID);
    key[3] = 'x';
    assert_false(anti_exfil_is_key(key, 37));
    assert_int_equal(anti_exfil_parse_key(key, 37, &subtype, pubkey), ANTI_EXFIL_KEY_NONE);
}

static void test_noncanonical_namespace(void **state) {
    (void) state;
    uint8_t key[64], subtype, pubkey[32];
    for (size_t n = 2; n <= 8; n *= 2) {
        // Noncanonical identifier-length, subtype and proprietary-type encodings.
        uint8_t marker = n == 2 ? 0xfd : (n == 4 ? 0xfe : 0xff);
        memset(key, 0, sizeof(key));
        key[0] = 0xfc;
        key[1] = marker;
        key[2] = 2;
        key[2 + n] = 'a';
        key[3 + n] = 'e';
        assert_int_equal(anti_exfil_parse_key(key, 37 + n, &subtype, pubkey),
                         ANTI_EXFIL_KEY_INVALID);
        memset(key, 0, sizeof(key));
        memcpy(key,
               "\xfc\x02"
               "ae",
               4);
        key[4] = marker;
        assert_int_equal(anti_exfil_parse_key(key, 37 + n, &subtype, pubkey),
                         ANTI_EXFIL_KEY_INVALID);
        memset(key, 0, sizeof(key));
        key[0] = marker;
        key[1] = 0xfc;
        key[1 + n] = 2;
        key[2 + n] = 'a';
        key[3 + n] = 'e';
        assert_int_equal(anti_exfil_parse_key(key, 37 + n, &subtype, pubkey),
                         ANTI_EXFIL_KEY_INVALID);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_namespace),
        cmocka_unit_test(test_noncanonical_namespace),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
