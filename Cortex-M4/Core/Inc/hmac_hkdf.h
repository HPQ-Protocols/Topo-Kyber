#ifndef INC_HMAC_HKDF_H_
#define INC_HMAC_HKDF_H_

#include <stdint.h>
#include <stddef.h>

// Hàm HMAC sử dụng SHA3-256 làm lõi
void hmac_sha3_256(
    uint8_t *out,
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len
);

// Hàm HKDF sử dụng SHA3-256 làm lõi
void hkdf_sha3(
    uint8_t *out,
    const uint8_t *secret, size_t secret_len,
    const uint8_t *salt, size_t salt_len
);

#endif /* INC_HMAC_HKDF_H_ */