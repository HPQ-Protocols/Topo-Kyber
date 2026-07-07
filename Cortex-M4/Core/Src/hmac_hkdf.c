#include "hmac_hkdf.h"
#include "fips202.h"
#include <string.h>

#define SHA3_256_BLOCK_SIZE  136   // Kích thước Block (Rate) của SHA3-256
#define SHA3_256_OUTPUT_SIZE 32    // Kích thước đầu ra 256-bit (32 bytes)

void hmac_sha3_256(
    uint8_t *out,
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len
) {
    uint8_t k0[SHA3_256_BLOCK_SIZE] = {0};

    // Bước 1: Xử lý khóa đầu vào cho vừa kích thước Block
    if (key_len > SHA3_256_BLOCK_SIZE) {
        sha3_256(k0, key, key_len);
    } else {
        memcpy(k0, key, key_len);
    }

    // Bước 2: Tạo mảng ipad và opad thông qua phép XOR
    uint8_t ipad[SHA3_256_BLOCK_SIZE];
    uint8_t opad[SHA3_256_BLOCK_SIZE];
    for (size_t i = 0; i < SHA3_256_BLOCK_SIZE; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5C;
    }

    // Bước 3: Băm vòng trong (Inner Hash) = SHA3-256(ipad || in)
    // Tận dụng mảng VLA được hỗ trợ bởi cờ -std=gnu11 trong project của bạn
    size_t inner_len = SHA3_256_BLOCK_SIZE + in_len;
    uint8_t inner_input[inner_len];
    memcpy(inner_input, ipad, SHA3_256_BLOCK_SIZE);
    memcpy(inner_input + SHA3_256_BLOCK_SIZE, in, in_len);
    
    uint8_t inner_hash[SHA3_256_OUTPUT_SIZE];
    sha3_256(inner_hash, inner_input, inner_len);

    // Bước 4: Băm vòng ngoài (Outer Hash) = SHA3-256(opad || inner_hash)
    uint8_t outer_input[SHA3_256_BLOCK_SIZE + SHA3_256_OUTPUT_SIZE];
    memcpy(outer_input, opad, SHA3_256_BLOCK_SIZE);
    memcpy(outer_input + SHA3_256_BLOCK_SIZE, inner_hash, SHA3_256_OUTPUT_SIZE);

    sha3_256(out, outer_input, SHA3_256_BLOCK_SIZE + SHA3_256_OUTPUT_SIZE);
}

void hkdf_sha3(
    uint8_t *out,
    const uint8_t *secret, size_t secret_len,
    const uint8_t *salt, size_t salt_len
) {
    uint8_t prk[SHA3_256_OUTPUT_SIZE];
    uint8_t default_salt[SHA3_256_OUTPUT_SIZE] = {0};

    // 1. Giai đoạn HKDF-Extract
    if (salt == NULL || salt_len == 0) {
        hmac_sha3_256(prk, default_salt, SHA3_256_OUTPUT_SIZE, secret, secret_len);
    } else {
        hmac_sha3_256(prk, salt, salt_len, secret, secret_len);
    }

    // 2. Giai đoạn HKDF-Expand (Tối ưu riêng cho trường hợp xuất ra 32 bytes Ktemp/Ksession và info để trống)
    uint8_t constant_one = 0x01;
    hmac_sha3_256(out, prk, SHA3_256_OUTPUT_SIZE, &constant_one, 1);
}