#include "randombytes.h"
#include "stm32f4xx_hal.h"

extern RNG_HandleTypeDef hrng;

int randombytes(uint8_t *out, size_t outlen) {
    uint32_t val;
    for (size_t i = 0; i < outlen; i++) {
        if (i % 4 == 0) {
            HAL_RNG_GenerateRandomNumber(&hrng, &val);
        }
        out[i] = (uint8_t)(val >> ((i % 4) * 8));
    }
    return 0;
}
