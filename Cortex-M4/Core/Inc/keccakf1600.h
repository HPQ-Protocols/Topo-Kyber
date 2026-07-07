/*
 * keccakf1600.h
 *
 *  Created on: Apr 29, 2026
 *      Author: PaTuKi
 */

#ifndef KECCAKF1600_H
#define KECCAKF1600_H

#include <stdint.h>
#include <stddef.h>

void KeccakF1600_StatePermute(uint64_t *state);
void KeccakF1600_StateXORBytes(uint64_t *state, const uint8_t *data, unsigned int offset, unsigned int length);
void KeccakF1600_StateExtractBytes(uint64_t *state, uint8_t *data, unsigned int offset, unsigned int length);

#endif
