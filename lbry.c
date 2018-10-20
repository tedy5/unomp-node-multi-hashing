/**
 * Migrate to node-multi-hashing package, 
 * LBRY algorithm.
 * by trustfarm@github , May 2018
 * 
 * -----------------------------------------------------
 * refer from Lbry sph Implementation 
 * tpruvot@github July 2016
 */

#include "lbry.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_sha2.h"
#include "sha3/sph_ripemd.h"

void lbry_hash(const char* input, char* output)
{
    char    hashA[64];
    char    hashB[32];
    char    hashC[32];

    sph_sha256_context ctx_sha256;
    sph_sha512_context ctx_sha512;
    sph_ripemd160_context ctx_ripemd;

    // sha256d - hashA, hashA-MSB
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, input, 112);
    sph_sha256_close(&ctx_sha256, hashA);
    sph_sha256(&ctx_sha256, hashA, 32);
    sph_sha256_close(&ctx_sha256, hashA);

    // sha512 - hashA
    sph_sha512_init(&ctx_sha512);
    sph_sha512(&ctx_sha512, hashA, 32);
    sph_sha512_close(&ctx_sha512, hashA);

    // ripemd160d - hashA-MSB , close hashB
    sph_ripemd160_init(&ctx_ripemd);
    sph_ripemd160(&ctx_ripemd, hashA, 32);
    sph_ripemd160_close(&ctx_ripemd, hashB);

    // ripemd160d - hashA-LSB , close hashC
	sph_ripemd160(&ctx_ripemd, &hashA[32], 32); // weird
	sph_ripemd160_close(&ctx_ripemd, hashC);

    // sha256d - hashB , hashC , close hashA
    sph_sha256(&ctx_sha256, hashB, 20);
    sph_sha256(&ctx_sha256, hashC, 20);
	sph_sha256_close(&ctx_sha256, hashA);
    // sha256d - hashA 
    sph_sha256(&ctx_sha256, hashA, 32);
    sph_sha256_close(&ctx_sha256, hashA);

	memcpy(output, hashA, 32);
}
