#ifndef pack_H_
#define pack_H_

#include "common.h"

void para_judge(bool result,char* out);

void NegacyclicRightShiftInplace(seal::Ciphertext &ct, size_t shift,
                                 const seal::SEALContext &context);

void encode_to_plaintext(std::vector<uint64_t> &vec, size_t len, seal::Plaintext &pt);

void decode_to_vector(std::vector<uint64_t> &vec, size_t len, seal::Plaintext &pt);

void GenerateGaloisKeyForPacking(const seal::SEALContext &context, seal::GaloisKeys &out, seal::KeyGenerator &keygen);

void doPackingLWEs(std::vector<seal::Ciphertext> rlwes, seal::Ciphertext &ct_for_padding ,const seal::GaloisKeys &galois,
                          const seal::SEALContext &context, seal::Ciphertext &out);

void dobumblebeepack(std::vector<seal::Ciphertext> rlwes, const seal::GaloisKeys &galois,
                          const seal::SEALContext &context, seal::Ciphertext &out);                   

void shift_test();

void automorphism_test();

void packlwes_test();

void bumblebeepack_test();
#endif