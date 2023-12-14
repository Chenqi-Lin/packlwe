#include "packlwes_head.h"
#include "thread.h"

using namespace std;
using namespace seal;
using namespace threadset;

void shift_test(){
    // 这个部分测试encode和shift函数的正确性，其中多项式度为4096，明文模数20bits（选自addra）
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = poly_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PLAIN_MODULUS);
    SEALContext context(parms);

    // Print the parameters that we have chosen.
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    // generate the secret, public
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // Encryptor, Evaluator and Decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    size_t slot_count=poly_modulus_degree;
    size_t row_size = slot_count / 2;
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);
    Plaintext pt;
    cout << "encode plain_matrix to plaintext." << endl;
    encode_to_plaintext(pod_matrix, pod_matrix.size(), pt);
    cout << "Encrypt plaintext to ciphertext." << endl;
    Ciphertext ct;
    encryptor.encrypt(pt, ct);

    cout << "negative right shift." << endl;
    NegacyclicRightShiftInplace(ct,1,context);

    cout << "Decrypt ciphertext to plaintext." << endl;
    Plaintext shifted_pt;
    decryptor.decrypt(ct, shifted_pt);
    cout << "Decode and print the matrix." << endl;
    vector<uint64_t> result_matrix(poly_degree,0ULL);
    decode_to_vector(result_matrix, shifted_pt.coeff_count(), shifted_pt);
    print_matrix(result_matrix, row_size);
}

void automorphism_test(){
    // 这个部分测试encode和shift函数的正确性，其中多项式度为4096，明文模数20bits（选自addra）
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = poly_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PLAIN_MODULUS);
    SEALContext context(parms);

    // Print the parameters that we have chosen.
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    // generate the secret, public
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // generate the Galois keys
    GaloisKeys glk;
    // 需要传入生成的keygen，如果在函数中生成再生成的话，会导致产生的galois key无法使用
    // 或者使用context和之前生成的key一起生成keygen
    GenerateGaloisKeyForPacking(context,glk,keygen);
    //keygen.create_galois_keys(vector<uint32_t>{ 2048+1,4096+1 }, glk);

    // Encryptor, Evaluator and Decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    size_t slot_count=poly_modulus_degree;
    size_t row_size = slot_count / 2;
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);
    Plaintext pt;
    cout << "encode plain_matrix to plaintext." << endl;
    encode_to_plaintext(pod_matrix, pod_matrix.size(), pt);
    cout << "Encrypt plaintext to ciphertext." << endl;
    Ciphertext ct;
    encryptor.encrypt(pt, ct);

    cout << "automorphism." << endl;
    Ciphertext auto_result;
    evaluator.apply_galois(ct, poly_modulus_degree+1, glk,auto_result);
    evaluator.sub_inplace(ct,auto_result);

    cout << "Decrypt ciphertext to plaintext." << endl;
    Plaintext automorphism_pt;
    decryptor.decrypt(ct, automorphism_pt);
    cout << "Decode and print the matrix." << endl;
    vector<uint64_t> result_matrix(poly_degree,0ULL);
    decode_to_vector(result_matrix, automorphism_pt.coeff_count(), automorphism_pt);
    print_matrix(result_matrix, row_size);
}

void packlwes_test(){
    // 这个部分测试encode和shift函数的正确性，其中多项式度为4096，明文模数20bits（选自addra）
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = poly_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PLAIN_MODULUS);
    SEALContext context(parms);

    // Print the parameters that we have chosen.
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    // generate the secret, public
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // generate the Galois keys
    GaloisKeys glk;
    // 需要传入生成的keygen，如果在函数中生成再生成的话，会导致产生的galois key无法使用
    // 或者使用context和之前生成的key一起生成keygen
    GenerateGaloisKeyForPacking(context,glk,keygen);
    //keygen.create_galois_keys(vector<uint32_t>{ 2048+1,4096+1 }, glk);

    // Encryptor, Evaluator and Decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    size_t slot_count=poly_modulus_degree;
    size_t row_size = slot_count / 2;
    vector<uint64_t> pod_matrix(slot_count, 0ULL);

    // 创建全0密文用于padding
    Plaintext pt_for_padding;
    Ciphertext ct_for_padding;
    encode_to_plaintext(pod_matrix, pod_matrix.size(), pt_for_padding);
    encryptor.encrypt(pt_for_padding, ct_for_padding);

    pod_matrix[0] = 1ULL;
    pod_matrix[1] = 2ULL;
    pod_matrix[2] = 3ULL;
    pod_matrix[3] = 4ULL;
    pod_matrix[row_size] = 5ULL;
    pod_matrix[row_size + 1] = 6ULL;
    pod_matrix[row_size + 2] = 7ULL;
    pod_matrix[row_size + 3] = 8ULL;
    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    std::vector<seal::Ciphertext> cts;

    for (int i=0;i<num_of_cts;i++){
        Plaintext pt;
        Ciphertext ct;
        encode_to_plaintext(pod_matrix, pod_matrix.size(), pt);
        encryptor.encrypt(pt, ct);
        cts.push_back(ct);
    }

    cout << "Packlwes." << endl;
    Ciphertext pack_result;

    auto start = std::chrono::high_resolution_clock::now();
    doPackingLWEs(cts, ct_for_padding, glk, context, pack_result);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
     cout<<"packlwes latency :"<<double(duration.count()) <<endl;

    cout << "Decrypt ciphertext to plaintext." << endl;
    Plaintext pack_pt;
    decryptor.decrypt(pack_result, pack_pt);
    cout << "Decode and print the matrix." << endl;
    vector<uint64_t> result_matrix(poly_degree,0ULL);
    decode_to_vector(result_matrix, pack_pt.coeff_count(), pack_pt);
    print_matrix(result_matrix, row_size);
    // for (int i=0;i<poly_degree/2;i++){
    //     cout << result_matrix[i] << endl;
    // }
}

void bumblebeepack_test(){
    // 这个部分测试encode和shift函数的正确性，其中多项式度为4096，明文模数20bits（选自addra）
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = poly_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PLAIN_MODULUS);
    SEALContext context(parms);

    // Print the parameters that we have chosen.
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    // generate the secret, public
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // generate the Galois keys
    GaloisKeys glk;
    // 需要传入生成的keygen，如果在函数中生成再生成的话，会导致产生的galois key无法使用
    // 或者使用context和之前生成的key一起生成keygen
    GenerateGaloisKeyForPacking(context,glk,keygen);
    //keygen.create_galois_keys(vector<uint32_t>{ 2048+1,4096+1 }, glk);

    // Encryptor, Evaluator and Decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    size_t slot_count=poly_modulus_degree;
    size_t row_size = slot_count / 2;
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 1ULL;
    pod_matrix[1] = 2ULL;
    pod_matrix[2] = 3ULL;
    pod_matrix[3] = 4ULL;
    pod_matrix[row_size] = 5ULL;
    pod_matrix[row_size + 1] = 6ULL;
    pod_matrix[row_size + 2] = 7ULL;
    pod_matrix[row_size + 3] = 8ULL;
    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    std::vector<seal::Ciphertext> cts;

    for (int i=0;i<num_of_cts;i++){
        Plaintext pt;
        Ciphertext ct;
        encode_to_plaintext(pod_matrix, pod_matrix.size(), pt);
        encryptor.encrypt(pt, ct);
        cts.push_back(ct);
    }

    cout << "Bumblebee Pack." << endl;
    Ciphertext pack_result;

    auto start = std::chrono::high_resolution_clock::now();
    dobumblebeepack(cts, glk, context, pack_result);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
     cout<<"Bumblebee Pack latency :"<<double(duration.count()) <<endl;

    cout << "Decrypt ciphertext to plaintext." << endl;
    Plaintext pack_pt;
    decryptor.decrypt(pack_result, pack_pt);
    cout << "Decode and print the matrix." << endl;
    vector<uint64_t> result_matrix(poly_degree,0ULL);
    decode_to_vector(result_matrix, pack_pt.coeff_count(), pack_pt);
    print_matrix(result_matrix, row_size);
}
