#include "packlwes_head.h"
#include "thread.h"

using namespace std;
using namespace seal;
using namespace threadset;

void LaunchWorks(
    ThreadPool &tpool, size_t num_works,
    std::function<void(long wid, size_t start, size_t end)> program);

void para_judge(bool result,char* out){
    if (!result){
        cout << out << endl;
    }
}

void NegacyclicRightShiftInplace(seal::Ciphertext &ct, size_t shift,
                                 const seal::SEALContext &context) {
  if (shift == 0 || ct.size() == 0) {
    // nothing to do
    return;
  }

  auto cntxt = context.get_context_data(ct.parms_id());

  para_judge(cntxt != nullptr, "invalid ct");
  para_judge(not ct.is_ntt_form(), "need non-ntt ct for negacyclic shift");

  size_t num_coeff = ct.poly_modulus_degree();
  para_judge(shift < num_coeff , "shift must smaller than the num of coeff");

  std::vector<uint64_t> tmp(shift);
  //  i < N - s  ai*X^i -> ai*X^{i + s}
  // i >= N - s ai*X^i -> -ai*X^{(i + s) % N}
  const auto &modulus = cntxt->parms().coeff_modulus();
  for (size_t k = 0; k < ct.size(); ++k) {
    uint64_t *dst_ptr = ct.data(k);

    for (const auto &prime : modulus) {
      // save [N-s, N)
      std::copy_n(dst_ptr + num_coeff - shift, shift, tmp.data());

      // X^i for i \in [0, N-s)
      for (size_t i = num_coeff - shift; i > 0; --i) {
        dst_ptr[i - 1 + shift] = dst_ptr[i - 1];
      }

      // i \n [N-s, N)
      for (size_t i = 0; i < shift; ++i) {
        dst_ptr[i] = seal::util::negate_uint_mod(tmp[i], prime);
      }

      dst_ptr += num_coeff;
    }
  }
}

void encode_to_plaintext(vector<uint64_t> &vec, size_t len, seal::Plaintext &pt){
  para_judge(vec.size() != 0, "empty vector");
  // cout << len << '\t' << pt.coeff_count() << endl;

  size_t values_matrix_size = vec.size();
  for (auto v : vec){
    while(v>PLAIN_MODULUS){
      v-=PLAIN_MODULUS;
    }
  }
  // Set destination to full size
  pt.resize(poly_degree);
  pt.parms_id() = parms_id_zero;

  // First write the values to destination coefficients.
  // Read in top row, then bottom row.
  for (size_t i = 0; i < values_matrix_size; i++)
  {
    *(pt.data()+i) = vec[i];
  }
  for (size_t i = values_matrix_size; i < poly_degree; i++)
  {
    *(pt.data()+i) = 0;
  }

  //pt.resize(seal::util::mul_safe(N, PLAIN_MODULUS));
  //copy(vec.begin(),vec.end(),pt.data());
  //seal::util::modulo_poly_coeffs(vec, len, plain_modulus(), pt.data());
  //std::fill_n(pt.data() + len, pt.coeff_count() - len, 0);
}

void decode_to_vector(vector<uint64_t> &vec, size_t len, seal::Plaintext &pt){
  para_judge(len > 0 && len <= pt.coeff_count(), "len is larger than the degree");

  // int temp=0;
  // for (int i=0;i<pt.coeff_count();i++){
  //   temp=*(pt.data()+i);
  //   if(temp!=0){
  //     cout << temp << '\t' << i << endl;
  //   }
  // }

  cout << "明文系数个数："<<pt.coeff_count() << endl;
  //copy(vec.begin(),vec.begin()+pt.coeff_count(),pt.data());
  copy(pt.data(),pt.data()+pt.coeff_count(),vec.begin());

  // for (size_t i = 0; i < pt.coeff_count(); i++)
  // {
  //   vec[i]=*(pt.data()+i);
  // }
  // for (size_t i = pt.coeff_count(); i < poly_degree; i++)
  // {
  //   vec[i] = 0;
  // }
}

void GenerateGaloisKeyForPacking(const seal::SEALContext &context,  seal::GaloisKeys &out ,seal::KeyGenerator &keygen) {
  size_t N = poly_degree;
  size_t logN = log2(N);
  std::vector<uint32_t> galois_elt;
  for (uint32_t i = 1; i <= logN; i++) {
    //cout << (1u << i) + 1 << endl;
    galois_elt.push_back((1u << i) + 1);
  }

  keygen.create_galois_keys(galois_elt, out);
}

void LaunchWorks(
  ThreadPool &tpool, size_t num_works,
  std::function<void(long wid, size_t start, size_t end)> program) {

  cout << "num_works : " << num_works << endl;
  long pool_sze = tpool.pool_size();
  if (pool_sze <= 1L) {
    std::cout << "pool_sze <= 1L" << std::endl;
    return program(0, 0, num_works);
  } else {
    std::vector<std::future<void>> futures;
    size_t work_load = (num_works + pool_sze - 1) / pool_sze;
    if (num_works<pool_sze){
      pool_sze=num_works;
    }
    for (long wid = 0; wid < pool_sze; ++wid) {
      size_t start = wid * work_load;
      size_t end = std::min(start + work_load, num_works);
      //查看任务划分范围
      //cout << start << '\t' << end << endl;
      futures.push_back(tpool.enqueue(program, wid, start, end));
    }
  }
  while(true){
    //cout << "tasks_num:" << tpool.tasks_num() << endl;
    if(tpool.tasks_num()==0)break;
  }
  //std::this_thread::sleep_for(std::chrono::seconds(5));
}

void doPackingLWEs(std::vector<seal::Ciphertext> rlwes,seal::Ciphertext &ct_for_padding , const GaloisKeys &galois,
                          const seal::SEALContext &context, seal::Ciphertext &out) {
  auto cntxt = context.first_context_data();

  size_t N = cntxt->parms().poly_modulus_degree();
  size_t num_ct = rlwes.size();
  size_t num_ct_rec = rlwes.size();

  ThreadPool tpool(nthreads);
  // FFT-like method to merge RLWEs into one RLWE.
  seal::Evaluator evaluator(context);
  size_t depth = 1;
  while (num_ct_rec != 1) {
    // size_t n = num_ct / depth;// 该层有多少个密文需要pack

    // 每次循环改num_ct为n，终止条件改成num_ct_rec==1
    size_t n = num_ct_rec + (num_ct_rec % 2);
    // i+h>=num_ct,就break出for循环 第182行

    size_t h = n / 2;// pack之后密文个数或有多少组
    depth <<= 1;// 第一次循环的时候为2，shift正好移位N/2

    // 不使用多线程只需要把start和end改成0和h即可
    auto merge_callback = [&](long wid,int64_t start, int64_t end) {
      using namespace seal::util;
      for (int64_t i = start; i < end; ++i) {
        Ciphertext &ct_even = rlwes[i];
        Ciphertext ct_odd;
        if (i+h >= num_ct_rec)     
          ct_odd = ct_for_padding;
        else
          ct_odd = rlwes[i + h];
      
        bool is_odd_empty = ct_odd.size() == 0;
        bool is_even_empty = ct_even.size() == 0;
        // if (i+h>=N)
        //   is_odd_empty=1;
        if (is_even_empty && is_odd_empty) {
          ct_even.release();
          continue;
        }

        // GS-style butterfly
        // E' <- E + X^k*O + Auto(E - X^k*O, k')
        // O' <- E + X^k*O + Auto(E + X^k*O, k')
        // 先对odd密文右移N/depth位
        if (!is_odd_empty) {
          NegacyclicRightShiftInplace(ct_odd, N / depth, context);
        }

        if (!is_even_empty) {
          Ciphertext tmp = ct_even;
          if (!is_odd_empty) {
            evaluator.sub_inplace(ct_even, ct_odd);
            evaluator.add_inplace(tmp, ct_odd);
          }
          evaluator.apply_galois_inplace(
              ct_even, depth + 1, galois);
          evaluator.add_inplace(ct_even, tmp);
        } else {
          evaluator.negate(ct_odd, ct_even);
          evaluator.apply_galois_inplace(
              ct_even, depth + 1, galois);
          evaluator.add_inplace(ct_even, ct_odd);
        }
      }
      cout << "one thread finish" << endl;
    };
    
    cout << "depth : " << depth << endl;

    if (h > 0) {
      //yacl::parallel_for(0, h, calculateWorkLoad(h), merge_callback);
      (void)LaunchWorks(tpool, h, merge_callback);
    }

    num_ct_rec = h;
  }

  cout << "finish packlwes" << endl;
  out = rlwes[0];
  out.is_ntt_form() = false;
  out.scale() = 1.;

  // Step 2 to remove the extra factor (i.e., N/num_lwes) from Step 2.
  //size_t true_ct_num=num_ct
  size_t log2N = log2(N);
  size_t log2Nn = log2(N / num_ct);
  cout << "auto times : "  << log2Nn << endl;

  // k <= log2Nn
  for (size_t k = 1; k <= log2Nn; ++k) {
    Ciphertext tmp{out};
    uint32_t exp = (1UL << (log2N - k + 1)) + 1;
    evaluator.apply_galois_inplace(tmp, exp, galois);
    evaluator.add_inplace(out, tmp);
  }
  cout << "finish remove coefficients" << endl;
}

void dobumblebeepack(std::vector<seal::Ciphertext> rlwes, const GaloisKeys &galois,
                          const seal::SEALContext &context, seal::Ciphertext &out) {
  auto cntxt = context.first_context_data();

  size_t N = cntxt->parms().poly_modulus_degree();
  size_t num_ct = rlwes.size();

  ThreadPool tpool(nthreads);

  seal::Evaluator evaluator(context);

  auto removeandshift_func = [&](long wid,int64_t start, int64_t end){
    size_t log2N = log2(N);
    // 对每一个密文remove
    for (int64_t i = start; i < end; ++i){
      Ciphertext &ct_ras = rlwes[i];
      for (size_t k = 1; k <= log2N; ++k) {
        // 无用位置0
        // 密文复制
        Ciphertext tmp{ct_ras};
        uint32_t exp = (1UL << (log2N - k + 1)) + 1;
        evaluator.apply_galois_inplace(tmp, exp, galois);
        evaluator.add_inplace(ct_ras, tmp);
      }

      NegacyclicRightShiftInplace(ct_ras, i, context);
    }
  };
  (void)LaunchWorks(tpool, num_ct, removeandshift_func);

  for (size_t i=1;i<num_ct;i++){
    Ciphertext &ct_add0 = rlwes[0];
    Ciphertext &ct_addi = rlwes[i];
    evaluator.add_inplace(ct_add0, ct_addi);
  }
  out = rlwes[0];

  cout << "finish removeandshift_func" << endl;
}