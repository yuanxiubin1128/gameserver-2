/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Simon Sandström
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef UTILS_RSA_H_
#define UTILS_RSA_H_

#include <cstdint>
#include <string>

#include <gmp.h>

class RSA
{
 public:
  RSA()
  {
    mpz_init2(p_, 1024);
    mpz_init2(q_, 1024);
    mpz_init(n_);
    mpz_init2(d_, 1024);
    mpz_init(e_);

    mpz_set_str(p_, pStr_.c_str(), 10);
    mpz_set_str(q_, qStr_.c_str(), 10);

    mpz_set_ui(e_, 65537);

    mpz_mul(n_, p_, q_);

    mpz_t p_1;
    mpz_t q_1;
    mpz_t pq_1;
    mpz_init2(p_1, 1024);
    mpz_init2(q_1, 1024);
    mpz_init2(pq_1, 1024);

    mpz_sub_ui(p_1, p_, 1);
    mpz_sub_ui(q_1, q_, 1);

    mpz_mul(pq_1, p_1, q_1);

    mpz_invert(d_, e_, pq_1);

    mpz_clear(p_1);
    mpz_clear(q_1);
    mpz_clear(pq_1);
  }

  ~RSA()
  {
    mpz_clear(p_);
    mpz_clear(q_);
    mpz_clear(n_);
    mpz_clear(d_);
    mpz_clear(e_);
  }

  void decrypt(uint8_t* buffer) const
  {
    mpz_t c;
    mpz_t m;
    mpz_init2(c, 1024);
    mpz_init2(m, 1024);

    mpz_import(c, 128, 1, 1, 0, 0, buffer);

    mpz_powm(m, c, d_, n_);

    size_t count = (mpz_sizeinbase(m, 2) + 7) / 8;

    memset(buffer, 0, 128 - count);
    mpz_export(&buffer[128 - count], nullptr, 1, 1, 0, 0, m);

    mpz_clear(c);
    mpz_clear(m);
  }

 private:
  const std::string pStr_ = "14299623962416399520070177382898895550795403345466153217470516082934737582776038882967213386204600674145392845853859217990626450972452084065728686565928113";
  const std::string qStr_ = "7630979195970404721891201847792002125535401292779123937207447574596692788513647179235335529307251350570728407373705564708871762033017096809910315212884101";

  mpz_t p_;
  mpz_t q_;
  mpz_t n_;
  mpz_t d_;
  mpz_t e_;
};

#endif  // UTILS_RSA_H_
