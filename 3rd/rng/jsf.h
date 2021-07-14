#ifndef JSF_HPP_INCLUDED
#define JSF_HPP_INCLUDED 1

/*
 * A C++ implementation of a Bob Jenkins Small Fast (Noncryptographic) PRNGs
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Melissa E. O'Neill
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/* Based on code published by Bob Jenkins in 2007, adapted for C++ */

#include <cstdint>

namespace jsf_detail {

    template <typename itype, typename rtype,
            unsigned int p, unsigned int q, unsigned int r>
    class jsf {
    protected:
        itype a_, b_, c_, d_;

        static constexpr unsigned int ITYPE_BITS = 8*sizeof(itype);
        static constexpr unsigned int RTYPE_BITS = 8*sizeof(rtype);

        static itype rotate(itype x, unsigned int k)
        {
            return (x << k) | (x >> (ITYPE_BITS - k));
        }

    public:
        using result_type = rtype;
        using state_type = itype;

        static constexpr result_type min() { return 0; }
        static constexpr result_type max() { return ~ result_type(0); }

        jsf(itype seed = itype(0xcafe5eed00000001ULL))
                : a_(0xf1ea5eed), b_(seed), c_(seed), d_(seed)
        {
            for (unsigned int i=0; i<20; ++i)
                advance();
        }

        void advance()
        {
            itype e = a_ - rotate(b_, p);
            a_ = b_ ^ rotate(c_, q);
            b_ = c_ + (r ? rotate(d_, r) : d_);
            c_ = d_ + e;
            d_ = e + a_;
        }


        rtype operator()()
        {
            advance();
            return rtype(d_);
        }

        bool operator==(const jsf& rhs)
        {
            return (a_ == rhs.a_) && (b_ == rhs.b_)
                   && (c_ == rhs.c_) && (d_ == rhs.d_);
        }

        bool operator!=(const jsf& rhs)
        {
            return !operator==(rhs);
        }

        // Not (yet) implemented:
        //   - arbitrary jumpahead (doable, but annoying to write).
        //   - I/O
        //   - Seeding from a seed_seq.
    };

} // end namespace

///// ---- Specific JSF Generators ---- ////
//
// Each size has variations corresponding to different parameter sets.
// Each variant will create a distinct (and hopefully statistically
// independent) sequence.
//

// - 128 state bits, 32-bit output
//
// The constants are all those suggested by Bob Jenkins.  The n variants
// perform only two rotations, the r variants perform three.

using jsf32na = jsf_detail::jsf<uint32_t, uint32_t, 27, 17, 0>;
using jsf32nb = jsf_detail::jsf<uint32_t, uint32_t,  9, 16, 0>;
using jsf32nc = jsf_detail::jsf<uint32_t, uint32_t,  9, 24, 0>;
using jsf32nd = jsf_detail::jsf<uint32_t, uint32_t, 10, 16, 0>;
using jsf32ne = jsf_detail::jsf<uint32_t, uint32_t, 10, 24, 0>;
using jsf32nf = jsf_detail::jsf<uint32_t, uint32_t, 11, 16, 0>;
using jsf32ng = jsf_detail::jsf<uint32_t, uint32_t, 11, 24, 0>;
using jsf32nh = jsf_detail::jsf<uint32_t, uint32_t, 25,  8, 0>;
using jsf32ni = jsf_detail::jsf<uint32_t, uint32_t, 25, 16, 0>;
using jsf32nj = jsf_detail::jsf<uint32_t, uint32_t, 26,  8, 0>;
using jsf32nk = jsf_detail::jsf<uint32_t, uint32_t, 26, 16, 0>;
using jsf32nl = jsf_detail::jsf<uint32_t, uint32_t, 26, 17, 0>;
using jsf32nm = jsf_detail::jsf<uint32_t, uint32_t, 27, 16, 0>;

using jsf32ra = jsf_detail::jsf<uint32_t, uint32_t,  3, 14, 24>;
using jsf32rb = jsf_detail::jsf<uint32_t, uint32_t,  3, 25, 15>;
using jsf32rc = jsf_detail::jsf<uint32_t, uint32_t,  4, 15, 24>;
using jsf32rd = jsf_detail::jsf<uint32_t, uint32_t,  6, 16, 28>;
using jsf32re = jsf_detail::jsf<uint32_t, uint32_t,  7, 16, 27>;
using jsf32rf = jsf_detail::jsf<uint32_t, uint32_t,  8, 14,  3>;
using jsf32rg = jsf_detail::jsf<uint32_t, uint32_t, 11, 16, 23>;
using jsf32rh = jsf_detail::jsf<uint32_t, uint32_t, 12, 16, 22>;
using jsf32ri = jsf_detail::jsf<uint32_t, uint32_t, 12, 17, 23>;
using jsf32rj = jsf_detail::jsf<uint32_t, uint32_t, 13, 16, 22>;
using jsf32rk = jsf_detail::jsf<uint32_t, uint32_t, 15, 25,  3>;
using jsf32rl = jsf_detail::jsf<uint32_t, uint32_t, 16,  9,  3>;
using jsf32rm = jsf_detail::jsf<uint32_t, uint32_t, 17,  9,  3>;
using jsf32rn = jsf_detail::jsf<uint32_t, uint32_t, 17, 27,  7>;
using jsf32ro = jsf_detail::jsf<uint32_t, uint32_t, 19,  7,  3>;
using jsf32rp = jsf_detail::jsf<uint32_t, uint32_t, 23, 15, 11>;
using jsf32rq = jsf_detail::jsf<uint32_t, uint32_t, 23, 16, 11>;
using jsf32rr = jsf_detail::jsf<uint32_t, uint32_t, 23, 17, 11>;
using jsf32rs = jsf_detail::jsf<uint32_t, uint32_t, 24,  3, 16>;
using jsf32rt = jsf_detail::jsf<uint32_t, uint32_t, 24,  4, 16>;
using jsf32ru = jsf_detail::jsf<uint32_t, uint32_t, 25, 14,  3>;
using jsf32rv = jsf_detail::jsf<uint32_t, uint32_t, 27, 16,  6>;
using jsf32rw = jsf_detail::jsf<uint32_t, uint32_t, 27, 16,  7>;

using jsf32n = jsf32na;
using jsf32r = jsf32rq;
using jsf32  = jsf32n;

// - 256 state bits, uint64_t output

using jsf64na = jsf_detail::jsf<uint64_t, uint64_t, 39, 11,  0>;
using jsf64ra = jsf_detail::jsf<uint64_t, uint64_t,  7, 13, 37>;

using jsf64n = jsf64na;
using jsf64r = jsf64ra;
using jsf64  = jsf64r;

// TINY VERSIONS FOR TESTING AND SPECIALIZED USES ONLY
//
// Parameters derived using a variant of rngav.c, originally written by
// Bob Jenkins.

// - 64 state bits, uint16_t output

using jsf16na = jsf_detail::jsf<uint16_t, uint16_t, 13,  8,  0>;

using jsf16 = jsf16na;

// - 32 state bits, uint8_t output

using jsf8na = jsf_detail::jsf<uint8_t, uint8_t,  1,  4,  0>;

using jsf8 = jsf8na;

#endif // JSF_HPP_INCLUDED