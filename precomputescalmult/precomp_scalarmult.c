/*
 * precomp_scalarmult.c
 *
 * Configurable-window zero-doubling scalar multiplication for ristretto255.
 *
 * Set WINDOW_BITS at compile time to explore the cache/additions tradeoff:
 *
 *   cc ... -DWINDOW_BITS=3 ...   96KB table, ~86 additions, fits Apple M L1
 *   cc ... -DWINDOW_BITS=4 ...  150KB table, ~60 additions, fits L2
 *   cc ... -DWINDOW_BITS=5 ...  251KB table, ~42 additions, fits L2
 *   cc ... -DWINDOW_BITS=6 ...  433KB table, ~36 additions, fits L2
 *   cc ... -DWINDOW_BITS=8 ...  1.3MB table, ~25 additions, fits L2
 *
 * Table layout: table[i][j] = (j+1) * 2^(WINDOW_BITS*i) * P
 *   NUM_WINDOWS  = ceil(256 / WINDOW_BITS)
 *   WIN_ELEMS    = (1 << WINDOW_BITS) - 1   (all nonzero values)
 *
 * All arithmetic in raw ge25519_p3 extended Edwards — no fe-limb assumptions.
 */

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>

#include "libsodium-src/src/libsodium/include/sodium/private/ed25519_ref10.h"

extern int  ristretto255_frombytes(ge25519_p3 *h, const unsigned char *s);
extern void ristretto255_p3_tobytes(unsigned char *s, const ge25519_p3 *h);
extern void ge25519_p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p);
extern void ge25519_p3_to_cached(ge25519_cached *r, const ge25519_p3 *p);
extern void ge25519_add(ge25519_p1p1 *r, const ge25519_p3 *p,
                        const ge25519_cached *q);
extern void ge25519_sub(ge25519_p1p1 *r, const ge25519_p3 *p,
                        const ge25519_cached *q);
extern void crypto_core_ristretto255_scalar_reduce(unsigned char *r, const unsigned char *s);
extern void crypto_core_ristretto255_scalar_negate(unsigned char *recip, const unsigned char *s);

/* ── Window configuration ────────────────────────────────────────── */

#ifndef WINDOW_BITS
#define WINDOW_BITS 4                          /* default: w=4 */
#endif

#define WIN_ELEMS    ((1 << WINDOW_BITS) - 1)  /* nonzero entries per window */
#define NUM_WINDOWS  ((255 + WINDOW_BITS) / WINDOW_BITS)  /* ceil(255/w) */

#define POINT_BYTES  32
#define SCALAR_BYTES 32

typedef struct {
    ge25519_p3 table[NUM_WINDOWS][WIN_ELEMS];
} PrecompTable;

/* ── Helpers ─────────────────────────────────────────────────────── */

static void p3_double(ge25519_p3 *out, const ge25519_p3 *in)
{
    ge25519_p1p1   tmp;
    ge25519_cached cached;
    ge25519_p3_to_cached(&cached, in);
    ge25519_add(&tmp, in, &cached);
    ge25519_p1p1_to_p3(out, &tmp);
}

static void reduce_scalar(unsigned char out[32], const unsigned char in[32])
{
    unsigned char wide[64] = {0};
    memcpy(wide, in, 32);
    crypto_core_ristretto255_scalar_reduce(out, wide);
}

/* ── Build ──────────────────────────────────────────────────────── */

int precomp_build(PrecompTable **table_out, const unsigned char *point_bytes)
{
    PrecompTable *tbl = (PrecompTable *)malloc(sizeof(PrecompTable));
    if (!tbl) return -1;

    ge25519_p3    base;
    ge25519_p1p1  tmp;
    ge25519_cached cached;

    /* Decode once */
    if (ristretto255_frombytes(&base, point_bytes) != 0) {
        free(tbl);
        return -1;
    }

    for (int i = 0; i < NUM_WINDOWS; i++) {
        /*
         * Fill table[i][0..WIN_ELEMS-1] = [1*base, 2*base, ..., WIN_ELEMS*base]
         * Cache 1*base as the addend and step through additions.
         */
        tbl->table[i][0] = base;
        ge25519_p3_to_cached(&cached, &base);
        for (int j = 1; j < WIN_ELEMS; j++) {
            ge25519_add(&tmp, &tbl->table[i][j-1], &cached);
            ge25519_p1p1_to_p3(&tbl->table[i][j], &tmp);
        }

        /*
         * Advance base by 2^WINDOW_BITS for the next window.
         * = WINDOW_BITS doublings of base.
         */
        if (i < NUM_WINDOWS - 1) {
            for (int d = 0; d < WINDOW_BITS; d++)
                p3_double(&base, &base);
        }
    }

    *table_out = tbl;
    return 0;
}

/* ── Multiply ───────────────────────────────────────────────────── */
/*
 * Extract WINDOW_BITS-wide unsigned window from little-endian scalar
 * starting at bit position bit_pos.
 */
static inline uint32_t extract_window(const unsigned char *scalar, int bit_pos)
{
    int      byte_idx = bit_pos / 8;
    int      bit_off  = bit_pos % 8;
    uint32_t w;

    /* Read two bytes to safely straddle any window boundary */
    w = (uint32_t)scalar[byte_idx];
    if (byte_idx + 1 < SCALAR_BYTES)
        w |= (uint32_t)scalar[byte_idx + 1] << 8;

    /* Shift down and mask to WINDOW_BITS */
    return (w >> bit_off) & WIN_ELEMS;
}

static void zero_dbl_scalarmult(ge25519_p3          *result,
                                 const unsigned char *scalar,
                                 const PrecompTable  *tbl)
{
    unsigned char s[32];
    reduce_scalar(s, scalar);

    ge25519_p1p1   tmp;
    ge25519_cached cached;
    int            first = 1;

    for (int i = 0; i < NUM_WINDOWS; i++) {
        uint32_t w = extract_window(s, i * WINDOW_BITS);
        if (w == 0) continue;

        if (first) {
            *result = tbl->table[i][w - 1];
            first   = 0;
        } else {
            ge25519_p3_to_cached(&cached, &tbl->table[i][w - 1]);
            ge25519_add(&tmp, result, &cached);
            ge25519_p1p1_to_p3(result, &tmp);
        }
    }

    if (first) {
        /* Scalar is 0 mod l — return the proper Edwards identity (0:1:1:0) */
        memset(result, 0, sizeof(ge25519_p3));
        fe25519_1(result->Y);   /* Y = 1 */
        fe25519_1(result->Z);   /* Z = 1 */
        /* X and T remain 0 from the memset */
    }
}

/* ── Thread control ─────────────────────────────────────────────── */

/*
 * c_set_num_threads
 *
 * Set the number of OpenMP threads for subsequent batch operations.
 * Unlike OMP_NUM_THREADS environment variable, this takes effect
 * immediately at runtime without requiring a kernel restart.
 *
 * Recommended: set to number of performance cores (8 on M1 Pro).
 */
void c_set_num_threads(int n)
{
    omp_set_num_threads(n);
}

/*
 * c_get_num_threads
 *
 * Returns the current maximum number of OpenMP threads.
 */
int c_get_num_threads(void)
{
    return omp_get_max_threads();
}

/* ── Batch multiply ─────────────────────────────────────────────── */

/*
 * c_batch_scalarmult_raw
 *
 * Compute n scalar multiplications in a single C call, amortizing the
 * Python→C boundary cost across all n results.
 *
 * Each thread gets its own private copy of the precomputed table so
 * there is no shared L2 cache contention between cores.
 *
 * Parameters:
 *   results_out  — caller-allocated array of n ge25519_p3* pointers;
 *                  all n points are allocated in one contiguous block.
 *                  Free the whole batch with c_free_batch(results_out[0]).
 *   scalars      — packed array of n × SCALAR_BYTES little-endian scalars
 *   tbl          — precomputed table (read-only, copied per thread)
 *   n            — number of scalarmults to compute
 *
 * Returns 0 on success, -1 on allocation failure.
 */
int c_batch_scalarmult_raw(ge25519_p3         **results_out,
                            const unsigned char *scalars,
                            const PrecompTable  *tbl,
                            int                  n)
{
    /* Single allocation for all n result points — no per-iteration malloc */
    ge25519_p3 *block = (ge25519_p3 *)malloc(n * sizeof(ge25519_p3));
    if (!block) return -1;

    for (int k = 0; k < n; k++)
        results_out[k] = &block[k];

    #pragma omp parallel
    {
        /*
         * Each thread copies the table into its own private stack/heap buffer.
         * Eliminates shared L2 cache line bouncing between cores.
         * memcpy of 150KB at ~50GB/s = ~3µs one-time cost per thread.
         */
        PrecompTable *local_tbl = (PrecompTable *)malloc(sizeof(PrecompTable));
        if (local_tbl) {
            memcpy(local_tbl, tbl, sizeof(PrecompTable));

            #pragma omp for schedule(static)
            for (int k = 0; k < n; k++)
                zero_dbl_scalarmult(results_out[k],
                                    scalars + k * SCALAR_BYTES,
                                    local_tbl);

            memset(local_tbl, 0, sizeof(PrecompTable));
            free(local_tbl);
        }
    }

    return 0;
}

/*
 * c_free_batch
 *
 * Free the entire contiguous block allocated by c_batch_scalarmult_raw.
 * Call this once with results[0] after you are done with all batch results.
 * Do NOT call c_free_raw on individual batch points.
 */
void c_free_batch(ge25519_p3 *block)
{
    if (block) { memset(block, 0, sizeof(ge25519_p3)); free(block); }
}

/* ── Batch Pedersen commit ──────────────────────────────────────── */

/*
 * c_batch_pedersen_commit
 *
 * Compute n Pedersen commitments C_k = v_k*G + r_k*H in a single C call.
 *
 * Each commit is computed entirely in C:
 *   1. v_k * G  via tbl_G (zero doublings, windowed table)
 *   2. r_k * H  via tbl_H (zero doublings, windowed table)
 *   3. v_k*G + r_k*H  in raw Edwards (no encode/decode between steps)
 *   4. Encode result once → 32-byte ristretto255 output
 *
 * All n commits run in parallel across OpenMP threads.
 * Each thread gets private copies of both tables to avoid L2 contention.
 *
 * Parameters:
 *   out       — output buffer of n × 32 bytes (caller allocated)
 *   values    — packed n × 32 byte little-endian value scalars
 *   blinders  — packed n × 32 byte little-endian blinding scalars
 *   tbl_G     — precomputed table for G (value base point)
 *   tbl_H     — precomputed table for H (blinding base point)
 *   n         — number of commits
 *
 * Returns 0 on success, -1 on allocation failure.
 */
int c_batch_pedersen_commit(unsigned char       *out,
                             const unsigned char *values,
                             const unsigned char *blinders,
                             const PrecompTable  *tbl_G,
                             const PrecompTable  *tbl_H,
                             int                  n)
{
    #pragma omp parallel
    {
        ge25519_p3     vG, rH, commit;
        ge25519_p1p1   tmp;
        ge25519_cached cached;

        #pragma omp for schedule(dynamic, 64)
        for (int k = 0; k < n; k++) {
            /* Read-only access to shared tables — safe with no writes */
            zero_dbl_scalarmult(&vG, values   + k * SCALAR_BYTES, tbl_G);
            zero_dbl_scalarmult(&rH, blinders + k * SCALAR_BYTES, tbl_H);

            ge25519_p3_to_cached(&cached, &rH);
            ge25519_add(&tmp, &vG, &cached);
            ge25519_p1p1_to_p3(&commit, &tmp);

            ristretto255_p3_tobytes(out + k * POINT_BYTES, &commit);
        }
    }

    return 0;
}

int c_batch_pedersen_commit_raw(ge25519_p3         **results_out,
                                 const unsigned char *values,
                                 const unsigned char *blinders,
                                 const PrecompTable  *tbl_G,
                                 const PrecompTable  *tbl_H,
                                 int                  n)
{
    ge25519_p3 *block = (ge25519_p3 *)malloc(n * sizeof(ge25519_p3));
    if (!block) return -1;
    for (int k = 0; k < n; k++)
        results_out[k] = &block[k];

    #pragma omp parallel
    {
        ge25519_p3     vG, rH;
        ge25519_p1p1   tmp;
        ge25519_cached cached;

        #pragma omp for schedule(dynamic, 64)
        for (int k = 0; k < n; k++) {
            zero_dbl_scalarmult(&vG, values   + k * SCALAR_BYTES, tbl_G);
            zero_dbl_scalarmult(&rH, blinders + k * SCALAR_BYTES, tbl_H);
            ge25519_p3_to_cached(&cached, &rH);
            ge25519_add(&tmp, &vG, &cached);
            ge25519_p1p1_to_p3(results_out[k], &tmp);
        }
    }
    return 0;
}

/* ── Batch encode ────────────────────────────────────────────────── */

/*
 * c_batch_scalarmult_encode
 *
 * Like c_batch_scalarmult_raw but encodes each result to ristretto255
 * entirely in C — no Python RawPoint objects created.
 *
 * out     — n × 32 byte output buffer (caller allocated)
 * scalars — n × 32 byte packed scalars
 * tbl     — precomputed table
 * n       — number of scalarmults
 */
int c_batch_scalarmult_encode(unsigned char       *out,
                               const unsigned char *scalars,
                               const PrecompTable  *tbl,
                               int                  n)
{
    int nthreads = omp_get_max_threads();

    PrecompTable **thread_tables =
        (PrecompTable **)malloc(nthreads * sizeof(PrecompTable *));
    if (!thread_tables) return -1;

    for (int t = 0; t < nthreads; t++) {
        thread_tables[t] = (PrecompTable *)malloc(sizeof(PrecompTable));
        if (!thread_tables[t]) {
            for (int j = 0; j < t; j++) free(thread_tables[j]);
            free(thread_tables);
            return -1;
        }
        memcpy(thread_tables[t], tbl, sizeof(PrecompTable));
    }

    #pragma omp parallel
    {
        int        tid = omp_get_thread_num();
        ge25519_p3 result;

        #pragma omp for schedule(dynamic, 64)
        for (int k = 0; k < n; k++) {
            zero_dbl_scalarmult(&result, scalars + k * SCALAR_BYTES,
                                thread_tables[tid]);
            ristretto255_p3_tobytes(out + k * POINT_BYTES, &result);
        }
    }

    for (int t = 0; t < nthreads; t++) {
        memset(thread_tables[t], 0, sizeof(PrecompTable));
        free(thread_tables[t]);
    }
    free(thread_tables);
    return 0;
}

/* ── Public ABI ─────────────────────────────────────────────────── */

int precomp_scalarmult(unsigned char       *out,
                       const unsigned char *scalar_bytes,
                       const PrecompTable  *tbl)
{
    ge25519_p3 result;
    zero_dbl_scalarmult(&result, scalar_bytes, tbl);
    ristretto255_p3_tobytes(out, &result);
    return 0;
}


ge25519_p3 *c_scalarmult_raw(const unsigned char *scalar_bytes,
                              const PrecompTable  *tbl)
{
    ge25519_p3 *result = (ge25519_p3 *)malloc(sizeof(ge25519_p3));
    if (!result) return NULL;
    zero_dbl_scalarmult(result, scalar_bytes, tbl);
    return result;
}

ge25519_p3 *c_point_add_raw(const ge25519_p3 *a, const ge25519_p3 *b)
{
    ge25519_p3    *result = (ge25519_p3 *)malloc(sizeof(ge25519_p3));
    ge25519_p1p1   tmp;
    ge25519_cached cached;
    if (!result) return NULL;
    ge25519_p3_to_cached(&cached, b);
    ge25519_add(&tmp, a, &cached);
    ge25519_p1p1_to_p3(result, &tmp);
    return result;
}

void c_free_raw(ge25519_p3 *point)
{
    if (point) { memset(point, 0, sizeof(ge25519_p3)); free(point); }
}

ge25519_p3 *c_point_sub_raw(const ge25519_p3 *a, const ge25519_p3 *b)
{
    ge25519_p3    *result = (ge25519_p3 *)malloc(sizeof(ge25519_p3));
    ge25519_p1p1   tmp;
    ge25519_cached cached;
    if (!result) return NULL;
    ge25519_p3_to_cached(&cached, b);
    ge25519_sub(&tmp, a, &cached);
    ge25519_p1p1_to_p3(result, &tmp);
    return result;
}

ge25519_p3 *c_point_neg_raw(const ge25519_p3 *p)
{
    ge25519_p3     identity;
    ge25519_p3    *result = (ge25519_p3 *)malloc(sizeof(ge25519_p3));
    ge25519_p1p1   tmp;
    ge25519_cached cached;
    if (!result) return NULL;

    /* Identity point (0:1:1:0) */
    memset(&identity, 0, sizeof(identity));
    fe25519_1(identity.Y);
    fe25519_1(identity.Z);

    ge25519_p3_to_cached(&cached, p);
    ge25519_sub(&tmp, &identity, &cached);
    ge25519_p1p1_to_p3(result, &tmp);
    return result;
}

int c_encode_raw(unsigned char *out, const ge25519_p3 *point)
{
    ristretto255_p3_tobytes(out, point);
    return 0;
}


void precomp_free(PrecompTable *tbl)
{
    if (tbl) { memset(tbl, 0, sizeof(PrecompTable)); free(tbl); }
}

PrecompTable *c_precomp_build(const unsigned char *point_bytes)
{
    PrecompTable *tbl = NULL;
    if (precomp_build(&tbl, point_bytes) != 0) return NULL;
    return tbl;
}

int c_precomp_scalarmult(unsigned char       *out,
                         const unsigned char *scalar_bytes,
                         PrecompTable        *tbl)
{
    return precomp_scalarmult(out, scalar_bytes, tbl);
}

void c_precomp_free(PrecompTable *tbl) { precomp_free(tbl); }

/* ── Multiscalar Multiplication ─────────────────────────────────── */

/*
 * c_multiscalar_mult_raw
 *
 * Compute result = sum_k scalar_k * P_k  for k in [0, n)
 * using n precomputed windowed tables.
 *
 * Strategy: interleave all bases window-by-window.
 *   For each window index i across [0, NUM_WINDOWS):
 *     For each base k across [0, n):
 *       w = scalar_k[window i]
 *       if w != 0: result += table_k[i][w-1]
 *
 * This visits every table[k][i] row once per window pass, keeping
 * the active row hot in L1/L2 rather than doing N full-table scans.
 *
 * For n >= OMP thread count, parallelises by splitting bases into
 * per-thread chunks, each computing a local partial sum, then
 * reducing the partial sums sequentially (thread count is small).
 *
 * scalars  — packed n × SCALAR_BYTES little-endian scalars
 * tables   — array of n PrecompTable pointers (one per base point)
 * n        — number of (scalar, point) pairs
 *
 * Returns heap-allocated ge25519_p3, or NULL on alloc failure.
 * Caller must free with c_free_raw().
 */
ge25519_p3 *c_multiscalar_mult_raw(const unsigned char  *scalars,
                                    const PrecompTable  **tables,
                                    int                   n)
{
    if (n <= 0) return NULL;

    /* Reduce all scalars upfront — avoids repeated reductions inside threads */
    unsigned char *red = (unsigned char *)malloc(n * SCALAR_BYTES);
    if (!red) return NULL;
    for (int k = 0; k < n; k++)
        reduce_scalar(red + k * SCALAR_BYTES, scalars + k * SCALAR_BYTES);

    int nthreads = omp_get_max_threads();
    if (nthreads > n) nthreads = n;   /* no point spawning more threads than bases */

    /* One partial accumulator per thread */
    ge25519_p3 *partials     = (ge25519_p3 *)malloc(nthreads * sizeof(ge25519_p3));
    int        *partial_used = (int         *)calloc(nthreads,  sizeof(int));

    if (!partials || !partial_used) {
        free(red); free(partials); free(partial_used);
        return NULL;
    }

    #pragma omp parallel num_threads(nthreads)
    {
        int tid         = omp_get_thread_num();
        int chunk_start = (tid       * n) / nthreads;
        int chunk_end   = ((tid + 1) * n) / nthreads;

        ge25519_p1p1   tmp;
        ge25519_cached cached;
        int            first = 1;

        /*
         * Interleave window-first, base-second within this thread's chunk.
         * Each window row table[k][i] is a contiguous ge25519_p3 (160 B);
         * the inner k-loop streams through n such rows before advancing i.
         */
        for (int i = 0; i < NUM_WINDOWS; i++) {
            for (int k = chunk_start; k < chunk_end; k++) {
                uint32_t w = extract_window(red + k * SCALAR_BYTES,
                                            i * WINDOW_BITS);
                if (w == 0) continue;

                const ge25519_p3 *pt = &tables[k]->table[i][w - 1];

                if (first) {
                    partials[tid] = *pt;
                    first         = 0;
                } else {
                    ge25519_p3_to_cached(&cached, pt);
                    ge25519_add(&tmp, &partials[tid], &cached);
                    ge25519_p1p1_to_p3(&partials[tid], &tmp);
                }
            }
        }

        partial_used[tid] = !first;
    } /* end parallel */

    /* Sequential reduction of at most nthreads partial sums */
    ge25519_p3    *result = (ge25519_p3 *)malloc(sizeof(ge25519_p3));
    ge25519_p1p1   tmp;
    ge25519_cached cached;
    int            first = 1;

    if (result) {
        for (int t = 0; t < nthreads; t++) {
            if (!partial_used[t]) continue;
            if (first) {
                *result = partials[t];
                first   = 0;
            } else {
                ge25519_p3_to_cached(&cached, &partials[t]);
                ge25519_add(&tmp, result, &cached);
                ge25519_p1p1_to_p3(result, &tmp);
            }
        }

        if (first) {
            /* All scalars were 0 mod l — return identity */
            memset(result, 0, sizeof(ge25519_p3));
            fe25519_1(result->Y);
            fe25519_1(result->Z);
        }
    }

    memset(red,      0, n * SCALAR_BYTES);
    memset(partials, 0, nthreads * sizeof(ge25519_p3));
    free(red);
    free(partials);
    free(partial_used);
    return result;
}

/*
 * c_multiscalar_mult_encode
 *
 * Like c_multiscalar_mult_raw but encodes the result to a 32-byte
 * ristretto255 point directly in C.
 *
 * out     — 32-byte output buffer (caller allocated)
 * scalars — packed n × SCALAR_BYTES little-endian scalars
 * tables  — array of n PrecompTable pointers
 * n       — number of (scalar, point) pairs
 *
 * Returns 0 on success, -1 on allocation failure.
 */
int c_multiscalar_mult_encode(unsigned char       *out,
                               const unsigned char *scalars,
                               const PrecompTable **tables,
                               int                  n)
{
    ge25519_p3 *result = c_multiscalar_mult_raw(scalars, tables, n);
    if (!result) return -1;
    ristretto255_p3_tobytes(out, result);
    memset(result, 0, sizeof(ge25519_p3));
    free(result);
    return 0;
}

/*
 * c_batch_multiscalar_mult_raw
 *
 * Compute batch_size independent MSMs in parallel:
 *   result_m = sum_k scalar_{m,k} * P_k   for m in [0, batch_size)
 *
 * All batch items share the same set of n base-point tables (same
 * generators, different scalar vectors — the Bulletproofs pattern).
 *
 * Memory layout of `scalars`:
 *   scalars[m * n * SCALAR_BYTES + k * SCALAR_BYTES ... +32]
 *   i.e. batch-major: all n scalars for MSM m are contiguous.
 *
 * results_out — caller-allocated array of batch_size ge25519_p3 pointers;
 *               all points live in one contiguous block.
 *               Free with c_free_batch(results_out[0]).
 * scalars     — batch_size × n × SCALAR_BYTES packed scalars
 * tables      — n PrecompTable pointers, shared across all batch items
 * n           — number of (scalar, point) pairs per MSM
 * batch_size  — number of independent MSMs
 *
 * Returns 0 on success, -1 on allocation failure.
 */
int c_batch_multiscalar_mult_raw(ge25519_p3         **results_out,
                                  const unsigned char *scalars,
                                  const PrecompTable **tables,
                                  int                  n,
                                  int                  batch_size)
{
    if (n <= 0 || batch_size <= 0) return -1;

    /* Single contiguous block for all batch results */
    ge25519_p3 *block = (ge25519_p3 *)malloc(batch_size * sizeof(ge25519_p3));
    if (!block) return -1;
    for (int m = 0; m < batch_size; m++)
        results_out[m] = &block[m];

    /* Pre-reduce every scalar: batch_size × n scalars total */
    size_t total_scalars = (size_t)batch_size * n;
    unsigned char *red = (unsigned char *)malloc(total_scalars * SCALAR_BYTES);
    if (!red) { free(block); return -1; }

    for (size_t idx = 0; idx < total_scalars; idx++)
        reduce_scalar(red + idx * SCALAR_BYTES,
                      scalars + idx * SCALAR_BYTES);

    /*
     * Outer parallel loop over batch items — each thread owns one MSM
     * at a time and iterates window-by-window over all n bases.
     * schedule(dynamic, 1) handles uneven work per MSM (sparse scalars
     * cause short-circuit; dense scalars run longer).
     */
    #pragma omp parallel
    {
        ge25519_p1p1   tmp;
        ge25519_cached cached;

        #pragma omp for schedule(dynamic, 1)
        for (int m = 0; m < batch_size; m++) {
            const unsigned char *s_row = red + (size_t)m * n * SCALAR_BYTES;
            ge25519_p3          *res   = results_out[m];
            int                  first = 1;

            for (int i = 0; i < NUM_WINDOWS; i++) {
                for (int k = 0; k < n; k++) {
                    uint32_t w = extract_window(s_row + k * SCALAR_BYTES,
                                                i * WINDOW_BITS);
                    if (w == 0) continue;

                    const ge25519_p3 *pt = &tables[k]->table[i][w - 1];

                    if (first) {
                        *res  = *pt;
                        first = 0;
                    } else {
                        ge25519_p3_to_cached(&cached, pt);
                        ge25519_add(&tmp, res, &cached);
                        ge25519_p1p1_to_p3(res, &tmp);
                    }
                }
            }

            if (first) {
                /* All scalars zero mod l for this batch item — identity */
                memset(res, 0, sizeof(ge25519_p3));
                fe25519_1(res->Y);
                fe25519_1(res->Z);
            }
        }
    } /* end parallel */

    memset(red, 0, total_scalars * SCALAR_BYTES);
    free(red);
    return 0;
}

/*
 * c_batch_multiscalar_mult_encode
 *
 * Like c_batch_multiscalar_mult_raw but encodes every result to
 * ristretto255 bytes directly in C — no RawPoint objects allocated.
 *
 * out        — batch_size × 32-byte output buffer (caller allocated)
 * scalars    — batch_size × n × SCALAR_BYTES packed scalars
 * tables     — n PrecompTable pointers, shared across all batch items
 * n          — number of (scalar, point) pairs per MSM
 * batch_size — number of independent MSMs
 *
 * Returns 0 on success, -1 on allocation failure.
 */
int c_batch_multiscalar_mult_encode(unsigned char       *out,
                                     const unsigned char *scalars,
                                     const PrecompTable **tables,
                                     int                  n,
                                     int                  batch_size)
{
    if (n <= 0 || batch_size <= 0) return -1;

    size_t total_scalars = (size_t)batch_size * n;
    unsigned char *red = (unsigned char *)malloc(total_scalars * SCALAR_BYTES);
    if (!red) return -1;

    for (size_t idx = 0; idx < total_scalars; idx++)
        reduce_scalar(red + idx * SCALAR_BYTES,
                      scalars + idx * SCALAR_BYTES);

    #pragma omp parallel
    {
        ge25519_p1p1   tmp;
        ge25519_cached cached;
        ge25519_p3     res;

        #pragma omp for schedule(dynamic, 1)
        for (int m = 0; m < batch_size; m++) {
            const unsigned char *s_row = red + (size_t)m * n * SCALAR_BYTES;
            int                  first = 1;

            for (int i = 0; i < NUM_WINDOWS; i++) {
                for (int k = 0; k < n; k++) {
                    uint32_t w = extract_window(s_row + k * SCALAR_BYTES,
                                                i * WINDOW_BITS);
                    if (w == 0) continue;

                    const ge25519_p3 *pt = &tables[k]->table[i][w - 1];

                    if (first) {
                        res   = *pt;
                        first = 0;
                    } else {
                        ge25519_p3_to_cached(&cached, pt);
                        ge25519_add(&tmp, &res, &cached);
                        ge25519_p1p1_to_p3(&res, &tmp);
                    }
                }
            }

            if (first) {
                memset(&res, 0, sizeof(ge25519_p3));
                fe25519_1(res.Y);
                fe25519_1(res.Z);
            }

            ristretto255_p3_tobytes(out + m * POINT_BYTES, &res);
        }
    }

    memset(red, 0, total_scalars * SCALAR_BYTES);
    free(red);
    return 0;
}

/*
 * c_scalarmult_point_raw
 *
 * One-shot variable-base scalar multiplication: scalar * point.
 * No precomputed table — use this for single-use bases where table
 * build cost would exceed the savings.
 *
 * Internally: encode → crypto_scalarmult_ristretto255 → decode back to p3.
 * Cost: ~2 field encodes + one variable-base scalarmult. No heap table.
 */
ge25519_p3 *c_scalarmult_point_raw(const unsigned char *scalar_bytes,
                                    const ge25519_p3    *point)
{
    ge25519_p3    *result = (ge25519_p3 *)malloc(sizeof(ge25519_p3));
    unsigned char  encoded[32], out[32];
    if (!result) return NULL;

    ristretto255_p3_tobytes(encoded, point);
    if (crypto_scalarmult_ristretto255(out, scalar_bytes, encoded) != 0) {
        free(result);
        return NULL;
    }
    if (ristretto255_frombytes(result, out) != 0) {
        free(result);
        return NULL;
    }
    return result;
}

/* ── Short-scalar MSM with subset-sum tables ─────────────────────── */
/*
 * Two variants that compute  result = sum_{k=0}^{n-1} s_k * P_k
 * where points are given as ordinary 32-byte ristretto255 encodings
 * (no precomputed windowed tables required).
 *
 * Both split the n points into ceil(n / MSM_BATCH) buckets and build a
 * subset-sum table of 2^MSM_BATCH entries per bucket:
 *
 *   table[idx] = sum of P_k  where bit k of idx is 1
 *
 * Variant 1 — double-and-add  (c_short_msm_raw / _encode)
 *   One table per bucket.  Evaluation iterates scalar bits MSB→LSB,
 *   doubling the accumulator at each step, then adding the table entry
 *   for each bucket.  Cost: scalar_bits doublings + scalar_bits×buckets
 *   additions.  Minimal memory.
 *
 * Variant 2 — zero-doubling  (c_short_msm_zd_raw / _encode)
 *   scalar_bits tables per bucket, each derived by doubling every entry
 *   of the previous level.  Evaluation is additions only — zero doublings.
 *   Cost: scalar_bits×buckets additions at eval, but
 *   (scalar_bits−1)×2^MSM_BATCH doublings + 2^MSM_BATCH−MSM_BATCH−1
 *   additions per bucket at build time.  More memory.
 *
 * MSM_BATCH sizes (entries per table = 2^MSM_BATCH):
 *   MSM_BATCH=4    16 entries/bucket    2.5 KB
 *   MSM_BATCH=6    64 entries/bucket     10 KB
 *   MSM_BATCH=8   256 entries/bucket     40 KB
 *   MSM_BATCH=10 1024 entries/bucket    160 KB
 */

#ifndef MSM_BATCH
#define MSM_BATCH 8
#endif
#define MSM_TBL_SZ (1 << MSM_BATCH)   /* 2^B entries per bucket */

/* Extract a single bit from a little-endian scalar. */
static inline int scalar_bit(const unsigned char *s, int pos)
{
    return (s[pos >> 3] >> (pos & 7)) & 1;
}

/* Build subset-sum table for one bucket of batch_n points.
 * tbl must have room for MSM_TBL_SZ ge25519_p3 entries.
 * Only indices 0 .. 2^batch_n − 1 are meaningful.             */
static void build_subset_sum(ge25519_p3       *tbl,
                             const ge25519_p3 *pts,
                             int               batch_n)
{
    /* tbl[0] = identity */
    memset(&tbl[0], 0, sizeof(ge25519_p3));
    fe25519_1(tbl[0].Y);
    fe25519_1(tbl[0].Z);

    ge25519_p1p1   tmp;
    ge25519_cached cached;

    for (int k = 0; k < batch_n; k++) {
        int pk = 1 << k;
        tbl[pk] = pts[k];
        ge25519_p3_to_cached(&cached, &pts[k]);
        for (int idx = 1; idx < pk; idx++) {
            ge25519_add(&tmp, &tbl[idx], &cached);
            ge25519_p1p1_to_p3(&tbl[pk | idx], &tmp);
        }
    }
}

/* Form MSM_BATCH-bit index from bit `bit_pos` of each scalar in a bucket. */
static inline uint32_t form_bucket_index(const unsigned char *scalars,
                                         int base, int batch_n,
                                         int bit_pos)
{
    uint32_t idx = 0;
    for (int k = 0; k < batch_n; k++)
        idx |= (uint32_t)scalar_bit(scalars + (base + k) * SCALAR_BYTES,
                                     bit_pos) << k;
    return idx;
}

/* ── Variant 1: double-and-add ──────────────────────────────────── */

ge25519_p3 *c_short_msm_raw(const unsigned char *scalars,
                              const unsigned char *points,
                              int                  n,
                              int                  scalar_bits)
{
    if (n <= 0 || scalar_bits <= 0) return NULL;
    if (scalar_bits > 256) scalar_bits = 256;

    int B           = MSM_BATCH;
    int num_buckets = (n + B - 1) / B;

    /* Decode all points */
    ge25519_p3 *decoded = (ge25519_p3 *)malloc(n * sizeof(ge25519_p3));
    if (!decoded) return NULL;
    for (int i = 0; i < n; i++) {
        if (ristretto255_frombytes(&decoded[i],
                                    points + i * POINT_BYTES) != 0) {
            free(decoded);
            return NULL;
        }
    }

    /* Reduce all scalars */
    unsigned char *red = (unsigned char *)malloc(n * SCALAR_BYTES);
    if (!red) { free(decoded); return NULL; }
    for (int i = 0; i < n; i++)
        reduce_scalar(red + i * SCALAR_BYTES, scalars + i * SCALAR_BYTES);

    /* Build one subset-sum table per bucket (parallelised) */
    ge25519_p3 *tables = (ge25519_p3 *)malloc(
        (size_t)num_buckets * MSM_TBL_SZ * sizeof(ge25519_p3));
    if (!tables) { free(red); free(decoded); return NULL; }

    #pragma omp parallel for schedule(static)
    for (int b = 0; b < num_buckets; b++) {
        int base    = b * B;
        int batch_n = (base + B <= n) ? B : (n - base);
        build_subset_sum(tables + (size_t)b * MSM_TBL_SZ,
                         decoded + base, batch_n);
    }
    free(decoded);

    /* Evaluate: double-and-add from MSB to LSB */
    ge25519_p3     result;
    ge25519_p1p1   tmp;
    ge25519_cached cached;
    int            first = 1;

    for (int j = scalar_bits - 1; j >= 0; j--) {
        if (!first)
            p3_double(&result, &result);

        for (int b = 0; b < num_buckets; b++) {
            int base    = b * B;
            int batch_n = (base + B <= n) ? B : (n - base);
            ge25519_p3 *tbl = tables + (size_t)b * MSM_TBL_SZ;

            uint32_t idx = form_bucket_index(red, base, batch_n, j);
            if (idx == 0) continue;

            if (first) {
                result = tbl[idx];
                first  = 0;
            } else {
                ge25519_p3_to_cached(&cached, &tbl[idx]);
                ge25519_add(&tmp, &result, &cached);
                ge25519_p1p1_to_p3(&result, &tmp);
            }
        }
    }

    ge25519_p3 *out = (ge25519_p3 *)malloc(sizeof(ge25519_p3));
    if (!out) { free(red); free(tables); return NULL; }
    if (first) {
        memset(out, 0, sizeof(ge25519_p3));
        fe25519_1(out->Y);
        fe25519_1(out->Z);
    } else {
        *out = result;
    }

    memset(red, 0, (size_t)n * SCALAR_BYTES);
    free(red);
    free(tables);
    return out;
}

int c_short_msm_encode(unsigned char       *out,
                        const unsigned char *scalars,
                        const unsigned char *points,
                        int                  n,
                        int                  scalar_bits)
{
    ge25519_p3 *r = c_short_msm_raw(scalars, points, n, scalar_bits);
    if (!r) return -1;
    ristretto255_p3_tobytes(out, r);
    memset(r, 0, sizeof(ge25519_p3));
    free(r);
    return 0;
}

/* ── Variant 2: zero-doubling ───────────────────────────────────── */
/*
 * Table layout per bucket:
 *   level_tables[j * MSM_TBL_SZ + idx] = 2^j * subset_sum[idx]
 *
 * Built by doubling every entry of the previous level.
 * Memory per bucket: scalar_bits × 2^MSM_BATCH × sizeof(ge25519_p3).
 */

ge25519_p3 *c_short_msm_zd_raw(const unsigned char *scalars,
                                 const unsigned char *points,
                                 int                  n,
                                 int                  scalar_bits)
{
    if (n <= 0 || scalar_bits <= 0) return NULL;
    if (scalar_bits > 256) scalar_bits = 256;

    int B           = MSM_BATCH;
    int num_buckets = (n + B - 1) / B;
    size_t lvl_sz   = (size_t)MSM_TBL_SZ;          /* entries per level     */
    size_t bkt_sz   = (size_t)scalar_bits * lvl_sz; /* entries per bucket    */

    /* Decode all points */
    ge25519_p3 *decoded = (ge25519_p3 *)malloc(n * sizeof(ge25519_p3));
    if (!decoded) return NULL;
    for (int i = 0; i < n; i++) {
        if (ristretto255_frombytes(&decoded[i],
                                    points + i * POINT_BYTES) != 0) {
            free(decoded);
            return NULL;
        }
    }

    /* Reduce all scalars */
    unsigned char *red = (unsigned char *)malloc(n * SCALAR_BYTES);
    if (!red) { free(decoded); return NULL; }
    for (int i = 0; i < n; i++)
        reduce_scalar(red + i * SCALAR_BYTES, scalars + i * SCALAR_BYTES);

    /* Allocate all level tables for all buckets */
    ge25519_p3 *tables = (ge25519_p3 *)malloc(
        (size_t)num_buckets * bkt_sz * sizeof(ge25519_p3));
    if (!tables) { free(red); free(decoded); return NULL; }

    /* Build tables per bucket — parallelise across buckets */
    #pragma omp parallel for schedule(static)
    for (int b = 0; b < num_buckets; b++) {
        int base    = b * B;
        int batch_n = (base + B <= n) ? B : (n - base);
        ge25519_p3 *bkt = tables + (size_t)b * bkt_sz;

        /* Level 0: base subset-sum table */
        build_subset_sum(bkt, decoded + base, batch_n);

        /* Levels 1 .. scalar_bits-1: double every entry from previous level */
        int active_entries = 1 << batch_n;   /* only these indices are used */
        for (int j = 1; j < scalar_bits; j++) {
            ge25519_p3 *prev = bkt + (size_t)(j - 1) * lvl_sz;
            ge25519_p3 *cur  = bkt + (size_t)j       * lvl_sz;

            /* Identity at index 0 stays identity after doubling */
            memset(&cur[0], 0, sizeof(ge25519_p3));
            fe25519_1(cur[0].Y);
            fe25519_1(cur[0].Z);

            for (int idx = 1; idx < active_entries; idx++)
                p3_double(&cur[idx], &prev[idx]);
        }
    }
    free(decoded);

    /* Evaluate: additions only, zero doublings */
    ge25519_p3     result;
    ge25519_p1p1   tmp;
    ge25519_cached cached;
    int            first = 1;

    for (int j = 0; j < scalar_bits; j++) {
        for (int b = 0; b < num_buckets; b++) {
            int base    = b * B;
            int batch_n = (base + B <= n) ? B : (n - base);
            ge25519_p3 *lvl = tables + (size_t)b * bkt_sz
                                     + (size_t)j * lvl_sz;

            uint32_t idx = form_bucket_index(red, base, batch_n, j);
            if (idx == 0) continue;

            if (first) {
                result = lvl[idx];
                first  = 0;
            } else {
                ge25519_p3_to_cached(&cached, &lvl[idx]);
                ge25519_add(&tmp, &result, &cached);
                ge25519_p1p1_to_p3(&result, &tmp);
            }
        }
    }

    ge25519_p3 *out = (ge25519_p3 *)malloc(sizeof(ge25519_p3));
    if (!out) { free(red); free(tables); return NULL; }
    if (first) {
        memset(out, 0, sizeof(ge25519_p3));
        fe25519_1(out->Y);
        fe25519_1(out->Z);
    } else {
        *out = result;
    }

    memset(red, 0, (size_t)n * SCALAR_BYTES);
    free(red);
    free(tables);
    return out;
}

int c_short_msm_zd_encode(unsigned char       *out,
                            const unsigned char *scalars,
                            const unsigned char *points,
                            int                  n,
                            int                  scalar_bits)
{
    ge25519_p3 *r = c_short_msm_zd_raw(scalars, points, n, scalar_bits);
    if (!r) return -1;
    ristretto255_p3_tobytes(out, r);
    memset(r, 0, sizeof(ge25519_p3));
    free(r);
    return 0;
}

/* ── Batch short-scalar MSM ─────────────────────────────────────── */
/*
 * c_batch_short_msm_raw
 *
 * Compute batch_size independent MSMs in parallel:
 *   result_m = sum_{k=0}^{n-1} scalar_{m,k} * P_k
 *
 * The n points are the SAME for every batch item — only the scalar
 * vectors differ.  This lets us build the subset-sum tables exactly
 * ONCE and reuse them across all batch_size evaluations, which is
 * the dominant cost saving over calling c_short_msm_raw in a loop.
 *
 * Memory layout of `scalars`:
 *   scalars[m * n * SCALAR_BYTES + k * SCALAR_BYTES ... +32]
 *   batch-major: all n scalars for item m are contiguous.
 *
 * Parameters:
 *   results_out — caller-allocated array of batch_size ge25519_p3*;
 *                 all points live in one contiguous block.
 *                 Free with c_free_batch(results_out[0]).
 *   scalars     — batch_size × n × SCALAR_BYTES packed scalars
 *   points      — n × POINT_BYTES ristretto255-encoded base points
 *   n           — number of (scalar, point) pairs per MSM
 *   batch_size  — number of independent MSMs
 *   scalar_bits — effective bit-length of the scalars
 *
 * Returns 0 on success, -1 on failure.
 */
int c_batch_short_msm_raw(ge25519_p3         **results_out,
                           const unsigned char *scalars,
                           const unsigned char *points,
                           int                  n,
                           int                  batch_size,
                           int                  scalar_bits)
{
    if (n <= 0 || batch_size <= 0 || scalar_bits <= 0) return -1;
    if (scalar_bits > 256) scalar_bits = 256;

    int    B           = MSM_BATCH;
    int    num_buckets = (n + B - 1) / B;
    size_t total_s     = (size_t)batch_size * n;

    /* Single contiguous block for all results */
    ge25519_p3 *block = (ge25519_p3 *)malloc(batch_size * sizeof(ge25519_p3));
    if (!block) return -1;
    for (int m = 0; m < batch_size; m++)
        results_out[m] = &block[m];

    /* Decode the n base points once */
    ge25519_p3 *decoded = (ge25519_p3 *)malloc(n * sizeof(ge25519_p3));
    if (!decoded) { free(block); return -1; }
    for (int i = 0; i < n; i++) {
        if (ristretto255_frombytes(&decoded[i],
                                    points + i * POINT_BYTES) != 0) {
            free(decoded); free(block); return -1;
        }
    }

    /* Reduce all batch_size × n scalars up front */
    unsigned char *red = (unsigned char *)malloc(total_s * SCALAR_BYTES);
    if (!red) { free(decoded); free(block); return -1; }
    for (size_t idx = 0; idx < total_s; idx++)
        reduce_scalar(red + idx * SCALAR_BYTES,
                      scalars + idx * SCALAR_BYTES);

    /* Build subset-sum tables once — shared read-only across all threads */
    ge25519_p3 *tables = (ge25519_p3 *)malloc(
        (size_t)num_buckets * MSM_TBL_SZ * sizeof(ge25519_p3));
    if (!tables) { free(red); free(decoded); free(block); return -1; }

    #pragma omp parallel for schedule(static)
    for (int b = 0; b < num_buckets; b++) {
        int base    = b * B;
        int batch_n = (base + B <= n) ? B : (n - base);
        build_subset_sum(tables + (size_t)b * MSM_TBL_SZ,
                         decoded + base, batch_n);
    }
    free(decoded);

    ge25519_p3 identity;
    memset(&identity, 0, sizeof(identity));
    fe25519_1(identity.Y);
    fe25519_1(identity.Z);

    /*
     * Evaluate all batch_size MSMs in parallel.
     * Tables are read-only — no synchronisation needed.
     * schedule(dynamic,1): uneven sparsity across scalar rows.
     */
    #pragma omp parallel for schedule(dynamic, 1)
    for (int m = 0; m < batch_size; m++) {
        const unsigned char *s_row = red + (size_t)m * n * SCALAR_BYTES;
        ge25519_p3    *res = results_out[m];
        ge25519_p1p1   tmp;
        ge25519_cached cached;
        int            first = 1;

        for (int j = scalar_bits - 1; j >= 0; j--) {
            if (!first)
                p3_double(res, res);

            for (int b = 0; b < num_buckets; b++) {
                int base    = b * B;
                int batch_n = (base + B <= n) ? B : (n - base);
                ge25519_p3 *tbl = tables + (size_t)b * MSM_TBL_SZ;

                uint32_t idx = form_bucket_index(s_row, base, batch_n, j);
                if (idx == 0) continue;

                if (first) {
                    *res  = tbl[idx];
                    first = 0;
                } else {
                    ge25519_p3_to_cached(&cached, &tbl[idx]);
                    ge25519_add(&tmp, res, &cached);
                    ge25519_p1p1_to_p3(res, &tmp);
                }
            }
        }

        if (first)
            *res = identity;
    }

    memset(red, 0, total_s * SCALAR_BYTES);
    free(red);
    free(tables);
    return 0;
}

/*
 * c_batch_short_msm_encode
 *
 * Like c_batch_short_msm_raw but encodes each result to a 32-byte
 * ristretto255 point entirely in C — no RawPoint objects allocated.
 *
 * out        — batch_size × POINT_BYTES output buffer (caller allocated)
 * scalars    — batch_size × n × SCALAR_BYTES packed scalars
 * points     — n × POINT_BYTES ristretto255-encoded base points
 * n          — number of (scalar, point) pairs per MSM
 * batch_size — number of independent MSMs
 * scalar_bits — effective bit-length of the scalars
 */
int c_batch_short_msm_encode(unsigned char       *out,
                               const unsigned char *scalars,
                               const unsigned char *points,
                               int                  n,
                               int                  batch_size,
                               int                  scalar_bits)
{
    if (n <= 0 || batch_size <= 0 || scalar_bits <= 0) return -1;
    if (scalar_bits > 256) scalar_bits = 256;

    int    B           = MSM_BATCH;
    int    num_buckets = (n + B - 1) / B;
    size_t total_s     = (size_t)batch_size * n;

    ge25519_p3 *decoded = (ge25519_p3 *)malloc(n * sizeof(ge25519_p3));
    if (!decoded) return -1;
    for (int i = 0; i < n; i++) {
        if (ristretto255_frombytes(&decoded[i],
                                    points + i * POINT_BYTES) != 0) {
            free(decoded); return -1;
        }
    }

    unsigned char *red = (unsigned char *)malloc(total_s * SCALAR_BYTES);
    if (!red) { free(decoded); return -1; }
    for (size_t idx = 0; idx < total_s; idx++)
        reduce_scalar(red + idx * SCALAR_BYTES,
                      scalars + idx * SCALAR_BYTES);

    ge25519_p3 *tables = (ge25519_p3 *)malloc(
        (size_t)num_buckets * MSM_TBL_SZ * sizeof(ge25519_p3));
    if (!tables) { free(red); free(decoded); return -1; }

    #pragma omp parallel for schedule(static)
    for (int b = 0; b < num_buckets; b++) {
        int base    = b * B;
        int batch_n = (base + B <= n) ? B : (n - base);
        build_subset_sum(tables + (size_t)b * MSM_TBL_SZ,
                         decoded + base, batch_n);
    }
    free(decoded);

    ge25519_p3 identity;
    memset(&identity, 0, sizeof(identity));
    fe25519_1(identity.Y);
    fe25519_1(identity.Z);

    #pragma omp parallel for schedule(dynamic, 1)
    for (int m = 0; m < batch_size; m++) {
        const unsigned char *s_row = red + (size_t)m * n * SCALAR_BYTES;
        ge25519_p3     res;
        ge25519_p1p1   tmp;
        ge25519_cached cached;
        int            first = 1;

        for (int j = scalar_bits - 1; j >= 0; j--) {
            if (!first)
                p3_double(&res, &res);

            for (int b = 0; b < num_buckets; b++) {
                int base    = b * B;
                int batch_n = (base + B <= n) ? B : (n - base);
                ge25519_p3 *tbl = tables + (size_t)b * MSM_TBL_SZ;

                uint32_t idx = form_bucket_index(s_row, base, batch_n, j);
                if (idx == 0) continue;

                if (first) {
                    res   = tbl[idx];
                    first = 0;
                } else {
                    ge25519_p3_to_cached(&cached, &tbl[idx]);
                    ge25519_add(&tmp, &res, &cached);
                    ge25519_p1p1_to_p3(&res, &tmp);
                }
            }
        }

        if (first)
            res = identity;
        ristretto255_p3_tobytes(out + m * POINT_BYTES, &res);
    }

    memset(red, 0, total_s * SCALAR_BYTES);
    free(red);
    free(tables);
    return 0;
}

/* ── Auto-width batch short-scalar MSM ──────────────────────────── */
/*
 * Like c_batch_short_msm_raw / _encode but with NO scalar_bits parameter.
 * Instead the function scans all reduced scalars to find the position of
 * the highest set bit, then iterates exactly that many bit positions.
 *
 * Padded zero bytes in the scalar buffers cost nothing: a batch of
 * 8-bit scalars stored in 32-byte LE buffers runs in the same time as
 * if scalar_bits=8 had been passed explicitly.
 */

/* Return the number of bit positions needed to represent the largest
 * value across total_n packed little-endian scalars (SCALAR_BYTES each).
 * Returns 1 when every scalar is zero so the eval loop runs once and
 * produces the identity correctly.                                   */
static int max_scalar_bitlen(const unsigned char *red, size_t total_n)
{
    int max_bit = 0;
    for (size_t k = 0; k < total_n; k++) {
        const unsigned char *s = red + k * SCALAR_BYTES;
        for (int byte = SCALAR_BYTES - 1; byte >= 0; byte--) {
            if (s[byte]) {
                int b = byte * 8 + (31 - __builtin_clz((unsigned)s[byte]));
                if (b > max_bit) max_bit = b;
                break;
            }
        }
    }
    return max_bit + 1;
}

int c_batch_short_msm_auto_raw(ge25519_p3         **results_out,
                                const unsigned char *scalars,
                                const unsigned char *points,
                                int                  n,
                                int                  batch_size)
{
    if (n <= 0 || batch_size <= 0) return -1;

    int    B           = MSM_BATCH;
    int    num_buckets = (n + B - 1) / B;
    size_t total_s     = (size_t)batch_size * n;

    ge25519_p3 *block = (ge25519_p3 *)malloc(batch_size * sizeof(ge25519_p3));
    if (!block) return -1;
    for (int m = 0; m < batch_size; m++)
        results_out[m] = &block[m];

    ge25519_p3 *decoded = (ge25519_p3 *)malloc(n * sizeof(ge25519_p3));
    if (!decoded) { free(block); return -1; }
    for (int i = 0; i < n; i++) {
        if (ristretto255_frombytes(&decoded[i],
                                    points + i * POINT_BYTES) != 0) {
            free(decoded); free(block); return -1;
        }
    }

    unsigned char *red = (unsigned char *)malloc(total_s * SCALAR_BYTES);
    if (!red) { free(decoded); free(block); return -1; }
    for (size_t idx = 0; idx < total_s; idx++)
        reduce_scalar(red + idx * SCALAR_BYTES,
                      scalars + idx * SCALAR_BYTES);

    /* Determine actual bit width — no wasted iterations on zero bits. */
    int scalar_bits = max_scalar_bitlen(red, total_s);

    ge25519_p3 *tables = (ge25519_p3 *)malloc(
        (size_t)num_buckets * MSM_TBL_SZ * sizeof(ge25519_p3));
    if (!tables) { free(red); free(decoded); free(block); return -1; }

    #pragma omp parallel for schedule(static)
    for (int b = 0; b < num_buckets; b++) {
        int base    = b * B;
        int batch_n = (base + B <= n) ? B : (n - base);
        build_subset_sum(tables + (size_t)b * MSM_TBL_SZ,
                         decoded + base, batch_n);
    }
    free(decoded);

    ge25519_p3 identity;
    memset(&identity, 0, sizeof(identity));
    fe25519_1(identity.Y);
    fe25519_1(identity.Z);

    #pragma omp parallel for schedule(dynamic, 1)
    for (int m = 0; m < batch_size; m++) {
        const unsigned char *s_row = red + (size_t)m * n * SCALAR_BYTES;
        ge25519_p3    *res = results_out[m];
        ge25519_p1p1   tmp;
        ge25519_cached cached;
        int            first = 1;

        for (int j = scalar_bits - 1; j >= 0; j--) {
            if (!first)
                p3_double(res, res);

            for (int b = 0; b < num_buckets; b++) {
                int base    = b * B;
                int batch_n = (base + B <= n) ? B : (n - base);
                ge25519_p3 *tbl = tables + (size_t)b * MSM_TBL_SZ;

                uint32_t idx = form_bucket_index(s_row, base, batch_n, j);
                if (idx == 0) continue;

                if (first) {
                    *res  = tbl[idx];
                    first = 0;
                } else {
                    ge25519_p3_to_cached(&cached, &tbl[idx]);
                    ge25519_add(&tmp, res, &cached);
                    ge25519_p1p1_to_p3(res, &tmp);
                }
            }
        }

        if (first)
            *res = identity;
    }

    memset(red, 0, total_s * SCALAR_BYTES);
    free(red);
    free(tables);
    return 0;
}

int c_batch_short_msm_auto_encode(unsigned char       *out,
                                   const unsigned char *scalars,
                                   const unsigned char *points,
                                   int                  n,
                                   int                  batch_size)
{
    if (n <= 0 || batch_size <= 0) return -1;

    int    B           = MSM_BATCH;
    int    num_buckets = (n + B - 1) / B;
    size_t total_s     = (size_t)batch_size * n;

    ge25519_p3 *decoded = (ge25519_p3 *)malloc(n * sizeof(ge25519_p3));
    if (!decoded) return -1;
    for (int i = 0; i < n; i++) {
        if (ristretto255_frombytes(&decoded[i],
                                    points + i * POINT_BYTES) != 0) {
            free(decoded); return -1;
        }
    }

    unsigned char *red = (unsigned char *)malloc(total_s * SCALAR_BYTES);
    if (!red) { free(decoded); return -1; }
    for (size_t idx =0; idx < total_s; idx++)
        reduce_scalar(red + idx * SCALAR_BYTES,
                      scalars + idx * SCALAR_BYTES);

    int scalar_bits = max_scalar_bitlen(red, total_s);

    ge25519_p3 *tables = (ge25519_p3 *)malloc(
        (size_t)num_buckets * MSM_TBL_SZ * sizeof(ge25519_p3));
    if (!tables) { free(red); free(decoded); return -1; }

    #pragma omp parallel for schedule(static)
    for (int b = 0; b < num_buckets; b++) {
        int base    = b * B;
        int batch_n = (base + B <= n) ? B : (n - base);
        build_subset_sum(tables + (size_t)b * MSM_TBL_SZ,
                         decoded + base, batch_n);
    }
    free(decoded);

    ge25519_p3 identity;
    memset(&identity, 0, sizeof(identity));
    fe25519_1(identity.Y);
    fe25519_1(identity.Z);

    #pragma omp parallel for schedule(dynamic, 1)
    for (int m = 0; m < batch_size; m++) {
        const unsigned char *s_row = red + (size_t)m * n * SCALAR_BYTES;
        ge25519_p3     res;
        ge25519_p1p1   tmp;
        ge25519_cached cached;
        int            first = 1;

        for (int j = scalar_bits - 1; j >= 0; j--) {
            if (!first)
                p3_double(&res, &res);

            for (int b = 0; b < num_buckets; b++) {
                int base    = b * B;
                int batch_n = (base + B <= n) ? B : (n - base);
                ge25519_p3 *tbl = tables + (size_t)b * MSM_TBL_SZ;

                uint32_t idx = form_bucket_index(s_row, base, batch_n, j);
                if (idx == 0) continue;

                if (first) {
                    res   = tbl[idx];
                    first = 0;
                } else {
                    ge25519_p3_to_cached(&cached, &tbl[idx]);
                    ge25519_add(&tmp, &res, &cached);
                    ge25519_p1p1_to_p3(&res, &tmp);
                }
            }
        }

        if (first)
            res = identity;
        ristretto255_p3_tobytes(out + m * POINT_BYTES, &res);
    }

    memset(red, 0, total_s * SCALAR_BYTES);
    free(red);
    free(tables);
    return 0;
}
/* ── Batch offset subtract ──────────────────────────────────────── */

/*
 * int64_to_scalar
 *
 * Encode a signed 64-bit integer as a ristretto255 scalar (mod L) in
 * little-endian form.  Handles negative values via negation.
 *
 * For v >= 0: write v into low 8 bytes of a 64-byte buffer, reduce mod L.
 * For v <  0: do the same for |v|, then negate (L - |v| mod L).
 */
static void int64_to_scalar(unsigned char out[32], int64_t v)
{
    unsigned char wide[64] = {0};
    uint64_t      abs_v    = (v >= 0) ? (uint64_t)v : (uint64_t)(-v);

    for (int k = 0; k < 8; k++)
        wide[k] = (unsigned char)((abs_v >> (k * 8)) & 0xFF);

    crypto_core_ristretto255_scalar_reduce(out, wide);

    if (v < 0)
        crypto_core_ristretto255_scalar_negate(out, out);
}

/*
 * c_batch_offset_subtract_raw
 *
 * For each row i of a hypervector matrix:
 *
 *   sum_h          = sum(hvecs[i][0..num_cols-1])          (int64)
 *   offset_scalar  = (M * sum_h) mod L                     (ristretto scalar)
 *   offset_point   = offset_scalar * G                     (via zero_dbl_scalarmult)
 *   result[i]      = dot_pts[i] - offset_point             (raw Edwards subtraction)
 *
 * All rows are processed in parallel with OpenMP.
 *
 * Parameters:
 *   results_out  — caller-allocated array of num_rows ge25519_p3 pointers;
 *                  all points live in one contiguous block.
 *                  Free with c_free_batch(results_out[0]).
 *   dot_pts      — array of num_rows ge25519_p3* input points (read-only)
 *   hvecs        — packed int32 matrix, row-major [num_rows x num_cols]
 *   M            — scalar multiplier (e.g. 2047)
 *   tbl_G        — precomputed table for basepoint G
 *   num_rows     — number of rows (= length of dot_pts list)
 *   num_cols     — number of columns per row
 *
 * Returns 0 on success, -1 on allocation failure.
 */
int c_batch_offset_subtract_raw(ge25519_p3        **results_out,
                                 ge25519_p3 * const *dot_pts,
                                 const int32_t      *hvecs,
                                 int64_t             M,
                                 const PrecompTable *tbl_G,
                                 int                 num_rows,
                                 int                 num_cols)
{
    ge25519_p3 *block = (ge25519_p3 *)malloc((size_t)num_rows * sizeof(ge25519_p3));
    if (!block) return -1;

    for (int i = 0; i < num_rows; i++)
        results_out[i] = &block[i];

    #pragma omp parallel
    {
        PrecompTable *local_tbl = (PrecompTable *)malloc(sizeof(PrecompTable));
        if (local_tbl) {
            memcpy(local_tbl, tbl_G, sizeof(PrecompTable));

            #pragma omp for schedule(static)
            for (int i = 0; i < num_rows; i++) {
                /* 1. Row sum of hypervector */
                int64_t sum_h = 0;
                const int32_t *row = hvecs + (size_t)i * num_cols;
                for (int j = 0; j < num_cols; j++)
                    sum_h += (int64_t)row[j];

                /* 2. Encode (M * sum_h) as scalar mod L */
                unsigned char offset_scalar[32];
                int64_to_scalar(offset_scalar, M * sum_h);

                /* 3. Compute offset_point = offset_scalar * G */
                ge25519_p3    offset_pt;
                zero_dbl_scalarmult(&offset_pt, offset_scalar, local_tbl);

                /* 4. result[i] = dot_pts[i] - offset_point */
                ge25519_p1p1   tmp;
                ge25519_cached cached;
                ge25519_p3_to_cached(&cached, &offset_pt);
                ge25519_sub(&tmp, dot_pts[i], &cached);
                ge25519_p1p1_to_p3(&block[i], &tmp);

                memset(offset_scalar, 0, 32);
            }

            memset(local_tbl, 0, sizeof(PrecompTable));
            free(local_tbl);
        }
    }

    return 0;
}

/*
 * c_batch_offset_subtract_encode
 *
 * Same as c_batch_offset_subtract_raw but encodes each result to a
 * 32-byte ristretto255 point directly into `out`.
 * No RawPoint allocation — results are plain encoded bytes.
 *
 * Parameters:
 *   out          — output buffer of num_rows x 32 bytes (caller allocated)
 *   (remaining parameters same as c_batch_offset_subtract_raw)
 *
 * Returns 0 on success, -1 on allocation failure.
 */
int c_batch_offset_subtract_encode(unsigned char      *out,
                                    ge25519_p3 * const *dot_pts,
                                    const int32_t      *hvecs,
                                    int64_t             M,
                                    const PrecompTable *tbl_G,
                                    int                 num_rows,
                                    int                 num_cols)
{
    #pragma omp parallel
    {
        PrecompTable *local_tbl = (PrecompTable *)malloc(sizeof(PrecompTable));
        if (local_tbl) {
            memcpy(local_tbl, tbl_G, sizeof(PrecompTable));

            #pragma omp for schedule(static)
            for (int i = 0; i < num_rows; i++) {
                int64_t sum_h = 0;
                const int32_t *row = hvecs + (size_t)i * num_cols;
                for (int j = 0; j < num_cols; j++)
                    sum_h += (int64_t)row[j];

                unsigned char offset_scalar[32];
                int64_to_scalar(offset_scalar, M * sum_h);

                ge25519_p3    offset_pt, result;
                ge25519_p1p1   tmp;
                ge25519_cached cached;

                zero_dbl_scalarmult(&offset_pt, offset_scalar, local_tbl);

                ge25519_p3_to_cached(&cached, &offset_pt);
                ge25519_sub(&tmp, dot_pts[i], &cached);
                ge25519_p1p1_to_p3(&result, &tmp);

                ristretto255_p3_tobytes(out + (size_t)i * POINT_BYTES, &result);
                memset(offset_scalar, 0, 32);
            }

            memset(local_tbl, 0, sizeof(PrecompTable));
            free(local_tbl);
        }
    }

    return 0;
}

/* ── Batch power-of-2 multiply ──────────────────────────────────── */

/*
 * c_batch_pow2_mult_raw
 *
 * For each input point, compute 2^k * point by applying k successive
 * doublings. This is dramatically faster than a full scalar multiplication
 * when the scalar happens to be a power of two.
 *
 * Example: scalar_shift = 2^32 → k = 32 doublings per point.
 *          Cost: 32 doublings × n points, fully parallelised.
 *          Compare to: n full 252-bit scalar mults (~250× slower).
 *
 * Parameters:
 *   results_out  — caller-allocated array of n ge25519_p3 pointers;
 *                  all points live in one contiguous block.
 *                  Free with c_free_batch(results_out[0]).
 *   points       — array of n ge25519_p3* input points (read-only)
 *   k            — number of doublings (i.e., multiply by 2^k)
 *   n            — number of points
 *
 * Returns 0 on success, -1 on allocation failure.
 */
int c_batch_pow2_mult_raw(ge25519_p3        **results_out,
                           ge25519_p3 * const *points,
                           int                 k,
                           int                 n)
{
    ge25519_p3 *block = (ge25519_p3 *)malloc((size_t)n * sizeof(ge25519_p3));
    if (!block) return -1;

    for (int i = 0; i < n; i++)
        results_out[i] = &block[i];

    #pragma omp parallel for schedule(static)
    for (int i = 0; i < n; i++) {
        ge25519_p3 acc = *points[i];
        for (int d = 0; d < k; d++)
            p3_double(&acc, &acc);
        block[i] = acc;
    }

    return 0;
}

/* ── Batch varying-scalar varying-point multiply ────────────────── */

/*
 * c_batch_scalarmult_pairs_raw
 *
 * Compute result[i] = scalar[i] * point[i] for i = 0..n-1 in parallel.
 * Both scalar and point vary per element — no precomputed table possible.
 * Uses crypto_scalarmult_ristretto255 internally (full 252-bit).
 *
 * Parameters:
 *   results_out : caller-allocated array of n ge25519_p3 pointers;
 *                 all points live in one contiguous block.
 *                 Free with c_free_batch(results_out[0]).
 *   scalars     : packed n × 32 bytes, one little-endian scalar per entry
 *   points      : array of n ge25519_p3* input points (read-only)
 *   n           : number of pairs
 *
 * Returns 0 on success, -1 on allocation failure.
 */
int c_batch_scalarmult_pairs_raw(ge25519_p3        **results_out,
                                  const unsigned char *scalars,
                                  ge25519_p3 * const  *points,
                                  int                  n)
{
    ge25519_p3 *block = (ge25519_p3 *)malloc((size_t)n * sizeof(ge25519_p3));
    if (!block) return -1;

    for (int i = 0; i < n; i++)
        results_out[i] = &block[i];

    #pragma omp parallel for schedule(static)
    for (int i = 0; i < n; i++) {
        unsigned char encoded[32], out[32];
        ristretto255_p3_tobytes(encoded, points[i]);
        if (crypto_scalarmult_ristretto255(out,
                scalars + (size_t)i * SCALAR_BYTES, encoded) != 0) {
            /* On error write the identity point */
            memset(&block[i], 0, sizeof(ge25519_p3));
            fe25519_1(block[i].Y);
            fe25519_1(block[i].Z);
            continue;
        }
        ristretto255_frombytes(&block[i], out);
    }

    return 0;
}

/* ── Batch NIZK Fiat-Shamir hash verification ───────────────────── */

/*
 * c_batch_nizk_hash_verify
 *
 * Single-challenge NIZK verifier over the combined statement of n tuples.
 *
 * Encodes all A_hat_C[i] and A_hat_R[i] in parallel, then builds one
 * combined hash input:
 *
 *   "JointPedR_v1" (12)
 *   || G_bytes (32) || H_bytes (32)
 *   || for i in 0..n-1: C_bytes[i](32) || R_bytes[i](32)
 *                        || A_hat_C_enc[i](32) || A_hat_R_enc[i](32)
 *
 * and checks that SHA-512(input) reduced mod L equals e_expected.
 *
 * Parameters:
 *   a_hat_c    : array of n ge25519_p3* — reconstructed A_hat_C points
 *   a_hat_r    : array of n ge25519_p3* — reconstructed A_hat_R points
 *   C_bytes    : packed n × 32 bytes — original commitment encodings
 *   R_bytes    : packed n × 32 bytes — encoded r-commitment bytes
 *   G_bytes    : 32-byte encoding of generator G
 *   H_bytes    : 32-byte encoding of generator H
 *   e_expected : 32 bytes — single expected challenge scalar (little-endian)
 *   n          : number of statements
 *
 * Returns 1 if hash matches, 0 if mismatch, -1 on internal error.
 */
int c_batch_nizk_hash_verify(ge25519_p3 * const  *a_hat_c,
                              ge25519_p3 * const  *a_hat_r,
                              const unsigned char *C_bytes,
                              const unsigned char *R_bytes,
                              const unsigned char *G_bytes,
                              const unsigned char *H_bytes,
                              const unsigned char *e_expected,
                              int                  n)
{
    static const char PREFIX[]  = "JointPedR_v1";
    static const int  PREFIX_LEN = 12;

    /* Step 1: encode all points in parallel into temporary buffers */
    unsigned char *ac_encs = malloc((size_t)n * 32);
    unsigned char *ar_encs = malloc((size_t)n * 32);
    if (!ac_encs || !ar_encs) { free(ac_encs); free(ar_encs); return -1; }

    #pragma omp parallel for schedule(static)
    for (int i = 0; i < n; i++) {
        ristretto255_p3_tobytes(ac_encs + (size_t)i * 32, a_hat_c[i]);
        ristretto255_p3_tobytes(ar_encs + (size_t)i * 32, a_hat_r[i]);
    }

    /* Step 2: build combined hash input:
     *   PREFIX(12) + G(32) + H(32) + n*(C(32)+R(32)+AC(32)+AR(32)) = 76 + n*128 bytes */
    size_t msg_len = PREFIX_LEN + 32 + 32 + (size_t)n * 128;
    unsigned char *msg = malloc(msg_len);
    if (!msg) { free(ac_encs); free(ar_encs); return -1; }

    memcpy(msg,      PREFIX,  PREFIX_LEN);
    memcpy(msg + 12, G_bytes, 32);
    memcpy(msg + 44, H_bytes, 32);
    for (int i = 0; i < n; i++) {
        size_t off = 76 + (size_t)i * 128;
        memcpy(msg + off,       C_bytes  + (size_t)i * 32, 32);
        memcpy(msg + off + 32,  R_bytes  + (size_t)i * 32, 32);
        memcpy(msg + off + 64,  ac_encs  + (size_t)i * 32, 32);
        memcpy(msg + off + 96,  ar_encs  + (size_t)i * 32, 32);
    }
    free(ac_encs); free(ar_encs);

    /* Step 3: single SHA-512 → reduce mod L → compare */
    unsigned char digest[64];
    crypto_hash_sha512(digest, msg, msg_len);
    free(msg);

    unsigned char e_computed[32];
    crypto_core_ristretto255_scalar_reduce(e_computed, digest);

    return (sodium_memcmp(e_computed, e_expected, 32) == 0) ? 1 : 0;
}

/* ── Batch NIZK Fiat-Shamir hash prove ──────────────────────────── */

/*
 * c_batch_nizk_hash_prove
 *
 * Single-challenge NIZK prover over the combined statement of n tuples.
 *
 * Step 1 (parallel): encode all A_C[i], A_R[i], R[i] to compressed form.
 * Step 2 (sequential): one SHA-512 over the full combined statement:
 *     "JointPedR_v1" || G || H
 *     || for i in 0..n-1: C_i || R_enc_i || A_C_enc_i || A_R_enc_i
 *   reduced mod L → single challenge e.
 * Step 3 (parallel): for each i:
 *     s_x_i = kx_i + e * x_i  mod L
 *     s_r_i = kr_i + e * r_i  mod L
 *
 * Output layout (32 + n*64 bytes):
 *   e (32) || s_x_0 (32) || s_r_0 (32) || ... || s_x_{n-1} (32) || s_r_{n-1} (32)
 *
 * Parameters:
 *   a_c_pts    : n ge25519_p3*  — announcement points A_C_i = k_x*G + k_r*H
 *   a_r_pts    : n ge25519_p3*  — announcement points A_R_i = k_r*G
 *   r_pts      : n ge25519_p3*  — blinding commitments R_i = r*G
 *   C_bytes    : n × 32         — Pedersen commitment encodings
 *   G_bytes    : 32             — generator G
 *   H_bytes    : 32             — generator H
 *   kx_packed  : n × 32         — nonce scalars k_x_i
 *   kr_packed  : n × 32         — nonce scalars k_r_i
 *   x_packed   : n × 32         — message scalars x_i
 *   r_packed   : n × 32         — blinding scalars r_i
 *   proofs_out : 32 + n*64      — output buffer; caller allocates
 *   n          : number of statements
 *
 * Returns 0 on success, -1 on allocation failure.
 */
int c_batch_nizk_hash_prove(ge25519_p3 * const  *a_c_pts,
                             ge25519_p3 * const  *a_r_pts,
                             ge25519_p3 * const  *r_pts,
                             const unsigned char *C_bytes,
                             const unsigned char *G_bytes,
                             const unsigned char *H_bytes,
                             const unsigned char *kx_packed,
                             const unsigned char *kr_packed,
                             const unsigned char *x_packed,
                             const unsigned char *r_packed,
                             unsigned char       *proofs_out,
                             int                  n)
{
    static const char PREFIX[]  = "JointPedR_v1";
    static const int  PREFIX_LEN = 12;

    /* Step 1: encode all points in parallel */
    unsigned char *ac_encs = malloc((size_t)n * 32);
    unsigned char *ar_encs = malloc((size_t)n * 32);
    unsigned char *r_encs  = malloc((size_t)n * 32);
    if (!ac_encs || !ar_encs || !r_encs) {
        free(ac_encs); free(ar_encs); free(r_encs); return -1;
    }

    #pragma omp parallel for schedule(static)
    for (int i = 0; i < n; i++) {
        ristretto255_p3_tobytes(ac_encs + (size_t)i * 32, a_c_pts[i]);
        ristretto255_p3_tobytes(ar_encs + (size_t)i * 32, a_r_pts[i]);
        ristretto255_p3_tobytes(r_encs  + (size_t)i * 32, r_pts[i]);
    }

    /* Step 2: build combined hash input and compute single challenge e
     *   PREFIX(12) + G(32) + H(32) + n*(C(32)+R(32)+AC(32)+AR(32)) = 76 + n*128 bytes */
    size_t msg_len = PREFIX_LEN + 32 + 32 + (size_t)n * 128;
    unsigned char *msg = malloc(msg_len);
    if (!msg) { free(ac_encs); free(ar_encs); free(r_encs); return -1; }

    memcpy(msg,      PREFIX,  PREFIX_LEN);
    memcpy(msg + 12, G_bytes, 32);
    memcpy(msg + 44, H_bytes, 32);
    for (int i = 0; i < n; i++) {
        size_t off = 76 + (size_t)i * 128;
        memcpy(msg + off,       C_bytes  + (size_t)i * 32, 32);
        memcpy(msg + off + 32,  r_encs   + (size_t)i * 32, 32);
        memcpy(msg + off + 64,  ac_encs  + (size_t)i * 32, 32);
        memcpy(msg + off + 96,  ar_encs  + (size_t)i * 32, 32);
    }
    free(ac_encs); free(ar_encs); free(r_encs);

    unsigned char digest[64];
    crypto_hash_sha512(digest, msg, msg_len);
    free(msg);

    unsigned char e[32];
    crypto_core_ristretto255_scalar_reduce(e, digest);

    /* Write single challenge e as first 32 bytes of output */
    memcpy(proofs_out, e, 32);

    /* Step 3: compute all responses in parallel using the single e */
    #pragma omp parallel for schedule(static)
    for (int i = 0; i < n; i++) {
        /* s_x = kx + e * x  mod L */
        unsigned char ex[32], sx[32];
        crypto_core_ristretto255_scalar_mul(ex, e, x_packed  + (size_t)i * 32);
        crypto_core_ristretto255_scalar_add(sx, kx_packed + (size_t)i * 32, ex);

        /* s_r = kr + e * r  mod L */
        unsigned char er[32], sr_val[32];
        crypto_core_ristretto255_scalar_mul(er, e, r_packed  + (size_t)i * 32);
        crypto_core_ristretto255_scalar_add(sr_val, kr_packed + (size_t)i * 32, er);

        /* pack at offset 32 + i*64: sx || sr */
        unsigned char *out = proofs_out + 32 + (size_t)i * 64;
        memcpy(out,      sx,     32);
        memcpy(out + 32, sr_val, 32);
    }

    return 0;
}

/* ── Batch hash + encrypt / decrypt for PAKE DB ─────────────��──────────── */

/*
 * c_batch_hash_enc
 *
 * For each of n PRF point encodings, computes in parallel:
 *   tag[i]    = SHA-256("TAG" || prf_bytes[i])              (32 bytes)
 *   key[i]    = SHA-256("KEY" || prf_bytes[i])              (32 bytes)
 *   cipher[i] = crypto_secretbox_easy(payload, ZERO_NONCE, key[i])  (48 bytes)
 *
 * Safe to use a zero nonce because every key[i] is unique (one-time use).
 * Used during DB registration: caller writes DB[hex(tag[i])] = cipher[i].
 *
 * prf_bytes   — n × 32 packed PRF point encodings
 * payload     — 32-byte plaintext (same for all variants)
 * tags_out    — n × 32 output tags
 * ciphers_out — n × 48 output ciphertexts
 * n           — number of variants
 */
int c_batch_hash_enc(const unsigned char *prf_bytes,
                      const unsigned char *payload,
                      unsigned char       *tags_out,
                      unsigned char       *ciphers_out,
                      int                  n)
{
    static const unsigned char ZERO_NONCE[24] = {0};

    #pragma omp parallel for schedule(static)
    for (int i = 0; i < n; i++) {
        unsigned char buf[35];
        unsigned char key[32];

        /* tag = SHA-256("TAG" || prf_bytes[i]) */
        buf[0] = 'T'; buf[1] = 'A'; buf[2] = 'G';
        memcpy(buf + 3, prf_bytes + (size_t)i * 32, 32);
        crypto_hash_sha256(tags_out + (size_t)i * 32, buf, 35);

        /* key = SHA-256("KEY" || prf_bytes[i]) */
        buf[0] = 'K'; buf[1] = 'E'; buf[2] = 'Y';
        crypto_hash_sha256(key, buf, 35);

        /* cipher = secretbox_easy(payload, 32, ZERO_NONCE, key) → 48 bytes */
        crypto_secretbox_easy(ciphers_out + (size_t)i * 48,
                               payload, 32, ZERO_NONCE, key);
    }
    return 0;
}

/*
 * c_batch_sha256_tag_key
 *
 * Computes tags and keys for all n variants in parallel — no encryption.
 * Used during audit before the Python DB lookup step.
 *
 * prf_bytes — n × 32 packed PRF point encodings
 * tags_out  — n × 32 output tags  (SHA-256("TAG" || prf[i]))
 * keys_out  — n × 32 output keys  (SHA-256("KEY" || prf[i]))
 * n         — number of variants
 */
int c_batch_sha256_tag_key(const unsigned char *prf_bytes,
                             unsigned char       *tags_out,
                             unsigned char       *keys_out,
                             int                  n)
{
    #pragma omp parallel for schedule(static)
    for (int i = 0; i < n; i++) {
        unsigned char buf[35];

        buf[0] = 'T'; buf[1] = 'A'; buf[2] = 'G';
        memcpy(buf + 3, prf_bytes + (size_t)i * 32, 32);
        crypto_hash_sha256(tags_out + (size_t)i * 32, buf, 35);

        buf[0] = 'K'; buf[1] = 'E'; buf[2] = 'Y';
        crypto_hash_sha256(keys_out + (size_t)i * 32, buf, 35);
    }
    return 0;
}

/*
 * c_batch_secretbox_open_verify
 *
 * Decrypts and verifies n ciphertexts in parallel using their precomputed keys.
 * Each cipher[i] must be 48 bytes (as produced by c_batch_hash_enc).
 * Returns 1 if every decryption succeeds and matches expected_payload, 0 otherwise.
 *
 * keys             — n × 32 keys (from c_batch_sha256_tag_key)
 * ciphers          — n × 48 packed ciphertexts
 * expected_payload — 32-byte expected plaintext
 * n                — number of variants
 */
int c_batch_secretbox_open_verify(const unsigned char *keys,
                                   const unsigned char *ciphers,
                                   const unsigned char *expected_payload,
                                   int                  n)
{
    static const unsigned char ZERO_NONCE[24] = {0};
    int all_ok = 1;

    #pragma omp parallel for schedule(static) reduction(&:all_ok)
    for (int i = 0; i < n; i++) {
        unsigned char decrypted[32];
        int ret = crypto_secretbox_open_easy(
                      decrypted,
                      ciphers + (size_t)i * 48, 48,
                      ZERO_NONCE,
                      keys + (size_t)i * 32);
        if (ret != 0 || memcmp(decrypted, expected_payload, 32) != 0)
            all_ok &= 0;
    }
    return all_ok;
}
