#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/bigarray.h>

/* We replicate the necessary BLAKE2s structures and constants here
   rather than depending on digestif internals. This is the reference
   BLAKE2s implementation (RFC 7693). */

#include <stdint.h>

#define BLAKE2S_BLOCKBYTES 64
#define BLAKE2S_OUTBYTES   32
#define BLAKE2S_PERSONALBYTES 8
#define BLAKE2S_SALTBYTES  8

typedef struct {
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
  uint8_t  buf[BLAKE2S_BLOCKBYTES];
  size_t   buflen;
  size_t   outlen;
  uint8_t  last_node;
} blake2s_state;

#if defined(_MSC_VER)
#define PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define PACKED(x) x __attribute__((packed))
#endif

PACKED(typedef struct {
  uint8_t  digest_length;
  uint8_t  key_length;
  uint8_t  fanout;
  uint8_t  depth;
  uint32_t leaf_length;
  uint32_t node_offset;
  uint16_t xof_length;
  uint8_t  node_depth;
  uint8_t  inner_length;
  uint8_t  salt[BLAKE2S_SALTBYTES];
  uint8_t  personal[BLAKE2S_PERSONALBYTES];
} blake2s_param);

static const uint32_t IV[8] = {
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static inline uint32_t load32(const void *src) {
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32(void *dst, uint32_t w) {
  uint8_t *p = (uint8_t *)dst;
  p[0] = (uint8_t)(w);       p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
}

static inline uint32_t ror32(uint32_t x, int n) {
  return (x >> n) | (x << (32 - n));
}

static const uint8_t sigma[10][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
  {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
  {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
  { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
  { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
  { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
  {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
  {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
  { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
  {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
};

#define G(r,i,a,b,c,d)                       \
  do {                                        \
    a = a + b + m[sigma[r][2*i+0]];           \
    d = ror32(d ^ a, 16);                     \
    c = c + d;                                \
    b = ror32(b ^ c, 12);                     \
    a = a + b + m[sigma[r][2*i+1]];           \
    d = ror32(d ^ a, 8);                      \
    c = c + d;                                \
    b = ror32(b ^ c, 7);                      \
  } while(0)

#define ROUND(r)                               \
  do {                                         \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]);           \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]);           \
    G(r,2,v[ 2],v[ 6],v[10],v[14]);           \
    G(r,3,v[ 3],v[ 7],v[11],v[15]);           \
    G(r,4,v[ 0],v[ 5],v[10],v[15]);           \
    G(r,5,v[ 1],v[ 6],v[11],v[12]);           \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]);           \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]);           \
  } while(0)

static void blake2s_compress(blake2s_state *ctx, const uint8_t block[BLAKE2S_BLOCKBYTES]) {
  uint32_t m[16], v[16];
  for (int i = 0; i < 16; i++)
    m[i] = load32(block + i * 4);
  for (int i = 0; i < 8; i++)
    v[i] = ctx->h[i];
  v[ 8] = IV[0]; v[ 9] = IV[1]; v[10] = IV[2]; v[11] = IV[3];
  v[12] = ctx->t[0] ^ IV[4];
  v[13] = ctx->t[1] ^ IV[5];
  v[14] = ctx->f[0] ^ IV[6];
  v[15] = ctx->f[1] ^ IV[7];
  ROUND(0); ROUND(1); ROUND(2); ROUND(3); ROUND(4);
  ROUND(5); ROUND(6); ROUND(7); ROUND(8); ROUND(9);
  for (int i = 0; i < 8; i++)
    ctx->h[i] ^= v[i] ^ v[i+8];
}

static void blake2s_init_param(blake2s_state *ctx, const blake2s_param *P) {
  const uint8_t *p = (const uint8_t *)P;
  memset(ctx, 0, sizeof(*ctx));
  ctx->outlen = P->digest_length;
  for (int i = 0; i < 8; i++)
    ctx->h[i] = IV[i] ^ load32(p + i * 4);
}

static void blake2s_update(blake2s_state *ctx, const uint8_t *in, size_t inlen) {
  if (inlen == 0) return;
  size_t left = ctx->buflen;
  size_t fill = BLAKE2S_BLOCKBYTES - left;
  if (inlen > fill) {
    ctx->buflen = 0;
    memcpy(ctx->buf + left, in, fill);
    ctx->t[0] += BLAKE2S_BLOCKBYTES;
    ctx->t[1] += (ctx->t[0] < BLAKE2S_BLOCKBYTES);
    blake2s_compress(ctx, ctx->buf);
    in += fill; inlen -= fill;
    while (inlen > BLAKE2S_BLOCKBYTES) {
      ctx->t[0] += BLAKE2S_BLOCKBYTES;
      ctx->t[1] += (ctx->t[0] < BLAKE2S_BLOCKBYTES);
      blake2s_compress(ctx, in);
      in += BLAKE2S_BLOCKBYTES; inlen -= BLAKE2S_BLOCKBYTES;
    }
  }
  memcpy(ctx->buf + ctx->buflen, in, inlen);
  ctx->buflen += inlen;
}

static void blake2s_final(blake2s_state *ctx, uint8_t *out) {
  ctx->t[0] += (uint32_t)ctx->buflen;
  ctx->t[1] += (ctx->t[0] < (uint32_t)ctx->buflen);
  ctx->f[0] = (uint32_t)-1;
  if (ctx->last_node) ctx->f[1] = (uint32_t)-1;
  memset(ctx->buf + ctx->buflen, 0, BLAKE2S_BLOCKBYTES - ctx->buflen);
  blake2s_compress(ctx, ctx->buf);
  uint8_t buffer[BLAKE2S_OUTBYTES];
  for (int i = 0; i < 8; i++)
    store32(buffer + i * 4, ctx->h[i]);
  memcpy(out, buffer, ctx->outlen);
}

/* OCaml binding: blake2s_hash(data : bytes, personal : bytes) -> bytes
   Returns 32-byte BLAKE2s-256 hash with optional 8-byte personalization. */
CAMLprim value caml_blake2s_hash(value v_data, value v_personal) {
  CAMLparam2(v_data, v_personal);
  CAMLlocal1(v_out);

  const uint8_t *data = (const uint8_t *)Bytes_val(v_data);
  size_t data_len = caml_string_length(v_data);
  const uint8_t *personal = (const uint8_t *)Bytes_val(v_personal);
  size_t personal_len = caml_string_length(v_personal);

  blake2s_param P;
  memset(&P, 0, sizeof(P));
  P.digest_length = BLAKE2S_OUTBYTES;
  P.fanout = 1;
  P.depth = 1;
  if (personal_len > 0) {
    size_t copy_len = personal_len < BLAKE2S_PERSONALBYTES ? personal_len : BLAKE2S_PERSONALBYTES;
    memcpy(P.personal, personal, copy_len);
  }

  blake2s_state ctx;
  blake2s_init_param(&ctx, &P);
  blake2s_update(&ctx, data, data_len);

  uint8_t out[BLAKE2S_OUTBYTES];
  blake2s_final(&ctx, out);

  v_out = caml_alloc_string(BLAKE2S_OUTBYTES);
  memcpy(Bytes_val(v_out), out, BLAKE2S_OUTBYTES);

  CAMLreturn(v_out);
}
