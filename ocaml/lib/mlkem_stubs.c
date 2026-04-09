#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>

/* mlkem-native requires a randombytes function for randomized operations */
void randombytes(unsigned char *out, size_t outlen) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { memset(out, 0, outlen); return; }
    size_t pos = 0;
    while (pos < outlen) {
        ssize_t n = read(fd, out + pos, outlen - pos);
        if (n <= 0) break;
        pos += (size_t)n;
    }
    close(fd);
}

/* ML-KEM-768 sizes (FIPS 203) */
#define MLKEM768_PUBLICKEYBYTES  1184
#define MLKEM768_SECRETKEYBYTES  2400
#define MLKEM768_CIPHERTEXTBYTES 1088
#define MLKEM768_BYTES           32
#define MLKEM768_SYMBYTES        32

/* mlkem-native symbols for ML-KEM-768 */
extern int PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand(
    unsigned char *pk,
    unsigned char *sk,
    const unsigned char *coins  /* 64 bytes: d || z */
);

extern int PQCP_MLKEM_NATIVE_MLKEM768_enc_derand(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk,
    const unsigned char *coins  /* 32 bytes */
);

extern int PQCP_MLKEM_NATIVE_MLKEM768_enc(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk
);

extern int PQCP_MLKEM_NATIVE_MLKEM768_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk
);

/* caml_mlkem768_keypair_derand : bytes(64) -> bytes(1184) * bytes(2400) */
CAMLprim value caml_mlkem768_keypair_derand(value v_seed) {
    CAMLparam1(v_seed);
    CAMLlocal3(v_pair, v_pk, v_sk);

    if (caml_string_length(v_seed) != 64)
        caml_failwith("mlkem768_keypair_derand: seed must be 64 bytes");

    unsigned char pk[MLKEM768_PUBLICKEYBYTES];
    unsigned char sk[MLKEM768_SECRETKEYBYTES];

    int ret = PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand(
        pk, sk, (const unsigned char *)Bytes_val(v_seed));

    if (ret != 0)
        caml_failwith("mlkem768_keypair_derand: keygen failed");

    v_pk = caml_alloc_string(MLKEM768_PUBLICKEYBYTES);
    memcpy(Bytes_val(v_pk), pk, MLKEM768_PUBLICKEYBYTES);

    v_sk = caml_alloc_string(MLKEM768_SECRETKEYBYTES);
    memcpy(Bytes_val(v_sk), sk, MLKEM768_SECRETKEYBYTES);

    v_pair = caml_alloc_tuple(2);
    Store_field(v_pair, 0, v_pk);
    Store_field(v_pair, 1, v_sk);

    CAMLreturn(v_pair);
}

/* caml_mlkem768_encaps : bytes(1184) -> bytes(32) * bytes(1088) */
CAMLprim value caml_mlkem768_encaps(value v_pk) {
    CAMLparam1(v_pk);
    CAMLlocal3(v_pair, v_ss, v_ct);

    if (caml_string_length(v_pk) != MLKEM768_PUBLICKEYBYTES)
        caml_failwith("mlkem768_encaps: pk must be 1184 bytes");

    unsigned char ct[MLKEM768_CIPHERTEXTBYTES];
    unsigned char ss[MLKEM768_BYTES];

    int ret = PQCP_MLKEM_NATIVE_MLKEM768_enc(
        ct, ss, (const unsigned char *)Bytes_val(v_pk));

    if (ret != 0)
        caml_failwith("mlkem768_encaps: encapsulation failed");

    v_ss = caml_alloc_string(MLKEM768_BYTES);
    memcpy(Bytes_val(v_ss), ss, MLKEM768_BYTES);

    v_ct = caml_alloc_string(MLKEM768_CIPHERTEXTBYTES);
    memcpy(Bytes_val(v_ct), ct, MLKEM768_CIPHERTEXTBYTES);

    v_pair = caml_alloc_tuple(2);
    Store_field(v_pair, 0, v_ss);
    Store_field(v_pair, 1, v_ct);

    CAMLreturn(v_pair);
}

/* caml_mlkem768_encaps_derand : bytes(1184) -> bytes(32) -> bytes(32) * bytes(1088) */
CAMLprim value caml_mlkem768_encaps_derand(value v_pk, value v_coins) {
    CAMLparam2(v_pk, v_coins);
    CAMLlocal3(v_pair, v_ss, v_ct);

    if (caml_string_length(v_pk) != MLKEM768_PUBLICKEYBYTES)
        caml_failwith("mlkem768_encaps_derand: pk must be 1184 bytes");
    if (caml_string_length(v_coins) != MLKEM768_SYMBYTES)
        caml_failwith("mlkem768_encaps_derand: coins must be 32 bytes");

    unsigned char ct[MLKEM768_CIPHERTEXTBYTES];
    unsigned char ss[MLKEM768_BYTES];

    int ret = PQCP_MLKEM_NATIVE_MLKEM768_enc_derand(
        ct, ss,
        (const unsigned char *)Bytes_val(v_pk),
        (const unsigned char *)Bytes_val(v_coins));

    if (ret != 0)
        caml_failwith("mlkem768_encaps_derand: encapsulation failed");

    v_ss = caml_alloc_string(MLKEM768_BYTES);
    memcpy(Bytes_val(v_ss), ss, MLKEM768_BYTES);

    v_ct = caml_alloc_string(MLKEM768_CIPHERTEXTBYTES);
    memcpy(Bytes_val(v_ct), ct, MLKEM768_CIPHERTEXTBYTES);

    v_pair = caml_alloc_tuple(2);
    Store_field(v_pair, 0, v_ss);
    Store_field(v_pair, 1, v_ct);

    CAMLreturn(v_pair);
}

/* caml_mlkem768_decaps : bytes(2400) -> bytes(1088) -> bytes(32) */
CAMLprim value caml_mlkem768_decaps(value v_sk, value v_ct) {
    CAMLparam2(v_sk, v_ct);
    CAMLlocal1(v_ss);

    if (caml_string_length(v_sk) != MLKEM768_SECRETKEYBYTES)
        caml_failwith("mlkem768_decaps: sk must be 2400 bytes");
    if (caml_string_length(v_ct) != MLKEM768_CIPHERTEXTBYTES)
        caml_failwith("mlkem768_decaps: ct must be 1088 bytes");

    unsigned char ss[MLKEM768_BYTES];

    int ret = PQCP_MLKEM_NATIVE_MLKEM768_dec(
        ss,
        (const unsigned char *)Bytes_val(v_ct),
        (const unsigned char *)Bytes_val(v_sk));

    if (ret != 0)
        caml_failwith("mlkem768_decaps: decapsulation failed");

    v_ss = caml_alloc_string(MLKEM768_BYTES);
    memcpy(Bytes_val(v_ss), ss, MLKEM768_BYTES);

    CAMLreturn(v_ss);
}
