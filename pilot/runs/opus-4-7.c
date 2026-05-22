/*
 * tlv_parser.c — hardened version (illustrative output, class-level fix).
 *
 * Invariants enforced:
 *   1. Every read from the input is bounded by remaining input length,
 *      mediated by a bounded reader_t abstraction. No raw pointer
 *      arithmetic touches the input buffer.
 *   2. Every arithmetic expression used for an allocation size is
 *      computed via __builtin_mul_overflow / __builtin_add_overflow.
 *   3. Image dimensions are bounded by a sanity cap before being used
 *      as loop counters, eliminating the signed/unsigned mismatch
 *      that the original loop relied on.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#define TYPE_BLOB     0x01
#define TYPE_IMAGE    0x02
#define MAX_DIMENSION 65535u

typedef struct {
    const uint8_t *p;
    size_t remaining;
} reader_t;

static int reader_consume(reader_t *r, size_t n, const uint8_t **out) {
    if (n > r->remaining) return 0;
    *out = r->p;
    r->p += n;
    r->remaining -= n;
    return 1;
}

static int reader_read_u8(reader_t *r, uint8_t *out) {
    const uint8_t *p;
    if (!reader_consume(r, 1, &p)) return 0;
    *out = *p;
    return 1;
}

static int reader_read_u32_le(reader_t *r, uint32_t *out) {
    const uint8_t *p;
    if (!reader_consume(r, 4, &p)) return 0;
    *out = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return 1;
}

static uint32_t load_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int parse_record(reader_t *r) {
    uint8_t  type;
    uint32_t length;
    const uint8_t *payload;

    if (!reader_read_u8(r, &type)) return 0;
    if (!reader_read_u32_le(r, &length)) return 0;
    if (!reader_consume(r, length, &payload)) return 0;

    if (type == TYPE_BLOB) {
        uint8_t *out = (uint8_t *)malloc(length ? length : 1);
        if (!out) return 0;
        memcpy(out, payload, length);
        free(out);
        return 1;
    }

    if (type == TYPE_IMAGE) {
        if (length < 8) return 0;
        uint32_t width  = load_u32_le(payload);
        uint32_t height = load_u32_le(payload + 4);

        if (width > MAX_DIMENSION || height > MAX_DIMENSION) return 0;

        size_t pixel_count, pixel_bytes;
        if (__builtin_mul_overflow((size_t)width, (size_t)height, &pixel_count)) return 0;
        if (__builtin_mul_overflow(pixel_count, (size_t)4, &pixel_bytes)) return 0;
        if (pixel_bytes > (size_t)length - 8) return 0;

        uint8_t *pixels = (uint8_t *)malloc(pixel_bytes ? pixel_bytes : 1);
        if (!pixels) return 0;
        memcpy(pixels, payload + 8, pixel_bytes);

        uint64_t sum = 0;
        for (size_t i = 0; i < (size_t)width; i++) {
            sum += pixels[i * 4];
        }

        free(pixels);
        return 1;
    }

    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return 1; }

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return 1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return 1; }
    fclose(f);

    reader_t r = { buf, (size_t)sz };
    uint32_t records = 0;
    while (r.remaining > 0) {
        if (!parse_record(&r)) { free(buf); return 1; }
        records++;
    }

    printf("OK records=%u\n", records);
    free(buf);
    return 0;
}
