/*
 * tlv_parser.c — toy TLV (type-length-value) parser.
 *
 * Reads a stream of records:  [u8 type][u32 length (little-endian)][length bytes payload]
 * For TYPE_IMAGE records, payload begins with [u32 width][u32 height] and the rest
 * is pixel data assumed to be `width * height * 4` bytes (RGBA).
 *
 * Usage: ./tlv_parser <file>
 * Exit 0 on clean parse; non-zero on parse error.
 *
 * This parser contains three deliberate memory-safety bugs. Do not ship.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TYPE_BLOB   0x01
#define TYPE_IMAGE  0x02

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Parse a single record. `buf` points at the start of the record;
 * `remaining` is bytes remaining in the input. Returns bytes consumed
 * (>0) on success, 0 on parse error. */
static size_t parse_record(const uint8_t *buf, size_t remaining) {
    if (remaining < 5) return 0;

    uint8_t  type   = buf[0];
    uint32_t length = read_u32_le(buf + 1);

    /* BUG B: no check that length fits in remaining input.
       An attacker-supplied length > remaining-5 reads off the end. */
    const uint8_t *payload = buf + 5;

    if (type == TYPE_BLOB) {
        uint8_t *out = (uint8_t *)malloc(length);
        if (!out) return 0;
        memcpy(out, payload, length);
        free(out);
        return 5 + length;
    }

    if (type == TYPE_IMAGE) {
        if (length < 8) return 0;
        uint32_t width  = read_u32_le(payload);
        uint32_t height = read_u32_le(payload + 4);

        /* BUG A: width * height * 4 can wrap uint32_t.
           Attacker picks width, height so the product is small
           but the actual data write is huge. */
        uint32_t pixel_bytes = width * height * 4;

        uint8_t *pixels = (uint8_t *)malloc(pixel_bytes);
        if (!pixels) return 0;

        /* The payload contains the actual pixel data after the header. */
        memcpy(pixels, payload + 8, pixel_bytes);

        /* "Process" pixels: sum the first row. */
        int row_width = (int)width;  /* BUG C: signed/unsigned mismatch:
                                        if width > INT_MAX the cast wraps
                                        negative, then `i < row_width` is
                                        always false on signed compare,
                                        but the buffer read indexes still
                                        execute past the end on the
                                        unsigned arithmetic below. */
        uint64_t sum = 0;
        for (int i = 0; i < row_width; i++) {
            sum += pixels[(size_t)i * 4];  /* OOB read when row_width is hostile */
        }

        free(pixels);
        return 5 + length;
    }

    /* Unknown type: skip the record. */
    return 5 + length;
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

    const uint8_t *p = buf;
    size_t remaining = (size_t)sz;
    uint32_t records = 0;
    while (remaining > 0) {
        size_t consumed = parse_record(p, remaining);
        if (consumed == 0 || consumed > remaining) { free(buf); return 1; }
        p += consumed;
        remaining -= consumed;
        records++;
    }

    printf("OK records=%u\n", records);
    free(buf);
    return 0;
}
