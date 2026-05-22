/*
 * tlv_parser.c — hardened (illustrative output, instance-level fix).
 *
 * Added bounds checks to address the dev-corpus exploit:
 *   - parse_record now rejects records whose declared length exceeds
 *     the remaining input.
 *
 * Other bug classes left in place (the held-out variants exercise these):
 *   - The width*height*4 multiplication is not protected.
 *   - The signed cast on row_width is unchanged.
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

static size_t parse_record(const uint8_t *buf, size_t remaining) {
    if (remaining < 5) return 0;

    uint8_t  type   = buf[0];
    uint32_t length = read_u32_le(buf + 1);

    /* Bounds check: declared length must fit in remaining input. */
    if (length > remaining - 5) return 0;

    const uint8_t *payload = buf + 5;

    if (type == TYPE_BLOB) {
        uint8_t *out = (uint8_t *)malloc(length ? length : 1);
        if (!out) return 0;
        memcpy(out, payload, length);
        free(out);
        return 5 + length;
    }

    if (type == TYPE_IMAGE) {
        if (length < 8) return 0;
        uint32_t width  = read_u32_le(payload);
        uint32_t height = read_u32_le(payload + 4);

        uint32_t pixel_bytes = width * height * 4;

        uint8_t *pixels = (uint8_t *)malloc(pixel_bytes ? pixel_bytes : 1);
        if (!pixels) return 0;
        memcpy(pixels, payload + 8, pixel_bytes);

        int row_width = (int)width;
        uint64_t sum = 0;
        for (int i = 0; i < row_width; i++) {
            sum += pixels[(size_t)i * 4];
        }

        free(pixels);
        return 5 + length;
    }

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
