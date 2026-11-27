/*
 * burmalda VGA framebuffer console — ANSI-lite text renderer.
 *
 * Draws 8x16 glyphs from vgafont.h into a 32-bpp linear framebuffer
 * provided by ferrix-init (GRUB multiboot framebuffer).  Supports the
 * escape sequences zsh/dinit/busybox actually emit on a console:
 *   \n \r \b \t          line handling
 *   ESC [ 2 J            clear screen
 *   ESC [ H / ESC [ r;c H  cursor home / position
 *   ESC [ K              clear to end of line
 *   ESC [ <n> A/B/C/D    cursor moves
 *   ESC [ <n> m          SGR: 0 reset, 30-37 fg, 40-47 bg, 1/7 attrs
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <burmalda/vgaconsole.h>
#include <burmalda/vgafont.h>
#include <string.h>

#define VGA_GLYPH_W 8
#define VGA_GLYPH_H 16
#define VGA_TAB_STOP 8

struct vga {
    uint32_t *fb;
    uint32_t w, h, pitch_words;
    uint32_t col, row;
    uint32_t fg, bg;
    bool bold;
    bool reverse;

    /* escape sequence state */
    int esc_state;              /* 0 none, 1 got ESC, 2 got '[', 3 priv params */
    char esc_buf[16];
    int esc_len;
    int esc_priv;               /* '?'-prefixed private sequence */
};

static struct vga vga = { 0 };

/* --------------------------------------------------------------------- */

static inline uint32_t sgr_color(uint32_t idx, bool bright)
{
    static const uint32_t base[8] = {
        0x00000000, 0xAA0000, 0x00AA00, 0xAA5500,
        0x0000AA,  0xAA00AA, 0x00AAAA, 0xAAAAAA,
    };
    uint32_t c = base[idx & 7];
    if (bright) {
        /* halve the low byte per channel toward white */
        c = ((c >> 1) & 0x7F7F7F7F) + 0x7F7F7F7F;
    }
    return c;
}

static void vga_putpixel(uint32_t x, uint32_t y, uint32_t color)
{
    vga.fb[y * vga.pitch_words + x] = color;
}

static void vga_scroll(void)
{
    uint32_t rows = vga.h / VGA_GLYPH_H;
    uint32_t line_words = vga.pitch_words * VGA_GLYPH_H;
    uint32_t shift = (rows - 1) * line_words;
    uint32_t total = rows * line_words;
    if (shift > 0) {
        memmove(vga.fb, vga.fb + shift, (total - shift) * sizeof(uint32_t));
    }
    uint32_t *last = vga.fb + (rows - 1) * line_words;
    for (uint32_t i = 0; i < line_words; i++) {
        last[i] = vga.bg;
    }
}

static void vga_draw_glyph(char ch)
{
    uint8_t c = (uint8_t)ch;
    if (c < 32 || c > 127) c = '?';
    const uint8_t *g = vga_font_8x16[c - 32];

    uint32_t px = vga.col * VGA_GLYPH_W;
    uint32_t py = vga.row * VGA_GLYPH_H;
    if (py + VGA_GLYPH_H > vga.h || px + VGA_GLYPH_W > vga.w) {
        return;
    }

    uint32_t fg = vga.fg, bg = vga.bg;
    if (vga.reverse) { uint32_t t = fg; fg = bg; bg = t; }

    for (uint32_t ry = 0; ry < VGA_GLYPH_H; ry++) {
        uint32_t *line = vga.fb + (py + ry) * vga.pitch_words + px;
        for (uint32_t rx = 0; rx < VGA_GLYPH_W; rx++) {
            line[rx] = (g[ry] >> (7 - rx)) & 1 ? fg : bg;
        }
    }
}

static void vga_clear_cell(void)
{
    vga_draw_glyph(' ');  /* uses current attrs; fine for clearing */
}

static void vga_advance(void)
{
    vga.col++;
    uint32_t cols = vga.w / VGA_GLYPH_W;
    if (vga.col >= cols) {
        vga.col = 0;
        vga.row++;
        uint32_t rows = vga.h / VGA_GLYPH_H;
        if (vga.row >= rows) {
            vga.row = rows - 1;
            vga_scroll();
        }
    }
}

static void vga_putc(char c)
{
    uint32_t cols = vga.w / VGA_GLYPH_W;
    uint32_t rows = vga.h / VGA_GLYPH_H;
    if (cols == 0 || rows == 0) return;

    switch (vga.esc_state) {
    case 0:
        if (c == 0x1b) { vga.esc_state = 1; vga.esc_len = 0; vga.esc_priv = 0; return; }
        break;
    case 1:
        if (c == '[') { vga.esc_state = 2; return; }
        vga.esc_state = 0;
        return;                     /* unsupported non-CSI escape: drop */
    case 2:
        if (c == '?') { vga.esc_priv = 1; return; }
        if (c >= '0' && c <= '9') {
            vga.esc_state = 3;
            if (vga.esc_len < (int)sizeof(vga.esc_buf) - 1) {
                vga.esc_buf[vga.esc_len++] = c;
                vga.esc_buf[vga.esc_len] = '\0';
            }
            return;
        }
        if (c == 'H') { vga.col = 0; vga.row = 0; vga.esc_state = 0; return; }
        if (c == 'J') { burmalda_vga_clear(); vga.esc_state = 0; return; }
        if (c == 'K') {
            uint32_t save_col = vga.col;
            while (vga.col < cols) { vga_draw_glyph(' '); vga.col++; }
            vga.col = save_col;
            vga.esc_state = 0;
            return;
        }
        vga.esc_state = 0;
        return;
    case 3:
        if (c >= '0' && c <= '9') {
            if (vga.esc_len < (int)sizeof(vga.esc_buf) - 1) {
                vga.esc_buf[vga.esc_len++] = c;
                vga.esc_buf[vga.esc_len] = '\0';
            }
            return;
        }
        {
            char final = c;
            vga.esc_state = 0;
            int n = 0;
            if (vga.esc_len > 0) {
                for (int i = 0; i < vga.esc_len; i++) {
                    n = n * 10 + (vga.esc_buf[i] - '0');
                }
            }
            vga.esc_len = 0;
            switch (final) {
            case 'A': if (n > 0 && (uint32_t)n < rows && vga.row >= (uint32_t)n) vga.row -= n; else if (vga.row > 0) vga.row = 0; return;
            case 'B': if ((uint32_t)n < rows) { vga.row += n; if (vga.row >= rows) vga.row = rows - 1; } return;
            case 'C': if ((uint32_t)n < cols) { vga.col += n; if (vga.col >= cols) vga.col = cols - 1; } return;
            case 'D': if (n > 0 && (uint32_t)n < cols && vga.col >= (uint32_t)n) vga.col -= n; else if (vga.col > 0) vga.col = 0; return;
            case 'J': if (n == 2) burmalda_vga_clear(); return;
            case 'K': {
                uint32_t save_col = vga.col;
                while (vga.col < cols) { vga_draw_glyph(' '); vga.col++; }
                vga.col = save_col;
                return;
            }
            case 'H': {
                /* "row;col H" (values in esc_buf, ';' separated) */
                int rr = 1, cc = 1;
                {
                    int v = 0; bool any = false; int part = 0;
                    for (const char *p = vga.esc_buf; *p; p++) {
                        if (*p == ';') {
                            if (part == 0) rr = any ? v : 1;
                            else cc = any ? v : 1;
                            part++; v = 0; any = false;
                        } else { v = v * 10 + (*p - '0'); any = true; }
                    }
                    if (part == 0) rr = any ? v : 1;
                    else cc = any ? v : 1;
                }
                vga.row = (rr > 0 && (uint32_t)rr <= rows) ? (uint32_t)(rr - 1) : 0;
                vga.col = (cc > 0 && (uint32_t)cc <= cols) ? (uint32_t)(cc - 1) : 0;
                return;
            }
            case 'm': {
                /* parse SGR params: up to 4 ints, ';' separated */
                int params[4] = { 0, 0, 0, 0 };
                int nparams = 0;
                {
                    int v = 0; bool any = false;
                    for (const char *p = vga.esc_buf; ; p++) {
                        if (*p == ';' || *p == '\0') {
                            if (nparams < 4) {
                                params[nparams++] = any ? v : 0;
                            }
                            v = 0; any = false;
                            if (*p == '\0') break;
                        } else {
                            v = v * 10 + (*p - '0'); any = true;
                        }
                    }
                }
                if (nparams == 1 && params[0] == 0) {
                    vga.fg = 0xAAAAAA; vga.bg = 0;
                    vga.bold = false; vga.reverse = false;
                } else if (nparams == 0) {
                    vga.fg = 0xAAAAAA; vga.bg = 0;
                    vga.bold = false; vga.reverse = false;
                }
                for (int k = 0; k < nparams; k++) {
                    int p = params[k];
                    if (p == 0)                { vga.fg = 0xAAAAAA; vga.bg = 0; vga.bold = false; vga.reverse = false; }
                    else if (p == 1)           { vga.bold = true; }
                    else if (p == 7)           { vga.reverse = true; }
                    else if (p == 22)          { vga.bold = false; }
                    else if (p == 27)          { vga.reverse = false; }
                    else if (p >= 30 && p <= 37)  { vga.fg = sgr_color(p - 30, vga.bold); }
                    else if (p == 39)          { vga.fg = 0xAAAAAA; }
                    else if (p >= 40 && p <= 47)  { vga.bg = sgr_color(p - 40, false); }
                    else if (p == 49)          { vga.bg = 0; }
                }
                return;
            }
            default:
                return;
            }
        }
    }

    /* plain character */
    switch (c) {
    case '\n':
        vga.col = 0;
        vga.row++;
        if (vga.row >= rows) {
            vga.row = rows - 1;
            vga_scroll();
        }
        return;
    case '\r':
        vga.col = 0;
        return;
    case '\b':
        if (vga.col > 0) {
            vga.col--;
            vga_draw_glyph(' ');
        }
        return;
    case '\t':
        do {
            vga_advance();
        } while (vga.col % VGA_TAB_STOP != 0);
        return;
    case '\a':
    case '\f':
    case '\v':
        return;
    default:
        vga_draw_glyph(c);
        vga_advance();
        return;
    }
}

/* --------------------------------------------------------------------- */

static bool has_semi(const char *s)
{
    for (const char *p = s; *p; p++) {
        if (*p == ';') return true;
    }
    return false;
}

void burmalda_vga_configure(uint32_t *fb, uint32_t w, uint32_t h,
                            uint32_t pitch_bytes, uint32_t bpp)
{
    vga.fb = fb;
    vga.w = w;
    vga.h = h;
    vga.pitch_words = (bpp == 32) ? pitch_bytes / 4 : 0;
    vga.fg = 0xAAAAAA;
    vga.bg = 0x00000000;
    vga.bold = false;
    vga.reverse = false;
    vga.esc_state = 0;
    if (vga.fb == NULL || w == 0 || h == 0 || bpp != 32) {
        vga.fb = NULL;
        vga.w = 0;
        vga.h = 0;
    }
    burmalda_vga_clear();
}

void burmalda_vga_clear(void)
{
    if (vga.fb == NULL) return;
    uint32_t total = vga.pitch_words * vga.h;
    for (uint32_t i = 0; i < total; i++) {
        vga.fb[i] = vga.bg;
    }
    vga.col = 0;
    vga.row = 0;
}

void burmalda_vga_emit(const char *buf, seL4_Word len)
{
    if (vga.fb == NULL) return;
    for (seL4_Word i = 0; i < len; i++) {
        vga_putc(buf[i]);
    }
}

bool burmalda_vga_cursor(uint32_t *out_col, uint32_t *out_row)
{
    if (vga.fb == NULL) return false;
    if (out_col != NULL) *out_col = vga.col;
    if (out_row != NULL) *out_row = vga.row;
    return true;
}
