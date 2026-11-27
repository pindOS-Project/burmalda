/*
 * burmalda VGA framebuffer console.
 *
 * Optional linear-framebuffer text console: ferrix-init maps the GRUB
 * framebuffer at boot and calls burmalda_vga_configure(); afterwards
 * every console write (fd 1/2) is mirrored to the screen by
 * burmalda_vga_emit().  Serial output is unaffected.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sel4/sel4.h>

/* Attach the framebuffer (32 bpp assumed, type 1 = RGB).  pitch is in
 * bytes.  NULL fb / w==0 disables the console. */
void burmalda_vga_configure(uint32_t *fb, uint32_t w, uint32_t h,
                            uint32_t pitch_bytes, uint32_t bpp);

/* Clear the screen, reset cursor. */
void burmalda_vga_clear(void);

/* Feed console output through the ANSI-lite renderer. */
void burmalda_vga_emit(const char *buf, seL4_Word len);

/* Current cursor cell (for tests/diagnostics). */
bool burmalda_vga_cursor(uint32_t *out_col, uint32_t *out_row);
