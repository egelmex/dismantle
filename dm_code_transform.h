/*
 * Copyright (c) 2011, Ed Robbins <static.void01@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __DM_TRANSFORM_CODE_H
#define __DM_TRANSFORM_CODE_H

#include "common.h"
#include "dm_cfg.h"

void			dm_transform_call(struct dm_cfg_node *n);
void			dm_transform_div(struct dm_cfg_node *n);
void			dm_transform_pop(struct dm_cfg_node *n);
void			dm_transform_push(struct dm_cfg_node *n);

void			dm_code_transform_free();
void			dm_transform_code();
void			dm_flatten_indirect_addressing(struct dm_cfg_node *n, int indirect_operand);
struct instruction*	dm_new_pseudo_insn(enum ud_mnemonic_code mnemonic, uint64_t pc, void *op[3], enum op_type type[3], uint8_t inp_ctr);
struct instruction*	dm_new_insn();
void			dm_add_insn(struct dm_cfg_node *node, struct instruction *insn);
struct variable*	get_new_free_variable();
enum address_mode	dm_get_indirect_address_mode(struct ud_operand op);
struct ud_operand	dm_make_ud_register_operand(enum ud_type reg);
struct ud_operand	dm_make_ud_register_mem_operand(enum ud_type reg);
struct ud_operand	dm_make_ud_literal_operand();
int			dm_neg_offset(struct ud_operand *op, struct ud *u);
struct ud_operand	dm_get_offset(struct ud_operand *op, struct ud *u);

#endif

