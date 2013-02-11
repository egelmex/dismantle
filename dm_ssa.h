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

#ifndef __DM_SSA_H
#define __DM_SSA_H

#include "common.h"
#include "dm_dom.h"
#include "dm_cfg.h"

struct dm_ssa_index {
	enum ud_type		  reg;
	int			  count;
	int			 *stack;
	int			  s_size;
	struct dm_cfg_node	**def_nodes; /* Nodes where var defined */
	int			  dn_count;
	struct dm_cfg_node	**phi_nodes; /* Nodes with phi funcs for var */
	int			  pn_count;
};

int			dm_print_superphi(struct super_phi *superphi);
void			dm_amalgamate_phis();
void			dm_add_reg_to_node_defs(struct dm_cfg_node *n, int reg);
void			dm_add_node_to_var_defs(int reg, struct dm_cfg_node *n);
void			gen_pseudo_operand_ssa(struct instruction *insn, int op);
struct variable*	get_new_free_variable();
int			dm_get_register_size(enum ud_mnemonic_code reg);
void			dm_cmd_find_direct_branch(char **args);
void			dm_find_indirect_nodes();
void			dm_free_ssa();
unsigned int		dm_ssa_disassemble(struct ud* u);
struct ptrs*		mergeSort(struct ptrs *list);
struct ptrs*		merge(struct ptrs *left, struct ptrs *right);
struct ptrs*		split(struct ptrs *list);
void			dm_print_ssa();
int			dm_print_block_header(struct dm_cfg_node *node);
int			dm_print_phi_function(struct phi_function *phi);
int			dm_print_ssa_instruction(struct instruction *insn);
void			dm_phi_remove_duplicates(struct phi_function *phi);
void			dm_ssa_index_stack_push(int reg, int i);
int			dm_ssa_index_stack_pop(int reg);
void			dm_rename_variables(struct dm_cfg_node *n);
void			gen_operand_ssa(struct ud* u, struct ud_operand* op, int syn_cast, int *index, int pseudo);
void			dm_translate_intel_ssa(struct instruction *insn);
void			dm_place_phi_functions();
void			dm_ssa_find_var_defs();
void			dm_ssa_index_init();
void			dm_ssa_settings_init();
int			dm_cmd_ssa(char **args);
int			dm_array_contains(struct dm_cfg_node **list, int c, struct dm_cfg_node *term);
void			dm_cmd_find_direct_branch(char **args);

#endif

