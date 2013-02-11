/*
 * Copyright (c) 2011, Ed Robbins <edd.robbins@gmail.com>
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

#ifndef __CFG_H
#define __CFG_H

#include "common.h"
#include "dm_dis.h"

void dm_print_post_messages();
void dm_new_post_message(char *message);
void dm_free_post_messages();

enum op_type {
	DM,
	UD,
	DM_PTR,
	NONE
};

enum address_mode {
	T_PTR_OFFSET,
	T_PTR_BASE,
	T_PTR_BASE_OFFSET,
	T_PTR_BASE_INDEX_SCALE,
	T_PTR_BASE_INDEX_SCALE_OFFSET,
	T_PTR_INDEX_SCALE_OFFSET
};


struct dm_instruction_se {
	enum ud_mnemonic_code	instruction;
	int			write[4];
	int			jump;
	int			ret;
	int			disjunctive;
	int			_signed;
	int			_float;
	int			_double;
	int			_string;
	int			shift;
	int			_unsigned;
	int			unknown;
	int			_class;
};

struct dm_cfg_node {
	NADDR			  start;
	NADDR			  end;
	struct dm_cfg_node	**children;
	struct dm_cfg_node	**parents;
	int			  c_count;
	int			  p_count;
	int			  nonlocal;
	int			  visited;
	int			  pre;     /* Pre-order position */
	int			  post;    /* Post-order position */
	int			  rpost;   /* Reverse Post-order position */
	struct dm_cfg_node	 *idom;	   /* Immediate dominator of node */
	struct dm_cfg_node	**df_set;  /* Dominance frontier set of node */
	int			  df_count;
	enum ud_type		 *def_vars;/* Vars defined in this node */
	int			  dv_count;
	struct phi_function	 *phi_functions;/* Vars requiring phi funcs */
	int			  pf_count;
	struct super_phi	 *superphi;
	struct instruction	**instructions; /* Instructions in this node */
	int			  i_count;
	int			  phi_inserted;
	int			  added;
	struct dm_cfg_node	 *function_head;
	struct dm_cfg_node	**function_return;
	int			  is_function_head;
	int			  is_function_return;
	struct dm_cfg_node	**function_nodes;
	int			  fn_count;
	struct dm_cfg_node	**return_nodes;
	int			  rn_count;
};

struct indirect_branch {
	NADDR	address;
	struct instruction *insn;
	struct dm_cfg_node *node;
};

struct branch {
	NADDR addr;
	NADDR target;
	struct instruction *insn;
	struct dm_cfg_node *node;
};

struct phi_function {
	enum ud_type		   var;
	int			   arguments;
	int			   index;
	int			  *indexes;
	struct type_constraint	***constraints;
	int			  *c_counts;
	int			   d_count;
};

struct super_phi {
	enum ud_type		  *vars;
	int			   var_count;
	int			   arguments;
	int			  *index;
	int			 **indexes;
	struct type_constraint	***constraints;
	int			  *c_counts;
	int			   d_count;
};

struct variable {
	int index;
	int ssa_i;
};

struct instruction {
	struct ud		   ud;
	int			   index[3][2];
	int			   psuedo;
	int			   cast[3]; /* XXX - change cast and fv_operands into single operand type array */
	int			   fv_operands[3];
	struct variable		  *operands[3];
	struct type_constraint	***constraints; /* Constraints */
	int			  *c_counts; /*# conjunctions */
	int			   d_count; /*# disjunctions */
	int			   covered;
	int			   paddr;
};

enum type_class {
	T_REGISTER,
	T_PTR,
	T_BASIC,
	T_ALPHA,
	T_ARRAY,
	T_STRUCT
};

enum basic_type {
	//BT_CHAR = 8,	/* 8 bit uint8 */
	//BT_SHORT = 16,	/* 16 bit uint16 */
	//BT_INT = 32,	/* 32 bit uint32 */
	//BT_LONG = 64,	/* 64 bit uint64 */
	BT_UBYTE = 8,
	BT_UWORD = 16,
	BT_UDWORD = 32,
	BT_UQWORD = 64,
	BT_SBYTE = -8,
	BT_SWORD = -16,
	BT_SDWORD = -32,
	BT_SQWORD = -64,
	BT_FLOAT = 31,
	BT_DOUBLE = 63
};

struct lval {
	int	_signed;
	int	size;
	union {
		int8_t		sbyte;
		uint8_t		ubyte;
		int16_t		sword;
		uint16_t	uword;
		int32_t		sdword;
		uint32_t	udword;
		int64_t		sqword;
		uint64_t	uqword;
	} lval_u;
};

struct type_descriptor {
	enum type_class		  c_type;
	/* If register */
	enum ud_mnemonic_code	  reg;
	int			r_index;
	int			r_size;
	/* If ptr */
	struct type_descriptor	 *p_type;
	/* If struct */
	struct type_descriptor	**types;
	struct lval		 *offsets;
	int			  t_count;
	/* If basic type */
	enum basic_type		  b_type;
	/* If alpha */
	int			  a_index;
	/* If array */
	struct type_descriptor	 *a_type;
	/* */
	struct type_descriptor	 *set;
	struct type_constraint	 *def;
};

struct type_constraint {
	struct type_descriptor	  *left;
	struct type_descriptor	  *right;
};

/*
 * A linked list of all the CFG blocks so we can free them at the end.
 * XXX queue.h
 */
struct ptrs {
	void		*ptr;
	struct ptrs	*next;
};

void			dm_graph_cg_aux(struct dm_cfg_node *node, FILE *fp);
void			dm_add_node_to_function(struct dm_cfg_node *func, struct dm_cfg_node *node);
void			dm_add_return_node(struct dm_cfg_node *node, struct dm_cfg_node *return_node);
void			dm_print_node_info(struct dm_cfg_node *node);
void			dm_check_cfg_consistency();
void			dm_instruction_se_init();
int			dm_cmd_cfg(char **args);

void			dm_free_jumps();
int			dm_is_target_in_text(NADDR addr);
struct dm_cfg_node*	dm_recover_cfg();
void			dm_init_cfg();
struct dm_cfg_node*	dm_new_cfg_node(NADDR nstart, NADDR nend);
void			dm_print_cfg();
void			dm_graph_cfg();
void			dm_free_cfg();
struct dm_cfg_node*	dm_gen_cfg_block(struct dm_cfg_node *node, struct dm_cfg_node *function_head, struct dm_cfg_node **function_return);

void			dm_dfw(struct dm_cfg_node *node);
struct dm_cfg_node*	dm_get_unvisited_node();
void			dm_depth_first_walk(struct dm_cfg_node *cfg);

void			dm_add_child(struct dm_cfg_node *node, struct dm_cfg_node *child);
void			dm_add_parent(struct dm_cfg_node *node, struct dm_cfg_node *parent);
struct dm_cfg_node*	dm_split_cfg_block(struct dm_cfg_node *node, NADDR addr);
struct dm_cfg_node*	dm_find_cfg_node_starting(NADDR addr);
struct dm_cfg_node*	dm_find_cfg_node_ending(NADDR addr);
struct dm_cfg_node*	dm_find_cfg_node_containing(NADDR addr);
char*			dm_disassemble_node(struct dm_cfg_node *node);
#endif
