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
#define _GNU_SOURCE
#include "dm_ssa.h"
#include "dm_dwarf.h"
#include "dm_code_transform.h"
#include "dm_util.h"

void opr_cast(struct ud* u, struct ud_operand* op);

//extern void mkasm(struct ud* u, const char* fmt, ...);
//extern void opr_cast(struct ud* u, struct ud_operand* op);
//extern const char* ud_reg_tab[];

extern struct dm_instruction_se *instructions;
extern struct ptrs		*p_head;
extern struct ptrs		*p;
extern int			 p_length;

struct dm_ssa_index		*indices = NULL;

unsigned long long int coverageTC = 0;

extern struct indirect_branch* iBranches;
extern int	iBranchesCount;

//extern struct ptrs *variables = NULL;
//extern struct ptrs *variables_head = NULL;
extern int variables_count;

int
dm_cmd_ssa(char **args)
{
	NADDR			 addr = cur_addr;
	struct dm_cfg_node	*cfg = NULL;
	char			 message[200];
	GElf_Shdr		 shdr;
	unsigned long long int	 size = 0;

	(void) args;

	/* Initialise structures */
	dm_init_cfg();

	/* Get CFG */
	printf("Recovering CFG...");
	cfg = dm_recover_cfg();
	printf("done\n");

	/* Build dominator tree */
	printf("Building dominator tree...");
	dm_dom(cfg);
	printf("done\n");

	/* Build dominance frontier sets*/
	printf("Building dominance frontier sets...");
	dm_dom_frontiers();
	printf("done\n");

	/* Transform instructions */
	dm_transform_code();

	/* Load settings */
	dm_ssa_settings_init();

	/* Initialise register index structure */
	dm_ssa_index_init();

	printf("Building list of variable definitions...");
	/* Build lists of variables defined in each node */
	dm_ssa_find_var_defs();
	printf("done\n");

	printf("Placing phi functions...");
	/* Place phi functions in correct nodes */
	dm_place_phi_functions();
	printf("done\n");

	printf("Renaming variables...");
	/* Rename all the variables with SSA indexes */
	dm_rename_variables(cfg);
	printf("done\n");

	printf("Amalgamating phis...");
	dm_amalgamate_phis();
	printf("done\n");

	/* Print SSA version of the function */
	dm_print_ssa();

	if ((dm_find_section(".text", &shdr)) != DM_FAIL) {
		size = shdr.sh_size;
		sprintf(message, "Coverage = %llu/%llu bytes = %f%%", coverageTC, size, ((double)coverageTC/(double)size) * 100);
		dm_new_post_message(message);
		sprintf(message, "Latex table string: & %.1f & %llu/%llu & %d \\\\", ((double)coverageTC/(double)size) * 100, coverageTC, size, iBranchesCount);
	}
	else
		sprintf(message, "Coverage = %llu bytes", coverageTC);
	dm_new_post_message(message);
	coverageTC = 0;

	dm_print_post_messages();

	dm_find_indirect_nodes();

	dm_free_jumps();

	/* Free all memory used */
	dm_free_ssa();

	dm_code_transform_free();

	/* Free dominance frontier sets */
	dm_dom_frontiers_free();

	/* Free all CFG structures */
	dm_free_cfg();

	dm_free_post_messages();

	/* Rewind back */
	dm_seek(addr);

	return (0);
}

int flatten = 0;
int transform = 0;

void
dm_ssa_settings_init()
{
	struct  dm_setting	*set_transform = NULL, *set_flatten = NULL;

	/* Get fcalls setting */
	dm_find_setting("ssa.transform", &set_transform);
	dm_find_setting("ssa.flatten", &set_flatten);
	flatten = set_flatten->val.ival;
	transform = set_transform->val.ival;
}

int
dm_get_register_size(enum ud_mnemonic_code reg)
{
	if ((reg > 0) && (reg < 21)) {
		return 8;
	} /* 16 bit GPRs */
	else if (reg < 37) {
		return 16;
	} /* 32 bit GPRs */
	else if (reg < 53) {
		return 32;
	} /* 64 bit GPRs and x87 FPU registers */
	else if ((reg < 69) || ((reg > 114) && (reg < 123))){
		return 64;
	} /* Have to guess  - arch memory width (32/64 bit)*/
	else {
		return file_info.bits;
	}
}

extern struct branch *branches;
extern int branchesCount;

void
dm_cmd_find_direct_branch(char **args)
{
	NADDR			 addr = strtoll(args[0], NULL, 0);
	NADDR			 oaddr = cur_addr;
	struct dm_cfg_node	*cfg = NULL;
	int			 i = 0, j = 0, found = 0;
	(void) args;

	printf("Finding branches to " NADDR_FMT "...\n", addr);

	dm_init_cfg();
	cfg = dm_recover_cfg();
	dm_dom(cfg);
	dm_dom_frontiers();
	dm_ssa_index_init();
	dm_ssa_find_var_defs();
	dm_place_phi_functions();
	dm_rename_variables(cfg);
	for (; i < branchesCount; i++) {
		if(branches[i].target == addr) {
			if ((branches[i].node = dm_find_cfg_node_containing(branches[i].addr)) != NULL) 
				found = 1;
			else if ((branches[i].node = dm_find_cfg_node_starting(branches[i].addr)) != NULL)
				found = 1;
			else if ((branches[i].node = dm_find_cfg_node_ending(branches[i].addr)) != NULL)
				found = 1;
			if (found) {
				for (j = 0; j < branches[i].node->i_count; j++) {
					if (branches[i].addr == dm_get_jump_target(branches[i].node->instructions[j]->ud)) {
						branches[i].insn = branches[i].node->instructions[j];
						printf("Jump to " NADDR_FMT " at " NADDR_FMT ": %s (in node %d, start: " NADDR_FMT ", end: " NADDR_FMT ")\n",
							addr, branches[i].addr, branches[i].insn->ud.insn_buffer, branches[i].node->post, branches[i].node->start, branches[i].node->end);
					}
				}
				found = 0;
			}
			else
				printf("Jump to " NADDR_FMT " at " NADDR_FMT "\n", addr, branches[i].addr);
		}
	}
	dm_free_jumps();
	dm_free_ssa();
	dm_dom_frontiers_free();
	dm_free_cfg();
	dm_free_post_messages();
	dm_seek(oaddr);
}

void
dm_find_indirect_nodes()
{
	int i = 0, j = 0, found = 0;
	printf("# indirect branches: %d\n", iBranchesCount);
	for (; i < iBranchesCount; i++) {
		if ((iBranches[i].node = dm_find_cfg_node_containing(iBranches[i].address)) != NULL)
			found = 1;
		else if ((iBranches[i].node = dm_find_cfg_node_starting(iBranches[i].address)) != NULL)
			found = 1;
		else if ((iBranches[i].node = dm_find_cfg_node_ending(iBranches[i].address)) != NULL)
			found = 1;
		if (found == 1) {
			for (j = 0; j < iBranches[i].node->i_count; j++) {
				if (iBranches[i].address == (iBranches[i].node->instructions[j]->ud.pc - ud_insn_len(&(iBranches[i].node->instructions[j]->ud)))) {
					iBranches[i].insn = iBranches[i].node->instructions[j];
					break;
				}
			}
			printf("\tFound unfollowed branch (%s) in node %d (start: " NADDR_FMT ", end: " NADDR_FMT ") at address " NADDR_FMT "\n",
				iBranches[i].insn->ud.insn_buffer, iBranches[i].node->post, iBranches[i].node->start, iBranches[i].node->end, iBranches[i].address);
			/* See if any parents define this variable */
			/*for (j = 0; j < iBranches[i].node->p_count; j++) {

			}*/
		}
		found = 0;
	}
}

/*
 * Disassemble without translating into assembler (just decode instructions)
 */
unsigned int
dm_ssa_disassemble(struct ud* u)
{
	if (ud_input_end(u))
		return 0;

	u->insn_buffer[0] = u->insn_hexcode[0] = 0;

	if (ud_decode(u) == 0)
		return 0;
	return ud_insn_len(u);
}

struct ptrs*
mergeSort(struct ptrs *list)
{
	struct ptrs *right;

	if (list->next == NULL)
	return list;

	right = split(list);

	return merge(mergeSort(list), mergeSort(right));
}

struct ptrs*
merge(struct ptrs *left, struct ptrs *right)
{
	struct dm_cfg_node *left_p = NULL, *right_p = NULL;
	if (left) left_p = (struct dm_cfg_node*)left->ptr;
	if (right) right_p = (struct dm_cfg_node*)right->ptr;
	if (left == NULL)
		return right;
	else if (right == NULL)
		return left;
	else if (left_p->start > right_p->start)
		return merge(right, left);
	else {
		left->next = merge(left->next, right);
		return left;
	}
}

struct ptrs*
split(struct ptrs *list)
{
	struct ptrs *right;

	if ((list == NULL) || (list->next == NULL))
		return NULL;

	right = list->next;
	list->next = right->next;
	right->next = split(list->next);

	return right;
}

/*
 * Print ssa assembler of all blocks
 */
void
dm_print_ssa()
{
	int			 i = 0;
	struct dm_cfg_node	*node = NULL;

	/* Sort blocks in order of starting address */
	p_head = mergeSort(p_head);

	/* Print blocks in ssa assembler */
	for (p = p_head; (p != NULL); p = p->next) {
		node = (struct dm_cfg_node*)p->ptr;
		/* Print header */
		dm_print_block_header(node);
		/* Print phi nodes */
		for (i = 0; i < node->pf_count; i++) {
			dm_phi_remove_duplicates(&node->phi_functions[i]);
			//dm_print_phi_function(&node->phi_functions[i]);
			//printf("\n");
		}
		if (node->superphi) {
			dm_print_superphi(node->superphi);
			printf("\n");
		}
		/* Print standard instructions */
		for (i = 0; i < node->i_count; i++) {
			dm_print_ssa_instruction(node->instructions[i]);
			printf("\n");
		}
	}
	/*for (i = 0; i < 8; i++) {
		for (j = 0; j < 6; j++)
			printf("\033[%d;7;%dm    Test    ", j, i + 30);
	}
	printf("%s%s%s%s%s     ", ESCAPE, NORMAL, INVERT, FG, BLUE);
	printf("\033[0m\n");*/
}

/*
 * Print the header of a CFG block
 */
int
dm_print_block_header(struct dm_cfg_node *node)
{
	struct dm_dwarf_sym_cache_entry	*sym = NULL;
	int				 length = 0;
	if (dm_dwarf_find_sym_at_offset(node->start, &sym) == DM_OK)
		length += printf("%sBlock %d (%s):\n%s", ANSII_LIGHTBLUE, node->post, sym->name, ANSII_WHITE);
	else
		length += printf("%sBlock %d:\n%s", ANSII_LIGHTBLUE, node->post, ANSII_WHITE);
	return length;
}

int
dm_print_superphi(struct super_phi *superphi)
{
	int	 length = 0, i = 0, j = 0;
	char	*temp = NULL, *temp2 = NULL;

	printf("%s", ANSII_GREEN);
	length += xasprintf(&temp, "%41smov [%s_%d", "", ud_reg_tab[superphi->vars[0] - 1], superphi->index[0]);
	if (superphi->var_count > 1)
		for (i = 1; i < superphi->var_count; i++) {
			temp2 = temp;
			length += xasprintf(&temp, "%s, %s_%d", temp2, ud_reg_tab[superphi->vars[i] - 1], superphi->index[i]);
			free(temp2);
		}
	temp2 = temp;
	length += xasprintf(&temp, "%s], phi([", temp2);
	free(temp2);
	for (i = 0; i < superphi->arguments; i++) {
		temp2 = temp;
		length += xasprintf(&temp, "%s[", temp2);
		free(temp2);
		for (j = 0; j < superphi->var_count; j++) {
			temp2 = temp;
			length += xasprintf(&temp, "%s%s_%d", temp2, ud_reg_tab[superphi->vars[j] - 1], superphi->indexes[j][i]);
			free(temp2);
			if (j != superphi->var_count -1) {
				temp2 = temp;
				length += xasprintf(&temp, "%s, ", temp2);
				free(temp2);
			}
		}
		temp2 = temp;
		length += xasprintf(&temp, "%s]", temp2);
		free(temp2);
		if (i != superphi->arguments - 1) {
			temp2 = temp;
			length += xasprintf(&temp, "%s, ", temp2);
			free(temp2);
		}
	}
	temp2 = temp;
	length += xasprintf(&temp, "%s)", temp2);
	free(temp2);
	printf("%s", temp);
	free(temp);
	printf(ANSII_WHITE);
	return length;
}

/*
 * Print a phi function
 */
int
dm_print_phi_function(struct phi_function *phi)
{
	int	 i = 0, length = 0, length2 = 0;
	int	 newlines = 0;
	char	*temp = NULL, *temp2 = NULL;

	printf("%s", ANSII_GREEN);
	if (phi->var - 1 < UD_OP_CONST)
		length2 += xasprintf(&temp, "%41smov %s_%d, phi(", "", ud_reg_tab[phi->var - 1], phi->index);
	else
		length2 += xasprintf(&temp, "%41smov var%d_%d, phi(", "", phi->var - (UD_OP_CONST), phi->index);

	for (i = 0; i < phi->arguments; i++){
		temp2 = temp;
		if (phi->var - 1 < UD_OP_CONST)
			length2 += xasprintf(&temp, "%s%s_%d", temp, ud_reg_tab[phi->var - 1], phi->indexes[i]);
		else
			length2 += xasprintf(&temp, "%svar%d_%d", temp, phi->var - (UD_OP_CONST), phi->indexes[i]);
		free(temp2);
		if (i != phi->arguments - 1) {
			temp2 = temp;
			length2 += xasprintf(&temp, "%s, ", temp);
			free(temp2);
			if (length2 > 200) {
				printf("%-81s\n", temp);
				free(temp);
				xasprintf(&temp, "%43s", "");
				length2 = 0;
				newlines++;
			}
		}
	}
	temp2 = temp;
	xasprintf(&temp, "%s)", temp);
	free(temp2);
	length += printf("%-81s", temp);
	printf(ANSII_WHITE);
	free(temp);
	return newlines;
}

/*
 * Since we generate one argument for every parent of a node in the phi
 * function, some arguments may be duplicates of each other. Therefore we
 * must remove them.
 */
void
dm_phi_remove_duplicates(struct phi_function *phi)
{
	int i = 0, j = 0, duplicate = 0;
	int arguments = 0, *indexes = NULL;
	for (i = 0; i < phi->arguments; i++) {
		duplicate = 0;
		for (j = 0; j < phi->arguments; j++)
			if ((phi->indexes[i] == phi->indexes[j]) && (i != j) && (j > i))
				duplicate = 1;
		if (!duplicate) {
			indexes = xrealloc(indexes, ++arguments * sizeof(int));
			indexes[arguments - 1] = phi->indexes[i];
		}
	}
	free(phi->indexes);
	phi->indexes = indexes;
	phi->arguments = arguments;
}

void
dm_amalgamate_phis()
{
	struct dm_cfg_node	*node = NULL;
	struct super_phi	*superphi = NULL;
	int			 i = 0, j = 0;
	struct ptrs             *p_iter = NULL;

	for (p_iter = p_head; p_iter != NULL; p_iter = p_iter->next) {
		node = (struct dm_cfg_node*) p_iter->ptr;
		if (node->pf_count) {
			superphi = xmalloc(sizeof(struct super_phi));
			superphi->vars = xmalloc(node->pf_count * sizeof(int));
			superphi->var_count = node->pf_count;
			superphi->arguments = node->phi_functions[0].arguments;

			superphi->index = xmalloc(superphi->var_count * sizeof(int));
			superphi->indexes = xmalloc(superphi->var_count * sizeof(int*));

			for (i = 0; i < superphi->var_count; i++) {
				superphi->indexes[i] = xmalloc(superphi->arguments * sizeof(int));
				superphi->index[i] = node->phi_functions[i].index;
				superphi->vars[i] = node->phi_functions[i].var;
				for (j = 0; j < superphi->arguments; j++) {
					superphi->indexes[i][j] = node->phi_functions[i].indexes[j];
				}
			}
			node->superphi = superphi;
		}
	}
}

/*
 * Print an instruction
 */
int
dm_print_ssa_instruction(struct instruction *insn)
{
	struct dm_dwarf_sym_cache_entry *sym = NULL;
	struct dm_cfg_node		*found_node = NULL;
	NADDR				 addr = 0;
	char				*hex = NULL, *temp = NULL;
	int				 colour_set = 0, length = 0;

	/* Translate into ssa assembler */
	dm_translate_intel_ssa(insn);

	if ((insn->ud.br_far) || (insn->ud.br_near) ||
	    (instructions[insn->ud.mnemonic].jump)) {
		/* jumps and calls are yellow */
		printf(ANSII_BROWN);
		colour_set = 1;
	}
	else if ((insn->ud.mnemonic == UD_Iret) ||
	    (insn->ud.mnemonic == UD_Iretf)) {
		/* Returns are red */
		printf(ANSII_RED);
		colour_set = 1;
	}

	length += printf("  ");
	addr = insn->ud.pc - ud_insn_len(&(insn->ud));
	length += printf(NADDR_FMT, addr);
	if (insn->paddr != -1)
		printf(".%d", insn->paddr);
	else
		printf("  ");
	hex = ud_insn_hex(&(insn->ud));
	/* If possible print target of jumps and calls as a block number or
	 * function name */
	if (instructions[insn->ud.mnemonic].jump ||
	    (insn->ud.mnemonic == UD_Icall))
		addr = dm_get_jump_target(insn->ud);

	if ((instructions[insn->ud.mnemonic].jump) &&
	    (found_node = dm_find_cfg_node_starting(addr))) {
		xasprintf(&temp, "%s (Block %d)", insn->ud.insn_buffer, found_node->post);
		length += printf(": %-25s%-40s  ", hex, temp);
		free(temp);
	}
	else if ((insn->ud.mnemonic == UD_Icall) &&
	    (dm_dwarf_find_sym_at_offset(addr, &sym) == DM_OK)) {
		xasprintf(&temp, "%s (%s)", insn->ud.insn_buffer, sym->name);
		length += printf(": %-25s%-40s  ", hex, temp);
		free(temp);
	}
	else
		length += printf(": %-25s%-40s  ", hex, insn->ud.insn_buffer);

	/* Set colour back to white if required */
	if (colour_set) {
		printf(ANSII_WHITE);
		colour_set = 0;
	}
	return 0;
}

/*
 * Index all variable uses, build a list of instructions for each block
 */
void
dm_rename_variables(struct dm_cfg_node *n)
{
	struct instruction	*insn = NULL;
	struct ptrs		*p_iter = NULL;
	struct dm_cfg_node	*node = NULL;
	int			 reg = 0, s_size = 0;
	int			 i = 0, j = 0, k = 0;

	/* For each statement in node n */
	/* Start with phi functions */
	for (i = 0; i < n->pf_count; i++) {
		reg = n->phi_functions[i].var;
		indices[reg].count++;
		dm_ssa_index_stack_push((enum ud_type)reg, indices[reg].count);
		n->phi_functions[i].index =
		    indices[reg].stack[indices[reg].s_size - 1];
	}
	/* Then normal instructions/statements */
	for (i = 0; i < n->i_count; i++) {
		/*printf("Renaming variables for block %d - start: " NADDR_FMT ", end: " NADDR_FMT
			"\n", n->post, n->start, n->end);*/
		insn = n->instructions[i];
		/* For each use of a variable, use the correct index */
		for (k = 0; k < 3; k++) {
			if (insn->fv_operands[k]) {
				if (instructions[insn->ud.mnemonic].write[k] && (insn->cast[k] == 0)) {
					reg = insn->operands[k]->index + UD_OP_CONST;
					//printf("Reg = %d, Index = %d\n", reg, insn->operands[k]->index);
					indices[reg].count++;
					dm_ssa_index_stack_push(reg, indices[reg].count);
					s_size = indices[reg].s_size - 1;
					insn->index[k][0] = indices[reg].stack[s_size];
					insn->index[k][1] = -1;
					insn->operands[k]->ssa_i = indices[reg].stack[s_size];
				}
				else {
					reg = insn->operands[k]->index + UD_OP_CONST;
					//printf("Reg = %d, Index = %d\n", reg, insn->operands[k]->index);
					s_size = indices[reg].s_size - 1;
					insn->index[k][0] = indices[reg].stack[s_size];
					insn->index[k][1] = -1;
					insn->operands[k]->ssa_i = indices[reg].stack[s_size];
				}
			}
			else {
				if (insn->ud.operand[k].type == UD_OP_MEM) {
					reg = (int)insn->ud.operand[k].base;
					s_size = indices[reg].s_size - 1;
					insn->index[k][0] = indices[reg].stack[s_size];
					reg = (int)insn->ud.operand[k].index;
					s_size = indices[reg].s_size - 1;
					insn->index[k][1] = indices[reg].stack[s_size];
				}
				else if (instructions[insn->ud.mnemonic].write[k] && insn->ud.operand[k].type == UD_OP_REG) {
					reg = (int)insn->ud.operand[k].base;
					indices[reg].count++;
					dm_ssa_index_stack_push(reg, indices[reg].count);
					s_size = indices[reg].s_size - 1;
					insn->index[k][0] = indices[reg].stack[s_size];
					insn->index[k][1] = -1;
				}
				else if (insn->ud.operand[k].type == UD_OP_REG) {
					reg = (int)insn->ud.operand[k].base;
					s_size = indices[reg].s_size - 1;
					insn->index[k][0] = indices[reg].stack[s_size];
					insn->index[k][1] = -1;
				}
				else {
					insn->index[k][0] = -1;
					insn->index[k][1] = -1;
				}
			}
		}
	}
	/* For each child of n */
	for (i = 0; i < n->c_count; i++) {
		for (j = 0; j < n->children[i]->p_count; j++)
			if (n->children[i]->parents[j] == n)
				break;
		node = (struct dm_cfg_node*) n->children[i];
		/* n is the jth parent of child i */
		/* Put the right index on the jth argument of all phi funcs in
		 * child i */
		for (k = 0; k < node->pf_count; k++) {
			reg = node->phi_functions[k].var;
			node->phi_functions[k].indexes[j] =
			    indices[reg].stack[indices[reg].s_size - 1];
		}
	}
	/* Call this function on all children (in dom tree) of this node */
	for (p_iter = p_head; p_iter != NULL; p_iter = p_iter->next) {
		node = (struct dm_cfg_node*)p_iter->ptr;
		if ((node->idom == n) && (node != n))
			dm_rename_variables(node);
	}
	/* Now for every definition of a variable in this node pop the ssa
	 * index that was added */
	for (i = 0; i < n->i_count; i++) {
		insn = n->instructions[i];
		for (k = 0; k < 3; k++) {
			if (instructions[insn->ud.mnemonic].write[k]) {
				if (insn->fv_operands[k] && (insn->cast[k] == 0)) {
					reg = insn->operands[k]->index + UD_OP_CONST;
					//printf("Reg = %d, Index = %d\n", reg, insn->operands[k]->index);
					dm_ssa_index_stack_pop(reg);
				}
				else if ((insn->fv_operands[k] == 0) && (insn->ud.operand[k].type == UD_OP_REG)) {
					reg = (int)insn->ud.operand[k].base;
					dm_ssa_index_stack_pop(reg);
				}
			}
		}
	}
	/* Same for phi functions */
	for (i = 0; i < n->pf_count; i++) {
		reg = n->phi_functions[i].var;
		dm_ssa_index_stack_pop(reg);
	}
}

void
gen_pseudo_operand_ssa(struct instruction *insn, int op)
{
	struct ud* u = &(insn->ud);
	if (op)
		mkasm(u, ", ");
	if (insn->cast[op])
		mkasm(u, "[var%d_%d]", insn->operands[op]->index, insn->index[op][0]);
	else
		mkasm(u, "var%d_%d", insn->operands[op]->index, insn->index[op][0]);
}

/*
 * Translate a ud struct (instruction) into ssa assembler
 */
void
dm_translate_intel_ssa(struct instruction *insn)
{
	struct ud*	u = &(insn->ud);
	int		index[3][2];
	int		i = 0, fv_operand = 0;

	for (; i < 3; i++) {
		if (insn->fv_operands[i])
			fv_operand = 1;
	}

	memcpy(index, insn->index, sizeof(index));
	/* -- prefixes -- */

	if (!fv_operand) {
	/* check if P_OSO prefix is used */
	if (! P_OSO(u->itab_entry->prefix) && u->pfx_opr) {
		switch (u->dis_mode) {
			case 16:
				mkasm(u, "o32 ");
				break;
			case 32:
			case 64:
				mkasm(u, "o16 ");
				break;
		}
	}

	/* check if P_ASO prefix was used */
	if (! P_ASO(u->itab_entry->prefix) && u->pfx_adr) {
		switch (u->dis_mode) {
			case 16:
				mkasm(u, "a32 ");
				break;
			case 32:
				mkasm(u, "a16 ");
				break;
			case 64:
				mkasm(u, "a32 ");
				break;
		}
	}

	if (u->pfx_seg && u->operand[0].type != UD_OP_MEM &&
	    u->operand[1].type != UD_OP_MEM ) {
	    mkasm(u, "%s", ud_reg_tab[u->pfx_seg - UD_R_AL]);
	}
	if (u->pfx_lock)
		mkasm(u, "lock ");
	if (u->pfx_rep)
		mkasm(u, "rep ");
	if (u->pfx_repne)
		mkasm(u, "repne ");
	}

	/* print the instruction mnemonic */
	mkasm(u, "%s ", ud_lookup_mnemonic(u->mnemonic));

	if (insn->fv_operands[0])
		gen_pseudo_operand_ssa(insn, 0);
	else {
		/* operand 1 */
		if (u->operand[0].type != UD_NONE) {
			int cast = 0;
			if (u->operand[0].type == UD_OP_IMM &&
			    u->operand[1].type == UD_NONE)
				cast = u->c1;
			if (u->operand[0].type == UD_OP_MEM) {
				cast = u->c1;
				if (u->operand[1].type == UD_OP_IMM ||
				    u->operand[1].type == UD_OP_CONST)
					cast = 1;
				if (u->operand[1].type == UD_NONE)
						cast = 1;
				if ((u->operand[0].size != u->operand[1].size ) &&
				    u->operand[1].size)
					cast = 1;
			} else if ( u->operand[ 0 ].type == UD_OP_JIMM )
				if ( u->operand[ 0 ].size > 8 )
					cast = 1;
			insn->cast[0] = cast;
			gen_operand_ssa(u, &u->operand[0], cast, index[0], fv_operand);
		}
	}

	if (insn->fv_operands[1])
		gen_pseudo_operand_ssa(insn, 1);
	else {
		/* operand 2 */
		if (u->operand[1].type != UD_NONE) {
			int cast = 0;
			mkasm(u, ", ");
			if ( u->operand[1].type == UD_OP_MEM ) {
				cast = u->c1;
				if ( u->operand[0].type != UD_OP_REG )
					cast = 1;
				if ( u->operand[0].size != u->operand[1].size &&
				    u->operand[1].size )
					cast = 1;
				if ( u->operand[0].type == UD_OP_REG &&
				    u->operand[0].base >= UD_R_ES &&
				    u->operand[0].base <= UD_R_GS )
					cast = 0;
			}
			insn->cast[1] = cast;
			gen_operand_ssa(u, &u->operand[1], cast, index[1], fv_operand);
		}
	}

	/* operand 3 */
	if (u->operand[2].type != UD_NONE) {
		mkasm(u, ", ");
		insn->cast[2] = u->c3;
		gen_operand_ssa(u, &u->operand[2], u->c3, index[2], fv_operand);
	}
}

/*
 * Translate an operand of a ud struct into ssa assembly form
 */
void
gen_operand_ssa(struct ud* u, struct ud_operand* op, int syn_cast, int *index, int pseudo)
{
	switch(op->type) {
		case UD_OP_REG:
			mkasm(u, "%s_%d", ud_reg_tab[op->base - UD_R_AL],
			    index[0]);
			break;
		case UD_OP_MEM: {
			int op_f = 0;

			if (syn_cast)
				opr_cast(u, op); /* XXX fix warning */

			mkasm(u, "[");

			if (u->pfx_seg)
				mkasm(u, "%s:",
				    ud_reg_tab[u->pfx_seg - UD_R_AL]);

			if (op->base) {
				mkasm(u, "%s_%d",
				    ud_reg_tab[op->base - UD_R_AL], index[0]);
				op_f = 1;
			}

			if (op->index) {
				if (op_f)
					mkasm(u, "+");
				mkasm(u, "%s_%d",
				    ud_reg_tab[op->index -UD_R_AL], index[1]);
				op_f = 1;
			}

			if (op->scale)
				mkasm(u, "*%d", op->scale);

			if (op->offset == 8) {
				if (op->lval.sbyte < 0)
					mkasm(u, "-0x%x", -op->lval.sbyte);
				else
					mkasm(u, "%s0x%x", (op_f) ? "+" : "",
					    op->lval.sbyte);
			}
			else if (op->offset == 16)
				mkasm(u, "%s0x%x", (op_f) ? "+" : "",
				    op->lval.uword);
			else if (op->offset == 32) {
				if (u->adr_mode == 64) {
					if (op->lval.sdword < 0)
						mkasm(u, "-0x%x",
						    -op->lval.sdword);
					else
						mkasm(u, "%s0x%x",
						    (op_f) ? "+" : "",
						    op->lval.sdword);
				}
				else
					mkasm(u, "%s0x%lx", (op_f) ? "+" : "",
					    op->lval.udword);
			}
			else if (op->offset == 64)
				mkasm(u, "%s0x" FMT64 "x", (op_f) ? "+" : "",
				    op->lval.uqword);

			mkasm(u, "]");
			break;
		}

		case UD_OP_IMM: {
			int64_t  imm = 0;
			uint64_t sext_mask = 0xffffffffffffffffull;
			unsigned sext_size = op->size;

			if (syn_cast)
				opr_cast(u, op);
			switch (op->size) {
				case  8: imm = op->lval.sbyte; break;
				case 16: imm = op->lval.sword; break;
				case 32: imm = op->lval.sdword; break;
				case 64: imm = op->lval.sqword; break;
			}
			if (!pseudo) {
			if ( P_SEXT( u->itab_entry->prefix ) ) {
				sext_size = u->operand[ 0 ].size;
				if ( u->mnemonic == UD_Ipush )
					/* push sign-extends to operand size */
					sext_size = u->opr_mode;
			}
			}
			if ( sext_size < 64 )
				sext_mask = ( 1ull << sext_size ) - 1;
			mkasm( u, "0x" FMT64 "x", imm & sext_mask );

			break;
		}

		case UD_OP_JIMM:
			if (syn_cast) opr_cast(u, op);
			switch (op->size) {
				case  8:
					mkasm(u, "0x" FMT64 "x", u->pc +
					    op->lval.sbyte);
					break;
				case 16:
					mkasm(u, "0x" FMT64 "x", ( u->pc +
					    op->lval.sword ) & 0xffff );
					break;
				case 32:
					mkasm(u, "0x" FMT64 "x", ( u->pc +
					    op->lval.sdword ) & 0xfffffffful );
					break;
				default:break;
			}
			break;

		case UD_OP_PTR:
			switch (op->size) {
				case 32:
					mkasm(u, "word 0x%x:0x%x",
					    op->lval.ptr.seg,
					    op->lval.ptr.off & 0xFFFF);
					break;
				case 48:
					mkasm(u, "dword 0x%x:0x%lx",
					    op->lval.ptr.seg,
					    op->lval.ptr.off);
					break;
			}
			break;

		case UD_OP_CONST:
			if (syn_cast) opr_cast(u, op);
			mkasm(u, "%d", op->lval.udword);
			break;

		default: return;
	}
}

/*
 * Place phi functions in all the correct nodes
 */
void
dm_place_phi_functions()
{
	struct dm_cfg_node	**W = NULL, *n = NULL, *dn = NULL, *node = NULL;
	unsigned int		  i = 0;
	int			  j = 0, w_size = 0;

	/* For each variable */
	for (i = 0; i < UD_OP_CONST; i++) {
		for (p = p_head; p != NULL; p = p->next) {
			node = (struct dm_cfg_node*)p->ptr;
			/* added tracks whether node has already been added to list */
			node->added = 0;
			/* phi_inserted tracks that we already added a phi for this node */
			node->phi_inserted = 0;
		}
		/* Build a worklist W of all nodes that define this var */
		free(W);
		W = xmalloc(indices[i].dn_count * sizeof(void*));
		for (j = 0; j < indices[i].dn_count; j++) {
			indices[i].def_nodes[j]->added = 1;
			W[j] = indices[i].def_nodes[j];
		}
		w_size = indices[i].dn_count;

		/* While the worklist is not empty */
		while (w_size) {
			/* Remove a node n from worklist */
			n = W[w_size - 1];
			W = xrealloc(W, --w_size * sizeof(void*));
			/* For each node dn in DF of n */
			for (j = 0; j < n->df_count; j++) {
				dn = (struct dm_cfg_node*)n->df_set[j];
				/* Note in variable i that i has a phi in node dn */
				if (!dn->phi_inserted) {
					indices[i].phi_nodes = xrealloc(indices[i].phi_nodes, ++indices[i].pn_count * sizeof(void*));
					indices[i].phi_nodes[indices[i].pn_count -1] = dn;
					dn->phi_inserted = 1;
					dn->phi_functions = xrealloc(dn->phi_functions, ++dn->pf_count * sizeof(struct phi_function));
					dn->phi_functions[dn->pf_count - 1].var = i;
					dn->phi_functions[dn->pf_count - 1].arguments = dn->p_count;
					dn->phi_functions[dn->pf_count - 1].indexes = xmalloc(dn->p_count * sizeof(int));
					dn->phi_functions[dn->pf_count - 1].index = 0;
					dn->phi_functions[dn->pf_count - 1].constraints = NULL;
					dn->phi_functions[dn->pf_count - 1].c_counts = NULL;
					dn->phi_functions[dn->pf_count - 1].d_count = 0;
					/* Add dn to worklist */
					if (!dn->added) {
						W = xrealloc(W, ++w_size * sizeof(void*));
						W[w_size - 1] = dn;
					}
				}
			}
		}
	}
	free(W);
}

/*
 * Returns 1 if an array contains a specific node, 0 otherwise
 */
int
dm_array_contains(struct dm_cfg_node **list, int c, struct dm_cfg_node *term)
{
	int i = 0;
	for (i = 0; i < c; i++) {
		if (list[i] == term)
			return 1;
	}
	return 0;
}

/*
 * Find all definitions of all vairables
 */
void
dm_ssa_find_var_defs()
{
	struct dm_cfg_node	*n = NULL;
	struct instruction	*insn = NULL;
	enum ud_type		 reg = 0;
	int			 duplicate = 0, i = 0, j = 0, k = 0;
	int			 cont = 0;

	/* For all nodes n */
	for (p = p_head; p != NULL; p = p->next) {
		n = (struct dm_cfg_node*)p->ptr;
		/*printf("Finding variable definitions for block %d - start: " NADDR_FMT ", end: " NADDR_FMT
				"\n", n->post, n->start, n->end);*/
		//printf("Address ");
		/* For all statements in node n */
		for (j = 0; j < n->i_count; j++) {
			insn = n->instructions[j];
			//printf(NADDR_FMT " ", ud.pc); //0x00005e9c, end: 0x00005ea4 End of block... addr: 0x00005ea7 ... insn length: 2  block 971
			//coverageTC += read;
			/* If instruction writes to a register */
			for (k = 0; k < 3; k ++) {
				cont = 0;
				if (instructions[insn->ud.mnemonic].write[k]) {
					if (insn->fv_operands[k] && (insn->cast[k] == 0)) {
						reg = UD_OP_CONST + insn->operands[k]->index;
						//printf("Node %d defines: Reg = %d, Index = %d\n", n->post, reg, insn->operands[k]->index);
						cont = 1;
					}
					else if ((insn->fv_operands[k] == 0) && (insn->ud.operand[k].type == UD_OP_REG)) {
						reg = insn->ud.operand[k].base;
						cont = 1;
					}
					if (cont) {
						if (!dm_array_contains(indices[reg].def_nodes, indices[reg].dn_count, n))
							dm_add_node_to_var_defs(reg, n);

						duplicate = 0;
						for (i = 0; i < n->dv_count; i++)
							if (n->def_vars[i] == reg) {
								duplicate = 1;
								break;
							}
						if (!duplicate)
							dm_add_reg_to_node_defs(n, reg);
					}
				}
			}
		}
	}
}
			/*if ((ud.pc - ud_insn_len(&ud)) > n->end) {
				sprintf(pm, "Ran past end of block %d (start: " NADDR_FMT", end: "NADDR_FMT" at addr: " NADDR_FMT ", insn length: %x\n", n->post, n->start, n->end, ud.pc, ud_insn_len(&ud));
				dm_new_post_message(pm);
				//getchar();
				//break;
			}*/
		//}
		//printf("\n");
	//}
//}

void
dm_add_node_to_var_defs(int reg, struct dm_cfg_node *n) {
	indices[reg].def_nodes = xrealloc(indices[reg].def_nodes, ++indices[reg].dn_count * sizeof(void*));
	indices[reg].def_nodes[indices[reg].dn_count -1] = n;
}

void
dm_add_reg_to_node_defs(struct dm_cfg_node *n, int reg) {
	n->def_vars = xrealloc(n->def_vars, ++n->dv_count * sizeof(int));
	n->def_vars[n->dv_count -1] = reg;
}

/*
 * Push an index onto the stack for a register
 */
void
dm_ssa_index_stack_push(int reg, int i)
{
	indices[reg].stack = xrealloc(indices[reg].stack, (++indices[reg].s_size) * sizeof(int));
	indices[reg].stack[indices[reg].s_size - 1] = i;
}

/*
 * Pop an index from a reisters stack
 */
int
dm_ssa_index_stack_pop(int reg)
{
	if (!indices[reg].s_size) {
		if (reg < UD_OP_CONST)
			printf("Tried to pop empty stack (reg %s %d)!\n", ud_reg_tab[reg - 1], reg);
		else
			printf("Tried to pop empty stack (var%d)!\n", reg);
		return -1;
	}
	int i = indices[reg].stack[indices[reg].s_size - 1];
	indices[reg].stack = xrealloc(indices[reg].stack, (--indices[reg].s_size) * sizeof(int));
	return i;
}

/*
 * Initialise the register indexing struct array
 */
void
dm_ssa_index_init()
{
	int	i;

	indices = xmalloc(sizeof(struct dm_ssa_index) * (UD_OP_CONST + 1 + variables_count));

	/* Initialise struct for SSA indexes */
	for (i = 0; i < UD_OP_CONST + 1 + variables_count; i++) {
		indices[i].reg = i;
		indices[i].count = 0;
		indices[i].stack = xmalloc(sizeof(int));
		indices[i].stack[0] = 0;
		indices[i].s_size = 1;
		indices[i].def_nodes = NULL;
		indices[i].dn_count = 0;
		indices[i].phi_nodes = NULL;
		indices[i].pn_count = 0;
	}
}

void
dm_free_ssa()
{
	struct dm_cfg_node	*node = NULL;
	int			 i = 0, j = 0;

	for (p = p_head; p != NULL; p = p->next) {
		node = (struct dm_cfg_node*)p->ptr;
		free(node->def_vars);
		for (i = 0; i < node->pf_count; i++) {
			free(node->phi_functions[i].indexes);
		}
		free(node->phi_functions);
		for (i = 0; i < node->i_count; i ++) {
			free(node->instructions[i]);
		}
		free(node->instructions);
		if (node->superphi) {
			free(node->superphi->vars);
			free(node->superphi->index);
			for (j = 0; j < node->superphi->var_count; j++) {
				free(node->superphi->indexes[j]);
			}
			free(node->superphi->indexes);
			free(node->superphi);
		}
	}
	for (i = 0; i < UD_OP_CONST + 1 + variables_count; i++) {
		free(indices[i].stack);
		free(indices[i].def_nodes);
		free(indices[i].phi_nodes);
	}

	free(indices);
}

