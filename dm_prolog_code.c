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

#include "dm_prolog_code.h"
#include "dm_dwarf.h"
#include "dm_code_transform.h"


extern struct ptrs	*p_head;
extern struct ptrs	*p;

void opr_cast(struct ud* u, struct ud_operand* op);

FILE			*export;

extern char *fname;

char *symname = NULL;
int calls = 0;

int dm_cmd_pc(char **args)
{
	NADDR				 addr = cur_addr;
	struct dm_cfg_node		*cfg = NULL;
	struct dm_dwarf_sym_cache_entry	*ent;
	struct dm_setting		*fcalls = NULL;
	char				*out, *reach;
	int				 c;

	(void) args;

	/* Get fcalls setting */
	dm_find_setting("cfg.fcalls", &fcalls);
	calls = fcalls->val.ival;

	switch (calls) {
		case 4:
			c = asprintf(&reach, "complete_cfg-cg");
			break;
		case 3:
			c = asprintf(&reach, "cfg-cg");
			break;
		case 2:
			c = asprintf(&reach, "function");
			break;
		case 1:
			c = asprintf(&reach, "singleblock");
			break;
		case 0:
			c = asprintf(&reach, "functionblock");
			break;
	}

	dm_dwarf_find_nearest_sym_to_offset(addr, &ent);
	c = asprintf(&symname, "%s", ent->name);
	c = asprintf(&out, "%s.%s.%s.psc", fname, ent->name, reach);

	export = fopen(out, "wt");
	free(out);
	free(reach);

	/* Initialise structures */
	dm_init_cfg();

	/* Get CFG */
	cfg = dm_recover_cfg();

	/* Build dominator tree */
	dm_dom(cfg);

	/* Build dominance frontier sets*/
	dm_dom_frontiers();

	/* Transform instructions */
	dm_transform_code();

	/* Load settings */
	dm_ssa_settings_init();

	/* Initialise register index structure */
	dm_ssa_index_init();

	/* Build lists of variables defined in each node */
	dm_ssa_find_var_defs();

	/* Place phi functions in correct nodes */
	dm_place_phi_functions();

	/* Rename all the variables with SSA indexes */
	dm_rename_variables(cfg);
	dm_amalgamate_phis();

	/* Export prolog terms for constraints */
	dm_export_prolog_code();

	fclose(export);
	free(symname);

	/* Free memory used for ssa */
	dm_free_ssa();

	dm_code_transform_free();

	/* Free dominance frontier sets */
	dm_dom_frontiers_free();

	/* Free all CFG structures */
	dm_free_cfg();

	/* Rewind back */
	dm_seek(addr);

	(void)c;
	return (0);
}

void
print_pseudo_operand_ssa(struct instruction *insn, int op)
{
	if (op) {
		printf(", ");
		fprintf(export, ", ");
	}
	if (insn->cast[op]) {
		printf("([var%d^%d], %d)", insn->operands[op]->index, insn->index[op][0], ud.adr_mode/8);
		fprintf(export, "([var%d^%d], %d)", insn->operands[op]->index, insn->index[op][0], ud.adr_mode/8);
	}
	else {
		printf("(var%d^%d, %d)", insn->operands[op]->index, insn->index[op][0], ud.adr_mode/8);
		fprintf(export, "(var%d^%d, %d)", insn->operands[op]->index, insn->index[op][0], ud.adr_mode/8);
	}
}

void
print_operand_ssa(struct ud* u, struct ud_operand* op, int syn_cast, int *index, int pseudo)
{
	switch(op->type) {
		case UD_OP_REG:
			printf("%s^%d", ud_reg_tab[op->base - UD_R_AL], index[0]);
			fprintf(export, "%s^%d", ud_reg_tab[op->base - UD_R_AL], index[0]);
			break;
		case UD_OP_MEM: {
			int op_f = 0;

			if (syn_cast)
				opr_cast(u, op); /* XXX fix warning */

			printf("[");
			fprintf(export, "[");

			if (u->pfx_seg) {
				printf("%s:", ud_reg_tab[u->pfx_seg - UD_R_AL]);
				fprintf(export, "%s:", ud_reg_tab[u->pfx_seg - UD_R_AL]);
			}

			if (op->base) {
				printf("%s^%d", ud_reg_tab[op->base - UD_R_AL], index[0]);
				fprintf(export, "%s^%d", ud_reg_tab[op->base - UD_R_AL], index[0]);
				op_f = 1;
			}

			if (op->index) {
				if (op_f) {
					printf("+");
					fprintf(export, "+");
				}
				printf("%s^%d", ud_reg_tab[op->index -UD_R_AL], index[1]);
				fprintf(export, "%s^%d", ud_reg_tab[op->index -UD_R_AL], index[1]);
				op_f = 1;
			}

			if (op->scale) {
				printf("*%d", op->scale);
				fprintf(export, "*%d", op->scale);
			}

			if (op->offset == 8) {
				if (op->lval.sbyte < 0) {
					printf("-0x%x", -op->lval.sbyte);
					fprintf(export, "-0x%x", -op->lval.sbyte);
				}
				else {
					printf("%s0x%x", (op_f) ? "+" : "", op->lval.sbyte);
					fprintf(export, "%s0x%x", (op_f) ? "+" : "", op->lval.sbyte);
				}
			}
			else if (op->offset == 16) {
				printf("%s0x%x", (op_f) ? "+" : "", op->lval.uword);
				fprintf(export, "%s0x%x", (op_f) ? "+" : "", op->lval.uword);
			}
			else if (op->offset == 32) {
				if (u->adr_mode == 64) {
					if (op->lval.sdword < 0) {
						printf("-0x%x", -op->lval.sdword);
						fprintf(export, "-0x%x", -op->lval.sdword);
					}
					else {
						printf("%s0x%x", (op_f) ? "+" : "", op->lval.sdword);
						fprintf(export, "%s0x%x", (op_f) ? "+" : "", op->lval.sdword);
					}
				}
				else {
					printf("%s0x%lx", (op_f) ? "+" : "", op->lval.udword);
					fprintf(export, "%s0x%lx", (op_f) ? "+" : "", op->lval.udword);
				}
			}
			else if (op->offset == 64) {
				printf("%s0x" FMT64 "x", (op_f) ? "+" : "", op->lval.uqword);
				fprintf(export, "%s0x" FMT64 "x", (op_f) ? "+" : "", op->lval.uqword);
			}

			printf("]");
			fprintf(export, "]");
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
			printf("0x" FMT64 "x", imm & sext_mask );
			fprintf(export, "0x" FMT64 "x", imm & sext_mask );
			break;
		}

		case UD_OP_JIMM:
			if (syn_cast) opr_cast(u, op);
			switch (op->size) {
				case  8:
					printf("0x" FMT64 "x", u->pc + op->lval.sbyte);
					fprintf(export, "0x" FMT64 "x", u->pc + op->lval.sbyte);
					break;
				case 16:
					printf("0x" FMT64 "x", ( u->pc + op->lval.sword ) & 0xffff );
					fprintf(export, "0x" FMT64 "x", ( u->pc + op->lval.sword ) & 0xffff );
					break;
				case 32:
					printf("0x" FMT64 "x", ( u->pc + op->lval.sdword ) & 0xfffffffful );
					fprintf(export, "0x" FMT64 "x", ( u->pc + op->lval.sdword ) & 0xfffffffful );
					break;
				default:break;
			}
			break;

		case UD_OP_PTR:
			switch (op->size) {
				case 32:
					printf("word 0x%x:0x%x", op->lval.ptr.seg, op->lval.ptr.off & 0xFFFF);
					fprintf(export, "word 0x%x:0x%x", op->lval.ptr.seg, op->lval.ptr.off & 0xFFFF);
					break;
				case 48:
					printf("dword 0x%x:0x%lx", op->lval.ptr.seg, op->lval.ptr.off);
					fprintf(export, "dword 0x%x:0x%lx", op->lval.ptr.seg, op->lval.ptr.off);
					break;
			}
			break;

		case UD_OP_CONST:
			if (syn_cast) opr_cast(u, op);
			printf("%d", op->lval.udword);
			fprintf(export, "%d", op->lval.udword);
			break;

		default: return;
	}
}

void
dm_export_superphi(struct super_phi *superphi, NADDR addr)
{
	int length = 0, i = 0, j = 0;
	char *temp = NULL, *temp2 = NULL;

	length += asprintf(&temp, "(" NADDR_FMT "  :phi([(%s^%d, %d)",
								addr,
								ud_reg_tab[superphi->vars[0] - 1],
								superphi->index[0],
								dm_get_register_size(superphi->vars[0])/8);
	if (superphi->var_count > 1)
		for (i = 1; i < superphi->var_count; i++) {
			temp2 = temp;
			length += asprintf(&temp, "%s, (%s^%d, %d)",
									temp2,
									ud_reg_tab[superphi->vars[i] - 1],
									superphi->index[i],
									dm_get_register_size(superphi->vars[i])/8);
			free(temp2);
		}
	for (i = 0; i < superphi->arguments; i++) {
		for (j = 0; j < superphi->var_count; j++) {
			temp2 = temp;
			length += asprintf(&temp, "%s, (%s^%d, %d)",
									temp2,
									ud_reg_tab[superphi->vars[j] - 1],
									superphi->indexes[j][i],
									dm_get_register_size(superphi->vars[j])/8);
			free(temp2);
		}
	}
	temp2 = temp;
	length += asprintf(&temp, "%s]), _).", temp2);
	free(temp2);
	printf("%s\n", temp);
	fprintf(export, "%s\n", temp);
	free(temp);
}

void
dm_export_prolog_code()
{
	struct dm_cfg_node	*node = NULL;
	struct ud		*u = NULL;
	struct instruction	*insn = NULL;
	NADDR			 addr = 0;
	int			 index[3][2];
	int			 i = 0, fv_operand = 0, j = 0;
	int			 c;
	char			*filename = NULL;

	node = (struct dm_cfg_node*)p_head->ptr;
	insn = node->instructions[0];
	u = &(insn->ud);

	c = asprintf(&filename, "%s", fname);
	while(filename[i] != '\0') {
		if (filename[i] == '.')
			filename[i] = '_';
		i++;
	}
	i = 0;
	fprintf(export, "(%d, %d, %s, %s).\n", u->adr_mode, calls, filename, symname);

	/* For each CFG node */
	for (p = p_head; p != NULL; p = p->next) {
		node = (struct dm_cfg_node*)p->ptr;
		if (node->superphi)
			dm_export_superphi(node->superphi, node->start);

		/* For each instruction in node*/
		for (i = 0; i < node->i_count; i++) {
			insn = node->instructions[i];
			u = &(insn->ud);
			memcpy(index, insn->index, sizeof(index));

			fv_operand = 0;
			for (j = 0; j < 3; j++) {
				if (insn->fv_operands[j])
					fv_operand = 1;
			}
			addr = insn->ud.pc - ud_insn_len(&(insn->ud));
			if (insn->paddr != -1){
				fprintf(export, "(%llu.%d  :", addr, insn->paddr);
				printf("(" NADDR_FMT ".%d  :", addr, insn->paddr);
			}
			else{
				fprintf(export,"( %llu  :", addr);
				printf("(" NADDR_FMT "  :", addr);
			}
			printf("%s([", ud_lookup_mnemonic(u->mnemonic));
			fprintf(export, "%s([", ud_lookup_mnemonic(u->mnemonic));
			if (insn->fv_operands[0])
				print_pseudo_operand_ssa(insn, 0);
			else {
				/* operand 1 */
				if (u->operand[0].type != UD_NONE) {
					printf("(");
					fprintf(export, "(");

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
					print_operand_ssa(&(insn->ud), &(insn->ud.operand[0]), cast, index[0], fv_operand);
					if (u->operand[0].type == UD_OP_REG) {
						printf(", %d)", dm_get_register_size(u->operand[0].base)/8);
						fprintf(export, ", %d)", dm_get_register_size(u->operand[0].base)/8);
					}
					else if (u->operand[0].type == UD_OP_MEM) {
						printf(", %d)", u->adr_mode/8);
						fprintf(export, ", %d)", u->adr_mode/8);
					}
					else {
						printf(", %d)", u->operand[0].size/8);
						fprintf(export, ", %d)", u->operand[0].size/8);
					}
				}
			}
			if (insn->fv_operands[1]) {
				print_pseudo_operand_ssa(insn, 1);
			}
			else {
				/* operand 2 */
				if (u->operand[1].type != UD_NONE) {
					int cast = 0;
					printf(", (");
					fprintf(export, ", (");
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
					print_operand_ssa(u, &u->operand[1], cast, index[1], fv_operand);
					if (u->operand[1].type == UD_OP_REG) {
						printf(", %d)", dm_get_register_size(u->operand[1].base)/8);
						fprintf(export, ", %d)", dm_get_register_size(u->operand[1].base)/8);
					}
					else if (u->operand[1].type == UD_OP_MEM) {
						printf(", %d)", u->adr_mode/8);
						fprintf(export, ", %d)", u->adr_mode/8);
					}
					else {
						printf(", %d)", u->operand[1].size/8);
						fprintf(export, ", %d)", u->operand[1].size/8);
					}
				}
			}

			/* operand 3 */
			if (u->operand[2].type != UD_NONE) {
				printf(", (");
				fprintf(export, ", (");
				insn->cast[2] = u->c3;
				print_operand_ssa(u, &u->operand[2], u->c3, index[2], fv_operand);
				if (u->operand[2].type == UD_OP_REG) {
					printf(", %d)", dm_get_register_size(u->operand[2].base)/8);
					fprintf(export, ", %d)", dm_get_register_size(u->operand[2].base)/8);
				}
				else if (u->operand[2].type == UD_OP_MEM) {
					printf(", %d)", u->adr_mode/8);
					fprintf(export, ", %d)", u->adr_mode/8);
				}
				else {
					printf(", %d)", u->operand[2].size/8);
					fprintf(export, ", %d)", u->operand[2].size/8);
				}
			}
			printf("]), _).\n");
			fprintf(export, "]), _).\n");
		}
	}
	(void)c;
}

