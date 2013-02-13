#include "dm_code_transform.h"
#include "dm_ssa.h"
#include "dm_dis.h"
#include "dm_util.h"

extern struct ptrs              *p_head;
extern struct ptrs              *p;
extern int                       p_length;

extern int			 flatten;
extern int			 transform;

int next_free_variable = 0;

struct ptrs *variables = NULL;
struct ptrs *variables_head = NULL;
int variables_count = 0;

/*
 * Purpose of this is to transform code before SSA. Major refactoring happening now...
 */
void
dm_transform_code()
{
	struct dm_cfg_node      *n = NULL;
	struct instruction      *insn = NULL;
	enum address_mode	 m[2];
	int			 use_original = 1;
	/* For all nodes n */
	for (p = p_head; p != NULL; p = p->next) {
		n = (struct dm_cfg_node*)p->ptr;
		if (!n->nonlocal) {
		/* For all statements in node n */
		for (dm_seek(n->start); ud.pc - ud_insn_len(&ud) < n->end;) {
			dm_ssa_disassemble(&ud);
			use_original = 1;

			if (flatten) {
				m[0] = dm_get_indirect_address_mode(ud.operand[0]);
				m[1] = dm_get_indirect_address_mode(ud.operand[1]);
				if ((ud.operand[0].type == UD_OP_MEM) && (m[0] != T_PTR_OFFSET)) {
					if (!((ud.mnemonic == UD_Imov) && (m[0] == T_PTR_BASE))) {
						dm_flatten_indirect_addressing(n, 1);
						use_original = 0;
					}
				}
				else
				if ((ud.operand[1].type == UD_OP_MEM) && (m[1] != T_PTR_OFFSET)) {
					if (!((ud.mnemonic == UD_Imov) && (m[1] == T_PTR_BASE))) {
						dm_flatten_indirect_addressing(n, 2);
						use_original = 0;
					}
				}
			}
			if (transform) {
				if (ud.mnemonic == UD_Ipush) {
					dm_transform_push(n);
					use_original = 0;
				}
				else if (ud.mnemonic == UD_Ipop) {
					dm_transform_pop(n);
					use_original = 0;
				}
				else if ((ud.mnemonic == UD_Idiv) || (ud.mnemonic == UD_Iidiv) ||
					 (ud.mnemonic == UD_Imul) || (ud.mnemonic == UD_Iimul)) {
					dm_transform_div(n);
					use_original = 0;
				}
			}
			if (ud.mnemonic == UD_Icall) {
				if (!dm_is_target_in_text(dm_get_jump_target(ud)) || ud.operand[0].index) {
					dm_transform_call(n);
					use_original = 0;
				}
			}
			if (use_original) {
				insn = dm_new_insn();
				insn->ud = ud;
				/* Add instruction to block's list */
				dm_add_insn(n, insn);
			}
		}
		}
	}
}

void
dm_fill_op(void *dest, void *src) {
	memcpy(dest, src, 3 * sizeof(void*));
}

void
dm_fill_type(enum op_type dest[3], enum op_type src[3]) {
	memcpy(dest, src, 3 * sizeof(enum op_type));
}

void
dm_transform_call(struct dm_cfg_node *n)
{
	int			 reg = 0;
	struct instruction	*insn = NULL;
	struct ud_operand	 op2;
	void			*ops[3];
	enum op_type		 op_types[3];

	if (ud.adr_mode == 32)
		reg = (int)UD_R_EAX;
	else
		reg = (int)UD_R_RAX;

	op2 = dm_make_ud_register_operand(reg);
	dm_fill_op(ops, (void *[]){ &ud.operand[0], &op2, NULL });
	dm_fill_type(op_types, (enum op_type[]){ UD, UD, NONE });
	insn = dm_new_pseudo_insn(ud.mnemonic, ud.pc, ops, op_types, ud_insn_len(&ud));
	insn->paddr = 0;
	dm_add_insn(n, insn);
}

/* Add missing operands to div/idiv/mul/imul instructions */
void
dm_transform_div(struct dm_cfg_node *n)
{
	int			 reg = 0, reg2 = 0;
	struct instruction	*insn = NULL;
	struct ud_operand	 op1, op2;
	void			*ops[3];
	enum op_type		 op_types[3];

	switch (ud.operand[0].size) {
		case 8:
			reg = (int)UD_R_AX;
			reg2 = 0;
			break;
		case 16:
			reg = (int)UD_R_DX;
			reg2 = (int)UD_R_AX;
			break;
		case 32:
			reg = (int)UD_R_EDX;
			reg2 = (int)UD_R_EAX;
			break;
		case 64:
			reg = (int)UD_R_RDX;
			reg2 = (int)UD_R_RAX;
			break;
	}
	op1 = dm_make_ud_register_operand(reg);
	if (ud.operand[0].size != 8) {
		op2 = dm_make_ud_register_operand(reg2);
		dm_fill_op(ops, (void *[]){ &op1, &op2, &ud.operand[0] });
		dm_fill_type(op_types, (enum op_type[]){ UD, UD, UD });
		insn = dm_new_pseudo_insn(ud.mnemonic, ud.pc, ops, op_types, ud_insn_len(&ud));
	}
	else {
		dm_fill_op(ops, (void*[]){ &op1, &ud.operand[0], NULL });
		dm_fill_type(op_types, (enum op_type[]){ UD, UD, NONE });
		insn = dm_new_pseudo_insn(ud.mnemonic, ud.pc, ops, op_types, ud_insn_len(&ud));
	}
	insn->paddr = 0;
	dm_add_insn(n, insn);
}

/* Change push into add and mov */
void
dm_transform_push(struct dm_cfg_node *n)
{
	struct instruction	*insn = NULL;
	void			*ops[3];
	enum op_type		 op_types[3];
	struct ud_operand	 op1, op2, op3;
	int			 reg = 0;

	op2 = dm_make_ud_literal_operand();
	op2.size = 8;
	if (ud.adr_mode == 32) {
		reg = (int)UD_R_ESP;
		op2.lval.ubyte = 4;
	}
	else {
		reg = (int)UD_R_RSP;
		op2.lval.ubyte = 8;
	}
	op1 = dm_make_ud_register_operand(reg);
	op3 = dm_make_ud_register_mem_operand(reg);
	dm_fill_op(ops, (void*[]){ &op1, &op2, NULL });
	dm_fill_type(op_types, (enum op_type[]){ UD, UD, NONE });
	insn = dm_new_pseudo_insn(UD_Iadd, ud.pc, ops, op_types, ud_insn_len(&ud));
	insn->paddr = 0;
	dm_add_insn(n, insn);

	dm_fill_op(ops, (void*[]){ &op3, &ud.operand[0], NULL });
	dm_fill_type(op_types, (enum op_type[]){ UD, UD, NONE });
	insn = dm_new_pseudo_insn(UD_Imov, ud.pc, ops, op_types, ud_insn_len(&ud));
	insn->paddr = 1;
	dm_add_insn(n, insn);
}

/* Change pop into mov and sub */
void
dm_transform_pop(struct dm_cfg_node *n)
{
	struct instruction	*insn = NULL;
	void			*ops[3];
	enum op_type		 op_types[3];
	struct ud_operand	 op1, op2, op3;
	int			 reg = 0;

	op2 = dm_make_ud_literal_operand();
	op2.size = 8;
	if (ud.adr_mode == 32) {
		reg = (int)UD_R_ESP;
		op2.lval.ubyte = 4;
	}
	else {
		reg = (int)UD_R_RSP;
		op2.lval.ubyte = 8;
	}
	op1 = dm_make_ud_register_operand(reg);
	op3 = dm_make_ud_register_mem_operand(reg);

	dm_fill_op(ops, (void*[]) { &ud.operand[0], &op3, NULL });
	dm_fill_type(op_types, (enum op_type[]) { UD, UD, NONE });
	insn = dm_new_pseudo_insn(UD_Imov, ud.pc, ops, op_types, ud_insn_len(&ud));
	insn->paddr = 0;
	dm_add_insn(n, insn);

	dm_fill_op(ops, (void*[]) { &op1, &op2, NULL });
	dm_fill_type(op_types, (enum op_type[]) { UD, UD, NONE });
	insn = dm_new_pseudo_insn(UD_Isub, ud.pc, ops, op_types, ud_insn_len(&ud));
	insn->paddr = 1;
	dm_add_insn(n, insn);
}

/* Flatten indirect addressing with pseudo instructions */
void
dm_flatten_indirect_addressing(struct dm_cfg_node *n, int indirect_operand)
{
	struct ud_operand	 ud_op[3];
	struct variable         *var = NULL, *var2 = NULL, *var3 = NULL;
	int			 paddr = 0;
	int			 opr = indirect_operand - 1;
	enum ud_mnemonic_code	 mne;
	void			*ops[3];
	enum op_type		 op_types[3];
	struct instruction	*insn = NULL;
	int			 shift = 0;

	/* Mov index into new intermediate var1 */
	if (ud.operand[opr].index) {
		var = get_new_free_variable();
		ud_op[opr].type = UD_OP_REG;
		ud_op[opr].base = ud.operand[opr].index;

		dm_fill_op(ops, (void*[]){ var, &ud_op[opr], NULL });
		dm_fill_type(op_types, (enum op_type[]){ DM, UD, NONE });
		insn = dm_new_pseudo_insn(UD_Imov, ud.pc, ops, op_types, ud_insn_len(&ud));
		insn->paddr = paddr++;
		dm_add_insn(n, insn);
		/* left shift (sal/shl) var1 according to scale */
		if ((ud.operand[opr].scale) && (ud.operand[opr].scale != 1)) {
			shift = (ud.operand[opr].scale + 2) / 3;
			ud_op[opr].type = UD_OP_IMM;
			ud_op[opr].size = 8;
			ud_op[opr].lval.ubyte = shift;

			dm_fill_op(ops, (void*[]){ var, &ud_op[opr], NULL });
			dm_fill_type(op_types, (enum op_type[]){ DM, UD, NONE });
			insn = dm_new_pseudo_insn(UD_Ishl, ud.pc, ops, op_types, ud_insn_len(&ud));
			insn->paddr = paddr++;
			dm_add_insn(n, insn);
		}
	}
	/* Mov base into new intermediate var2 */
	if (ud.operand[opr].base) {
		var2 = get_new_free_variable();
		ud_op[opr].type = UD_OP_REG;
		ud_op[opr].base = ud.operand[opr].base;
		dm_fill_op(ops, (void*[]) { var2, &ud_op[opr], NULL });
		dm_fill_type(op_types, (enum op_type[]){ DM, UD, NONE });
		insn = dm_new_pseudo_insn(UD_Imov, ud.pc, ops, op_types, ud_insn_len(&ud));
		insn->paddr = paddr++;
		dm_add_insn(n, insn);
	}
	/* Add base and shifted index */
	if (ud.operand[opr].base && ud.operand[opr].index) {
		dm_fill_op(ops, (void*[]) { var, var2, NULL });
		dm_fill_type(op_types, (enum op_type[]){ DM, DM, NONE });
		insn = dm_new_pseudo_insn(UD_Iadd, ud.pc, ops, op_types, ud_insn_len(&ud));
		insn->paddr = paddr++;
		dm_add_insn(n, insn);
	}
	else if (ud.operand[opr].base) {
		var = var2;
	}
	/* Add/sub offset to/from result */
	if (ud.operand[opr].offset) {
		ud_op[opr] = dm_get_offset(&ud.operand[opr], &ud);
		if (dm_neg_offset(&ud.operand[opr], &ud))
			mne = UD_Isub;
		else
			mne = UD_Iadd;
		dm_fill_op(ops, (void*[]){ var, &ud_op[opr], NULL });
		dm_fill_type(op_types, (enum op_type[]){ DM, UD, NONE });
		insn = dm_new_pseudo_insn(mne, ud.pc, ops, op_types, ud_insn_len(&ud));
		insn->paddr = paddr++;
		dm_add_insn(n, insn);
	}
	/* Create a final mov to remove indirect addressing completely from final instruction */
	if (ud.mnemonic != UD_Imov) {
		var3 = get_new_free_variable();
		dm_fill_op(ops, (void*[]){ var3, var, NULL });
		dm_fill_type(op_types, (enum op_type[]){ DM, DM_PTR, NONE });
		insn = dm_new_pseudo_insn(UD_Imov, ud.pc, ops, op_types, ud_insn_len(&ud));
		insn->paddr = paddr++;
		dm_add_insn(n, insn);
	}
	/* Finally, carry out original instruction but with indirect addressing flattened */
	if (opr) {
		if (ud.mnemonic != UD_Imov) {
			dm_fill_op(ops, (void*[]){ &ud.operand[0], var3, NULL });
			dm_fill_type(op_types, (enum op_type[]){ UD, DM, NONE });
			insn = dm_new_pseudo_insn(ud.mnemonic, ud.pc, ops, op_types, ud_insn_len(&ud));
		}
		else {
			dm_fill_op(ops, (void*[]){ &ud.operand[0], var, NULL });
			dm_fill_type(op_types, (enum op_type[]){ UD, DM_PTR, NONE });
			insn = dm_new_pseudo_insn(ud.mnemonic, ud.pc, ops, op_types, ud_insn_len(&ud));
		}
	}
	else {
		if (ud.mnemonic != UD_Imov) {
			dm_fill_op(ops, (void*[]){ var3, &ud.operand[1], NULL });
			dm_fill_type(op_types, (enum op_type[]){ DM, UD, NONE });
			insn = dm_new_pseudo_insn(ud.mnemonic, ud.pc, ops, op_types, ud_insn_len(&ud));
		}
		else {
			dm_fill_op(ops, (void*[]){ var, &ud.operand[1], NULL });
			dm_fill_type(op_types, (enum op_type[]){ DM_PTR, UD, NONE });
			insn = dm_new_pseudo_insn(ud.mnemonic, ud.pc, ops, op_types, ud_insn_len(&ud));
		}
	}
	insn->paddr = paddr++;
	dm_add_insn(n, insn);
}

struct instruction*
dm_new_pseudo_insn(enum ud_mnemonic_code mnemonic, uint64_t pc, void *op[3], enum op_type type[3], uint8_t inp_ctr)
{
	struct instruction	*insn = NULL;
	int i = 0;

	insn = xcalloc(1, sizeof(struct instruction));
	insn->ud.mnemonic = mnemonic;
	insn->ud.pc = pc;
	insn->ud.inp_ctr = inp_ctr;
	insn->ud.itab_entry = &ud_itab[mnemonic];
	insn->ud.adr_mode = ud.adr_mode;
	insn->paddr = -1;
	snprintf(insn->ud.insn_hexcode, 32, "(%s)", ud_lookup_mnemonic(ud.mnemonic));

	for (; i < 3; i++) {
		switch (type[i]) {
			case DM_PTR:
				insn->cast[i] = 1;
			case DM:
				insn->fv_operands[i] = 1;
				/* If operand is null get a free variable */
				if (op[i] == NULL) {
					insn->operands[i] = get_new_free_variable();
					//insn->index[i][0] = ((struct variable *) op[i])->ssa_i;
				}
				else {
					insn->operands[i] = (struct variable *)op[i];
					//insn->index[i][0] = ((struct variable *) op[i])->ssa_i;
				}
				break;
			case UD:
				insn->ud.operand[i] = *((struct ud_operand*)op[i]);
				break;
			case NONE:
				break;
		}
	}
	return insn;
}

struct instruction*
dm_new_insn()
{
	struct instruction *insn = NULL;
	insn = xcalloc(1, sizeof(struct instruction));
	insn->paddr = -1;
	return insn;
}

void
dm_add_insn(struct dm_cfg_node *node, struct instruction *insn)
{
	node->instructions = xrealloc(node->instructions, sizeof(void*) * ++node->i_count);
	node->instructions[node->i_count - 1] = insn;
}

struct variable*
get_new_free_variable()
{
	struct variable *var;
	var = xmalloc(sizeof(struct variable));
	var->index = next_free_variable++;
	var->ssa_i = 0;
	if (variables) {
		variables->next = xcalloc(1, sizeof(struct ptrs));
		variables = variables->next;
		variables->ptr = (void*)var;
	}
	else {
		variables = xcalloc(1, sizeof(struct ptrs));
		variables->ptr = (void*)var;
		variables_head = variables;
	}
	variables_count++;
	return var;
}

enum address_mode
dm_get_indirect_address_mode(struct ud_operand op)
{
	if (op.base != UD_NONE) {
		if (op.offset) {
			if (op.index != UD_NONE)
				return T_PTR_BASE_INDEX_SCALE_OFFSET;
			else
				return T_PTR_BASE_OFFSET;
		}
		else {
			if (op.index != UD_NONE)
				return T_PTR_BASE_INDEX_SCALE;
			else
				return T_PTR_BASE;
		}
	}
	else if (op.index != UD_NONE)
		return T_PTR_INDEX_SCALE_OFFSET;
	else
		return T_PTR_OFFSET;
}

struct ud_operand
dm_make_ud_register_operand(enum ud_type reg) {
	struct ud_operand *op;

	op = xcalloc(1, sizeof(struct ud_operand));
	op->type = UD_OP_REG;
	op->base = reg;
	return *op;
}

struct ud_operand
dm_make_ud_register_mem_operand(enum ud_type reg) {
	struct ud_operand *op;

	op = xcalloc(1, sizeof(struct ud_operand));
	op->type = UD_OP_MEM;
	op->base = reg;
	return *op;
}

struct ud_operand
dm_make_ud_literal_operand() {
	struct ud_operand *op;
	op = xcalloc(1, sizeof(struct ud_operand));
	op->type = UD_OP_IMM;
	return *op;
}

int
dm_neg_offset(struct ud_operand *op, struct ud *u)
{
	int ret = 0;
	if (op->offset == 8) {
		if (op->lval.sbyte < 0)
			return 1;
		else
			return 0;
	}
	else if (op->offset == 16)
		return 0;
	else if (op->offset == 32) {
		if (u->adr_mode == 64) {
			if (op->lval.sdword < 0)
				return 1;
			else
				return 0;
		}
		else
			return 0;
	}
	else if (op->offset == 64)
		return 0;
	return ret;
}

struct ud_operand
dm_get_offset(struct ud_operand *op, struct ud *u)
{
	struct ud_operand opo;

	opo.size = op->offset;
	opo.type = UD_OP_IMM;

	if (op->offset == 8) {
		if (op->lval.sbyte < 0)
			opo.lval.sbyte = -op->lval.sbyte;
		else
			opo.lval.sbyte = op->lval.sbyte;
	}
	else if (op->offset == 16)
		opo.lval.sword = (int16_t)op->lval.uword;
	else if (op->offset == 32) {
		if (u->adr_mode == 64) {
			if (op->lval.sdword < 0)
				opo.lval.sdword = -op->lval.sdword;
			else
				opo.lval.sdword = op->lval.sdword;
		}
		else
			opo.lval.sdword = (int32_t) op->lval.udword;
	}
	else if (op->offset == 64)
		opo.lval.sqword = (int64_t) op->lval.uqword;
	return opo;
}

void
dm_code_transform_free()
{
	struct variable *var = NULL;
	struct ptrs *p_prev = NULL;

	for (variables = variables_head; variables != NULL; variables = variables->next) {
		var = (struct variable*) variables->ptr;
		free(var);
	}

	variables = variables_head;
	while (variables != NULL) {
		p_prev = variables;
		variables = variables->next;
		free(p_prev);
	}
	variables = NULL;
	variables_head = NULL;
	next_free_variable = 0;
	variables_count = 0;
}

