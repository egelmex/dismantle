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
#include <stdio.h>
#include "dm_cfg.h"
#include "dm_gviz.h"
#include "dm_dwarf.h"
#include "dm_util.h"
#include "dm_ssa.h"
#include <assert.h>

extern char *fname;
char *sym_name = NULL;

extern int flatten;
extern int transform;

struct indirect_branch *iBranches = NULL;
int	iBranchesCount = 0;
struct branch *branches = NULL;
int branchesCount = 0;

/* Head of the list and a list iterator */
struct ptrs	*p_head = NULL;
struct ptrs	*p = NULL;
struct ptrs	*p_iter = NULL;

/* Explicitly record the list length */
int		p_length = 0;

struct dm_instruction_se *instructions = NULL;

void **rpost; /* Pointers to nodes in reverse post-order */

int fcalls_i = 0;
int verbosity = 1;

/*
 * Generate static CFG for a function.
 * Continues until it reaches ret, does not follow calls.
 */
int
dm_cmd_cfg(char **args) {
	struct dm_cfg_node		*cfg = NULL;
	struct dm_dwarf_sym_cache_entry	*ent = NULL;
	int c;

	(void) args;

	dm_dwarf_find_nearest_sym_to_offset(cur_addr, &ent);
	c = asprintf(&sym_name, "%s", ent->name);
	(void)c;

	/* Initialise structures */
	dm_init_cfg();

	/* Get CFG */
	cfg = dm_recover_cfg();

	/* Graph CFG */
	dm_graph_cfg();

	/* Check CFG for consistency! */
	dm_check_cfg_consistency();

	/* Print CFG */
	dm_print_cfg(cfg);

	dm_print_post_messages();

	/* Free all memory */
	dm_free_cfg();

	dm_free_post_messages();

	dm_free_jumps();

	return (0);
}

/*
 * This function actually starts the building process
 * Returns completed CFG
 */
struct dm_cfg_node*
dm_recover_cfg() {
	NADDR	addr = cur_addr;
	struct	dm_cfg_node *cfg = NULL;

	/* Create first node */
	cfg = dm_new_cfg_node(addr, 0);
	cfg->function_return = malloc(sizeof(void*));
	(*cfg->function_return) = NULL;

	/* Create CFG */
	dm_gen_cfg_block(cfg, cfg, cfg->function_return);

	/* Get reverse postorder, preorder and postorder of nodes */
        rpost = calloc(p_length, sizeof(void*));
        dm_depth_first_walk(cfg);

	/* Rewind back */
	dm_seek(addr);

	return cfg;
}

void
dm_check_cfg_consistency()
{
	struct dm_cfg_node *node = NULL;
	int i = 0, j = 0, consistent = 0;
	for (p = p_head; p != NULL; p = p->next) {
		node = (struct dm_cfg_node*)p->ptr;
		if (!node->function_head)
			printf("Node %d has no function head!\n", node->post);
		if (!node->function_return)
			printf("Node %d has no function return!\n", node->post);
		//for (i = 0; node->children[i] != NULL; i++) {
		for (i = 0; i < node->c_count; i++) {
			consistent = 0;
			for (j = 0; j < node->children[i]->p_count; j++) {
				if (node->children[i]->parents[j] == node)
					consistent = 1;
			}
			if (!consistent)
				printf("No link from node %d (start addr "NADDR_FMT ") to parent %d!\n",
				    node->children[i]->post, node->children[i]->start, node->post);
		}
		for (i = 0; i < node->p_count; i++) {
			consistent = 0;
			for (j = 0; node->parents[i]->children[j] != NULL; j++) {
				if (node->parents[i]->children[j] == node)
					consistent = 1;
			}
			if (!consistent)
				printf("No link from node %d (start addr "NADDR_FMT") to child %d (start addr "NADDR_FMT")!\n",
				    node->parents[i]->post, node->parents[i]->start, node->post, node->start);
		}
	}
}

/*
 * Initialise structures used for CFG recovery
 */
void
dm_init_cfg()
{
	struct	dm_setting	*fcalls = NULL;
	char			*fcallmessage;
	struct  dm_setting	*set_transform = NULL, *set_flatten = NULL, *cfg_verbosity = NULL;
	int			 c;

	/* Get flatten/transform settings */
	dm_find_setting("ssa.transform", &set_transform);
	dm_find_setting("ssa.flatten", &set_flatten);
	flatten = set_flatten->val.ival;
	transform = set_transform->val.ival;

	/* Get verbosity setting */
	dm_find_setting("cfg.verbose", &cfg_verbosity);
	verbosity = cfg_verbosity->val.ival;

	/* Get fcalls setting */
	dm_find_setting("cfg.fcalls", &fcalls);
	fcalls_i = fcalls->val.ival;
	switch (fcalls_i) {
		case 4:
			c = asprintf(&fcallmessage, "(fcalls = 4) complete cfg/cg reconstruction, flow trigger followed all reachable branches");
			break;
		case 3:
			c = asprintf(&fcallmessage, "(fcalls = 3) cfg/cg reconstruction, flow trigger followed all local (.text) branches");
			break;
		case 2:
			c = asprintf(&fcallmessage, "(fcalls = 2) function cfg reconstruction, flow trigger followed all local jumps");
			break;
		case 1:
			c = asprintf(&fcallmessage, "(fcalls = 1) single block reconstruction, flow trigger stopped at first branch");
			break;
		case 0:
			c = asprintf(&fcallmessage, "(fcalls = 0) function block recovery, flow trigger ignored all branches and halted at ret");
			break;
	}
	dm_new_post_message(fcallmessage);

	dm_instruction_se_init();

	(void)c;
}

void
dm_assign(int dest[4], int src[4])
{
	memcpy(dest, src, 4 * sizeof(int));
}

/*
 * We create an array of structures indicating semantics of each instruction
 */
/* nasty hack, overapproximates size of ud enum in itab.h, fix XXX */
#define DM_UD_ENUM_HACK				600
void
dm_instruction_se_init()
{
	/* XXX store in linked list (queue.h) */
	int c;

	instructions = malloc(sizeof(struct dm_instruction_se) * (DM_UD_ENUM_HACK));
	/* Initialise struct recording which instructions write to registers */
	for (c = 0; c < DM_UD_ENUM_HACK; c++) {
		instructions[c].instruction = c;
		dm_assign(instructions[c].write, (int[]){ 1, 0, 0, 0 });
		instructions[c].jump = 0;
		instructions[c].ret = 0;
		instructions[c].disjunctive = 0;
		instructions[c].shift = 0;
		instructions[c]._signed = 1;
		instructions[c]._unsigned = 1;
		instructions[c]._float = 1; /* 1 indicates float, 2 indicates packed float */
		instructions[c]._double = 1; /* 1 indicates double, 2 indicates packed double */
		instructions[c]._string = 0;
		instructions[c].unknown = 1;
	}
	instructions[UD_Inop].unknown = 0;
	dm_assign(instructions[UD_Inop].write, (int[]) { 0, 0, 0, 0 });

	instructions[UD_Ipop].unknown = 0;
	dm_assign(instructions[UD_Ipop].write, (int[]) { 1, 0, 0, 0 });

	dm_assign(instructions[UD_Ipush].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ipush].unknown = 0;

	dm_assign(instructions[UD_Itest].write, (int[]){ 0, 0, 0, 0 });
	instructions[UD_Itest].unknown = 0;
	instructions[UD_Itest]._class = 0;

	dm_assign(instructions[UD_Icmp].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Icmp].unknown = 0;
	instructions[UD_Icmp]._class = 0;

	/* Control flow instructions */
	dm_assign(instructions[UD_Icall].write, (int[]) { 0, 1, 0, 0 });
	instructions[UD_Icall].unknown = 0;
	if (fcalls_i > 2)
		instructions[UD_Icall].jump = 2;

	dm_assign(instructions[UD_Iret].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Iret].ret = 1;
	instructions[UD_Iret].unknown = 0;

	dm_assign(instructions[UD_Iretf].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Iretf].ret = 1;
	instructions[UD_Iretf].unknown = 0;

	dm_assign(instructions[UD_Ijmp].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijmp].jump = 1;
	instructions[UD_Ijmp].unknown = 0;

	dm_assign(instructions[UD_Ijz].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijz].jump = 2;
	instructions[UD_Ijz].unknown = 0;

	dm_assign(instructions[UD_Ijnz].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijnz].jump = 2;
	instructions[UD_Ijnz].unknown = 0;

	dm_assign(instructions[UD_Ijg].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijg].jump = 2;
	instructions[UD_Ijg].unknown = 0;

	dm_assign(instructions[UD_Ijae].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijae].jump = 2;
	instructions[UD_Ijae].unknown = 0;

	dm_assign(instructions[UD_Ijle].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijle].jump = 2;
	instructions[UD_Ijle].unknown = 0;

	dm_assign(instructions[UD_Ijl].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijl].jump = 2;
	instructions[UD_Ijl].unknown = 0;

	dm_assign(instructions[UD_Ija].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ija].jump = 2;
	instructions[UD_Ija].unknown = 0;

	dm_assign(instructions[UD_Ijb].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijb].jump = 2;
	instructions[UD_Ijb].unknown = 0;

	dm_assign(instructions[UD_Ijbe].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijbe].jump = 2;
	instructions[UD_Ijbe].unknown = 0;

	dm_assign(instructions[UD_Ijcxz].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijcxz].jump = 2;
	instructions[UD_Ijcxz].unknown = 0;

	dm_assign(instructions[UD_Ijnp].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijnp].jump = 2;
	instructions[UD_Ijnp].unknown = 0;

	dm_assign(instructions[UD_Ijge].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijge].jump = 2;
	instructions[UD_Ijge].unknown = 0;

	dm_assign(instructions[UD_Ijs].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijs].jump = 2;
	instructions[UD_Ijs].unknown = 0;

	dm_assign(instructions[UD_Ijns].write, (int[]) { 0, 0, 0, 0 });
	instructions[UD_Ijns].jump = 2;
	instructions[UD_Ijns].unknown = 0;

	instructions[UD_Ileave].unknown = 0;
	instructions[UD_Ipop].unknown = 0;
	instructions[UD_Ipush].unknown = 0;

	/* Standard arithemetic - add, sub, and etc */
	if (transform) {
		dm_assign(instructions[UD_Iidiv].write, (int[]) { 1, 1, 0, 0 });
		dm_assign(instructions[UD_Idiv].write, (int[]) { 1, 1, 0, 0 });
	}
	else {
		dm_assign(instructions[UD_Iidiv].write, (int[]) { 0, 0, 0, 0 });
		dm_assign(instructions[UD_Idiv].write, (int[]) { 0, 0, 0, 0 });
	}

	instructions[UD_Iadd].disjunctive = 1;
	instructions[UD_Iadd].unknown = 0;
	instructions[UD_Iadd]._class = 2;
	instructions[UD_Iadd]._float = 0;
	instructions[UD_Iadd]._double = 0;

	instructions[UD_Iadc].disjunctive = 1;
	instructions[UD_Iadc].unknown = 0;
	instructions[UD_Iadc]._class = 2;
	instructions[UD_Iadc]._float = 0;
	instructions[UD_Iadc]._double = 0;

	instructions[UD_Isub].disjunctive = 1;
	instructions[UD_Isub].unknown = 0;
	instructions[UD_Isub]._class = 2;
	instructions[UD_Isub]._float = 0;
	instructions[UD_Isub]._double = 0;

	instructions[UD_Iand].disjunctive = 1;
	instructions[UD_Iand].unknown = 0;
	instructions[UD_Iand]._class = 2;
	instructions[UD_Iand]._float = 0;
	instructions[UD_Iand]._double = 0;

	/* Shifts, xor, or */
	instructions[UD_Isar].unknown = 0;
	instructions[UD_Isar]._signed = 1;
	instructions[UD_Isar].shift = 1;

	instructions[UD_Isalc].unknown = 0;
	instructions[UD_Isalc].shift = 1;

	instructions[UD_Ishl].unknown = 0;
	instructions[UD_Ishl].shift = 1;

	instructions[UD_Ishr].unknown = 0;
	instructions[UD_Ishr].shift = 1;
	instructions[UD_Ishr]._unsigned = 1;

	instructions[UD_Ixor].unknown = 0;
	instructions[UD_Ixor]._class = 4;
	instructions[UD_Ixor]._float = 0;
	instructions[UD_Ixor]._double = 0;

	instructions[UD_Ior].unknown = 0;
	instructions[UD_Ior]._class = 4;
	instructions[UD_Ior]._float = 0;
	instructions[UD_Ior]._double = 0;

	instructions[UD_Inot].unknown = 0;
	instructions[UD_Inot]._class = 4;
	instructions[UD_Inot]._float = 0;
	instructions[UD_Inot]._double = 0;
	instructions[UD_Inot]._signed = 0;

	/* LEA */
	/*instructions[UD_Imov].unknown = 0;
	instructions[UD_Imov]._class = 5;*/

	/* Mov etc */
	instructions[UD_Imov].unknown = 0;
	instructions[UD_Imov]._class = 1;

	instructions[UD_Imovsx]._unsigned = 0;
	instructions[UD_Imovsx]._float = 0;
	instructions[UD_Imovsx]._double = 0;
	instructions[UD_Imovsx].unknown = 0;
	instructions[UD_Imovsx]._class = 1;

	instructions[UD_Imovsxd]._unsigned = 0;
	instructions[UD_Imovsxd]._float = 0;
	instructions[UD_Imovsxd]._double = 0;
	instructions[UD_Imovsxd].unknown = 0;
	instructions[UD_Imovsxd]._class = 1;

	/* SSE arithmetic */
	instructions[UD_Iaddpd]._unsigned = 0;
	instructions[UD_Iaddpd]._signed = 0;
	instructions[UD_Iaddpd]._float = 0;
	instructions[UD_Iaddpd].unknown = 0;
	instructions[UD_Iaddpd]._class = 3;

	instructions[UD_Iaddps]._unsigned = 0;
	instructions[UD_Iaddps]._signed = 0;
	instructions[UD_Iaddps]._double = 0;
	instructions[UD_Iaddps].unknown = 0;
	instructions[UD_Iaddps]._class = 3;

	instructions[UD_Iaddsd]._unsigned = 0;
	instructions[UD_Iaddsd]._signed = 0;
	instructions[UD_Iaddsd]._float = 0;
	instructions[UD_Iaddsd].unknown = 0;
	instructions[UD_Iaddsd]._class = 3;

	instructions[UD_Iaddss]._unsigned = 0;
	instructions[UD_Iaddss]._signed = 0;
	instructions[UD_Iaddss]._double = 0;
	instructions[UD_Iaddss].unknown = 0;
	instructions[UD_Iaddss]._class = 3;

	instructions[UD_Iaddsubpd]._unsigned = 0;
	instructions[UD_Iaddsubpd]._signed = 0;
	instructions[UD_Iaddsubpd]._float = 0;
	instructions[UD_Iaddsubpd].unknown = 0;
	instructions[UD_Iaddsubpd]._class = 3;

	instructions[UD_Iaddsubps]._unsigned = 0;
	instructions[UD_Iaddsubps]._signed = 0;
	instructions[UD_Iaddsubps]._double = 0;
	instructions[UD_Iaddsubps].unknown = 0;
	instructions[UD_Iaddsubps]._class = 3;

	instructions[UD_Iandpd]._unsigned = 0;
	instructions[UD_Iandpd]._signed = 0;
	instructions[UD_Iandpd]._float = 0;
	instructions[UD_Iandpd].unknown = 0;
	instructions[UD_Iandpd]._class = 3;

	instructions[UD_Iandps]._unsigned = 0;
	instructions[UD_Iandps]._signed = 0;
	instructions[UD_Iandps]._double = 0;
	instructions[UD_Iandps].unknown = 0;
	instructions[UD_Iandps]._class = 3;

	instructions[UD_Iandnpd]._unsigned = 0;
	instructions[UD_Iandnpd]._signed = 0;
	instructions[UD_Iandnpd]._float = 0;
	instructions[UD_Iandnpd].unknown = 0;
	instructions[UD_Iandnpd]._class = 3;

	instructions[UD_Iandnps]._unsigned = 0;
	instructions[UD_Iandnps]._signed = 0;
	instructions[UD_Iandnps]._double = 0;
	instructions[UD_Iandnps].unknown = 0;
	instructions[UD_Iandnps]._class = 3;
}

/*
 * Create a new node in the CFG
 */
struct dm_cfg_node *
dm_new_cfg_node(NADDR nstart, NADDR nend)
{
	struct dm_cfg_node		*node;

	node = malloc(sizeof(struct dm_cfg_node));
	node->start = nstart;
	node->end = nend;
	node->children = NULL;//calloc(1, sizeof(void*));
	node->c_count = 0;
	node->parents = NULL;
	node->p_count = 0;
	node->nonlocal = 0;
	node->visited = 0;
	node->pre = 0;
	node->rpost = 0;
	node->idom = NULL;
	node->df_set = NULL;
	node->df_count = 0;
	node->def_vars = NULL;
	node->dv_count = 0;
	node->phi_functions = NULL;
	node->pf_count = 0;
	node->instructions = NULL;
	node->i_count = 0;
	node->function_head = NULL;
	node->function_return = NULL;
	node->is_function_head = 0;
	node->is_function_return = 0;
	node->return_nodes = NULL;
	node->rn_count = 0;
	node->function_nodes = NULL;
	node->fn_count = 0;
	node->superphi = NULL;
	/* Add node to the free list so we can free the memory at the end */
	if (p) {
		p->next = calloc(1, sizeof(struct ptrs));
		p = p->next;
		p->ptr = (void*)node;
	}
	else {
		p = calloc(1, sizeof(struct ptrs));
		p->ptr = (void*)node;
		p_head = p;
	}
	p_length++;

	return (node);
}

void
dm_add_parent(struct dm_cfg_node *node, struct dm_cfg_node *parent)
{
	node->parents = realloc(node->parents, ++(node->p_count) * sizeof(void*));
	node->parents[node->p_count - 1] = parent;
}

void
dm_add_child(struct dm_cfg_node *node, struct dm_cfg_node *child)
{
	node->children = realloc(node->children, ++(node->c_count) * sizeof(void*));
	node->children[node->c_count - 1] = child;
}

void
dm_add_return_node(struct dm_cfg_node *node, struct dm_cfg_node *return_node)
{
	struct dm_cfg_node *function_head = NULL;

	if (node->is_function_head)
		function_head = node;
	else
		function_head = node->function_head;

	if (function_head == NULL) {
		printf("Tried to add recursive caller with NULL function head!\n");
		return;
	}
	function_head->return_nodes = realloc(function_head->return_nodes, ++(function_head->rn_count) * sizeof(void*));
	function_head->return_nodes[function_head->rn_count - 1] = return_node;
}

void
dm_add_node_to_function(struct dm_cfg_node *func, struct dm_cfg_node *node)
{
	struct dm_cfg_node *function_head = NULL;
	if (func->is_function_head)
		function_head = func;
	else
		function_head = func->function_head;

	function_head->function_nodes = realloc(function_head->function_nodes, ++(function_head->fn_count) * sizeof(void*));
	function_head->function_nodes[function_head->fn_count - 1] = node;
}

static char **post_messages = NULL;
static int npm = 0;

void
dm_print_post_messages()
{
	int i = 0;
	printf("Post messages:\n");
	for (; i < npm; i++) {
		printf("\t%s", post_messages[i]);
	}
}

void
dm_new_post_message(char *message)
{
	int c;
	npm++;
	post_messages = realloc(post_messages, npm * sizeof(void*));
	c = asprintf(&post_messages[npm - 1], "%s\n", message);
	(void)c;
}

void
dm_free_post_messages()
{
	int i = 0;
	for (; i < npm; i++) {
		free(post_messages[i]);
	}
	free(post_messages);
	post_messages = NULL;
	npm = 0;
}

void
dm_free_jumps()
{
	free(iBranches);
	iBranches = NULL;
	iBranchesCount = 0;
	free(branches);
	branches = NULL;
	branchesCount = 0;
}

/*
 * Main part of CFG recovery. Recursively find blocks.
 */
struct dm_cfg_node *
dm_gen_cfg_block(struct dm_cfg_node *node, struct dm_cfg_node *function_head, struct dm_cfg_node **function_return)
{
	NADDR			 addr = node->start;
	unsigned int		 read = 0, oldRead = 0;
	struct dm_cfg_node	*foundNode = NULL, *child = NULL;
	NADDR			 target = 0;
	int			 i = 0, duplicate = 0, local_target = 1, call = 0;
	char			 pm[300];

	node->function_head = function_head;
	node->function_return = function_return;
	if (function_head == node)
		node->is_function_head = 1;
	if (*function_return == node)
		node->is_function_return = 1;

	dm_seek(node->start);
	while (1) {
		oldRead = read;
		read = ud_disassemble(&ud);

		/* Check we haven't run into the start of another block */
		if ((foundNode = dm_find_cfg_node_starting(addr))
		    && (foundNode != node)) {
			//printf("Ran into the start of existing block at address " NADDR_FMT "!\n", addr);
			addr -= oldRead;
			/*free(node->children);
			node->children = calloc(2, sizeof(void*));
			node->children[0] = foundNode;
			node->c_count = 1;*/
			dm_add_child(node, foundNode);
			dm_add_parent(foundNode, node);
			break;
		}
		/*
		 * Check for jump instructions and create
		 * new nodes as necessary
		 *
		 * Make sure the target is inside the .text
		 * section */
		local_target = 1;
		if (instructions[ud.mnemonic].jump) {
			target = dm_get_jump_target(ud);
			if (ud.operand[0].index) {
				if ((ud.operand[0].base) && (ud.operand[0].scale) && (ud.operand[0].offset))
					sprintf(pm, "Branch to indirect address [%s+%s*%d+" NADDR_FMT "] at " NADDR_FMT, ud_reg_tab[ud.operand[0].base-UD_R_AL],
						ud_reg_tab[ud.operand[0].index-UD_R_AL], ud.operand[0].scale, dm_get_operand_lval(ud, 0, 1, 0), addr);
				else if ((ud.operand[0].scale) && (ud.operand[0].offset))
					sprintf(pm, "Branch to indirect address [%s*%d+" NADDR_FMT "] at " NADDR_FMT, ud_reg_tab[ud.operand[0].index-UD_R_AL],
						ud.operand[0].scale, dm_get_operand_lval(ud, 0, 1, 0), addr);
				else if (ud.operand[0].index)
					sprintf(pm, "Branch to indirect address [%s] at " NADDR_FMT, ud_reg_tab[ud.operand[0].index-UD_R_AL], addr);
				else
					sprintf(pm, "Branch to address outside of .text (" NADDR_FMT ") at " NADDR_FMT, target, addr);
				dm_new_post_message(pm);
				iBranchesCount++;
				iBranches = realloc(iBranches, iBranchesCount * sizeof(struct indirect_branch));
				iBranches[iBranchesCount - 1].address = addr;
				iBranches[iBranchesCount - 1].insn = NULL;
				iBranches[iBranchesCount - 1].node = node;
				local_target = 0;
			}
			if (!dm_is_target_in_text(target))
				local_target = 0;

			if (!ud.operand[0].index) {
				branchesCount++;
				branches = realloc(branches, branchesCount * sizeof(struct branch));
				branches[branchesCount - 1].addr = addr;
				branches[branchesCount - 1].target = target;
				branches[branchesCount - 1].insn = NULL;
				branches[branchesCount - 1].node = node;
			}
		}
		/* fcalls_i controls CFG reconstruction behaviour:
			0 = ignore all branch instructions
			1 = end block at first branch instruction and finish there
			2 = follow all local jump instructions (but not calls)
			3 = follow all local branch instructions (of any type)
			4 = attempt to follow all branch instructions (local or otherwise) (except indirect branches)
		*/

		if ((fcalls_i == 1) && instructions[ud.mnemonic].jump)
			break;

		if (instructions[ud.mnemonic].jump &&
			/*((local_target && fcalls_i &&  !((fcalls_i == 1) && (ud.mnemonic == UD_Icall)))
				|| ((!local_target) && (fcalls_i == 3)) || (local_target)) */
				((local_target && (fcalls_i > 0) && (ud.mnemonic != UD_Icall)) ||
				 (local_target && (fcalls_i > 2)) ||
				 ((!local_target) && (fcalls_i >3)))
				&& !ud.operand[0].index) {
			/* Get the target of the jump instruction */
			target = dm_get_jump_target(ud);

			/* End the block here */
			node->end = addr;
			//free(node->children);

			/* Make space for the children of this block */
			//node->children = calloc(instructions[ud.mnemonic].jump
			//    + 1, sizeof(void*));
			//node->c_count = instructions[ud.mnemonic].jump;

			/* Record if this is a call rather than jump */
			if (ud.mnemonic == UD_Icall) call = 1;

			/* Check if we are jumping to the start of an already
			 * existing block, if so use that as child of current
			 * block */
			if (((foundNode = dm_find_cfg_node_starting(target))
			    != NULL) && local_target) {
				//node->children[0] = foundNode;
				dm_add_child(node, foundNode);
				dm_add_parent(foundNode, node);
			}
			/* Check if we are jumping to the *middle* of an
			 * existing block, if so split it and use 2nd half as
			 * child of current block */
			else if (((foundNode = dm_find_cfg_node_containing(target)) != NULL) && local_target) {
				/* We found a matching block. Now find address
				 * before addr and split the block */
				//node->children[0] = dm_split_cfg_block(foundNode, target);
				child = dm_split_cfg_block(foundNode, target);
				dm_add_child(node, child);
				dm_add_node_to_function(node->function_head, child);
				duplicate = 0;
				/* Child may already have node as parent */
				for (i = 0; i < child->p_count; i++)
					if (child->parents[i] == node)
						duplicate = 1;
				/* Node is recursive, make it it's own parent */
				//if (duplicate)
				//	dm_add_parent(node->children[0],
				//	    node->children[0]);
				//else
				if (!duplicate)
					dm_add_parent(child, node);
			}
			/* This is a new block, so scan with a recursive call
			 * to find it's start, end, and children, assuming it's
			 * a local block (inside the binary) */
			else if (local_target) {
				child = dm_new_cfg_node(target, 0);
				dm_add_child(node, child);
				//node->children[0] = foundNode;
				dm_add_parent(child, node);
				if (call) {
					child->function_return = malloc(sizeof(void*));
					(*child->function_return) = NULL;
					dm_gen_cfg_block(child, child, child->function_return);
				}
				else {
					dm_add_node_to_function(node->function_head, child);
					//child->function_return = function_return;
					dm_gen_cfg_block(child, node->function_head, function_return);
				}
			}
			/* This target is outside of the binary. Just make a
			 * basic block for it and continue with a new
			 * block from the next insn */
			if (!local_target) {
				if ((foundNode = dm_find_cfg_node_starting(target)) != NULL) {
					dm_add_parent(foundNode, node);
					dm_add_child(node, foundNode);
					//node->children[0] = foundNode;
				}
				else {
					/* New block starts and ends at target addr */
					foundNode = dm_new_cfg_node(target, target);
					//node->children[0] = child;
					dm_add_child(node, foundNode);
					dm_add_parent(foundNode, node);
					foundNode->nonlocal = 1;
					foundNode->function_head = foundNode;
					foundNode->is_function_head = 1;
					foundNode->is_function_return = 1;
					foundNode->function_return = malloc(sizeof(void*));
					*(foundNode->function_return) = foundNode;
				}

				/* New node has child starting at next insn */
				dm_seek(addr);
				read = ud_disassemble(&ud);
				child = dm_new_cfg_node(ud.pc, 0);
				dm_add_child(foundNode, child);
				dm_add_parent(child, foundNode);
				dm_add_node_to_function(node->function_head, child);
				//child->function_head = function_head;
				//child->function_return = function_return;
				dm_gen_cfg_block(child, node->function_head, function_return);
				//foundNode->children =
				  //  xrealloc(foundNode->children, (1 + ++(foundNode->c_count))*sizeof(void*));
				//foundNode->children[foundNode->c_count-1] = dm_new_cfg_node(ud.pc, 0);
				//foundNode->children[foundNode->c_count] = NULL;
				//dm_add_parent(foundNode->children[foundNode->c_count-1], foundNode);
				//dm_gen_cfg_block(foundNode->children[foundNode->c_count-1], node->function_head, function_return);
			}
			else {
				/* Seek back to before we followed the jump */
				dm_seek(addr);
				read = ud_disassemble(&ud);
			}
			/* Check whether there was some sneaky splitting of the
			 * block we're working on while we were away! */
			if (node->end < addr) {
				/* Now we must find the right block to continue
				 * from */
				foundNode = dm_find_cfg_node_ending(addr);
				if (foundNode != NULL) {
					/*if (instructions[ud.mnemonic].jump > 1) {
						node->children = realloc(node->children, 2*sizeof(void*));
						node->children[1] = NULL;
						node->c_count = 1;
					}*/
					node = foundNode;
				}
			}

			/*
			 * If the jump was a conditional, now we must
			 * follow the other leg of the jump
			 */
			if (call && local_target) {
				/* Non-recursive case */
				if (node->children[0]->function_head != function_head) {
					if ((foundNode = dm_find_cfg_node_starting(ud.pc)) != NULL) {
						/* Already found the function return of called function */
						if (node->children[0]->function_return != NULL) {
							dm_add_child(*(node->children[0]->function_return), foundNode);
							dm_add_parent(foundNode, *(node->children[0]->function_return));
							call = 0;
							break;
						}
						else {
							dm_add_return_node(node->children[0], foundNode);
							call = 0;
							break;
						}
					}
					else {
						if (node->children[0]->function_return != NULL) {
							child = dm_new_cfg_node(ud.pc, 0);
							//node->children[1] = foundNode;
							dm_add_child(*(node->children[0]->function_return), child);
							dm_add_parent(child, *(node->children[0]->function_return));
							dm_add_node_to_function(node->function_head, child);
							child->function_head = node->function_head;
							child->function_return = function_return;
							node = child;
							call = 0;
						}
						else {
							child = dm_new_cfg_node(ud.pc, 0);
							dm_add_return_node(node->children[0], child);
							dm_add_node_to_function(node->function_head, child);
							child->function_head = node->function_head;
							child->function_return = function_return;
							node = child;
							call = 0;
						}
					}
				}
				/* Recursive case */
				else if (node->children[0]->function_head == function_head) {
					if ((foundNode = dm_find_cfg_node_starting(ud.pc)) != NULL) {
						if (*function_return != NULL) {
							dm_add_child(*function_return, foundNode);
							dm_add_parent(foundNode, *function_return);
							call = 0;
							break;
						}
						else {
							dm_add_return_node(function_head, foundNode);
							call = 0;
							break;
						}
					}
					else {
						if (*function_return != NULL) {
							child = dm_new_cfg_node(ud.pc, 0);
							dm_add_child(*function_return, child);
							dm_add_parent(child, *function_return);
							dm_add_node_to_function(node->function_head, child);
							child->function_head = node->function_head;
							child->function_return = function_return;
							node = child;
							call = 0;
						}
						else {
							child = dm_new_cfg_node(ud.pc, 0);
							dm_add_return_node(node->function_head, child);
							dm_add_node_to_function(node->function_head, child);
							child->function_head = node->function_head;
							child->function_return = function_return;
							node = child;
							call = 0;
						}
					}
				}
			}
			/* Conditional jump */
			else if (instructions[ud.mnemonic].jump > 1) {
				if ((foundNode = dm_find_cfg_node_starting(ud.pc)) != NULL) {
					dm_add_parent(foundNode, node);
					dm_add_child(node, foundNode);
					break;
				}
				else {
					child = dm_new_cfg_node(ud.pc, 0);
					//node->children[1] = foundNode;
					dm_add_child(node, child);
					dm_add_parent(child, node);
					dm_add_node_to_function(node->function_head, child);
					child->function_head = node->function_head;
					child->function_return = function_return;
					node = child;
				}
			}
			else
				break;
		}
		/* If we find a return end the block/node */
		if (instructions[ud.mnemonic].ret) {
			node->end = ud.pc;
			node->is_function_return = 1;
			*function_return = node;
			for (i = 0; i < node->function_head->rn_count; i++) {
				dm_add_child(node, node->function_head->return_nodes[i]);
				dm_add_parent(node->function_head->return_nodes[i], node);
			}
			free(node->function_head->return_nodes);
			node->function_head->return_nodes = NULL;
			node->function_head->rn_count = 0;
			break;
		}
		addr += read;
	}
	node->end = addr;
	return node;
}

void
dm_print_node_info(struct dm_cfg_node *node)
{
	int i = 0;
	printf("Node %d. \n\tStart: " NADDR_FMT " \n\tEnd: " NADDR_FMT ".\n\tHas children? ", node->post, node->start, node->end);
	if (node->c_count != 0) {
		printf("Yes, nodes ");
		for (; i < node->c_count; i++) {
			if (i != node->c_count - 1)
				printf("%d, ", node->children[i]->post);
			else
				printf("%d\n", node->children[i]->post);
		}
	}
	else
		printf("No\n");

	printf("Has parents? ");
	if (node->p_count != 0) {
		printf("Yes, nodes ");
		for (i = 0; i < node->p_count; i++) {
			if (i != node->p_count - 1)
				printf("%d, ", node->parents[i]->post);
			else
				printf("%d\n", node->parents[i]->post);
		}
	}
	else
		printf("No\n");
}

int
dm_is_target_in_text(NADDR addr)
{
	NADDR		start = 0, size = 0;
	GElf_Shdr	shdr;

	if ((dm_find_section(".text", &shdr)) == DM_FAIL) {
		return (0);
	}

	start = shdr.sh_offset;
	size = shdr.sh_size;

	if ((addr < start) || (addr > (start + size)))
		return (0);

	return (1);
}

/* Split node at addr, return second half (tail) */
struct dm_cfg_node *
dm_split_cfg_block(struct dm_cfg_node *node, NADDR addr)
{
	struct dm_cfg_node *tail = NULL;
	NADDR addr2 = node->start;
	unsigned int read = 0;
	int i = 0, j = 0;

	/* Tail node runs from split address to end of original node */
	tail = dm_new_cfg_node(addr, node->end);
	if (node->is_function_return) {
		node->is_function_return = 0;
		tail->is_function_return = 1;
		*(node->function_return) = tail;
	}
	tail->function_return = node->function_return;
	tail->function_head = node->function_head;
	//free(tail->children);

	/* Tail node must pick up original nodes children */
	tail->children = node->children;
	tail->c_count = node->c_count;

	/* First parent of tail node is the head node */
	dm_add_parent(tail, node);

	/* Find address of instruction before the split (end of head node) */
	for (dm_seek(node->start); addr2 + read < addr; addr2 += read)
		read = ud_disassemble(&ud);

	node->end = addr2;

	/* Head has only one child - the tail node */
	/*node->children = calloc(2, sizeof(void*));
	node->children[0] = tail;
	node->c_count = 1;*/
	node->children = NULL;
	node->c_count = 0;
	dm_add_child(node, tail);

	/* We must find all children of the original node and change the
	 * parents entry that pointed to the original node to point to the
	 * new tail node */
	//for (i = 0; tail->children[i] != NULL; i++)
	for (i = 0; i < tail->c_count; i++)
		for (j = 0; j < tail->children[i]->p_count; j++)
			if (tail->children[i]->parents[j] == node) {
				tail->children[i]->parents[j] = tail;
			}
	/* Finally, return the new tail node*/
	return tail;
}

/*
 * Searches all blocks for one starting with addr, and returns it if found
 * (otherwise returns NULL)
 */
struct dm_cfg_node *
dm_find_cfg_node_starting(NADDR addr)
{
	struct dm_cfg_node	*node;

	for (p_iter = p_head;
	    (p_iter != NULL); p_iter = p_iter->next) {
		if (p_iter->ptr != NULL) {
			node = (struct dm_cfg_node*)(p_iter->ptr);
			if (node->start == addr)
				return node;
		}
	}

	return (NULL);
}

/*
 * Searches all blocks for one ending with addr, and returns it if found
 * (otherwise returns NULL)
 */
struct dm_cfg_node *
dm_find_cfg_node_ending(NADDR addr)
{
	struct dm_cfg_node	*node;

	for (p_iter = p_head; p_iter != NULL; p_iter = p_iter->next) {
		node = (struct dm_cfg_node*)(p_iter->ptr);
		if (node->end == addr)
			return (node);
	}
	return (NULL);
}

/*
 * Searches all blocks to see if one contains addr and returns it if found
 * (otherwise returns NULL)
 */
struct dm_cfg_node *
dm_find_cfg_node_containing(NADDR addr)
{
	struct dm_cfg_node		*node;

	for (p_iter = p_head; p_iter != NULL; p_iter = p_iter->next) {

		node = (struct dm_cfg_node*) (p_iter->ptr);

		if ((node->start < addr) &&
		    (node->end != 0) && (node->end > addr)) {
			return node;
		}
	}
	return (NULL);
}

/*
 * Use the free list to print info on all the blocks we have found
 */
void
dm_print_cfg()
{
	struct dm_cfg_node	*node;
	int			c;

	for (p = p_head; p != NULL; p = p->next) {
		node = (struct dm_cfg_node*) (p->ptr);
		printf("Block %d start: " NADDR_FMT ", end: " NADDR_FMT ", function head: %d, return: %d\n", node->post, node->start, node->end, node->function_head->post, (*(node->function_return))->post);
		if (node->is_function_head) {
			printf("\tNodes in function: ");
			for (c = 0; c < node->fn_count; c++) {
				printf("%d ", node->function_nodes[c]->post);
			}
			printf("\n");
		}

		//if (node->children[0] != NULL) {
		if (node->c_count) {
			printf("\tChild blocks: ");
			for (c = 0; c < node->c_count; c++)
			//for (c = 0; node->children[c] != NULL; c++)
				printf("%d ", node->children[c]->post);
			printf("\n");
		}

		if (node->p_count) {
			printf("\tParent blocks: ");
			for (c = 0; c < node->p_count; c++)
				printf("%d ", node->parents[c]->post);
			printf("\n");
		}
	}
}

/*
 * Free all data structures used for building the CFG
 */
void
dm_free_cfg()
{
	struct ptrs *p_prev = NULL;
	struct dm_cfg_node *node = NULL;

	p = p_head;
	while (p != NULL) {
		if (p->ptr != NULL) {
			node = (struct dm_cfg_node*)(p->ptr);
			free(node->children);
			free(node->parents);
			if (node->rn_count)
				free(node->return_nodes);
			if (node->is_function_head) {
				free(node->function_return);
				free(node->function_nodes);
			}
		}
		free(p->ptr);
		p_prev = p;
		p = p->next;
		free(p_prev);
	}
	free(instructions);
	free(rpost);
	p_length = 0;
}

/*
 * Do a depth-first walk of the CFG to get the reverse post-order
 * (and post-order and pre-order) of the nodes
 */
int i, j;

void
dm_depth_first_walk(struct dm_cfg_node *cfg)
{
	struct dm_cfg_node *node = cfg;
	i = 0;
	j = p_length - 1;
	p = p_head;
	while ((node = dm_get_unvisited_node(p)))
		dm_dfw(node);
}

void
dm_dfw(struct dm_cfg_node *node)
{
	int c = 0;
	node->visited = 1;
	node->pre = i++;
	//for (;node->children[c] != NULL; c++)
	for (;c < node->c_count; c++)
		if (!node->children[c]->visited)
			dm_dfw(node->children[c]);
	rpost[j] = node;
	node->rpost = j--;
	node->post = p_length - 1 - node->rpost;
}

struct dm_cfg_node*
dm_get_unvisited_node()
{
	for (p = p_head; p != NULL; p = p->next) {
		if (!((struct dm_cfg_node*)(p->ptr))->visited)
			return p->ptr;
	}
        return NULL;
}

void
dm_graph_cg()
{
	struct dm_dwarf_sym_cache_entry	*sym = NULL;
	struct dm_cfg_node		*node = NULL;
	FILE				*fp = dm_new_graph("cg.dot");
	char				*itoa1 = NULL, *itoa2 = NULL;
	int				 c;

	if (!fp) return;

	c = asprintf(&itoa1, "CG of %s, starting from %s", fname, sym_name);
	dm_start_subgraph(fp, "CG", itoa1);
	free(itoa1);

	for (p = p_head; p != NULL; p = p->next) {
		node = (struct dm_cfg_node*)(p->ptr);
		if (node->is_function_head) {
			c = asprintf(&itoa1, "%d", node->post);
			if (node->nonlocal) {
				dm_colour_label(fp, itoa1, "red");
			}
			else if (dm_dwarf_find_sym_at_offset(node->start, &sym) == DM_OK) {
				c = asprintf(&itoa2, "%d (%s)\\nstart: " NADDR_FMT "\\nend: " NADDR_FMT, node->post, sym->name, node->start, node->end);
				dm_add_label(fp, itoa1, itoa2);
				free(itoa2);
			}
			else {
				c = asprintf(&itoa2, "%d\\nstart: " NADDR_FMT "\\nend: " NADDR_FMT, node->post, node->start, node->end);
				dm_add_label(fp, itoa1, itoa2);
				free(itoa2);
			}
			free(itoa1);
		}
		dm_graph_cg_aux(node, fp);
	}
	dm_end_subgraph(fp);
	dm_end_graph(fp);
	dm_display_graph("cg.dot");
	(void)c;
}

void
dm_graph_cg_aux(struct dm_cfg_node *node, FILE *fp)
{
	char	*itoa1 = NULL, *itoa2 = NULL;
	int	 c, i = 0;

	c = asprintf(&itoa1, "%d", node->function_head->post);
	for (; i < node->c_count; i++) {
		if (node->children[i]->function_head != node->function_head) {
			c = asprintf(&itoa2, "%d", node->children[i]->function_head->post);
			dm_add_edge(fp, itoa1, itoa2);
			free(itoa2);
		}
		if (node->children[i] == node->function_head)
			dm_add_edge(fp, itoa1, itoa1);
	}
	free(itoa1);
	(void)c;
}


void
dm_graph_cfg()
{
	struct dm_dwarf_sym_cache_entry	*sym = NULL;
        struct dm_cfg_node		*node = NULL, *child = NULL;
        FILE				*fp = dm_new_graph("cfg.dot");
        char				*itoa1 = NULL, *itoa2 = NULL, *itoa3 = NULL;
        int				 c = 0, i = 0;

	if (!fp) return;

	c = asprintf(&itoa1, "CFG of %s, starting from %s", fname, sym_name);

	dm_start_subgraph(fp, "CFG", itoa1);
	free(itoa1);

	for (p = p_head; p != NULL; p = p->next) {
		node = (struct dm_cfg_node*)(p->ptr);
		if (node->nonlocal) {
			c = asprintf(&itoa1, "%d", node->post);
			dm_colour_label(fp, itoa1, "red");
			free(itoa1);
		}
		else if (node->is_function_head) {
			c = asprintf(&itoa1, "%d", node->post);
			if (dm_dwarf_find_sym_at_offset(node->start, &sym) == DM_OK) {
				dm_start_subgraph(fp, sym->name, sym->name);
				dm_colour_label(fp, itoa1, "green");
				if (verbosity == 2) {
					itoa3 = dm_disassemble_node(node);
					c = asprintf(&itoa2, "%d \\nstart: " NADDR_FMT "\\n%s", node->post, node->start, itoa3);
					free(itoa3);
				}
				else
					c = asprintf(&itoa2, "%d \\nstart: " NADDR_FMT, node->post, node->start);
				dm_add_label(fp, itoa1, itoa2);
				free(itoa2);
			}
			else {
				c = asprintf(&itoa2, NADDR_FMT, node->start);
				dm_start_subgraph(fp, itoa2, itoa2);
				free(itoa2);
				if (verbosity == 2) {
					itoa3 = dm_disassemble_node(node);
					c = asprintf(&itoa2, "%d\\nstart: " NADDR_FMT "\\n%s", node->post, node->start, itoa3);
					free(itoa3);
				}
				else
					c = asprintf(&itoa2, "%d\\nstart: " NADDR_FMT, node->post, node->start);
				dm_colour_label(fp, itoa1, "green");
				dm_add_label(fp, itoa1, itoa2);
				free(itoa2);
			}
			free(itoa1);
			for (i = 0; i < node->fn_count; i++) {
				child = node->function_nodes[i];
				c = asprintf(&itoa1, "%d", child->post);
				if (child->is_function_return) {
					if (verbosity == 2) {
						itoa3 = dm_disassemble_node(child);
						c = asprintf(&itoa2, "%d: " NADDR_FMT "\\nend: " NADDR_FMT "\\n%s", child->post, child->start, child->end, itoa3);
						free(itoa3);
					}
					else
						c = asprintf(&itoa2, "%d: " NADDR_FMT "\\nend: " NADDR_FMT, child->post, child->start, child->end);
					dm_add_label(fp, itoa1, itoa2);
					dm_colour_label(fp, itoa1, "lightpink");
					free(itoa2);
				}
				else if (verbosity == 1) {
					c = asprintf(&itoa2, "%d: " NADDR_FMT, child->post, child->start);
					dm_add_label(fp, itoa1, itoa2);
					free(itoa2);
				}
				else if (verbosity == 2) {
					itoa3 = dm_disassemble_node(child);
					c = asprintf(&itoa2, "%d: " NADDR_FMT "\\n%s", child->post, child->start, itoa3);
					free(itoa3);
					dm_add_label(fp, itoa1, itoa2);
					free(itoa2);
				}
				else
					dm_add_label(fp, itoa1, itoa1);
				free(itoa1);
			}
			dm_end_subgraph(fp);
		}
		c = asprintf(&itoa1, "%d", node->post);
		for (i = 0; i < node->c_count; i++) {
			c = asprintf(&itoa2, "%d", node->children[i]->post);
			dm_add_edge(fp, itoa1, itoa2);
			free(itoa2);
		}
		free(itoa1);
	}
	if (fcalls_i > 1) {
		dm_start_subgraph(fp, "Legend", "Legend");
		dm_invisible_edge(fp);
		dm_min_sep(fp);
		dm_add_label(fp, "Start", "Entry node");
		dm_colour_label(fp, "Start", "green");
		dm_add_label(fp, "End", "Exit node");
		dm_colour_label(fp, "End", "lightpink");
		dm_add_edge(fp, "Start", "End");
	}
	if (fcalls_i > 3) {
		dm_add_label(fp, "External", "Non-local\\nfunction call");
		dm_colour_label(fp, "External", "red");
		dm_add_edge(fp, "End", "External");
	}
	if (fcalls_i > 1)
		dm_end_subgraph(fp);
	dm_end_subgraph(fp);
	dm_end_graph(fp);
	dm_display_graph("cfg.dot");

	if (fcalls_i > 2)
		dm_graph_cg();
	(void)c;
}

char*
dm_disassemble_node(struct dm_cfg_node *node)
{
	NADDR a;
	char *temp1 = NULL, *temp2 = NULL;
	int c = 0;
	a = ud.pc;
	c = asprintf(&temp1, "%s", "");
	for (dm_seek(node->start); ud.pc - ud_insn_len(&ud) < node->end;) {
		ud_disassemble(&ud);
		temp2 = temp1;
		c = asprintf(&temp1, "%s%s\\l", temp1, ud_insn_asm(&ud));
		free(temp2);
	}
	dm_seek(a);
	(void)c;
	return temp1;
}

