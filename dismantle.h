/*
 * Copyright (c) 2011, Edd Barrett <vext01@gmail.com>
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
#ifndef __DISMANTLE_H
#define __DISMANTLE_H

#include "common.h"
#include "dm_dis.h"
#include "dm_elf.h"
#include "dm_cfg.h"
#include "dm_dom.h"
#include "dm_ssa.h"
#include "dm_dwarf.h"
#include "dm_util.h"
#include "dm_prolog_code.h"

int     dm_cmd_help();
int     dm_cmd_hex(char **args);
int     dm_cmd_hex_noargs(char **args);
int     dm_cmd_findstr(char **args);
int     dm_cmd_info(char **args);
int     dm_cmd_debug(char **args);
int     dm_cmd_debug_noargs(char **args);
int     dm_cmd_ansii_noargs(char **args);
int     dm_cmd_ansii(char **args);
int     dm_cmd_set_noargs(char **args);
int     dm_cmd_set_one_arg(char **args);
int     dm_cmd_set_two_args(char **args);

struct dm_cmd_sw {
	char		*cmd;
	uint8_t		 args;
	int		(*handler)(char **args);
} dm_cmds[] = {
	{"ansii", 0, dm_cmd_ansii_noargs}, {"ansii", 1, dm_cmd_ansii},
	{"bits", 0, dm_cmd_bits_noargs},
	{"bits", 1, dm_cmd_bits},
	{"cfg", 0, dm_cmd_cfg},
	{"debug", 0, dm_cmd_debug_noargs},
	{"debug", 1, dm_cmd_debug},
	{"dis", 0, dm_cmd_dis_noargs},  {"pd", 0, dm_cmd_dis_noargs},
	{"dis", 1, dm_cmd_dis},         {"pd", 1, dm_cmd_dis},
	{"dom", 0, dm_cmd_dom},
	{"disf", 0, dm_cmd_dis_func},   {"pdf", 0, dm_cmd_dis_func},
	{"findstr", 1, dm_cmd_findstr}, {"/", 1, dm_cmd_findstr},
	{"funcs", 0, dm_cmd_dwarf_funcs}, {"f", 0, dm_cmd_dwarf_funcs},
	{"help", 0, dm_cmd_help},       {"?", 0, dm_cmd_help},
	{"hex", 0, dm_cmd_hex_noargs},  {"px", 0, dm_cmd_hex_noargs},
	{"hex", 1, dm_cmd_hex},         {"px", 1, dm_cmd_hex},
	{"info", 0, dm_cmd_info},       {"i", 0, dm_cmd_info},
	{"offset", 1, dm_cmd_offset},
	{"pht", 0, dm_cmd_pht},
	{"set", 0, dm_cmd_set_noargs},
	{"set", 1, dm_cmd_set_one_arg},
	{"set", 2, dm_cmd_set_two_args},
	{"seek", 1, dm_cmd_seek},       {"s", 1, dm_cmd_seek},
	{"sht", 0, dm_cmd_sht},
	{"ssa", 0, dm_cmd_ssa},
	{"pc", 0, dm_cmd_pc},
	{"nsym", 1, dm_cmd_find_nearest_symbol},
	{"findbranch", 1, dm_cmd_find_direct_branch},
	{NULL, 0, NULL}
};

struct dm_help_rec {
	char	*cmd;
	char	*descr;
} help_recs[] = {
	{"  / str",			"Find ASCII string from current pos"},
	{"  CTRL+D",			"Exit"},
	{"  ansii",			"Get/set ANSII colours setting"},
	{"  bits [set_to]",		"Get/set architecture (32 or 64)"},
	{"  cfg",			"Show static CFG for current function"},
	{"  debug [level]",		"Get/set debug level (0-3)"},
	{"  dis/pd [ops]",		"Disassemble (8 or 'ops' operations)"},
	{"  disf/pdf",			"Disassemble function (up until the next RET)"},
	{"  dom",			"Show dominance tree and frontiers of cur func"},
	{"  funcs/f",			"Show functions from dwarf data"},
	{"  help/?",			"Show this help"},
	{"  hex/px [len]",		"Dump hex (64 or 'len' bytes)"},
	{"  info/i",			"Show file information"},
	{"  pht",			"Show program header table"},
	{"  set [var] [val]",		"Show/ammend settings"},
	{"  seek/s addr",		"Seek to an address"},
	{"  sht",			"Show section header table"},
	{"  ssa",			"Output SSA form"},
	{"  nsym",			"Find nearest symbol to address"},
	{"  findbranch [address]",	"Search for branches with 'address' as target"},
	{NULL, 0},
};

#endif
