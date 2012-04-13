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
