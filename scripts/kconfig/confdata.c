#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define LKC_DIRECT_LINK
#include "lkc.h"

static void conf_warning(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

static const char *conf_filename;
static int conf_lineno, conf_warnings, conf_unsaved;

const char conf_defname[] = "arch/$ARCH/defconfig";

static void conf_warning(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s:%d:warning: ", conf_filename, conf_lineno);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	conf_warnings++;
}

const char *conf_get_configname(void)
{
	char *name = getenv("KCONFIG_CONFIG");

	return name ? name : ".config";
}

const char *conf_get_autoconfig_name(void)
{
	char *name = getenv("KCONFIG_AUTOCONFIG");

	return name ? name : "include/config/auto.conf";
}

static char *conf_expand_value(const char *in)
{
	struct symbol *sym;
	const char *src;
	static char res_value[SYMBOL_MAXLENGTH];
	char *dst, name[SYMBOL_MAXLENGTH];

	res_value[0] = 0;
	dst = name;
	while ((src = strchr(in, '$'))) {
		strncat(res_value, in, src - in);
		src++;
		dst = name;
		while (isalnum(*src) || *src == '_')
			*dst++ = *src++;
		*dst = 0;
		sym = sym_lookup(name, 0);
		sym_calc_value(sym);
		strcat(res_value, sym_get_string_value(sym));
		in = src;
	}
	strcat(res_value, in);

	return res_value;
}

char *conf_get_default_confname(void)
{
	struct stat buf;
	static char fullname[PATH_MAX+1];
	char *env, *name;

	name = conf_expand_value(conf_defname);
	env = getenv(SRCTREE);
	if (env) {
		sprintf(fullname, "%s/%s", env, name);
		if (!stat(fullname, &buf))
			return fullname;
	}
	return name;
}

static int conf_set_sym_val(struct symbol *sym, int def, int def_flags, char *p)
{
	char *p2;

	switch (sym->type) {
	case S_TRISTATE:
		if (p[0] == 'm') {
			sym->def[def].tri = mod;
			sym->flags |= def_flags;
			break;
		}
	case S_BOOLEAN:
		if (p[0] == 'y') {
			sym->def[def].tri = yes;
			sym->flags |= def_flags;
			break;
		}
		if (p[0] == 'n') {
			sym->def[def].tri = no;
			sym->flags |= def_flags;
			break;
		}
		conf_warning("symbol value '%s' invalid for %s", p, sym->name);
		break;
	case S_OTHER:
		if (*p != '"') {
			for (p2 = p; *p2 && !isspace(*p2); p2++)
				;
			sym->type = S_STRING;
			goto done;
		}
	case S_STRING:
		if (*p++ != '"')
			break;
		for (p2 = p; (p2 = strpbrk(p2, "\"\\")); p2++) {
			if (*p2 == '"') {
				*p2 = 0;
				break;
			}
			memmove(p2, p2 + 1, strlen(p2));
		}
		if (!p2) {
			conf_warning("invalid string found");
			return 1;
		}
	case S_INT:
	case S_HEX:
	done:
		if (sym_string_valid(sym, p)) {
			sym->def[def].val = strdup(p);
			sym->flags |= def_flags;
		} else {
			conf_warning("symbol value '%s' invalid for %s", p, sym->name);
			return 1;
		}
		break;
	default:
		;
	}
	return 0;
}

int conf_read_simple(const char *name, int def)
{
	FILE *in = NULL;
	char line[1024];
	char *p, *p2;
	struct symbol *sym;
	int i, def_flags;

	if (name) {
		in = zconf_fopen(name);
	} else {
		struct property *prop;

		name = conf_get_configname();
		in = zconf_fopen(name);
		if (in)
			goto load;
		sym_add_change_count(1);
		if (!sym_defconfig_list)
			return 1;

		for_all_defaults(sym_defconfig_list, prop) {
			if (expr_calc_value(prop->visible.expr) == no ||
			    prop->expr->type != E_SYMBOL)
				continue;
			name = conf_expand_value(prop->expr->left.sym->name);
			in = zconf_fopen(name);
			if (in) {
				printf(_("#\n"
					 "# using defaults found in %s\n"
					 "#\n"), name);
				goto load;
			}
		}
	}
	if (!in)
		return 1;

load:
	conf_filename = name;
	conf_lineno = 0;
	conf_warnings = 0;
	conf_unsaved = 0;

	def_flags = SYMBOL_DEF << def;
	for_all_symbols(i, sym) {
		sym->flags |= SYMBOL_CHANGED;
		sym->flags &= ~(def_flags|SYMBOL_VALID);
		if (sym_is_choice(sym))
			sym->flags |= def_flags;
		switch (sym->type) {
		case S_INT:
		case S_HEX:
		case S_STRING:
			if (sym->def[def].val)
				free(sym->def[def].val);
		default:
			sym->def[def].val = NULL;
			sym->def[def].tri = no;
		}
	}

	while (fgets(line, sizeof(line), in)) {
		conf_lineno++;
		sym = NULL;
		switch (line[0]) {
		case '#':
			if (memcmp(line + 2, "CONFIG_", 7))
				continue;
			p = strchr(line + 9, ' ');
			if (!p)
				continue;
			*p++ = 0;
			if (strncmp(p, "is not set", 10))
				continue;
			if (def == S_DEF_USER) {
				sym = sym_find(line + 9);
				if (!sym) {
					sym_add_change_count(1);
					break;
				}
			} else {
				sym = sym_lookup(line + 9, 0);
				if (sym->type == S_UNKNOWN)
					sym->type = S_BOOLEAN;
			}
			if (sym->flags & def_flags) {
				conf_warning("override: reassigning to symbol %s", sym->name);
			}
			switch (sym->type) {
			case S_BOOLEAN:
			case S_TRISTATE:
				sym->def[def].tri = no;
				sym->flags |= def_flags;
				break;
			default:
				;
			}
			break;
		case 'C':
			if (memcmp(line, "CONFIG_", 7)) {
				conf_warning("unexpected data");
				continue;
			}
			p = strchr(line + 7, '=');
			if (!p)
				continue;
			*p++ = 0;
			p2 = strchr(p, '\n');
			if (p2) {
				*p2-- = 0;
				if (*p2 == '\r')
					*p2 = 0;
			}
			if (def == S_DEF_USER) {
				sym = sym_find(line + 7);
				if (!sym) {
					sym_add_change_count(1);
					break;
				}
			} else {
				sym = sym_lookup(line + 7, 0);
				if (sym->type == S_UNKNOWN)
					sym->type = S_OTHER;
			}
			if (sym->flags & def_flags) {
				conf_warning("override: reassigning to symbol %s", sym->name);
			}
			if (conf_set_sym_val(sym, def, def_flags, p))
				continue;
			break;
		case '\r':
		case '\n':
			break;
		default:
			conf_warning("unexpected data");
			continue;
		}
		if (sym && sym_is_choice_value(sym)) {
			struct symbol *cs = prop_get_symbol(sym_get_choice_prop(sym));
			switch (sym->def[def].tri) {
			case no:
				break;
			case mod:
				if (cs->def[def].tri == yes) {
					conf_warning("%s creates inconsistent choice state", sym->name);
					cs->flags &= ~def_flags;
				}
				break;
			case yes:
				if (cs->def[def].tri != no)
					conf_warning("override: %s changes choice state", sym->name);
				cs->def[def].val = sym;
				break;
			}
			cs->def[def].tri = EXPR_OR(cs->def[def].tri, sym->def[def].tri);
		}
	}
	fclose(in);

	if (modules_sym)
		sym_calc_value(modules_sym);
	return 0;
}

int conf_read(const char *name)
{
	struct symbol *sym, *choice_sym;
	struct property *prop;
	struct expr *e;
	int i, flags;

	sym_set_change_count(0);

	if (conf_read_simple(name, S_DEF_USER))
		return 1;

	for_all_symbols(i, sym) {
		sym_calc_value(sym);
		if (sym_is_choice(sym) || (sym->flags & SYMBOL_AUTO))
			goto sym_ok;
		if (sym_has_value(sym) && (sym->flags & SYMBOL_WRITE)) {
			 
			switch (sym->type) {
			case S_BOOLEAN:
			case S_TRISTATE:
				if (sym->def[S_DEF_USER].tri != sym_get_tristate_value(sym))
					break;
				if (!sym_is_choice(sym))
					goto sym_ok;
			default:
				if (!strcmp(sym->curr.val, sym->def[S_DEF_USER].val))
					goto sym_ok;
				break;
			}
		} else if (!sym_has_value(sym) && !(sym->flags & SYMBOL_WRITE))
			 
			goto sym_ok;
		conf_unsaved++;
		 
	sym_ok:
		if (!sym_is_choice(sym))
			continue;
		 
		prop = sym_get_choice_prop(sym);
		flags = sym->flags;
		expr_list_for_each_sym(prop->expr, e, choice_sym)
			if (choice_sym->visible != no)
				flags &= choice_sym->flags;
		sym->flags &= flags | ~SYMBOL_DEF_USER;
	}

	for_all_symbols(i, sym) {
		if (sym_has_value(sym) && !sym_is_choice_value(sym)) {
			 
			if (sym->visible == no && !conf_unsaved)
				sym->flags &= ~SYMBOL_DEF_USER;
			switch (sym->type) {
			case S_STRING:
			case S_INT:
			case S_HEX:
				 
				if (sym_string_within_range(sym, sym->def[S_DEF_USER].val))
					break;
				sym->flags &= ~(SYMBOL_VALID|SYMBOL_DEF_USER);
				conf_unsaved++;
				break;
			default:
				break;
			}
		}
	}

	sym_add_change_count(conf_warnings || conf_unsaved);

	return 0;
}

int conf_write(const char *name)
{
	FILE *out;
	struct symbol *sym;
	struct menu *menu;
	const char *basename;
	char dirname[128], tmpname[128], newname[128];
	int type, l;
	const char *str;
	time_t now;
	int use_timestamp = 1;
	char *env;

	dirname[0] = 0;
	if (name && name[0]) {
		struct stat st;
		char *slash;

		if (!stat(name, &st) && S_ISDIR(st.st_mode)) {
			strcpy(dirname, name);
			strcat(dirname, "/");
			basename = conf_get_configname();
		} else if ((slash = strrchr(name, '/'))) {
			int size = slash - name + 1;
			memcpy(dirname, name, size);
			dirname[size] = 0;
			if (slash[1])
				basename = slash + 1;
			else
				basename = conf_get_configname();
		} else
			basename = name;
	} else
		basename = conf_get_configname();

	sprintf(newname, "%s%s", dirname, basename);
	env = getenv("KCONFIG_OVERWRITECONFIG");
	if (!env || !*env) {
		sprintf(tmpname, "%s.tmpconfig.%d", dirname, (int)getpid());
		out = fopen(tmpname, "w");
	} else {
		*tmpname = 0;
		out = fopen(newname, "w");
	}
	if (!out)
		return 1;

	sym = sym_lookup("KERNELVERSION", 0);
	sym_calc_value(sym);
	time(&now);
	env = getenv("KCONFIG_NOTIMESTAMP");
	if (env && *env)
		use_timestamp = 0;

	fprintf(out, _("#\n"
		       "# Automatically generated make config: don't edit\n"
		       "# Linux kernel version: %s\n"
		       "%s%s"
		       "#\n"),
		     sym_get_string_value(sym),
		     use_timestamp ? "# " : "",
		     use_timestamp ? ctime(&now) : "");

	if (!conf_get_changed())
		sym_clear_all_valid();

	menu = rootmenu.list;
	while (menu) {
		sym = menu->sym;
		if (!sym) {
			if (!menu_is_visible(menu))
				goto next;
			str = menu_get_prompt(menu);
			fprintf(out, "\n"
				     "#\n"
				     "# %s\n"
				     "#\n", str);
		} else if (!(sym->flags & SYMBOL_CHOICE)) {
			sym_calc_value(sym);
			if (!(sym->flags & SYMBOL_WRITE))
				goto next;
			sym->flags &= ~SYMBOL_WRITE;
			type = sym->type;
			if (type == S_TRISTATE) {
				sym_calc_value(modules_sym);
				if (modules_sym->curr.tri == no)
					type = S_BOOLEAN;
			}
			switch (type) {
			case S_BOOLEAN:
			case S_TRISTATE:
				switch (sym_get_tristate_value(sym)) {
				case no:
					fprintf(out, "# CONFIG_%s is not set\n", sym->name);
					break;
				case mod:
					fprintf(out, "CONFIG_%s=m\n", sym->name);
					break;
				case yes:
					fprintf(out, "CONFIG_%s=y\n", sym->name);
					break;
				}
				break;
			case S_STRING:
				str = sym_get_string_value(sym);
				fprintf(out, "CONFIG_%s=\"", sym->name);
				while (1) {
					l = strcspn(str, "\"\\");
					if (l) {
						fwrite(str, l, 1, out);
						str += l;
					}
					if (!*str)
						break;
					fprintf(out, "\\%c", *str++);
				}
				fputs("\"\n", out);
				break;
			case S_HEX:
				str = sym_get_string_value(sym);
				if (str[0] != '0' || (str[1] != 'x' && str[1] != 'X')) {
					fprintf(out, "CONFIG_%s=%s\n", sym->name, str);
					break;
				}
			case S_INT:
				str = sym_get_string_value(sym);
				fprintf(out, "CONFIG_%s=%s\n", sym->name, str);
				break;
			}
		}

	next:
		if (menu->list) {
			menu = menu->list;
			continue;
		}
		if (menu->next)
			menu = menu->next;
		else while ((menu = menu->parent)) {
			if (menu->next) {
				menu = menu->next;
				break;
			}
		}
	}
	fclose(out);

	if (*tmpname) {
		strcat(dirname, basename);
		strcat(dirname, ".old");
		rename(newname, dirname);
		if (rename(tmpname, newname))
			return 1;
	}

	printf(_("#\n"
		 "# configuration written to %s\n"
		 "#\n"), newname);

	sym_set_change_count(0);

	return 0;
}

static int conf_split_config(void)
{
	const char *name;
	char path[128];
	char *s, *d, c;
	struct symbol *sym;
	struct stat sb;
	int res, i, fd;

	name = conf_get_autoconfig_name();
	conf_read_simple(name, S_DEF_AUTO);

	if (chdir("include/config"))
		return 1;

	res = 0;
	for_all_symbols(i, sym) {
		sym_calc_value(sym);
		if ((sym->flags & SYMBOL_AUTO) || !sym->name)
			continue;
		if (sym->flags & SYMBOL_WRITE) {
			if (sym->flags & SYMBOL_DEF_AUTO) {
				 
				switch (sym->type) {
				case S_BOOLEAN:
				case S_TRISTATE:
					if (sym_get_tristate_value(sym) ==
					    sym->def[S_DEF_AUTO].tri)
						continue;
					break;
				case S_STRING:
				case S_HEX:
				case S_INT:
					if (!strcmp(sym_get_string_value(sym),
						    sym->def[S_DEF_AUTO].val))
						continue;
					break;
				default:
					break;
				}
			} else {
				 
				switch (sym->type) {
				case S_BOOLEAN:
				case S_TRISTATE:
					if (sym_get_tristate_value(sym) == no)
						continue;
					break;
				default:
					break;
				}
			}
		} else if (!(sym->flags & SYMBOL_DEF_AUTO))
			 
			continue;
		 
		s = sym->name;
		d = path;
		while ((c = *s++)) {
			c = tolower(c);
			*d++ = (c == '_') ? '/' : c;
		}
		strcpy(d, ".h");

		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd == -1) {
			if (errno != ENOENT) {
				res = 1;
				break;
			}
			 
			d = path;
			while ((d = strchr(d, '/'))) {
				*d = 0;
				if (stat(path, &sb) && mkdir(path, 0755)) {
					res = 1;
					goto out;
				}
				*d++ = '/';
			}
			 
			fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (fd == -1) {
				res = 1;
				break;
			}
		}
		close(fd);
	}
out:
	if (chdir("../.."))
		return 1;

	return res;
}

#ifdef MY_ABC_HERE
static int syno_autoconf_check(const char *name) 
{
	int ret; 
	
	if (strncmp(name, "SYNO", 4) == 0)
		return 1;
	if (strcmp(name, "FS_SYNO_ACL") == 0)
		return 1;
	return 0;
}
#endif
int conf_write_autoconf(void)
{
	struct symbol *sym;
	const char *str;
	const char *name;
	FILE *out, *out_h;
	time_t now;
	int i, l;
#ifdef MY_ABC_HERE
	FILE *syno_h;
	int syno_write_string = 0;
#endif
	sym_clear_all_valid();

	file_write_dep("include/config/auto.conf.cmd");

	if (conf_split_config())
		return 1;

	out = fopen(".tmpconfig", "w");
	if (!out)
		return 1;

	out_h = fopen(".tmpconfig.h", "w");
	if (!out_h) {
		fclose(out);
		return 1;
	}

#ifdef MY_ABC_HERE
	syno_h = fopen(".tmpsynoconfig.h", "w");
	if (!syno_h) {
		fclose(out);
		fclose(out_h);
		return 1;
	}
#endif

	sym = sym_lookup("KERNELVERSION", 0);
	sym_calc_value(sym);
	time(&now);
	fprintf(out, "#\n"
		     "# Automatically generated make config: don't edit\n"
		     "# Linux kernel version: %s\n"
		     "# %s"
		     "#\n",
		     sym_get_string_value(sym), ctime(&now));
	fprintf(out_h, "/*\n"
		       " * Automatically generated C config: don't edit\n"
		       " * Linux kernel version: %s\n"
		       " * %s"
		       " */\n"
		       "#define AUTOCONF_INCLUDED\n",
		       sym_get_string_value(sym), ctime(&now));

#ifdef MY_ABC_HERE
	fprintf(syno_h, "/*\n"
		        " * Automatically generated C config: don't edit\n"
		        " * Linux kernel version: %s\n"
		        " * %s"
		        " */\n"
		        "#ifndef __SYNO_AUTOCONF_H__\n"
		        "#define __SYNO_AUTOCONF_H__\n",
		        sym_get_string_value(sym), ctime(&now));
#endif

	for_all_symbols(i, sym) {
		sym_calc_value(sym);
		if (!(sym->flags & SYMBOL_WRITE) || !sym->name)
			continue;
		switch (sym->type) {
		case S_BOOLEAN:
		case S_TRISTATE:
			switch (sym_get_tristate_value(sym)) {
			case no:
				break;
			case mod:
				fprintf(out, "CONFIG_%s=m\n", sym->name);
				fprintf(out_h, "#define CONFIG_%s_MODULE 1\n", sym->name);
#ifdef MY_ABC_HERE
				if (syno_autoconf_check(sym->name)) {
					fprintf(syno_h, "#define CONFIG_%s_MODULE 1\n", sym->name);
				}
#endif
				break;
			case yes:
				fprintf(out, "CONFIG_%s=y\n", sym->name);
				fprintf(out_h, "#define CONFIG_%s 1\n", sym->name);
#ifdef MY_ABC_HERE
				if (syno_autoconf_check(sym->name)) {
					fprintf(syno_h, "#define CONFIG_%s 1\n", sym->name);
				}
#endif
				break;
			}
			break;
		case S_STRING:
			str = sym_get_string_value(sym);
			fprintf(out, "CONFIG_%s=\"", sym->name);
			fprintf(out_h, "#define CONFIG_%s \"", sym->name);
#ifdef MY_ABC_HERE
			syno_write_string = 0;
			if (syno_autoconf_check(sym->name)) {
				syno_write_string = 1;
				fprintf(syno_h, "#define CONFIG_%s \"", sym->name);
			}
#endif

			while (1) {
				l = strcspn(str, "\"\\");
				if (l) {
					fwrite(str, l, 1, out);
					fwrite(str, l, 1, out_h);
#ifdef MY_ABC_HERE
					if (syno_write_string) {
						fwrite(str, l, 1, syno_h);
					}
#endif
					str += l;
				}
				if (!*str)
					break;
				fprintf(out, "\\%c", *str);
				fprintf(out_h, "\\%c", *str);
#ifdef MY_ABC_HERE
				if (syno_write_string) {
					fprintf(syno_h, "\\%c", *str);
				}
#endif
				str++;
			}
			fputs("\"\n", out);
			fputs("\"\n", out_h);
#ifdef MY_ABC_HERE
			if (syno_write_string) {
				fputs("\"\n", syno_h);
			}
#endif
			break;
		case S_HEX:
			str = sym_get_string_value(sym);
			if (str[0] != '0' || (str[1] != 'x' && str[1] != 'X')) {
				fprintf(out, "CONFIG_%s=%s\n", sym->name, str);
				fprintf(out_h, "#define CONFIG_%s 0x%s\n", sym->name, str);
#ifdef MY_ABC_HERE
				if (syno_autoconf_check(sym->name)) {
					fprintf(syno_h, "#define CONFIG_%s 0x%s\n", sym->name, str);
				}
#endif
				break;
			}
		case S_INT:
			str = sym_get_string_value(sym);
			fprintf(out, "CONFIG_%s=%s\n", sym->name, str);
			fprintf(out_h, "#define CONFIG_%s %s\n", sym->name, str);
#ifdef MY_ABC_HERE
			if (syno_autoconf_check(sym->name)) {
				fprintf(syno_h, "#define CONFIG_%s %s\n", sym->name, str);
			}
#endif
			break;
		default:
			break;
		}
	}
	fclose(out);
	fclose(out_h);
#ifdef MY_ABC_HERE
	fprintf(syno_h, "#endif /* __SYNO_AUTOCONF_H__ */\n");
	fclose(syno_h);
	if (rename(".tmpsynoconfig.h", "include/linux/syno_autoconf.h"))
		return 1;
#endif
	name = getenv("KCONFIG_AUTOHEADER");
	if (!name)
		name = "include/linux/autoconf.h";
	if (rename(".tmpconfig.h", name))
		return 1;
	name = conf_get_autoconfig_name();
	 
	if (rename(".tmpconfig", name))
		return 1;

	return 0;
}

static int sym_change_count;
static void (*conf_changed_callback)(void);

void sym_set_change_count(int count)
{
	int _sym_change_count = sym_change_count;
	sym_change_count = count;
	if (conf_changed_callback &&
	    (bool)_sym_change_count != (bool)count)
		conf_changed_callback();
}

void sym_add_change_count(int count)
{
	sym_set_change_count(count + sym_change_count);
}

bool conf_get_changed(void)
{
	return sym_change_count;
}

void conf_set_changed_callback(void (*fn)(void))
{
	conf_changed_callback = fn;
}

void conf_set_all_new_symbols(enum conf_def_mode mode)
{
	struct symbol *sym, *csym;
	struct property *prop;
	struct expr *e;
	int i, cnt, def;

	for_all_symbols(i, sym) {
		if (sym_has_value(sym))
			continue;
		switch (sym_get_type(sym)) {
		case S_BOOLEAN:
		case S_TRISTATE:
			switch (mode) {
			case def_yes:
				sym->def[S_DEF_USER].tri = yes;
				break;
			case def_mod:
				sym->def[S_DEF_USER].tri = mod;
				break;
			case def_no:
				sym->def[S_DEF_USER].tri = no;
				break;
			case def_random:
				sym->def[S_DEF_USER].tri = (tristate)(rand() % 3);
				break;
			default:
				continue;
			}
			if (!(sym_is_choice(sym) && mode == def_random))
				sym->flags |= SYMBOL_DEF_USER;
			break;
		default:
			break;
		}

	}

	sym_clear_all_valid();

	if (mode != def_random)
		return;
	 
	for_all_symbols(i, csym) {
		if (sym_has_value(csym) || !sym_is_choice(csym))
			continue;

		sym_calc_value(csym);

		if (csym->curr.tri != yes)
			continue;

		prop = sym_get_choice_prop(csym);

		cnt = 0;
		expr_list_for_each_sym(prop->expr, e, sym)
			cnt++;

		def = (rand() % cnt);

		cnt = 0;
		expr_list_for_each_sym(prop->expr, e, sym) {
			if (def == cnt++) {
				sym->def[S_DEF_USER].tri = yes;
				csym->def[S_DEF_USER].val = sym;
			}
			else {
				sym->def[S_DEF_USER].tri = no;
			}
		}
		csym->flags |= SYMBOL_DEF_USER;
		 
		csym->flags &= ~(SYMBOL_VALID);
	}
}
