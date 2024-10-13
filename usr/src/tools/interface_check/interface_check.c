/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Jason King
 */

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libcustr.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/stat.h>

#include "category.h"
#include "find_elf.h"
#include "header.h"
#include "exceptions.h"
#include "util.h"

typedef struct scn_info {
	Elf_Scn	*si_scn;
	size_t	si_nent;
	uint_t	si_stridx;
} scn_info_t;

typedef struct version {
	GElf_Verdef	*v_verdef;
	category_t	v_cat;
	uint_t		v_ancestors;
	uint_t		v_weak_ancestors;
	GElf_Sym	*v_syms;
	size_t		v_nsyms;
	size_t		v_syms_alloc;
} version_t;

typedef struct obj {
	const char	*o_prefix;
	int		o_dirfd;
	elf_obj_t	*o_elfobj;
	Elf		*o_elf;
	scn_info_t	o_verdef;
	scn_info_t	o_versym;
	scn_info_t	o_dynsym;
	scn_info_t	o_dyn;
	size_t		o_soname_idx;
	uint_t		o_errcnt;
	version_t	*o_versions;
	uint_t		o_npubvers;
} obj_t;

static void load_find_elf(const char *);
static void run_find_elf(int, char **);
static void process_object(int, const char *, elf_obj_t *);
static void errmsg(obj_t *, const char *, ...);
static FILE *fopenat(int, const char *, const char *);

static void check_path(obj_t *);
static bool has_versions(obj_t *, bool);
static bool open_obj(obj_t *);
static void obj_close(obj_t *);
static bool check_version_names(obj_t *);
static void print_symbols(obj_t *);

static void get_symbols(obj_t *);
static void add_sym(version_t *, GElf_Sym *);
static int cmp_sym(const void *, const void *, void *);

static void print_version(obj_t *, GElf_Verdef *, bool);

static exceptions_t *exceptions;
static elf_objs_t **elf_objs;
static uint_t n_objs;

static bool do_header = true;
static const char *errfname = "(stdout)";
static FILE *errf = stdout;
static FILE *intf;
static bool expand_inheritance;
static bool one_liner;
static int filedir = AT_FDCWD;

static inline const char *
obj_path(const obj_t *obj)
{
	return (obj->o_elfobj->eo_relpath);
}

static inline const char *
obj_soname(obj_t *obj)
{
	return (elf_strptr(obj->o_elf, obj->o_dyn.si_stridx,
	    obj->o_soname_idx));
}

static inline GElf_Verdef *
verdef_next(GElf_Verdef *v)
{
	uintptr_t next = (uintptr_t)v + v->vd_next;
	return ((GElf_Verdef *)next);
}

static inline GElf_Verdaux *
verdef_aux(GElf_Verdef *v)
{
	uintptr_t aux = (uintptr_t)v + v->vd_aux;
	return ((GElf_Verdaux *)aux);
}

static inline GElf_Verdaux *
vaux_next(GElf_Verdaux *aux)
{
	uintptr_t next = (uintptr_t)aux + aux->vda_next;
	return ((GElf_Verdaux *)next);
}

static inline const char *
vaux_name(obj_t *obj, GElf_Verdaux *vaux)
{
	return (elf_strptr(obj->o_elf, obj->o_verdef.si_stridx,
	    vaux->vda_name));
}

static inline const char *
verdef_name(obj_t *obj, GElf_Verdef *verdef)
{
	GElf_Verdaux *vaux = verdef_aux(verdef);
	return (vaux_name(obj, vaux));
}

static inline size_t
num_versions(obj_t *obj)
{
	return (obj->o_verdef.si_nent);
}

static inline const char *
dsym_name(obj_t *obj, const GElf_Sym *dsym)
{
	return (elf_strptr(obj->o_elf, obj->o_dynsym.si_stridx, dsym->st_name));
}

static void __NORETURN
usage(const char *name)
{
	(void) fprintf(stderr,
	    "Usage: %s [-hIo] [-c vtype_mod] [-E errfile] [-e exfile]\n",
	    "\t\t[-f listfile] [-i intffile] [-w outdir] file | dir, ...\n"
	    "\n"
	    "\t[-c vtype_mod]\tsupply alternative version category module\n"
	    "\t[-E errfile]\tdirect error output to file\n"
	    "\t[-e exfile]\texceptions file\n"
	    "\t[-f listfile]\tuse file list produced by find_elf -r\n"
	    "\t[-h]\t\tdo not produce a CDDL/Copyright header comment\n"
	    "\t[-I]\t\tExpand inheritance in -i output (debugging)\n"
	    "\t[-i intffile]\tcreate interface description output file\n"
	    "\t[-o]\t\tproduce one-liner output (prefixed with pathname)\n"
	    "\t[-w outdir]\tinterpret all files relative to given directory\n",
	    name);

	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	const char *intfile = NULL;
	const char *errfile = NULL;
	const char *elffile = NULL;
	const char *exfile = NULL;
	const char *wfile = NULL;
	int c;

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EXIT_FAILURE, "elf library is out of date");

	while ((c = getopt(argc, argv, "c:E:e:f:hIi:ow:")) != -1) {
		switch (c) {
		case 'c':
			// TODO
			break;
		case 'E':
			errfile = optarg;
			break;
		case 'e':
			exfile = optarg;
			break;
		case 'f':
			elffile = optarg;
			break;
		case 'h':
			do_header = false;
			break;
		case 'I':
			expand_inheritance = true;
			break;
		case 'i':
			intfile = optarg;
			break;
		case 'o':
			one_liner = true;
			break;
		case 'w':
			wfile = optarg;
			break;
		case '?':
			(void) fprintf(stderr, "Unknown option -%c\n", optopt);
			usage(argv[0]);
		}
	}

	if (argc <= optind && elffile == NULL)
		usage(argv[0]);

	category_init();

	if (wfile != NULL) {
		int fd;

		fd = open(wfile, O_RDONLY|O_DIRECTORY);
		if (fd == -1)
			err(EXIT_FAILURE, "failed to open %s", wfile);
		filedir = fd;
	}

	if (errfile != NULL) {
		errf = fopenat(filedir, errfile, "w");
		if (errf == NULL)
			err(EXIT_FAILURE, "Failed to open %s", errfile);

		errfname = errfile;
	}

	if (exfile != NULL) {
		FILE *f;

		f = fopenat(filedir, exfile, "r");
		if (f == NULL)
			err(EXIT_FAILURE, "Failed to open %s", exfile);

		exceptions = load_exceptions(f, exfile);
		VERIFY0(fclose(f));
	} else {
		char *fname;
		FILE *f;

		fname = find_exception_file(filedir, "interface_check");
		if (fname == NULL)
			errx(EXIT_FAILURE, "failed to find exception file");

		f = fopenat(filedir, fname, "r");
		exceptions = load_exceptions(f, fname);
		VERIFY0(fclose(f));
		free(fname);
	}

	if (intfile != NULL) {
		if (strcmp(intfile, "-") == 0) {
			intf = stdout;
		} else {
			intf = fopenat(filedir, intfile, "w");
			if (intf == NULL)
				err(EXIT_FAILURE, "Unable to open %s", intfile);
		}
	}

	if (do_header && intf != NULL)
		print_header(intf, argc, argv);

	if (elffile != NULL) {
		load_find_elf(elffile);
	} else {
		run_find_elf(argc - optind, argv + optind);
	}

	for (uint_t i = 0; i < n_objs; i++) {
		elf_objs_t *objs = elf_objs[i];
		elf_obj_t *obj;
		int prefixfd = -1;

		prefixfd = openat(filedir, objs->eos_prefix,
		    O_RDONLY|O_DIRECTORY);
		if (prefixfd == -1) {
			err(EXIT_FAILURE, "failed to open %s",
			    objs->eos_prefix);
		}

		for (obj = avl_first(&objs->eos_objs); obj != NULL;
		    obj = AVL_NEXT(&objs->eos_objs, obj)) {
			process_object(prefixfd, objs->eos_prefix, obj);
		}

		VERIFY0(close(prefixfd));

		elf_objs_free(objs);
		elf_objs[i] = NULL;
	}

	if (errf != stdout)
		VERIFY0(fclose(errf));
	if (intf != NULL && intf != stdout)
		VERIFY0(fclose(intf));
	if (filedir != AT_FDCWD)
		VERIFY0(close(filedir));

	exceptions_free(exceptions);
	return (EXIT_SUCCESS);
}

static void
load_find_elf(const char *filename)
{
	FILE *f;

	elf_objs = xcalloc(1, sizeof (elf_objs_t *));
	n_objs = 1;

	f = fopenat(filedir, filename, "r");
	if (f == NULL)
		err(EXIT_FAILURE, "Unable to open %s", filename);

	elf_objs[0] = read_find_elf(f, filename);
	VERIFY0(fclose(f));

	if (elf_objs[0] == NULL)
		errx(EXIT_FAILURE, "error reading %s", filename);
}

static void
run_find_elf(int argc, char **argv)
{
	elf_objs = xcalloc(argc, sizeof (elf_objs_t *));
	n_objs = argc;

	for (uint_t i = 0; i < argc; i++) {
		FILE		*pipe;
		char		*cmd;
		struct stat	sb = { 0 };
		bool		is_dir = false;

		if (stat(argv[i], &sb) < 0)
			err(EXIT_FAILURE, "Failed to stat %s", argv[i]);

		if (S_ISDIR(sb.st_mode))
			is_dir = true;

		if (asprintf(&cmd, "find_elf -frs%s %s", is_dir ? " -a" : "",
		    argv[i]) < 0) {
			err(EXIT_FAILURE, "asprintf failed");
		}

		pipe = popen(cmd, "r");
		if (pipe == NULL)
			err(EXIT_FAILURE, "Failed to run '%s'", cmd);

		elf_objs[i] = read_find_elf(pipe, argv[i]);
		if (elf_objs[i] == NULL)
			errx(EXIT_FAILURE, "error reading output of '%s'", cmd);

		free(cmd);
	}
}

static void
process_object(int dirfd, const char *prefix, elf_obj_t *eobj)
{
	obj_t obj = {
		.o_prefix = prefix,
		.o_dirfd = dirfd,
		.o_elfobj = eobj,
	};
	bool is_plugin;

	if (eobj->eo_type != ET_DYN)
		return;

	is_plugin = is_exception(eobj->eo_relpath, "PLUGIN", exceptions);
	if (!is_plugin)
		check_path(&obj);

	/* If there's no versions in the file, then we're done */
	if (!has_versions(&obj, is_plugin))
		return;

	if (!open_obj(&obj))
		return;

	if (!check_version_names(&obj))
		goto done;

	// TODO more of the tests

	print_symbols(&obj);

done:
	obj_close(&obj);
}

/* Check if pathname does not follow the runtime versioned name convention */
static void
check_path(obj_t *obj)
{
	const char *path = obj_path(obj);
	struct stat sb;

	/*
	 * The check here is pretty simple -- it must contain '.so.' if
	 * the path is not a symlink.
	 */
	if (strstr(path, ".so.") != NULL)
		return;

	if (fstatat(obj->o_dirfd, path, &sb, AT_SYMLINK_NOFOLLOW) < 0) {
		warn("failed to stat %s/%s", obj->o_prefix, path);
		return;
	}

	if (S_ISLNK(sb.st_mode))
		return;

	errmsg(obj, "does not have a versioned name");
}

static bool
has_versions(obj_t *obj, bool is_plugin)
{
	if (obj->o_elfobj->eo_has_verdef)
		return (true);

	if (!is_plugin && !is_exception(obj_path(obj), "NOVERDEF", exceptions))
		errmsg(obj, "no versions found");

	return (false);
}

/* Wrapper around elf_begin(3ELF) */
static bool
open_obj(obj_t *obj)
{
	const char	*path = obj_path(obj);
	Elf_Scn		*scn;
	Elf_Data	*data;
	GElf_Verdef	*verdef;
	GElf_Ehdr	ehdr;
	GElf_Dyn	dyn;
	int		fd;
	bool		has_soname;

	fd = openat(obj->o_dirfd, obj_path(obj), O_RDONLY);
	if (fd < 0) {
		warn("failed to open %s/%s", obj->o_prefix, path);
		return (false);
	}

	obj->o_elf = elf_begin(fd, ELF_C_READ, NULL);
	if (obj->o_elf == NULL) {
		int e = elf_errno();

		warnx("elf_begin on %s/%s failed: %s", obj->o_prefix, path,
		    elf_errmsg(e));
		return (false);
	}

	/* Cache sections we're interested in */
	if (gelf_getehdr(obj->o_elf, &ehdr) == NULL)
		goto fail;

	scn = NULL;
	while ((scn = elf_nextscn(obj->o_elf, scn)) != NULL) {
		GElf_Shdr shdr = { 0 };

		if (gelf_getshdr(scn, &shdr) == NULL)
			goto fail;

		switch (shdr.sh_type) {
		case SHT_SUNW_verdef:
			obj->o_verdef.si_scn = scn;
			obj->o_verdef.si_nent = shdr.sh_info;
			obj->o_verdef.si_stridx = shdr.sh_link;
			break;
		case SHT_SUNW_versym:
			obj->o_versym.si_scn = scn;
			obj->o_versym.si_nent = shdr.sh_size / shdr.sh_entsize;
			obj->o_versym.si_stridx = shdr.sh_link;
			break;
		case SHT_DYNAMIC:
			obj->o_dyn.si_scn = scn;
			obj->o_dyn.si_nent = shdr.sh_size / shdr.sh_entsize;
			obj->o_dyn.si_stridx = shdr.sh_link;
			break;
		case SHT_DYNSYM:
			obj->o_dynsym.si_scn = scn;
			obj->o_dynsym.si_nent = shdr.sh_size / shdr.sh_entsize;
			obj->o_dynsym.si_stridx = shdr.sh_link;
			break;
		}
	}

	/* Cache all of the GElf_Verdef (ELF version) objects */
	obj->o_versions = xcalloc(num_versions(obj), sizeof (version_t));
	data = elf_getdata(obj->o_verdef.si_scn, NULL);
	if (data == NULL)
		goto fail;

	verdef = (GElf_Verdef *)data->d_buf;
	for (uint_t i = 0; i < num_versions(obj); i++) {
		version_t	*v = &obj->o_versions[i];

		v->v_verdef = verdef;
		verdef = verdef_next(verdef);
	}

	/*
	 * The way versions are linked/inherited is the additional
	 * verdaux entries (the first verdaux is for the current entry)
	 * list the version names this verdef inherits. However, to determine
	 * which versions are 'top' versions (i.e. they are not inherited by
	 * any other version), we have to walk all of the inheritance chains
	 * and mark all of the entries that are inherited.
	 *
	 */
	for (uint_t i = 0; i < num_versions(obj); i++) {
		GElf_Verdaux	*vaux, *vancestor;
		bool		is_weak = false;

		verdef = obj->o_versions[i].v_verdef;

		if ((verdef->vd_flags & VER_FLG_WEAK) != 0)
			is_weak = true;

		/*
		 * Iterate through all of the ancestors. The first entry
		 * is 'this' version, so we ignore it.
		 */
		vancestor = verdef_aux(verdef);

		for (uint_t j = 1; j < verdef->vd_cnt; j++) {
			vancestor = vaux_next(vancestor);

			/* Find the verdef of this ancestor */
			for (uint_t k = 0; k < num_versions(obj); k++) {
				if (k == i)
					continue;

				vaux = verdef_aux(obj->o_versions[k].v_verdef);

				if (vancestor->vda_name == vaux->vda_name) {
					version_t *v = &obj->o_versions[k];

					if (is_weak)
						v->v_weak_ancestors++;
					v->v_ancestors++;
				}
			}
		}
	}

	/* Get the string index of the soname (if it exists) */
	data = elf_getdata(obj->o_dyn.si_scn, NULL);
	if (data == NULL)
		goto fail;

	has_soname = false;
	for (uint_t i = 0; i < obj->o_dyn.si_nent; i++) {
		if (gelf_getdyn(data, i, &dyn) == NULL)
			goto fail;

		if (dyn.d_tag == DT_SONAME) {
			obj->o_soname_idx = dyn.d_un.d_ptr;
			has_soname = true;
			break;
		}
	}

	/*
	 * If there isn't a soname, we use the base version (which should
	 * be the name of the library) instead.
	 */
	if (!has_soname) {
		for (uint_t i = 0; i < num_versions(obj); i++) {
			verdef = obj->o_versions[i].v_verdef;
			if ((verdef->vd_flags & VER_FLG_BASE) != 0) {
				GElf_Verdaux *vaux;

				vaux = verdef_aux(verdef);
				obj->o_soname_idx = vaux->vda_name;
			}
		}
	}

	/* We can't categorize the version until we have the soname */
	for (uint_t i = 0; i < num_versions(obj); i++) {
		version_t	*v = &obj->o_versions[i];
		const char	*vname, *soname;

		vname = verdef_name(obj, v->v_verdef);
		soname = obj_soname(obj);
		parse_category(vname, soname, &v->v_cat);

		/* Count the number of non-private versions */
		if (v->v_cat.c_type != CT_SONAME &&
		    v->v_cat.c_type != CT_PRIVATE) {
			obj->o_npubvers++;
		}
	}

	get_symbols(obj);

	return (true);

fail:
	obj_close(obj);
	return (false);
}

static void
obj_close(obj_t *obj)
{
	for (uint_t i = 0; i < num_versions(obj); i++) {
		version_t *v = &obj->o_versions[i];

		arrayfree(v->v_syms, v->v_syms_alloc, sizeof (GElf_Sym));
	}

	arrayfree(obj->o_versions, num_versions(obj), sizeof (version_t));
	obj->o_versions = NULL;

	if (obj->o_elf != NULL)
		VERIFY0(elf_end(obj->o_elf));
	obj->o_elf = NULL;
}

/*
 * Verify all of the version names in this object follow our standard
 * (or is an exception).
 *
 * Currently, allowed version names are:
 *	ILLUMOS_x.y.[.z]
 *	SUNW_x.y.[z]
 *	ILLUMOS_private(_nnn)
 *	SUNW_private(_nnn)
 *	SYSVABI_1.2
 *	SYSVAVI_1.3
 *	SISCD_2.3[ab*]
 *
 * See category.c for the explicit regexes used to test the version names.
 */
static bool
check_version_names(obj_t *obj)
{
	size_t		vercnt;

	vercnt = 0;
	for (uint_t i = 0; i < num_versions(obj); i++) {
		version_t *v = &obj->o_versions[i];

		/*
		 * Ignore weak versions. This should match the behavior
		 * of pvs without the -v option (e.g. pvs -v shows weak
		 * versions, omits them without it). The original script
		 * did not check version names of weak versions, so we don't
		 * as well.
		 */
		if ((v->v_verdef->vd_flags & VER_FLG_WEAK) != 0)
			continue;

		/* Count non-weak versions */
		vercnt++;

		if (v->v_cat.c_type == CT_UNKNOWN &&
		    !is_exception(obj_path(obj), "NONSTD_VERNAME",
		    exceptions)) {
			const char *vname = verdef_name(obj, v->v_verdef);
			errmsg(obj, "non-standard version name: %s", vname);
		}
	}

	if (vercnt == 0) {
		errmsg(obj, "scoped object contains no versions");
		return (false);
	}

	return (true);
}

static void
get_symbols(obj_t *obj)
{
	Elf_Data *data;
	Elf_Data *vdata;
	GElf_Versym *vsym;

	data = elf_getdata(obj->o_dynsym.si_scn, NULL);
	VERIFY3P(data, !=, NULL);

	vdata = elf_getdata(obj->o_versym.si_scn, NULL);
	VERIFY3P(data, !=, NULL);

	vsym = (GElf_Versym *)vdata->d_buf;
	for (uint_t i = 0; i < obj->o_dynsym.si_nent; i++, vsym++) {
		GElf_Sym sym;

		(void) gelf_getsym(data, i, &sym);

		if (sym.st_shndx == 0 || *vsym == 0)
			continue;

		version_t *v;
		const char *vername;
		const char *symname;

		v = &obj->o_versions[(*vsym) - 1];
		vername = verdef_name(obj, v->v_verdef);
		symname = dsym_name(obj, &sym);

		/*
		 * The version name appears in the dynamic symbol table as
		 * symbol. We don't want to include it.
		 */
		if (strcmp(vername, symname) == 0)
			continue;

		add_sym(v, &sym);
	}

	for (uint_t i = 0; i < num_versions(obj); i++) {
		version_t *v = &obj->o_versions[i];

		qsort_r(v->v_syms, v->v_nsyms, sizeof (GElf_Sym), cmp_sym, obj);
	}
}

static void
print_symbols(obj_t *obj)
{
	elf_obj_t	*eo = obj->o_elfobj;

	if (intf == NULL)
		return;

	/* Only output objects that include public versions */
	if (obj->o_npubvers == 0)
		return;

	/* Start with the header */

	(void) fprintf(intf,
	    "OBJECT\t%s\n"
	    "CLASS\t%s\n"
	    "TYPE\t%s\n", obj_path(obj), elf_class_str(eo->eo_class),
	    elf_type_str(eo->eo_type));
	for (size_t i = 0; i < eo->eo_nalias; i++)
		(void) fprintf(intf, "ALIAS\t%s\n", eo->eo_aliases[i]);

	for (uint_t i = 0; i < num_versions(obj); i++) {
		version_t *v = &obj->o_versions[i];
		bool is_top;

		if (v->v_cat.c_type == CT_SONAME ||
		    v->v_cat.c_type == CT_PRIVATE)
			continue;

		if (v->v_ancestors == 0) {
			is_top = true;
		} else {
			is_top = false;
		}

#if 0
		if (v->v_ancestors > 0 && v->v_ancestors != v->v_weak_ancestors)
			is_top = false;
		else
			is_top = true;

		if (is_top && (v->v_verdef->vd_flags & VER_FLG_WEAK) != 0) {
		}
#endif

		print_version(obj, v->v_verdef, is_top);

		for (size_t j = 0; j < v->v_nsyms; j++) {
			(void) fprintf(intf, "\tSYMBOL\t%s\n",
			    dsym_name(obj, &v->v_syms[j]));
		}
	}

	(void) fputc('\n', intf);
}

static void
print_version(obj_t *obj, GElf_Verdef *verdef, bool top)
{
	GElf_Verdaux *vaux;

	if (intf == NULL)
		return;

	if (top)
		(void) fprintf(intf, "TOP_");

	vaux = verdef_aux(verdef);
	(void) fprintf(intf, "VERSION\t%s", vaux_name(obj, vaux));

	if (verdef->vd_cnt > 1) {
		vaux = vaux_next(vaux);

		(void) fprintf(intf, "\t{");
		for (uint_t i = 1; i < verdef->vd_cnt; i++) {
			if (i > 1)
				(void) fputc(',', intf);
			(void) fprintf(intf, "%s", vaux_name(obj, vaux));
			vaux = vaux_next(vaux);
		}
		(void) fputc('}', intf);
	}
	(void) fputc('\n', intf);
}

static void
errmsg(obj_t *obj, const char *fmt, ...)
{
	const char *path = obj_path(obj);
	va_list ap;

	va_start(ap, fmt);
	if (one_liner) {
		(void) fprintf(errf, "%s: ", path);
		(void) vfprintf(errf, fmt, ap);
	} else {
		if (obj->o_errcnt == 0)
			(void) fprintf(errf, "==== %s ====\n", path);

		(void) fputc('\t', errf);
		(void) vfprintf(errf, fmt, ap);
	}
	va_end(ap);

	(void) fputc('\n', errf);
	obj->o_errcnt++;
}

static FILE *
fopenat(int dirfd, const char *path, const char *mode)
{
	int fd;
	int flag = 0;

	VERIFY3P(mode, !=, NULL);

	switch (mode[0]) {
	case 'r':
		flag = O_RDONLY;
		break;
	case 'w':
		flag = O_WRONLY | O_TRUNC | O_CREAT;
		break;
	case 'a':
		flag = O_WRONLY | O_APPEND | O_CREAT;
		break;
	}

	fd = openat(dirfd, path, flag);
	if (fd == -1)
		return (NULL);

	return (fdopen(fd, mode));
}

#define	SYM_CHUNK 8
static void
add_sym(version_t *v, GElf_Sym *sym)
{
	if (v->v_nsyms == v->v_syms_alloc) {
		size_t newsz = v->v_syms_alloc + SYM_CHUNK;

		v->v_syms = xcreallocarray(v->v_syms, v->v_syms_alloc, newsz,
		    sizeof (GElf_Sym));
		v->v_syms_alloc = newsz;
	}
	v->v_syms[v->v_nsyms++] = *sym;
}

static int
cmp_sym(const void *a, const void *b, void *arg)
{
	obj_t *obj = arg;

	const GElf_Sym *l = a;
	const GElf_Sym *r = b;

	return (strcmp(dsym_name(obj, l), dsym_name(obj, r)));
}
