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

/*
 * Check versioning information.
 *
 * This is a replacement for the original perl interface_check script. It
 * inspects ELF shared objects (as listed by find_elf) for version
 * definitions, verifies that the common versioning rules have been
 * followed, and optionally writes an interface description of each object
 * (see interface_check(1ONBLD)).
 *
 * Where the perl script ran pvs(1), we read the ELF data directly, but
 * apply the same rules pvs does so that the results match:
 *
 *  - A symbol belongs to the version definition whose vd_ndx matches the
 *    symbol's versym entry, using the symbol table the versym section is
 *    linked to. The absolute symbol each version defines for its own name
 *    is not counted (pvs only shows it with -v).
 *
 *  - Weak versions are treated like any other version (pvs only shows the
 *    WEAK attribute with -v; it does not hide weak versions).
 *
 *  - The 'top' versions are those left after pvs -n normalization: every
 *    version inherited by a non-weak version (directly or indirectly) is
 *    removed, a version inherited by a weak version is removed only if it
 *    is itself weak, and the base version is always removed.
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libcustr.h>
#include <limits.h>
#include <regex.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <umem.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "category.h"
#include "find_elf.h"
#include "header.h"
#include "exceptions.h"
#include "util.h"

extern char **environ;

typedef struct scn_info {
	Elf_Scn	*si_scn;
	size_t	si_nent;
	uint_t	si_link;	/* sh_link of the section */
} scn_info_t;

typedef struct version {
	GElf_Verdef	*v_verdef;
	const char	*v_name;
	category_t	v_cat;
	uint_t		v_nsyms;	/* Symbols assigned to this version */
	bool		v_top;		/* Survives pvs -n normalization */
} version_t;

typedef struct dsym {
	const char	*ds_name;
	uint_t		ds_version;	/* Index of obj->o_versions */
} dsym_t;

typedef struct obj {
	const char	*o_prefix;
	int		o_dirfd;
	int		o_fd;
	elf_obj_t	*o_elfobj;
	Elf		*o_elf;
	scn_info_t	o_verdef;
	scn_info_t	o_versym;
	scn_info_t	o_dyn;
	const char	*o_soname;
	uint_t		o_errcnt;
	version_t	*o_versions;
	uint_t		o_nversions;
	dsym_t		*o_dsyms;
	uint_t		o_ndsyms;
	uint_t		o_dsyms_alloc;
} obj_t;

static void load_find_elf(const char *);
static void run_find_elf(int, char **);
static void process_object(int, const char *, elf_obj_t *);
static void errmsg(obj_t *, const char *, ...);
static FILE *fopen_mode(const char *, const char *);

static void check_path(obj_t *);
static bool has_versions(obj_t *, bool);
static bool open_obj(obj_t *);
static void obj_close(obj_t *);
static bool check_version_names(obj_t *);
static void print_symbols(obj_t *);

static void get_symbols(obj_t *);
static void add_sym(obj_t *, uint_t, const char *);
static int cmp_dsym(const void *, const void *);

static exceptions_t *exceptions;
static elf_objs_t **elf_objs;
static uint_t n_objs;

static bool do_header = true;
static FILE *errf;
static FILE *intf;
static uint_t intf_objcnt;	/* Number of OBJECTs written to intf */
static bool expand_inheritance;
static bool one_liner;

static inline const char *
obj_path(const obj_t *obj)
{
	return (obj->o_elfobj->eo_relpath);
}

static inline const char *
path_basename(const char *path)
{
	const char *p = strrchr(path, '/');

	return ((p == NULL) ? path : p + 1);
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
	return (elf_strptr(obj->o_elf, obj->o_verdef.si_link,
	    vaux->vda_name));
}

static inline bool
version_is_weak(const version_t *v)
{
	return ((v->v_verdef->vd_flags & VER_FLG_WEAK) != 0);
}

static void __NORETURN
usage(const char *name)
{
	(void) fprintf(stderr,
	    "Usage: %s [-hIo] [-E errfile] [-e exfile] [-f listfile]\n"
	    "\t\t[-i intffile] [-w outdir] file | dir, ...\n"
	    "\n"
	    "\t[-E errfile]\tdirect error output to file\n"
	    "\t[-e exfile]\texceptions file\n"
	    "\t[-f listfile]\tuse file list produced by find_elf -r\n"
	    "\t[-h]\t\tdo not produce a CDDL/Copyright header comment\n"
	    "\t[-I]\t\tExpand inheritance in -i output (debugging)\n"
	    "\t[-i intffile]\tcreate interface description output file\n"
	    "\t\t\t('-' writes it to stdout)\n"
	    "\t[-o]\t\tproduce one-liner output (prefixed with pathname)\n"
	    "\t[-w outdir]\tinterpret all files relative to given directory\n",
	    name);

	exit(EXIT_FAILURE);
}

/*
 * The absolute path of the directory containing this binary, used to
 * locate the exception file installed alongside it. This has to be
 * determined before any -w chdir, as getexecname() may be relative.
 */
static char *
get_execdir(void)
{
	const char	*exe = getexecname();
	char		*path, *slash;

	if (exe == NULL || (path = realpath(exe, NULL)) == NULL)
		return (NULL);

	slash = strrchr(path, '/');
	if (slash == NULL) {
		free(path);
		return (NULL);
	}
	*slash = '\0';
	return (path);
}

static void
close_output(FILE *f, const char *name)
{
	if (f == NULL)
		return;

	if (f == stdout) {
		if (fflush(f) != 0 || ferror(f))
			err(EXIT_FAILURE, "error writing %s", name);
		return;
	}

	if (ferror(f) || fclose(f) != 0)
		err(EXIT_FAILURE, "error writing %s", name);
}

int
main(int argc, char **argv)
{
	const char *intfile = NULL;
	const char *errfile = NULL;
	const char *elffile = NULL;
	const char *exfile = NULL;
	const char *wdir = NULL;
	char *execdir;
	int c;

	umem_nofail_callback(nomem_callback);

	errf = stdout;

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EXIT_FAILURE, "elf library is out of date");

	while ((c = getopt(argc, argv, ":E:e:f:hIi:ow:")) != -1) {
		switch (c) {
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
			wdir = optarg;
			break;
		case ':':
			(void) fprintf(stderr, "%s: option -%c requires an "
			    "argument\n", getprogname(), optopt);
			usage(argv[0]);
		case '?':
			(void) fprintf(stderr, "%s: unknown option -%c\n",
			    getprogname(), optopt);
			usage(argv[0]);
		}
	}

	if (argc <= optind && elffile == NULL)
		usage(argv[0]);

	category_init();

	execdir = get_execdir();

	/*
	 * As with the perl version, -w changes the working directory, and
	 * every other path (including the arguments) is relative to it.
	 */
	if (wdir != NULL && chdir(wdir) != 0)
		err(EXIT_FAILURE, "can't cd to %s", wdir);

	if (errfile != NULL) {
		errf = fopen_mode(errfile, "w");
		if (errf == NULL)
			err(EXIT_FAILURE, "failed to open %s", errfile);
	}

	if (exfile == NULL) {
		char *fname = find_exception_file(execdir, "interface_check");

		/* As with the perl version, no exception file is fine */
		if (fname == NULL) {
			exceptions = zalloc(sizeof (*exceptions));
		} else {
			FILE *f = fopen_mode(fname, "r");

			if (f == NULL)
				err(EXIT_FAILURE, "failed to open %s", fname);

			exceptions = load_exceptions(f, fname);
			(void) fclose(f);
			if (exceptions == NULL)
				errx(EXIT_FAILURE, "failed to load %s", fname);
			free(fname);
		}
	} else {
		FILE *f = fopen_mode(exfile, "r");

		if (f == NULL)
			err(EXIT_FAILURE, "failed to open %s", exfile);

		exceptions = load_exceptions(f, exfile);
		(void) fclose(f);
		if (exceptions == NULL)
			errx(EXIT_FAILURE, "failed to load %s", exfile);
	}

	free(execdir);

	if (intfile != NULL) {
		if (strcmp(intfile, "-") == 0) {
			intf = stdout;
		} else {
			intf = fopen_mode(intfile, "w");
			if (intf == NULL)
				err(EXIT_FAILURE, "unable to open %s", intfile);
		}

		if (do_header)
			print_header(intf, argc, argv);
	}

	if (elffile != NULL)
		load_find_elf(elffile);

	/*
	 * Process each argument. The perl version processed both -f and
	 * any arguments, so we do as well.
	 */
	if (argc > optind)
		run_find_elf(argc - optind, argv + optind);

	for (uint_t i = 0; i < n_objs; i++) {
		elf_objs_t *objs = elf_objs[i];
		int prefixfd;

		if (objs == NULL)
			continue;

		prefixfd = open(objs->eos_prefix, O_RDONLY|O_DIRECTORY);
		if (prefixfd == -1) {
			err(EXIT_FAILURE, "failed to open %s",
			    objs->eos_prefix);
		}

		/* Process objects in the order find_elf listed them */
		for (size_t j = 0; j < objs->eos_n; j++)
			process_object(prefixfd, objs->eos_prefix,
			    objs->eos_order[j]);

		VERIFY0(close(prefixfd));

		elf_objs_free(objs);
		elf_objs[i] = NULL;
	}
	arrayfree(elf_objs, n_objs, sizeof (elf_objs_t *));

	close_output(intf, intfile);
	close_output(errf, (errfile != NULL) ? errfile : "(stdout)");

	exceptions_free(exceptions);
	return (EXIT_SUCCESS);
}

static void
add_elf_objs(elf_objs_t *objs)
{
	elf_objs = xcreallocarray(elf_objs, n_objs, n_objs + 1,
	    sizeof (elf_objs_t *));
	elf_objs[n_objs++] = objs;
}

static void
load_find_elf(const char *filename)
{
	elf_objs_t *objs;
	FILE *f;

	f = fopen_mode(filename, "r");
	if (f == NULL)
		err(EXIT_FAILURE, "unable to open %s", filename);

	objs = read_find_elf(f, filename);
	(void) fclose(f);

	if (objs == NULL)
		errx(EXIT_FAILURE, "error reading %s", filename);

	add_elf_objs(objs);
}

/*
 * Run 'find_elf -frs [-a] path' for each argument. If the argument is not
 * a directory, alias processing is disabled (-a) so that the file is
 * processed whether or not it is a symlink. find_elf is run directly
 * (not via a shell) so that paths need no quoting.
 */
static void
run_find_elf(int argc, char **argv)
{
	for (int i = 0; i < argc; i++) {
		posix_spawn_file_actions_t	fa;
		struct stat	sb;
		char		*fargv[5];
		int		fargc = 0;
		int		pfd[2];
		int		ret, status;
		pid_t		pid;
		FILE		*pipe_f;
		elf_objs_t	*objs;
		bool		is_dir;

		is_dir = (stat(argv[i], &sb) == 0 && S_ISDIR(sb.st_mode));

		fargv[fargc++] = "find_elf";
		fargv[fargc++] = "-frs";
		if (!is_dir)
			fargv[fargc++] = "-a";
		fargv[fargc++] = argv[i];
		fargv[fargc] = NULL;

		if (pipe(pfd) != 0)
			err(EXIT_FAILURE, "pipe failed");

		if ((ret = posix_spawn_file_actions_init(&fa)) != 0 ||
		    (ret = posix_spawn_file_actions_addclose(&fa,
		    pfd[0])) != 0 ||
		    (ret = posix_spawn_file_actions_adddup2(&fa, pfd[1],
		    STDOUT_FILENO)) != 0 ||
		    (ret = posix_spawn_file_actions_addclose(&fa,
		    pfd[1])) != 0) {
			errno = ret;
			err(EXIT_FAILURE, "failed to set up find_elf");
		}

		ret = posix_spawnp(&pid, fargv[0], &fa, NULL, fargv, environ);
		if (ret != 0) {
			errno = ret;
			err(EXIT_FAILURE, "failed to run find_elf");
		}

		VERIFY0(posix_spawn_file_actions_destroy(&fa));
		VERIFY0(close(pfd[1]));

		pipe_f = fdopen(pfd[0], "r");
		if (pipe_f == NULL)
			err(EXIT_FAILURE, "fdopen failed");

		objs = read_find_elf(pipe_f, argv[i]);
		(void) fclose(pipe_f);

		while (waitpid(pid, &status, 0) == -1) {
			if (errno != EINTR)
				err(EXIT_FAILURE, "waitpid failed");
		}

		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			errx(EXIT_FAILURE, "find_elf failed for %s "
			    "(status 0x%x)", argv[i], status);
		}

		if (objs == NULL)
			errx(EXIT_FAILURE, "error reading find_elf output "
			    "for %s", argv[i]);

		add_elf_objs(objs);
	}
}

static void
process_object(int dirfd, const char *prefix, elf_obj_t *eobj)
{
	obj_t obj = {
		.o_prefix = prefix,
		.o_dirfd = dirfd,
		.o_fd = -1,
		.o_elfobj = eobj,
	};
	bool is_plugin;

	/* We are only interested in sharable objects */
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

	if (check_version_names(&obj))
		print_symbols(&obj);

	obj_close(&obj);
}

/* Check if pathname does not follow the runtime versioned name convention */
static void
check_path(obj_t *obj)
{
	const char *path = obj_path(obj);
	struct stat sb;

	/*
	 * The check here is pretty simple -- the file name must contain
	 * '.so.' if the path is not a symlink. Note that it can only be a
	 * symlink if a single file was given on the command line, as find_elf
	 * otherwise reports symlinks as aliases.
	 */
	if (strstr(path_basename(path), ".so.") != NULL)
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

	/*
	 * Report the lack of versioning, unless the object is a known
	 * plugin, or is explicitly exempt.
	 */
	if (!is_plugin && !is_exception(obj_path(obj), "NOVERDEF", exceptions))
		errmsg(obj, "no versions found");

	return (false);
}

/* Find the index into o_versions of the version with the given name. */
static bool
vername_to_idx(obj_t *obj, const char *name, uint_t *idxp)
{
	if (name == NULL)
		return (false);

	for (uint_t i = 0; i < obj->o_nversions; i++) {
		if (strcmp(obj->o_versions[i].v_name, name) == 0) {
			*idxp = i;
			return (true);
		}
	}
	return (false);
}

/*
 * Mirror pvs's gvers_derefer(): if the head of the inheritance list is
 * weak, only weak versions are removed, otherwise every inherited version
 * is removed. 'seen' guards against revisiting a version (and against
 * cycles in a malformed object).
 */
static void
derefer(obj_t *obj, uint_t idx, bool weak, bool *seen)
{
	version_t	*v = &obj->o_versions[idx];
	GElf_Verdaux	*vaux;
	uint_t		dep;

	if (seen[idx])
		return;
	seen[idx] = true;

	if (!weak || version_is_weak(v))
		v->v_top = false;

	vaux = verdef_aux(v->v_verdef);
	for (uint_t i = 1; i < v->v_verdef->vd_cnt; i++) {
		vaux = vaux_next(vaux);
		if (vername_to_idx(obj, vaux_name(obj, vaux), &dep))
			derefer(obj, dep, weak, seen);
	}
}

static void
find_top_versions(obj_t *obj)
{
	uint_t	n = obj->o_nversions;
	bool	*seen = xcalloc(n, sizeof (bool));

	for (uint_t i = 0; i < n; i++)
		obj->o_versions[i].v_top = true;

	for (uint_t i = 0; i < n; i++) {
		version_t	*v = &obj->o_versions[i];
		bool		weak = version_is_weak(v);
		GElf_Verdaux	*vaux = verdef_aux(v->v_verdef);
		uint_t		dep;

		for (uint_t j = 1; j < v->v_verdef->vd_cnt; j++) {
			vaux = vaux_next(vaux);
			if (!vername_to_idx(obj, vaux_name(obj, vaux), &dep))
				continue;

			(void) memset(seen, 0, n * sizeof (bool));
			derefer(obj, dep, weak, seen);
		}

		/* The base version is never a top version */
		if (v->v_verdef->vd_ndx == VER_NDX_GLOBAL)
			v->v_top = false;
	}

	arrayfree(seen, n, sizeof (bool));
}

/* Wrapper around elf_begin(3ELF) */
static bool
open_obj(obj_t *obj)
{
	const char	*path = obj_path(obj);
	Elf_Scn		*scn;
	Elf_Data	*data;
	GElf_Verdef	*verdef;
	uintptr_t	vd_end;

	obj->o_fd = openat(obj->o_dirfd, path, O_RDONLY);
	if (obj->o_fd < 0) {
		warn("failed to open %s/%s", obj->o_prefix, path);
		return (false);
	}

	obj->o_elf = elf_begin(obj->o_fd, ELF_C_READ, NULL);
	if (obj->o_elf == NULL || elf_kind(obj->o_elf) != ELF_K_ELF) {
		warnx("elf_begin on %s/%s failed: %s", obj->o_prefix, path,
		    elf_errmsg(-1));
		goto fail;
	}

	/* Cache sections we're interested in */
	scn = NULL;
	while ((scn = elf_nextscn(obj->o_elf, scn)) != NULL) {
		GElf_Shdr shdr = { 0 };

		if (gelf_getshdr(scn, &shdr) == NULL)
			goto elffail;

		switch (shdr.sh_type) {
		case SHT_SUNW_verdef:
			obj->o_verdef.si_scn = scn;
			obj->o_verdef.si_nent = shdr.sh_info;
			obj->o_verdef.si_link = shdr.sh_link;
			break;
		case SHT_SUNW_versym:
			obj->o_versym.si_scn = scn;
			obj->o_versym.si_nent = (shdr.sh_entsize == 0) ? 0 :
			    shdr.sh_size / shdr.sh_entsize;
			obj->o_versym.si_link = shdr.sh_link;
			break;
		case SHT_DYNAMIC:
			obj->o_dyn.si_scn = scn;
			obj->o_dyn.si_nent = (shdr.sh_entsize == 0) ? 0 :
			    shdr.sh_size / shdr.sh_entsize;
			obj->o_dyn.si_link = shdr.sh_link;
			break;
		}
	}

	if (obj->o_verdef.si_scn == NULL || obj->o_verdef.si_nent == 0) {
		warnx("%s/%s: no version definition section", obj->o_prefix,
		    path);
		goto fail;
	}

	/* Cache all of the GElf_Verdef (ELF version) objects */
	data = elf_getdata(obj->o_verdef.si_scn, NULL);
	if (data == NULL || data->d_buf == NULL)
		goto elffail;

	obj->o_nversions = obj->o_verdef.si_nent;
	obj->o_versions = xcalloc(obj->o_nversions, sizeof (version_t));

	verdef = (GElf_Verdef *)data->d_buf;
	vd_end = (uintptr_t)data->d_buf + data->d_size;
	for (uint_t i = 0; i < obj->o_nversions; i++) {
		version_t	*v = &obj->o_versions[i];

		if ((uintptr_t)verdef + sizeof (*verdef) > vd_end ||
		    verdef->vd_cnt == 0) {
			warnx("%s/%s: malformed version definition section",
			    obj->o_prefix, path);
			goto fail;
		}

		v->v_verdef = verdef;
		v->v_name = vaux_name(obj, verdef_aux(verdef));
		if (v->v_name == NULL)
			goto elffail;

		verdef = verdef_next(verdef);
	}

	find_top_versions(obj);

	/*
	 * Determine the name used for the base version. It should match the
	 * soname if the object has one, and the object basename otherwise.
	 */
	if (obj->o_dyn.si_scn != NULL &&
	    (data = elf_getdata(obj->o_dyn.si_scn, NULL)) != NULL) {
		for (uint_t i = 0; i < obj->o_dyn.si_nent; i++) {
			GElf_Dyn dyn;

			if (gelf_getdyn(data, i, &dyn) == NULL)
				goto elffail;

			if (dyn.d_tag == DT_NULL)
				break;

			if (dyn.d_tag == DT_SONAME) {
				obj->o_soname = elf_strptr(obj->o_elf,
				    obj->o_dyn.si_link, dyn.d_un.d_val);
				break;
			}
		}
	}

	if (obj->o_soname == NULL || obj->o_soname[0] == '\0')
		obj->o_soname = path_basename(path);

	/* We can't categorize the versions until we have the soname */
	for (uint_t i = 0; i < obj->o_nversions; i++) {
		version_t *v = &obj->o_versions[i];

		parse_category(v->v_name, obj->o_soname, &v->v_cat);
	}

	get_symbols(obj);

	return (true);

elffail:
	warnx("%s/%s: %s", obj->o_prefix, path, elf_errmsg(-1));
fail:
	obj_close(obj);
	return (false);
}

static void
obj_close(obj_t *obj)
{
	arrayfree(obj->o_dsyms, obj->o_dsyms_alloc, sizeof (dsym_t));
	obj->o_dsyms = NULL;
	obj->o_dsyms_alloc = obj->o_ndsyms = 0;

	arrayfree(obj->o_versions, obj->o_nversions, sizeof (version_t));
	obj->o_versions = NULL;
	obj->o_nversions = 0;

	if (obj->o_elf != NULL)
		(void) elf_end(obj->o_elf);
	obj->o_elf = NULL;

	if (obj->o_fd >= 0)
		VERIFY0(close(obj->o_fd));
	obj->o_fd = -1;
}

/*
 * Verify all of the version names in this object follow our standard
 * (or is an exception).
 *
 * Currently, allowed version names are:
 *	ILLUMOS_x.y[.z]
 *	SUNW_x.y[.z]
 *	ILLUMOSprivate[_nnn]
 *	SUNWprivate[_nnn]
 *	SYSVABI_1.2
 *	SYSVABI_1.3
 *	SISCD_2.3[ab...]
 *	the object's soname (the base version)
 *
 * See category.c for the explicit regexes used to test the version names.
 *
 * As with the perl version (which used 'pvs -dos'), only versions that
 * offer interfaces (i.e. have symbols) are considered.
 */
static bool
check_version_names(obj_t *obj)
{
	size_t vercnt = 0;

	for (uint_t i = 0; i < obj->o_nversions; i++) {
		version_t *v = &obj->o_versions[i];

		if (v->v_nsyms == 0)
			continue;

		vercnt++;

		if (v->v_cat.c_type == CT_UNKNOWN &&
		    !is_exception(obj_path(obj), "NONSTD_VERNAME",
		    exceptions)) {
			errmsg(obj, "non-standard version name: %s",
			    v->v_name);
		}
	}

	/*
	 * If this file has been scoped, but not versioned (i.e., a mapfile
	 * was used to demote symbols but no version name was applied to the
	 * global interfaces) then it's another non-standard case.
	 */
	if (vercnt == 0) {
		errmsg(obj, "scoped object contains no versions");
		return (false);
	}

	return (true);
}

/*
 * Collect the symbols for each version, following the same rules as
 * 'pvs -ds'. If there is no versym section, no symbols are assigned to any
 * version.
 */
static void
get_symbols(obj_t *obj)
{
	Elf_Scn		*symscn;
	Elf_Data	*data, *vdata;
	GElf_Shdr	shdr;
	GElf_Versym	*vsym;
	size_t		nsyms, strndx;

	if (obj->o_versym.si_scn == NULL)
		return;

	vdata = elf_getdata(obj->o_versym.si_scn, NULL);
	symscn = elf_getscn(obj->o_elf, obj->o_versym.si_link);
	if (vdata == NULL || vdata->d_buf == NULL || symscn == NULL ||
	    gelf_getshdr(symscn, &shdr) == NULL ||
	    (data = elf_getdata(symscn, NULL)) == NULL) {
		warnx("%s/%s: unable to read versioned symbols: %s",
		    obj->o_prefix, obj_path(obj), elf_errmsg(-1));
		return;
	}

	strndx = shdr.sh_link;
	nsyms = (shdr.sh_entsize == 0) ? 0 : shdr.sh_size / shdr.sh_entsize;
	if (nsyms > obj->o_versym.si_nent)
		nsyms = obj->o_versym.si_nent;
	if (nsyms > vdata->d_size / sizeof (GElf_Versym))
		nsyms = vdata->d_size / sizeof (GElf_Versym);

	vsym = (GElf_Versym *)vdata->d_buf;
	for (size_t i = 0; i < nsyms; i++) {
		GElf_Sym	sym;
		version_t	*v = NULL;
		const char	*symname;
		uint_t		vidx;

		/* Find the version definition this symbol belongs to */
		for (vidx = 0; vidx < obj->o_nversions; vidx++) {
			if (obj->o_versions[vidx].v_verdef->vd_ndx == vsym[i]) {
				v = &obj->o_versions[vidx];
				break;
			}
		}

		/* Local (0), or a version requirement rather than a verdef */
		if (v == NULL)
			continue;

		if (gelf_getsym(data, i, &sym) == NULL)
			continue;

		symname = elf_strptr(obj->o_elf, strndx, sym.st_name);
		if (symname == NULL)
			continue;

		/*
		 * Each version defines an absolute symbol of the same name.
		 * pvs only displays it with -v, so we skip it.
		 */
		if (sym.st_shndx == SHN_ABS && strcmp(v->v_name, symname) == 0)
			continue;

		add_sym(obj, vidx, symname);
		v->v_nsyms++;
	}

	qsort(obj->o_dsyms, obj->o_ndsyms, sizeof (dsym_t), cmp_dsym);
}

static void
traverse_versions(obj_t *obj, uint_t vidx, bool *encountered)
{
	version_t	*v = &obj->o_versions[vidx];
	GElf_Verdaux	*vaux = verdef_aux(v->v_verdef);
	uint_t		idx;

	if (encountered[vidx])
		return;
	encountered[vidx] = true;

	for (uint_t i = 1; i < v->v_verdef->vd_cnt; i++) {
		vaux = vaux_next(vaux);
		if (vername_to_idx(obj, vaux_name(obj, vaux), &idx))
			traverse_versions(obj, idx, encountered);
	}
}

/* Returns true if name ends in .so.<digits> */
static bool
has_so_suffix(const char *name)
{
	const char	*p = strstr(name, ".so.");
	const char	*q;

	while (p != NULL) {
		q = p + 4;
		if (*q != '\0') {
			while (isdigit((unsigned char)*q))
				q++;
			if (*q == '\0')
				return (true);
		}
		p = strstr(p + 1, ".so.");
	}
	return (false);
}

static void
print_object_header(obj_t *obj)
{
	elf_obj_t *eo = obj->o_elfobj;

	/* As with the perl version, -h also omits the blank separator */
	if (do_header && intf_objcnt > 0)
		(void) fputc('\n', intf);
	intf_objcnt++;

	(void) fprintf(intf,
	    "OBJECT\t%s\n"
	    "CLASS\t%s\n"
	    "TYPE\t%s\n", obj_path(obj), elf_class_str(eo->eo_class),
	    elf_type_str(eo->eo_type));
	for (size_t i = 0; i < eo->eo_nalias; i++)
		(void) fprintf(intf, "ALIAS\t%s\n", eo->eo_aliases[i]);
}

static void
print_version(obj_t *obj, version_t *v)
{
	GElf_Verdef	*verdef = v->v_verdef;
	GElf_Verdaux	*vaux;

	(void) fprintf(intf, "%sVERSION\t%s", v->v_top ? "TOP_" : "",
	    v->v_name);

	/* Formatted the same as 'pvs -v' lists inherited versions */
	if (verdef->vd_cnt > 1) {
		vaux = verdef_aux(verdef);
		(void) fprintf(intf, "\t{");
		for (uint_t i = 1; i < verdef->vd_cnt; i++) {
			vaux = vaux_next(vaux);
			(void) fprintf(intf, "%s%s", (i > 1) ? ", " : "",
			    vaux_name(obj, vaux));
		}
		(void) fputc('}', intf);
	}
	(void) fputc('\n', intf);
}

/*
 * Produce an interface description for the object. For each version,
 * generate a VERSION declaration of the form:
 *
 *	[TOP_]VERSION  version  [{inherited, ...}]
 *		SYMBOL	symname1
 *		SYMBOL	symname2
 *		...
 *
 * We suppress base and private versions from this output. If an object
 * only has base or private versions, we do not produce an interface
 * description for that object.
 */
static void
print_symbols(obj_t *obj)
{
	bool	*do_version;
	bool	header_done = false;

	if (intf == NULL)
		return;

	do_version = xcalloc(obj->o_nversions, sizeof (bool));

	for (uint_t i = 0; i < obj->o_nversions; i++) {
		version_t	*v = &obj->o_versions[i];
		dsym_t		*ds = obj->o_dsyms;
		const char	*symlabel = "SYMBOL";
		const char	*prev = NULL;

		if ((v->v_verdef->vd_flags & VER_FLG_BASE) != 0 ||
		    v->v_cat.c_type == CT_SONAME ||
		    v->v_cat.c_type == CT_PRIVATE ||
		    has_so_suffix(v->v_name)) {
			continue;
		}

		(void) memset(do_version, '\0',
		    obj->o_nversions * sizeof (bool));

		if (expand_inheritance) {
			/*
			 * Walk the inheritance tree and mark each
			 * version we find as one to output
			 */
			symlabel = "NEW";
			traverse_versions(obj, i, do_version);
		} else {
			do_version[i] = true;
		}

		if (!header_done) {
			print_object_header(obj);
			header_done = true;
		}

		print_version(obj, v);

		for (uint_t j = 0; j < obj->o_ndsyms; j++) {
			if (!do_version[ds[j].ds_version])
				continue;

			/* Thin out any duplicate names, as perl did */
			if (prev != NULL && strcmp(prev, ds[j].ds_name) == 0)
				continue;
			prev = ds[j].ds_name;

			(void) fprintf(intf, "\t%s\t%s\n",
			    (i == ds[j].ds_version) ? symlabel : "INHERIT",
			    ds[j].ds_name);
		}
	}

	arrayfree(do_version, obj->o_nversions, sizeof (bool));
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
fopen_mode(const char *path, const char *mode)
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
	default:
		errno = EINVAL;
		return (NULL);
	}

	/* Created files get the usual 0666 (less umask) */
	fd = open(path, flag, 0666);
	if (fd == -1)
		return (NULL);

	return (fdopen(fd, mode));
}

#define	SYM_CHUNK 64
static void
add_sym(obj_t *obj, uint_t idx, const char *name)
{
	if (obj->o_ndsyms == obj->o_dsyms_alloc) {
		size_t newsz = obj->o_dsyms_alloc + SYM_CHUNK;

		obj->o_dsyms = xcreallocarray(obj->o_dsyms, obj->o_dsyms_alloc,
		    newsz, sizeof (dsym_t));
		obj->o_dsyms_alloc = newsz;
	}

	dsym_t *ds = &obj->o_dsyms[obj->o_ndsyms++];

	ds->ds_name = name;
	ds->ds_version = idx;
}

static int
cmp_dsym(const void *a, const void *b)
{
	const dsym_t *l = a;
	const dsym_t *r = b;

	return (strcmp(l->ds_name, r->ds_name));
}
