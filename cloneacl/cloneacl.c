/*
 * Copyright 2018 iXsystems, Inc.
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/acl.h>
#include <sys/extattr.h>
#include <sys/stat.h>
#include <err.h>
#include <fts.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>


static void
usage(char *path)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] ...\n"
		"Where option is:\n"
		"    -s <path>                    # source\n"
		"    -p <path>                    # path to set\n"
		"    -v                           # verbose\n",
		path
	);
	exit(0);
}


struct windows_acl_info {

#define	WA_NULL			0x00000000	/* nothing */
#define	WA_VERBOSE		0x00000001	/* print more stuff */

/* default ACL entries if none are specified */

	char *source;
	char *path;
	acl_t source_acl;
	acl_t dacl;
	acl_t facl;
	uid_t uid;
	gid_t gid;
	int flags;
	int index;
};

static void
setarg(char **pptr, const char *src)
{
	char *ptr;

	ptr = *pptr;
	if (ptr != NULL)
		free(ptr);
	ptr = strdup(src);
	if (ptr == NULL)
		err(EX_OSERR, NULL);

	*pptr = ptr;
}

static struct windows_acl_info *
new_windows_acl_info(void)
{
	struct windows_acl_info *w;

	if ((w = malloc(sizeof(*w))) == NULL)
		err(EX_OSERR, "malloc() failed");
	w->source = NULL;
	w->source_acl = NULL;
	w->path = NULL;
	w->dacl = NULL;
	w->facl = NULL;
	w->flags = 0;
	w->index = -1;

	return (w);
}

static void
free_windows_acl_info(struct windows_acl_info *w)
{
	if (w == NULL)
		return;

	free(w->path);
	free(w->source);
	acl_free(w->source_acl);
	acl_free(w->dacl);
	acl_free(w->facl);
	free(w);
}

static int
remove_inherit_flags(acl_t *acl)
{
        int entry_id;
        acl_entry_t acl_entry;
        acl_flagset_t acl_flags;
        
        entry_id = ACL_FIRST_ENTRY;
        while (acl_get_entry(*acl, entry_id, &acl_entry) > 0) {
                entry_id = ACL_NEXT_ENTRY;

                if (acl_get_flagset_np(acl_entry, &acl_flags) < 0)
                        err(EX_OSERR, "acl_get_flagset_np() failed");
 
                acl_delete_flag_np(acl_flags, ACL_ENTRY_FILE_INHERIT);
                acl_delete_flag_np(acl_flags, ACL_ENTRY_DIRECTORY_INHERIT);
                acl_delete_flag_np(acl_flags, ACL_ENTRY_NO_PROPAGATE_INHERIT);
                acl_delete_flag_np(acl_flags, ACL_ENTRY_INHERIT_ONLY);
        
                if (acl_set_flagset_np(acl_entry, acl_flags) < 0)
                        err(EX_OSERR, "acl_set_flagset_np() failed");
        }

        return (0);
}       
 
/* add inherited flag to ACES in ACL */
static int
set_inherited_flag(acl_t *acl)
{
        int entry_id;
        acl_entry_t acl_entry;
        acl_flagset_t acl_flags;
                 
        entry_id = ACL_FIRST_ENTRY;
        while (acl_get_entry(*acl, entry_id, &acl_entry) > 0) {
                entry_id = ACL_NEXT_ENTRY;

                if (acl_get_flagset_np(acl_entry, &acl_flags) < 0)
                        err(EX_OSERR, "acl_get_flagset_np() failed");
 
                acl_add_flag_np(acl_flags, ACL_ENTRY_INHERITED);

                if (acl_set_flagset_np(acl_entry, acl_flags) < 0)
                        err(EX_OSERR, "acl_set_flagset_np() failed");
        }

        return (0);
}

static void
make_acls(struct windows_acl_info *w)
{
	/* create a directory acl */
	if ((w->dacl = acl_dup(w->source_acl)) == NULL)
		err(EX_OSERR, "acl_dup() failed");
	set_inherited_flag(&w->dacl);

	/* create a file acl */
	if ((w->facl = acl_dup(w->source_acl)) == NULL)
		err(EX_OSERR, "acl_dup() failed");
	remove_inherit_flags(&w->facl);
	set_inherited_flag(&w->facl);
}

/* merge two acl entries together */
static int
merge_acl_entries(acl_entry_t *entry1, acl_entry_t *entry2)
{
	acl_permset_t permset;
	acl_entry_type_t entry_type;
	acl_flagset_t flagset;

	if (acl_get_permset(*entry1, &permset) < 0)
		err(EX_OSERR, "acl_get_permset() failed");
	if (acl_set_permset(*entry2, permset) < 0)
		err(EX_OSERR, "acl_set_permset() failed");
	if (acl_get_entry_type_np(*entry1, &entry_type) < 0)
		err(EX_OSERR, "acl_get_entry_type_np() failed");
	if (acl_set_entry_type_np(*entry2, entry_type) < 0)
		err(EX_OSERR, "acl_set_entry_type_np() failed");
	if (acl_get_flagset_np(*entry1, &flagset) < 0)
		err(EX_OSERR, "acl_get_flagset_np() failed");
	if (acl_set_flagset_np(*entry2, flagset) < 0)
		err(EX_OSERR, "acl_set_flagset_np() failed");

	return (0);
}


/* merge two acl entries together if the qualifier is the same */
static int
merge_user_group(acl_entry_t *entry1, acl_entry_t *entry2)
{
	acl_permset_t permset;
	acl_entry_type_t entry_type;
	acl_flagset_t flagset;
	uid_t *id1, *id2;
	int rval = 0;

	if ((id1 = acl_get_qualifier(*entry1)) == NULL)
		err(EX_OSERR, "acl_get_qualifier() failed");
	if ((id2 = acl_get_qualifier(*entry2)) == NULL)
		err(EX_OSERR, "acl_get_qualifier() failed");
	if (*id1 == *id2) {
		merge_acl_entries(entry1, entry2);
		rval = 1;
	}

	acl_free(id1);
	acl_free(id2);

	return (rval);
}

/* merge 2 acl's together */
static int
merge_acl(acl_t acl, acl_t *prev_acl, const char *path)
{
	acl_t acl_new;
	acl_permset_t permset;
	acl_flagset_t flagset;
	acl_tag_t tag, tag_new;
	acl_entry_t entry, entry_new;
	acl_entry_type_t entry_type, entry_type_new;
	int entry_id, entry_id_new, have_entry, had_entry, entry_number = 0;

	if ((acl_new = acl_dup(*prev_acl)) == NULL)
		err(EX_OSERR, "%s: acl_dup() failed", path);

	entry_id = ACL_FIRST_ENTRY;
	while (acl_get_entry(acl, entry_id, &entry) == 1) {
		entry_id = ACL_NEXT_ENTRY;
		have_entry = had_entry = 0;

		entry_id_new = ACL_FIRST_ENTRY;
		while (acl_get_entry(acl_new, entry_id_new, &entry_new) > 0) {
			entry_id_new = ACL_NEXT_ENTRY;

			if (acl_get_tag_type(entry, &tag) < 0)
				err(EX_OSERR, "%s: acl_get_tag_type() failed", path);
			if (acl_get_tag_type(entry_new, &tag_new) < 0)
				err(EX_OSERR, "%s: acl_get_tag_type() failed", path);
			if (tag != tag_new)
				continue;

			if (acl_get_entry_type_np(entry, &entry_type) < 0)
				err(EX_OSERR, "%s: acl_get_entry_type_np() failed", path);
			if (acl_get_entry_type_np(entry_new, &entry_type_new) < 0)
				err(EX_OSERR, "%s: acl_get_entry_type_np() failed", path);
			if (entry_type != entry_type_new)
				continue;
		
			switch(tag) {
				case ACL_USER:
				case ACL_GROUP:
					have_entry = merge_user_group(&entry, &entry_new);
					if (have_entry == 0)
						break;

				case ACL_USER_OBJ:
				case ACL_GROUP_OBJ:
				case ACL_EVERYONE:
					merge_acl_entries(&entry, &entry_new);
					had_entry = have_entry = 1;
					break;

				default:
					errx(EX_OSERR, "%s: invalid tag type: %i", path, tag);
					break;
			}
		}

		if (had_entry == 0) {
			if (acl_create_entry_np(&acl_new, &entry_new, entry_number) < 0) {
				warn("%s: acl_create_entry_np() failed", path); 
				acl_free(acl_new);
				return (-1);
			}

			entry_number++;
			if (acl_copy_entry(entry_new, entry) < 0)
				err(EX_OSERR, "%s: acl_copy_entry() failed", path);
		}
	}

	acl_free(*prev_acl);
	*prev_acl = acl_new;

	return (0);
}

static int
set_windows_acl(struct windows_acl_info *w, FTSENT *fts_entry, bool is_rootdir)
{
	char *path;
	char *buf;
	struct stat st;
	acl_t acl, acl_new, tmp;

	if (fts_entry == NULL) 
		path = w->path;
	else
		path = fts_entry->fts_accpath;

	if (w->flags & WA_VERBOSE)
		fprintf(stdout, "%s\n", path);

	if ((acl = acl_get_file(path, ACL_TYPE_NFS4)) == NULL)
		err(EX_OSERR, "%s: acl_get_filed() failed", path);

	/* remove extended entries */
	if ((tmp = acl_strip_np(acl, 0)) == NULL)
		err(EX_OSERR, "%s: acl_strip_np() failed", path);

	acl_free(acl);
	acl = tmp;	
	
	bzero(&st, sizeof(st));
	if (stat(path, &st) < 0)
		err(EX_OSERR, "%s: acl_from_text() failed", path);

	if (is_rootdir) {
		acl_new = w->source_acl;
	}
	else {
		acl_new = (S_ISDIR(st.st_mode) == 0) ? w->facl : w->dacl;
	}

	/* merge the new acl with the existing acl */
	if (merge_acl(acl_new, &acl, path) < 0)
		warn("%s: merge_acl() failed", path);
	acl_free(acl);

	/* write out the acl to the file */
	if (acl_set_file(path, ACL_TYPE_NFS4, acl_new) < 0)
		warn("%s: acl_set_file() failed", path);

	return (0);
}

static int
fts_compare(const FTSENT * const *s1, const FTSENT * const *s2)
{
	return (strcoll((*s1)->fts_name, (*s2)->fts_name));
}

static int
set_windows_acls(struct windows_acl_info *w)
{
	FTS *tree;
	FTSENT *entry;
	int options = 0;
	char *paths[4];
	int rval;
	bool is_rootdir;

	if (w == NULL)
		return (-1);

	paths[0] = w->path;
	paths[1] = NULL;
	options = FTS_LOGICAL|FTS_NOSTAT;

	if ((tree = fts_open(paths, options, fts_compare)) == NULL)
		err(EX_OSERR, "fts_open");

	/* traverse directory hierarchy */
	for (rval = 0; (entry = fts_read(tree)) != NULL;) {
		if ((entry->fts_level) == FTS_ROOTLEVEL) {
			is_rootdir = 1;
			set_windows_acl(w, entry, is_rootdir);
		}
		else {
			switch (entry->fts_info) {
				case FTS_D:
					set_windows_acl(w, entry, 0);
					break;	

				case FTS_F:
					set_windows_acl(w, entry, 0);
					break;	

				case FTS_ERR:
					warnx("%s: %s", entry->fts_path, strerror(entry->fts_errno));
					rval = -2;
					continue;
			}
		}
	}	

	return (rval);
}

int
main(int argc, char **argv)
{
	int	ch, error, ret;
	struct 	windows_acl_info *w;
	acl_t	source_acl;

	if (argc < 2) {
		usage(argv[0]);
	}

	w = new_windows_acl_info();

	while ((ch = getopt(argc, argv, "s:p:v")) != -1) {
		switch(ch) {
		case 's':
			setarg(&w->source, optarg);
			break;
		case 'p':
			setarg(&w->path, optarg);
			break;
		case 'v':
			w->flags |= WA_VERBOSE;
			break;
		case '?':
		default:
			usage(argv[0]);
		}
	}

	/* set the source to the destination if we lack -s */
	if (w->source == NULL) {
		w->source = w->path;
	}

	ret = pathconf(w->source, _PC_ACL_NFS4);

	if (ret < 0) {
		warn("%s: pathconf(..., _PC_ACL_NFS4) failed. Path does not have NFS4 ACL.", w->source);
		free_windows_acl_info(w);
		return (-1);
	}

	source_acl = acl_get_file(w->source, ACL_TYPE_NFS4);
	w->source_acl = acl_dup(source_acl);
	acl_free(source_acl);

	if (w->source_acl < 0) {
		warn("failed to get acl from source");
		free_windows_acl_info(w);
		return (-1);
	}

	make_acls(w);
	set_windows_acls(w);
	free_windows_acl_info(w);
	return (0);
}
