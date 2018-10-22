#include <sys/types.h>
#include <libxo/xo.h>
#include <sys/acl.h>
#include <sys/extattr.h>
#include <sys/stat.h>
#include <err.h>
#include <fts.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>


#define FLAG_OUTPUT_NONE		0x00000000
#define FLAG_TRAVERSE			0x00000001
#define FLAG_RECURSIVE			0x00000004
#define FLAG_PRINT_MODE			0x00000008

static void
usage(void)
{
        fprintf(stderr, "scanacls [-xrv] [file ...]\n");
}

int
get_acl_type(FTSENT *fts_entry)
{
	int acl_type;

	if ((fts_entry->fts_statp->st_mode |= S_IFLNK) == 1) {
		acl_type = lpathconf(fts_entry->fts_accpath, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_TYPE_ACCESS;
	}
	else {
		acl_type = pathconf(fts_entry->fts_accpath, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_TYPE_ACCESS;
	}

	return acl_type;
}

int                             
print_output(FTSENT *fts_entry)
{
	char buf[PATH_MAX + 1];
	char *real_path =  realpath(fts_entry->fts_accpath, buf);
	xo_open_container("path");
	xo_emit("{:Realpath/%s} |",real_path);
	xo_close_container("path");

	xo_open_container("stat");
	xo_emit("{:is_dir/%d}| {:atime/%d} {:mtime/%d} {:ctime/%d} {:btime/%d}\n",
		 (fts_entry->fts_statp->st_mode & S_IFDIR ? 1 : 0),
		 fts_entry->fts_statp->st_atim, fts_entry->fts_statp->st_mtim,
		 fts_entry->fts_statp->st_ctim, fts_entry->fts_statp->st_birthtim);
	xo_close_container("stat");
	free(real_path);
	free(buf);
	return 0;
}

static int
scan_acl(FTSENT *fts_entry)
{
	int ret;
	acl_t tmp_acl;
	ret = get_acl_type(fts_entry);
	if (ret == ACL_TYPE_NFS4) {
		if ((tmp_acl = acl_get_file(fts_entry->fts_accpath, ACL_TYPE_NFS4)) == NULL) { 
			print_output(fts_entry);	
		}
		acl_free(tmp_acl);
	}  
}

static int
fts_compare(const FTSENT * const *s1, const FTSENT * const *s2)
{
	return (strcoll((*s1)->fts_name, (*s2)->fts_name));
}

static int
scan_acls(char *path, int flags)
{
	FTS *tree;
	FTSENT *entry;
	int options = 0;
	char *paths[4];
	int rval;

	paths[0] = path;
	paths[1] = NULL;
	options = FTS_LOGICAL;

	if ((tree = fts_open(paths, options, fts_compare)) == NULL)
		err(EX_OSERR, "fts_open");

	/* traverse directory hierarchy */
	for (rval = 0; (entry = fts_read(tree)) != NULL;) {
		switch (entry->fts_info) {
			case FTS_D:
			case FTS_F:
				scan_acl(entry);
				break;	

			case FTS_ERR:
				warnx("%s: %s", entry->fts_path, strerror(entry->fts_errno));
				rval = -2;
				continue;
		}
	} 

	return (rval);
}

int
main(int argc, char *argv[])
{
	int ch, ret, flags;

	flags = FLAG_OUTPUT_NONE;

	/* 
	 * n = display numeric ids
	 * r = output in raw form 
	 * v = verbose
	 */
	argc = xo_parse_args(argc, argv);
    	if (argc < 0)
        	exit(1);


	while ((ch = getopt(argc, argv, "xrv")) != -1)
	switch(ch) {
	case 'x':
		flags |= FLAG_TRAVERSE;
		break;
	case 'r':
		flags |= FLAG_RECURSIVE;
		break;
	case 'v':
		flags |= FLAG_PRINT_MODE; 
		break;
	default:
		usage();
		return(-1);
	}
	argc -= optind;
	argv += optind;

	if (!argv[0]){
		usage();
		return(-1);
	}

	ret = scan_acls(argv[0], flags);
	xo_finish();

	return (ret);
}
