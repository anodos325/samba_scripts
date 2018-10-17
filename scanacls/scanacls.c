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

struct file_info {
	char *path;
	char *real_path;
	struct stat st;
	
};

static struct file_info *
new_file_info(void)
{
	struct file_info *s;

	if ((s = malloc(sizeof(*s))) == NULL)
		err(EX_OSERR, "malloc() failed");

	s->path = NULL;
	s->real_path = NULL;
	return (s);
}

static void
free_file_info(struct file_info *f)
{
	if (f == NULL)
		return;

	free(f->path);
	free(f->real_path);
	free(f);
}

int
get_acl_type(struct file_info *file_info)
{
	int acl_type;

	if ((file_info->st.st_mode |= S_IFLNK) == 1) {
		acl_type = lpathconf(file_info->path, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_TYPE_ACCESS;
	}
	else {
		acl_type = pathconf(file_info->path, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_TYPE_ACCESS;
	}

	return acl_type;
}

int
get_stat_info(struct file_info *file_info)
{
	int ret;
	/* handling for broken symlinks */

	if ((ret = stat(file_info->path, &file_info->st)) == -1 &&
		errno == ENOENT &&
		(ret = lstat(file_info->path, &file_info->st)) == -1) {
			errno = ENOENT;
			return -1;	
	}

	return ret;
}

int                             
print_output(struct file_info *file_info)
{
	xo_open_container("path");
	xo_emit("{:Realpath/%s} |",file_info->real_path);
	xo_close_container("path");

	xo_open_container("stat");
	xo_emit("{:is_dir/%d}| {:atime/%d} {:mtime/%d} {:ctime/%d} {:btime/%d}\n",
		 (file_info->st.st_mode & S_IFDIR ? 1 : 0),
		 file_info->st.st_atim, file_info->st.st_mtim,
		 file_info->st.st_ctim, file_info->st.st_birthtim);
	xo_close_container("stat");

	return 0;
}

static int
scan_acl(char *path)
{
	int ret;
	char buf[PATH_MAX + 1];
	acl_t tmp_acl;
	struct file_info *file_info;
	file_info = new_file_info();

	setarg(&file_info->path, path);
	get_stat_info(file_info);
	ret = get_acl_type(file_info);
	if (ret == ACL_TYPE_NFS4) {
		if ((tmp_acl = acl_get_file(file_info->path, ACL_TYPE_NFS4)) == NULL) { 
			char *real_path =  realpath(path, buf);
			setarg(&file_info->real_path, real_path);
			get_stat_info(file_info);
			print_output(file_info);	
		}
		acl_free(tmp_acl);
	}  
	free_file_info(file_info);
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

	/* recursive not set, only do this entry */
	if (!(flags & FLAG_RECURSIVE)) {
		scan_acl(path);
		return (0);
	}

	paths[0] = path;
	paths[1] = NULL;
	options = FTS_LOGICAL|FTS_NOSTAT;

	if ((tree = fts_open(paths, options, fts_compare)) == NULL)
		err(EX_OSERR, "fts_open");

	/* traverse directory hierarchy */
	for (rval = 0; (entry = fts_read(tree)) != NULL;) {
		switch (entry->fts_info) {
			case FTS_D:
			case FTS_F:
				scan_acl(entry->fts_accpath);
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
