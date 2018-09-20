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


#define SAMBA_XATTR_DOSSTREAM_PREFIX	"DosStream."

#define FLAG_OUTPUT_NONE		0x00000000
#define FLAG_OUTPUT_JSON		0x00000001
#define FLAG_OUTPUT_NUMERIC		0x00000004
#define FLAG_OUTPUT_VERBOSE		0x00000008

static void
usage(void)
{

        fprintf(stderr, "smbinfo [-nsv] [file ...]\n");
}


struct smb_info {
	char *path;
	char *real_path;
	struct stat st;
	acl_t dacl;
	int num_streams;
	int num_snapshots;
	
};

static struct smb_info *
new_smb_info(void)
{
	struct smb_info *s;

	if ((s = malloc(sizeof(*s))) == NULL)
		err(EX_OSERR, "malloc() failed");

	s->path = NULL;
	s->real_path = NULL;
	s->dacl = NULL;
	s->num_streams = 0;
	s->num_snapshots = 0;

	return (s);
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

static char *
getuname(uid_t uid)
{
        #define INIT_LEN 1024
        size_t len = INIT_LEN;
        static char uids[10];
        struct passwd result;
        struct passwd *resultp;
        char *buffer = malloc(len);
        if (buffer == NULL){
                printf("WARN: malloc failed\n");
                (void)snprintf(uids, sizeof(uids), "%u", uid);
                return (uids);
        }
        int e;

        while ((e = getpwuid_r(uid, &result, buffer, len, &resultp)) == ERANGE)
        {
                size_t newlen = 2 * len;

                if (newlen < len) {
                        printf("WTF: newlen shorter than len\n");
                        free (buffer);
                        (void)snprintf(uids, sizeof(uids), "%u", uid);
                        return (uids);
                }
                
                len = newlen;
        
                char *newbuffer = realloc(buffer, len);
                
                if (newbuffer == NULL) {
                        printf("WARN: malloc failed\n");
                        free (buffer);
                        (void)snprintf(uids, sizeof(uids), "%u", uid);
                        return (uids);
                }

                buffer = newbuffer;
        }

        getpwuid_r(uid, &result, buffer, len, &resultp);

        if (e != 0) {
                printf("WARN: getgrgid_r failed\n");
                free (buffer);
                (void)snprintf(uids, sizeof(uids), "%u", uid);
                return (uids);
        }

        if (result.pw_name == NULL) {
                printf("pw_name is null\n");
                (void)snprintf(uids, sizeof(uids), "%u", uid);
                free (buffer);
                return (uids);
        }
        else {
                return (result.pw_name);
        }
}

static char *
getgname(gid_t gid)
{
 	#define INIT_LEN 1024
	size_t len = INIT_LEN;	
	static char gids[10];
	struct group result;
	struct group *resultp;
	char *buffer = malloc(len);
	if (buffer == NULL){
		printf("WARN: malloc failed\n");
                (void)snprintf(gids, sizeof(gids), "%u", gid);
                return (gids);
	}
	int e;

	while ((e = getgrgid_r(gid, &result, buffer, len, &resultp)) == ERANGE)
   	{
		size_t newlen = 2 * len;

		if (newlen < len) {
			printf("WTF: newlen shorter than len\n");
			free (buffer);
                	(void)snprintf(gids, sizeof(gids), "%u", gid);
                	return (gids);
		}

		len = newlen;

		char *newbuffer = realloc(buffer, len);

		if (newbuffer == NULL) {
			printf("WARN: malloc failed\n");
			free (buffer);
                	(void)snprintf(gids, sizeof(gids), "%u", gid);
                	return (gids);
		}

		buffer = newbuffer;
	}

	getgrgid_r(gid, &result, buffer, len, &resultp);

	if (e != 0) {
		printf("WARN: getgrgid_r failed\n");
		free (buffer);
                (void)snprintf(gids, sizeof(gids), "%u", gid);
                return (gids);
	}

	if (result.gr_name == NULL) {
		printf("gr_name is null\n");
		(void)snprintf(gids, sizeof(gids), "%u", gid);
		free (buffer);	
		return (gids);
	}
	else {
		return (result.gr_name);
	}
}

int
get_acl_type(struct smb_info *smb_info)
{
	int acl_type;

	if ((smb_info->st.st_mode |= S_IFLNK) == 1) {
		acl_type = lpathconf(smb_info->path, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_TYPE_ACCESS;
	}
	else {
		acl_type = pathconf(smb_info->path, _PC_ACL_NFS4) == 1 ? ACL_TYPE_NFS4 : ACL_TYPE_ACCESS;
	}

	return acl_type;
}

int
get_stat_info(struct smb_info *smb_info)
{
	int ret;
	/* handling for broken symlinks */

	if ((ret = stat(smb_info->path, &smb_info->st)) == -1 &&
		errno == ENOENT &&
		(ret = lstat(smb_info->path, &smb_info->st)) == -1) {
			errno = ENOENT;
			return -1;	
	}

	return ret;
}

int
print_output(struct smb_info *smb_info, int flags)
{
	int entry_id = 0;
	int acl_cnt =0;
	acl_entry_t acl_entry;
	acl_flagset_t acl_flags;
	acl_tag_t acl_tag;
        acl_permset_t permset;
	acl_entry_type_t entry_type;
	uid_t uid;
	gid_t gid;

	xo_open_container("path");
	xo_emit("{:Path/%s} ", smb_info->path);	
	xo_emit("{:Realpath/%s} ", smb_info->real_path);	
	xo_close_container("path");

	xo_open_container("stat");
	if (flags & FLAG_OUTPUT_NUMERIC) {
		xo_emit("{:Owner/%d} ", smb_info->st.st_uid);
		xo_emit("{:Group/%d} ", smb_info->st.st_gid);
	}
	else {
		char *pwname = NULL;
		char *grname = NULL;
		pwname = getuname(smb_info->st.st_uid);
		grname = getgname(smb_info->st.st_gid);
		xo_emit("{:Owner/%s} ", pwname);
		xo_emit("{:Group/%s} ", grname);
	}
	xo_emit("{:atime/%d} ", smb_info->st.st_atim);
	xo_emit("{:mtime/%d} ", smb_info->st.st_mtim);
	xo_emit("{:ctime/%d} ", smb_info->st.st_ctim);
	xo_emit("{:btime/%d} ", smb_info->st.st_birthtim);
	xo_close_container("stat");

	xo_open_container("dosmode");
	xo_emit("{:Directory/%d} ", (smb_info->st.st_mode & S_IFDIR ? 1 : 0));
	xo_emit("{:Archive/%d} ", (smb_info->st.st_flags & UF_ARCHIVE ? 1 : 0));
	xo_emit("{:Readonly/%d} ", (smb_info->st.st_flags & UF_READONLY ? 1 : 0));
	xo_emit("{:Hidden/%d} ", (smb_info->st.st_flags & UF_HIDDEN ? 1 : 0));
	xo_emit("{:System/%d} ", (smb_info->st.st_flags & UF_SYSTEM ? 1 : 0));
	xo_close_container("dosmode");

	xo_open_container("ACL");
	entry_id = ACL_FIRST_ENTRY;
	while (acl_get_entry(smb_info->dacl, entry_id, &acl_entry) > 0 ){
		uid_t *uid = NULL;
		gid_t *gid = NULL;
		entry_id = ACL_NEXT_ENTRY;
		acl_get_tag_type(acl_entry, &acl_tag);
		acl_get_permset(acl_entry, &permset);
		acl_get_flagset_np(acl_entry, &acl_flags);
		acl_get_entry_type_np(acl_entry, &entry_type);
		xo_open_container("ACL_ENTRY");

		xo_open_container("ae_id");
		if (acl_tag & ACL_USER_OBJ) {
			xo_emit("{:acl_tag/%s} ", "ACL_USER_OBJ");
			xo_emit("{:acl_qualifier/%s} ", "owner@");
		}
		else if(acl_tag & ACL_USER) {
			xo_emit("{:acl_tag/%s} ", "ACL_USER");
			uid = acl_get_qualifier(acl_entry);
			if (flags & FLAG_OUTPUT_NUMERIC) {
				xo_emit("{:acl_qualifier/%d} ", *uid);
			}
			else {
				char *pwname = NULL;
				pwname = getuname(*uid);
				xo_emit("{:acl_qualifier/%s} ", pwname);
			}
		}
		else if(acl_tag & ACL_GROUP_OBJ) {
			xo_emit("{:acl_tag/%s} ", "ACL_GROUP_OBJ");
			xo_emit("{:acl_qualifier/%s} ", "group@");
		}
                else if(acl_tag & ACL_GROUP) {
                        xo_emit("{:acl_tag/%s} ", "ACL_GROUP");
                        gid = acl_get_qualifier(acl_entry);
                        if (flags & FLAG_OUTPUT_NUMERIC) {
                                xo_emit("{:acl_qualifier/%d} ", *gid);
                        }
                        else {
                                char *grname = NULL;
                                grname = getgname(*gid);
                                xo_emit("{:acl_qualifier/%s} ", grname);
                        }
                }

		else if(acl_tag & ACL_EVERYONE) {
			xo_emit("{:acl_tag/%s} ", "ACL_EVERYONE");
			xo_emit("{:acl_qualifier/%s} ", "everyone@");
		}
		xo_close_container("ae_id");
 
		xo_open_container("ae_perm");
	 	xo_emit("{:r/%d} ", (*permset & ACL_READ_DATA ? 1 : 0));	
	 	xo_emit("{:w/%d} ", (*permset & ACL_WRITE_DATA ? 1 : 0));	
	 	xo_emit("{:x/%d} ", (*permset & ACL_EXECUTE ? 1 : 0));	
	 	xo_emit("{:d/%d} ", (*permset & ACL_DELETE_CHILD ? 1 : 0));	
	 	xo_emit("{:D/%d} ", (*permset & ACL_DELETE ? 1 : 0));	
	 	xo_emit("{:a/%d} ", (*permset & ACL_READ_ATTRIBUTES ? 1 : 0));	
	 	xo_emit("{:A/%d} ", (*permset & ACL_WRITE_ATTRIBUTES ? 1 : 0));	
	 	xo_emit("{:R/%d} ", (*permset & ACL_READ_NAMED_ATTRS ? 1 : 0));	
	 	xo_emit("{:W/%d} ", (*permset & ACL_WRITE_NAMED_ATTRS ? 1 : 0));	
		xo_close_container("ae_perm");

		xo_open_container("ae_flags");
	 	xo_emit("{:f/%d} ", (*acl_flags & ACL_ENTRY_FILE_INHERIT ? 1 : 0));	
	 	xo_emit("{:d/%d} ", (*acl_flags & ACL_ENTRY_DIRECTORY_INHERIT ? 1 : 0));	
	 	xo_emit("{:i/%d} ", (*acl_flags & ACL_ENTRY_INHERIT_ONLY ? 1 : 0));	
	 	xo_emit("{:n/%d} ", (*acl_flags & ACL_ENTRY_NO_PROPAGATE_INHERIT ? 1 : 0));	
	 	xo_emit("{:I/%d} ", (*acl_flags & ACL_ENTRY_INHERITED ? 1 : 0));	
		xo_close_container("ae_flags");

	 	xo_emit("{:ae_entry_type/%s} ", (entry_type & ACL_ENTRY_TYPE_ALLOW ? "allow" : "deny"));	
		
		xo_close_container("ACL_ENTRY");
		++acl_cnt;
	}
	xo_close_container("ACL");
	xo_finish();

	return 0;
}

int
main(int argc, char *argv[])
{
	int ch, error, i, ret, flags;
	struct smb_info *smb_info;
	smb_info = new_smb_info();
	int nentries;
	char *real_path;
	acl_t aclp;
	char *acl_text;
	char buf[PATH_MAX + 1];

	flags = FLAG_OUTPUT_NONE;

	/* 
	 * n = display numeric ids
	 * j = output in JSON
	 * v = verbose
	 */
	argc = xo_parse_args(argc, argv);
    	if (argc < 0)
        	exit(1);


	while ((ch = getopt(argc, argv, "njv")) != -1)
	switch(ch) {
	case 'n':
		flags |= FLAG_OUTPUT_NUMERIC;
		break;
	case 'j':
		flags |= FLAG_OUTPUT_JSON;
		break;
	case 'v':
		flags |= FLAG_OUTPUT_NUMERIC; 
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
	setarg(&smb_info->path, argv[0]);

 
/*
	if (argc == 0) {
		get_stat_info(smb_info);
		error = print_acl_from_stdin(nflag, jflag, vflag);
		return(error ? 1 : 0);
	}
 */
	for (i = 0; i < argc; i++) {
		smb_info = new_smb_info();
		char *real_path =  realpath(argv[i], buf);
		if (real_path == NULL) {
			printf("Realpath failed: %s\n", argv[i]);
			return -1;
		}
		setarg(&smb_info->real_path, real_path);
		setarg(&smb_info->path, argv[i]);

		ret = get_stat_info(smb_info);
		if (ret < 0) {
 			printf("Stat failed: %s\n", smb_info->path);
			continue;
		}	

		ret = get_acl_type(smb_info);

		if (ret == ACL_TYPE_NFS4) {
			smb_info->dacl = acl_get_file(smb_info->path, ACL_TYPE_NFS4);
		} 

		ret = print_output(smb_info, flags);
		if (ret < 0) {
			printf("Failed to print output: %s\n", smb_info->path);
		}

	}
	return 0;
}
