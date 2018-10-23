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
//#include "base64.h"

#include <sys/types.h>
#include <sys/sbuf.h>
#include <sys/uio.h>
#include <sys/extattr.h>

#include <libgen.h>
#include <libutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vis.h>
#include <err.h>
#include <errno.h>

#define SAMBA_XATTR_DOSSTREAM_PREFIX	"DosStream."

#define F_NONE                  0x0000
#define F_FORCE                 0x0001
#define F_NOFOLLOW              0x0002
#define F_FROM_STDIN            0x0004
#define F_HEX                   0x0008
#define F_BASE64                0x0010
#define F_EMIT_ALL		0x0020


static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
unsigned char * base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = malloc(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}


/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char * base64_decode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = malloc(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					free(out);
					return NULL;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return out;
}

/*
	END BASE64 CRAP
 */

struct xattr {
        char *name;
        unsigned char *value;
        size_t length;
        TAILQ_ENTRY(xattr) link;
};

TAILQ_HEAD(xattr_list, xattr);

static void __dead2
usage(void) 
{
		fprintf(stderr, "usage: (getextattr|lsextattr|rmextattr");
		fprintf(stderr, "|setextattr)\n");
		exit (-1);
}

static void
mkbuf(unsigned char **buf, int *oldlen, int newlen)
{

	if (*oldlen >= newlen)
		return;
	if (*buf != NULL)
		free(*buf);
	*buf = malloc(newlen);
	if (*buf == NULL)
		err(1, "malloc");
	*oldlen = newlen;
	return;
}

static int
get_extended_attributes(const char *path, struct xattr_list *xlist, u_int64_t flags)
{
	char *buf;
	int i, ch, ret, buflen;

	if ((ret = extattr_list_file(path, EXTATTR_NAMESPACE_USER, NULL, 0)) < 0)
		return (EX_OK);

	if ((buf = malloc(ret)) == NULL) {
		warn("malloc");
		return (-1);
	}

	buflen = ret;
	if ((ret = extattr_list_file(path, EXTATTR_NAMESPACE_USER, buf, buflen)) < 0) {
		free(buf);
		warn("extattr_list_fd");
		return (-1);
	}

	for (i = 0;i < ret;i += ch + 1) {
		struct xattr *xptr = NULL;
		char *name = NULL;
		unsigned char *value = NULL;
		int xa_len = 0;
		int getret;

		ch = (unsigned char)buf[i];

		if ((name = malloc(ch)) == NULL) {
			warn("malloc");
			continue;
		}

		strncpy(name, &buf[i + 1], ch);
		name[ch] = '\0';

		if ((flags & F_EMIT_ALL) == 0) {  
			if (strncmp(name, "DosStream.", 10) != 0) {
				free(name);
				continue;
			}
		}

		if ((getret = extattr_get_file(path, EXTATTR_NAMESPACE_USER,
			name, NULL, 0)) < 0) {
			free(name);
			continue;
		}

		mkbuf(&value, &xa_len, getret);

		if ((getret = extattr_get_file(path, EXTATTR_NAMESPACE_USER,
			name, value, xa_len)) < 0) {
			free(value);
			free(name);
			continue;
		}
		
		if ((xptr = malloc(sizeof(*xptr))) == NULL) {
			warn("malloc");	
			free(value);
			free(name);
			continue;
		}

		memset(xptr, 0, sizeof(*xptr));
		xptr->name = name;
		xptr->value = value;
		xptr->length = getret;

		TAILQ_INSERT_TAIL(xlist, xptr, link);
	}

	return (0);	
}

static void
free_extended_attributes(struct xattr_list *xlist)
{
	if (xlist != NULL) {
		struct xattr *xptr = NULL, *xtmp = NULL;

		TAILQ_FOREACH_SAFE(xptr, xlist, link, xtmp) {
			TAILQ_REMOVE(xlist, xptr, link);
			free(xptr->name);
			free(xptr->value);
			free(xptr);
		}
	}
}

static void
hexdump_ea(const char *path, const char *name, unsigned const char *buf, size_t length, int index)
{
	int i;

	if (path == NULL || name == NULL || buf == NULL || length == 0)
		return;

	xo_open_container("metadata");
	xo_emit("{:index/%d}:{:name/%s}:{:length/%zu}:",
		index, name, length);
	xo_close_container("metadata");

	xo_open_container("data");

	for (i = 0;i < length;i++)
		xo_emit("{:hex/%02x} ", (unsigned char)buf[i]);

	xo_close_container("data");
	xo_finish();
	printf("\n");
}

static void
b64dump_ea(const char *path, const char *name, const unsigned char *buf, size_t length, int index)
{
	char * b64ea = NULL;
	char * b64eashort = NULL;
	size_t b64_len = 0;
	size_t b64_len2 = length + 1;

	b64ea = (char *) base64_encode(buf, length, &b64_len);
        
        
        if (path == NULL || name == NULL || buf == NULL || length == 0) {
		printf("Exiting due to missing data \n");
		free(b64ea);
                return;
	}
                        
        xo_open_container("metadata");
        xo_emit("{:index/%d}:{:name/%s}:{:length/%zu}:",
                index, name, length);
        xo_close_container("metadata");
                
        xo_open_container("data");
	xo_emit("{:b64data/%s}", b64ea);
        xo_close_container("data");
        xo_finish();
	free(b64ea);

}

static int
process_ea_list(const char *path,
                u_int64_t flags, struct xattr_list *xlist)
{
        int ret = 0, setret = 0, index = 0;
        struct xattr *xptr = NULL, *xtmp = NULL;

        if (xlist == NULL)
                return (-1);

        TAILQ_FOREACH(xptr, xlist, link) {
                if (flags & F_HEX) {
                        hexdump_ea(path, xptr->name, xptr->value, xptr->length, index);
		}
                if (flags & F_BASE64) {
                        b64dump_ea(path, xptr->name, xptr->value, xptr->length, index);
		}
		++index;
        }

        return (ret);
}


static int
do_ea_stuff(const char *path, const char *attr, u_int64_t flags)
{
	int ret = 0;
	struct xattr_list xlist;
	TAILQ_INIT(&xlist);
	
	if (get_extended_attributes(path, &xlist, flags) < 0) {
		ret = EX_DATAERR;
		goto cleanup;
	}

	if (process_ea_list(path, flags, &xlist) < 0) {
		ret = EX_DATAERR;
	}

/*
	if (flags & F_EMIT_ALL) {
		if ((setret = emit_all(fd, path, flags, &xlist) < 0) {	
			ret = EX_DATAERR;
			goto cleanup;		
		}
		ret = setret;
	}
 */
	
cleanup:
	free_extended_attributes(&xlist);

	return (ret);
}

int
main(int argc, char *argv[])
{
#define STDIN_BUF_SZ 1024
	char	 stdin_data[STDIN_BUF_SZ];
	char	*p, *path, *realpath, *attr;

	const char *options, *attrname;
	size_t	len;
	ssize_t	ret;
	int	 ch, error, i, arg_counter, attrnamespace, minargc;

	char   *visbuf = NULL;
	int	visbuflen = 0;
	int	flags = F_NONE;
	char   *buf = NULL;
	int	buflen = 0;
	struct	sbuf *attrvalue = NULL;
	int	count_quiet = 0;
	options = "fhixba";

	argc = xo_parse_args(argc, argv);
    	if (argc < 0)
        	exit(1);

	while ((ch = getopt(argc, argv, options)) != -1) {
		switch (ch) {
		case 'f':
			flags |= F_FORCE;
			break;
		case 'h':
			flags |= F_NOFOLLOW;
			break;
		case 'i':
			flags |= F_FROM_STDIN;
			break;
		case 'x':
			flags |= F_HEX;
			break;
		case 'b':
			flags |= F_BASE64;
			break;
		case 'a':
			flags |= F_EMIT_ALL;
			break;
		case '?':
		default:
			usage();
		}
	}

	error = extattr_string_to_namespace("user", &attrnamespace);	
	if (error)
		err(-1, "%s", argv[0]);
	argc--; argv++;

	for (arg_counter = 0; arg_counter < argc; arg_counter++) {

		ret = do_ea_stuff(argv[arg_counter], attr, flags);
		
		/*
		if (flags & F_NOFOLLOW){
			ret = extattr_list_link(argv[arg_counter],
   				EXTATTR_NAMESPACE_USER, NULL, 0);
		}
		else{
			ret = extattr_list_file(argv[arg_counter],
				EXTATTR_NAMESPACE_USER, NULL, 0);
		}
		if (ret < 0){
			return (-1);
		}

		mkbuf(&buf, &buflen, ret);

		if (flags & F_NOFOLLOW){
			ret = extattr_list_link(argv[arg_counter],
				 EXTATTR_NAMESPACE_USER, buf, buflen);
		}
		else{
			ret = extattr_list_file(argv[arg_counter],
				 EXTATTR_NAMESPACE_USER, buf, buflen);
		}

		if (ret < 0)
			return (-1);	

		printf("# %s\n", argv[arg_counter]);
		for (i = 0; i < ret; i += ch + 1) {
		    ch = (unsigned char)buf[i];
	    	printf("%s%*.*s", i ? "\t" : "",
	   	 ch, ch, buf + i + 1);
		}

		if (!count_quiet || ret > 0)
			printf("\n");
		 */
	}
	return 1;
}
