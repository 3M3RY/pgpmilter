/*   gpg_filter - A Milter to PGP encrypt message bodies.    
*    Copyright (C) 2013  Emery Hemingway
*
*    This program is free software: you can redistribute it and/or modify
*    it under the terms of the GNU Affero General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU Affero General Public License for more details.
*
*    You should have received a copy of the GNU Affero General Public License
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "libmilter/mfapi.h"
#include <gpgme/gpgme.h>

#ifndef bool
# define bool	int
# define TRUE	1
# define FALSE	0
#endif /* ! bool */

#define MAX_RECIPIENTS 32
#define BUF_SIZE 512

#define BODY_TAIL "\n--PGP-Milter--\n"
#define BODY_TAIL_LEN 16

struct mlfiPriv {
  gpgme_ctx_t  gpgctx;
  gpgme_key_t keys[MAX_RECIPIENTS];
  int key_index;
  gpgme_data_t plain, cipher;
  char *fromaddr;
  char *toaddr;
  int importing;
};

#define MLFIPRIV	((struct mlfiPriv *) smfi_getpriv(ctx))

extern sfsistat		mlfi_cleanup(SMFICTX *);

sfsistat
fail_from_gpgme(gpgme_error_t err) {
  fprintf(stderr, "GPGME error: %s:%s", 
          gpgme_strsource(err), gpgme_strerror(err));
  return SMFIS_TEMPFAIL;
}

sfsistat
mlfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
  struct mlfiPriv *priv;
  gpgme_error_t err;
  
  /* allocate some private memory */
  priv = malloc(sizeof *priv);
  if (priv == NULL) {
    /* can't accept this message right now */
    return SMFIS_TEMPFAIL;
  }
  memset(priv, '\0', sizeof *priv);
  
  /* save the private data */
  smfi_setpriv(ctx, priv);
    
  err = gpgme_new(&priv->gpgctx);
  if (err) 
    fail_from_gpgme(err);
  gpgme_set_armor(priv->gpgctx, 1);
    
  /* continue processing */
  return SMFIS_CONTINUE;
}

sfsistat mlfi_envfrom(SMFICTX *ctx, char **argv) {
  struct mlfiPriv *priv = MLFIPRIV;

  priv->fromaddr = argv[0];

  return SMFIS_CONTINUE;
}

sfsistat
mlfi_envrcpt(SMFICTX *ctx, char **argv) {
  struct mlfiPriv *priv = MLFIPRIV;
  gpgme_error_t err;
  char *recipient;
  
  if (priv->key_index == MAX_RECIPIENTS)
    return SMFIS_REJECT;

  if (strncasecmp(argv[0], "<pgp-import@", 12) == 0) {
    priv->importing = 1;
    priv->toaddr = argv[0];
  }

  recipient = argv[0]+1;
  recipient[strlen(recipient) - 1] = '\0';

  // This could be used to check signatures
  err = gpgme_get_key(priv->gpgctx, recipient, &priv->keys[priv->key_index], 0);
  if (!err) 
    priv->key_index++;
  
  return SMFIS_CONTINUE;
}

sfsistat
mlfi_eoh(SMFICTX *ctx) {
  struct mlfiPriv *priv = MLFIPRIV;
  gpgme_error_t err;

  if (priv->keys[0] == NULL)
    return SMFIS_CONTINUE;
  
  err = gpgme_data_new(&priv->plain);
  if (err)
    fail_from_gpgme(err);
  
  return SMFIS_CONTINUE;
}

sfsistat
mlfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen) {
  struct mlfiPriv *priv = MLFIPRIV;
  
  if (priv->plain == NULL)
    return SMFIS_CONTINUE;
  
  ssize_t len;
  gpgme_error_t err;
  
  len = gpgme_data_write(priv->plain, bodyp, bodylen);
  if (len == -1) {
    fail_from_gpgme(gpgme_error_from_errno(errno));
    fprintf(stderr, "error pushing body to gpgme buffer: %s:%s\n",
            gpgme_strsource(err), gpgme_strerror(err));
  }
  return SMFIS_CONTINUE;
}

int
verifykeyowner(gpgme_ctx_t ctx, char *fingerprint, char *address) {
  gpgme_error_t err;
  gpgme_key_t key;
  err = gpgme_op_keylist_start(ctx, fingerprint, 0);
  if (err)
    return -1;
  
  while (!err)
    {
      err = gpgme_op_keylist_next(ctx, &key);
      if (err)
        printf("%s:", key->subkeys->keyid);
      if (key->uids && key->uids->name)
        printf(" %s", key->uids->name);
      if (key->uids && key->uids->email)
        printf (" <%s>", key->uids->email);
      putchar('\n');
      gpgme_key_release(key);
    }
  if (err != GPG_ERR_EOF)
    return -1;
  gpgme_op_keylist_end(ctx);
}

sfsistat
mlfi_eom(SMFICTX *ctx) {
  struct mlfiPriv *priv = MLFIPRIV;
  char *authen;
  gpgme_error_t err;
  gpgme_import_result_t import_result;
  gpgme_import_status_t key_status;
  int ret;
  char buf[BUF_SIZE];
  gpgme_encrypt_result_t encrypt_result;

  authen = smfi_getsymval(ctx, "{auth_authen}");


  if (priv->importing) {
    if (authen == NULL) {
        return SMFIS_REJECT;
    }

    smfi_chgfrom(ctx, priv->toaddr, NULL);
    smfi_delrcpt(ctx, priv->toaddr);
    smfi_addrcpt(ctx, priv->fromaddr);

    ret = gpgme_data_seek(priv->plain, 0, SEEK_SET);
    if (ret)
      return fail_from_gpgme(gpgme_err_code_from_errno(errno));
    
    err = gpgme_op_import(priv->gpgctx, priv->plain);
    if (err)
      return SMFIS_REJECT;

    key_status = import_result->imports;
    while (key_status) {
      verifykeyowner(priv->gpgctx, key_status->fpr, priv->fromaddr);
      key_status = key_status->next;
    }
    
    if (import_result->imported)
      sprintf(buf, "Imported %d new keys, %d unchanged.\n",
              import_result->imported, import_result->unchanged);
    else
      sprintf(buf, "Recieved %d keys, but none imported.\n", 
              import_result->considered);

    smfi_replacebody(ctx, buf, strlen(buf));
    return SMFIS_CONTINUE;
  }

  if (priv->keys[0] == NULL)
    return SMFIS_CONTINUE;
    
  err = gpgme_data_new(&priv->cipher);
  if (err) {
    fprintf(stderr, "error creating ciphertext buffer: %s:%s\n",
            gpgme_strsource(err), gpgme_strerror(err));
  }

  ret = gpgme_data_seek(priv->plain, 0, SEEK_SET);
  if (ret)
    return fail_from_gpgme(gpgme_err_code_from_errno(errno));
  
  err = gpgme_op_encrypt(priv->gpgctx, priv->keys, GPGME_ENCRYPT_ALWAYS_TRUST,
                         priv->plain, priv->cipher);
  if (err) {
      fprintf(stderr, "error encrypting gpgme buffer: %s:%s\n",
              gpgme_strsource(err), gpgme_strerror(err));
  }
  
  encrypt_result = gpgme_op_encrypt_result(priv->gpgctx);
  if (encrypt_result->invalid_recipients) {
    fprintf (stderr, "Invalid recipient encountered: %s\n",
             encrypt_result->invalid_recipients->fpr);
    exit (1);
  }
  
  ret = gpgme_data_seek(priv->cipher, 0, SEEK_SET);
  if (ret)
    return fail_from_gpgme(gpgme_err_code_from_errno(errno));
  
  smfi_addheader(ctx, "Mime-Version",  "1.0");
  smfi_replacebody(ctx, "Content-Type: multipart/encrypted; boundary=\"PGP_Milter\";\n  protocol=\"application/pgp-encrypted\"\n\n", 98);
  smfi_replacebody(ctx, "--PGP_Milter\n", 13);
  smfi_replacebody(ctx, "Content-Type: application/pgp-encrypted\n\n", 41);
  smfi_replacebody(ctx, "Version: 1\n\n", 12);
  smfi_replacebody(ctx, "--PGP_Milter\n", 13);
  smfi_replacebody(ctx, "Content-Type: application/octet-stream\n\n", 40);
  
  while ((ret = gpgme_data_read(priv->cipher, buf, BUF_SIZE)) > 0)
    smfi_replacebody(ctx, buf, ret);
  if (ret < 0)
    return fail_from_gpgme(gpgme_err_code_from_errno(errno));  
  
  smfi_replacebody(ctx, "\n--PGP_Milter--\n", 16);
  
  return mlfi_cleanup(ctx);
}

sfsistat
mlfi_abort(SMFICTX *ctx) {
  return mlfi_cleanup(ctx);
}

sfsistat
mlfi_cleanup(SMFICTX *ctx) {
  struct mlfiPriv *priv = MLFIPRIV;
  
  if (priv == NULL)
    return SMFIS_CONTINUE;
  
  mlfi_close(ctx);
  
  return SMFIS_CONTINUE;
}

mlfi_close(SMFICTX *ctx) {
  struct mlfiPriv *priv = MLFIPRIV;
  int i;
  
  if (priv == NULL)
    return SMFIS_CONTINUE;

  for (i = 0; priv->keys[i]; i++)
    gpgme_key_unref(priv->keys[i]);
  
    if (priv->plain != NULL)
      gpgme_data_release(priv->plain);
    if (priv->cipher != NULL)
      gpgme_data_release(priv->cipher);

    if (priv->gpgctx != NULL)
      gpgme_release(priv->gpgctx);
    
    free(priv);
    smfi_setpriv(ctx, NULL);
    return SMFIS_CONTINUE;
}

struct smfiDesc smfilter =
  {
    "PGPMilter",	// filter name
    SMFI_VERSION,	// version code -- do not change
    SMFIF_ADDHDRS|SMFIF_CHGFROM|SMFIF_ADDRCPT|SMFIF_DELRCPT|SMFIF_CHGBODY, // flags
    mlfi_connect, // connection info filter
    NULL,	  // SMTP HELO command filter
    mlfi_envfrom, // envelope sender filter
    mlfi_envrcpt, // envelope recipient filter
    NULL,         // header filter
    mlfi_eoh,	  // end of header
    mlfi_body,	  // body block filter
    mlfi_eom,	  // end of message
    mlfi_abort,	  // message aborted
    mlfi_close,	  // connection cleanup
    NULL,   	  // unknown SMTP commands
    NULL,    	  // DATA command
    NULL     	  // Once, at the start of each SMTP connection
  };

static void
usage(char *prog) {
  fprintf(stderr,
          "Usage: %s -p socket-addr [-t timeout] \n", prog);
}

int
main(int argc, char **argv) {
	bool setconn = FALSE;
	int c;
	const char *args = "p:t:r:a:h";
	extern char *optarg;

	// Process command line options */
	while ((c = getopt(argc, argv, args)) != -1)
	{
		switch (c)
		{
		  case 'p':
			if (optarg == NULL || *optarg == '\0')
			{
				(void) fprintf(stderr, "Illegal conn: %s\n",
					       optarg);
				exit(EX_USAGE);
			}
			if (smfi_setconn(optarg) == MI_FAILURE)
			{
				(void) fprintf(stderr,
					       "smfi_setconn failed\n");
				exit(EX_SOFTWARE);
			}

			/*
			**  If we're using a local socket, make sure it
			**  doesn't already exist.  Don't ever run this
			**  code as root!!
			*/

			if (strncasecmp(optarg, "unix:", 5) == 0)
				unlink(optarg + 5);
			else if (strncasecmp(optarg, "local:", 6) == 0)
				unlink(optarg + 6);
			setconn = TRUE;
			break;

		  case 't':
			if (optarg == NULL || *optarg == '\0')
			{
				(void) fprintf(stderr, "Illegal timeout: %s\n",
					       optarg);
				exit(EX_USAGE);
			}
			if (smfi_settimeout(atoi(optarg)) == MI_FAILURE)
			{
				(void) fprintf(stderr,
					       "smfi_settimeout failed\n");
				exit(EX_SOFTWARE);
			}
			break;

		  case 'h':
		  default:
			usage(argv[0]);
			exit(EX_USAGE);
		}
	}
	if (!setconn)
	{
		fprintf(stderr, "%s: Missing required -p argument\n", argv[0]);
		usage(argv[0]);
		exit(EX_USAGE);
	}

        gpgme_error_t err;
        gpgme_check_version (NULL);
        err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
        if (err) {
          fprintf(stderr, "%s: %s\n", gpgme_strsource(err), gpgme_strerror(err));
          exit(1);
        }

	if (smfi_register(smfilter) == MI_FAILURE) {
          fprintf(stderr, "smfi_register failed\n");
          exit(EX_UNAVAILABLE);
	}
	return smfi_main();
}
