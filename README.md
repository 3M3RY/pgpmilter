# PGP_Milter

A milter for postfix that encrypts emails. 

Results may vary, as MIME is a pathetic, fragile, and ambigiously defined encoding.

## Disclaimer
This software may be illegal in the united states as it passes private
communications through trapdoor encryption.

## TODO
+ Better mime supportt
+ don't re-ecrypt encrypted messages
+ encrypt headers

## Dependencies
* libmilter (part of sendmail) http://www.sendmail.org/
* gpgme http://www.gnupg.org/related_software/gpgme


## Install

    ./configure
    make
    make install


## Configuration
Add a line like this to /etc/postfix/main.cf

    smtpd_milters = inet:localhost:8989

Start pgp_milter like this:

    ./pgp_milter -p inet:8989

The user that is running the milter should have keys for email
recipients it it's gpg keyring. If the milter can't get a key for
atleast one recipient, the message should pass through unmodified.