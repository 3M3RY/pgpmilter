# PGP_Milter

A milter for postfix that encrypts emails. 

Results may vary, as MIME is pathetic, fragile, and ambigiously defined.


## Disclaimer
This software may be illegal in the united states as it passes private
communications through a trapdoor encryption operation.


## TODO
+ Better mime supportt
+ don't re-ecrypt encrypted messages
+ encrypt headers
+ In band key registration


## Dependencies
* libmilter (part of sendmail) http://www.sendmail.org/
* gpgme http://www.gnupg.org/related_software/gpgme


## Install

    autoreconf
    automake
    ./configure
    make
    make install

Or if you're on Gentoo:
    USE="git" emerge -uN layman
    layman -S
    layman -a emery
    emerge mail-filter/pgpmilter


## Configuration
Add a line like this to /etc/postfix/main.cf

    smtpd_milters = inet:localhost:8989

Start pgp_milter like this:

    ./pgp_milter -p inet:8989

The user that is running the milter should have keys for email
recipients it it's gpg keyring. If the milter can't get a key for
atleast one recipient, the message should pass through unmodified.
