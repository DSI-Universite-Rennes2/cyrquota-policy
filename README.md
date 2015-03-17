Cyrus Quota Check
-----------------

**Version**:   0.3

**Author** :   Sylvain Costard - Université Rennes 2
  
**URL**: https://github.com/bb2k/cyrquota-policy 


This is a translation in python of Postfix quota integration perl script written by Omni Flux (http://www.omniflux.com/devel/)
It tries to return to overquota status of a cyrus box as fast as possible. 

**Usage** : 

cyrquota-policy.py

**Limitation** :

This method will not catch overquota accounts if postfix
rewrites the address before performing local delivery
(aliases, virtual domains).

**Logs** : 

Logging is sent to syslogd.

**Installing** :


To run this from /etc/postfix/master.cf:

    cyrquota-policy	unix	-	n	n	-	-	spawn
       user=nobody argv=/usr/bin/python /usr/local/sbin/cyrquota-policy.py

 To use this from Postfix SMTPD, use in /etc/postfix/main.cf:

    smtpd_recipient_restrictions =
    ...
    reject_unlisted_recipient,
    check_policy_service unix:private/cyrquota-policy,
    permit_sasl_authenticated,
    reject_unauth_destination
    ...

This policy should be included after reject_unlisted_recipient if used,
but before any permit rules or maps which return OK.

**Testing** :

To test this script by hand, execute:

   % python cyrquota-policy.py

Each query is a bunch of attributes. Order does not matter.

    request=smtpd_access_policy
    recipient=bar@foo.tld
    [empty line]

The policy server script will answer in the same style, with an
attribute list followed by a empty line:

    action=dunno
    [empty line]
