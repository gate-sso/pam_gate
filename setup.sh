#!/bin/sh

PREFIX=/lib/x86_64*
SSHD_CONFIG_LOCATION=/etc/ssh/sshd_config
make
cp pam_gate.so $PREFIX/
cp gate_ssh.sh /usr/bin/

FOUND_SSHD=`grep "AuthorizedKeysCommand" $SSHD_CONFIG_LOCATION`

if "$FOUND_SSHD" == "1" ; then
  echo "AuthorizedKeysCommand /usr/bin/gate_ssh.sh" >> $SSHD_CONFIG_LOCATION
  echo "AuthorizedkeysCommandUser nobody" >> $SSHD_CONFIG_LOCATION
fi
