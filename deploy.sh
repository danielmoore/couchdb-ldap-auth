#!/bin/sh

couch_etc=$(cd $(dirname $(which couchdb))/../etc/couchdb && pwd)
couch_home=$(cd $(dirname $(which couchdb)) && cd $(dirname $(readlink couchdb))/.. && pwd)

couch_lib=$couch_home/lib/couchdb/erlang/lib

echo couch_etc $couch_etc
echo couch_home $couch_home
echo couch_lib $couch_lib

rebar clean compile

if [ -e "$couch_lib/ldap-auth" ]; then
    rm -rf $couch_lib/ldap-auth;
fi

mkdir $couch_lib/ldap-auth
cp -r ./ebin $couch_lib/ldap-auth/

cp -f ./priv/default.d/* $couch_etc/default.d/
cp -n ./priv/local.d/* $couch_etc/local.d/
