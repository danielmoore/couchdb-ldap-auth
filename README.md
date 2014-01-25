# LDAP Authentication Handler for CouchDB

## Features
- Basic authentication handler
- Session handler
	- works with CouchDB built-in `cookie_authentication_handler`
- Supports users and recursive-group association

## Installation

First, check out the source and `cd` into it.

### Prerequisites
- Erlang
- Rebar

### Build from Source

```
rebar clean compile
```

### Run Tests

```
rebar test
```

### Install binaries and config

```
# Create module folder
mkdir /usr/local/lib/couchdb/erlang/lib/ldap-auth
# Copy binaries
cp -R ebin /usr/local/lib/couchdb/erlang/lib/ldap-auth/

# Copy/overwrite the default config
cp -f priv/default.d/* /usr/local/etc/couchdb/default.d/

# Copy (but don't overwrite!) the custom config
cp -n priv/local.d/* /usr/local/etc/couchdb/local.d/
```

## Configuration

See [ldap_auth.ini] (priv/local.d/ldap_auth.ini) for details.