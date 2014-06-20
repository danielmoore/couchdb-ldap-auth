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
- eldap (bundled with Erlang >= R15B. See their [github repo][eldap].)

[eldap]: https://github.com/etnt/eldap

### Build from Source

```
rebar get-deps clean compile
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

### Authentication Handlers

The defaults included in `ldap_auth.ini` provide a basic, out-of-the-box
configuration for sessions, cookies, basic authentication, and system admin
role assignment based on LDAP. 

If you have a custom configuration of CouchDB, you may need to edit it.

Keep in mind that the first handler to authenticate a credential "wins."
Specifically, this means that if you keep the built-in 
`{couch_httpd_auth, default_authentication_handler}`, CouchDB will continue
to inspect the `_users` database for credentials and use the ini files
for system admins.

#### Basic Auth

To allow requests with the users' names and passwords encoded in the URL,
simply include ` {ldap_auth, handle_basic_auth_req}` in the
`authentication_handlers`:

[httpd]
    authentication_handlers = {ldap_auth, handle_basic_auth_req}

#### Sessions and Cookies

In order for session management and cookies to work, you need a few options set.

The first binds the `/_session` REST endpoint to the LDAP session manager.

```ini
[httpd_global_handlers]
    _session = {ldap_auth, handle_session_req}
```

The session manager will authenticate the POST payload credentials and provide
a cookie token.

In order to use the cookie token, the CouchDB built-in cookie handler must be
included in the list of authentication handlers:

[httpd]
    authentication_handlers = {couch_httpd_auth, cookie_authentication_handler}

Each time `handle_session_req` is called, the `_users` database is updated
with the user's roles. If the user document does not exist beforehand, a new one
is created; the user's password is not stored.

#### System Admin Delegation

If you'd like to use LDAP to also control the list of system administrators, 
rather than the CouchDB built-in list in .ini files, you can add 
`{ldap_auth, handle_admin_role}` to the end of the `authentication_handlers`
list.

### Options

#### UseSSL

Set to `true` to use SSL to bind to the LDAP server. Default: `false`

#### LdapServers

The LDAP servers to use for searches and authentication, separated by commas. These will be tried in-order.

#### BaseDN

The distinguished name to constrain the scope of which users may authenticate.
This may be as broad (the entire domain) or narrow (an OU or even a group) as
needed.

#### SearchUserDN and SearchUserPassword

In order to authenticate users by an arbitrary attribute (like username) instead
of a distinguished name, a service user must be available with permission to
query LDAP (no other permissions are needed). Some LDAP servers provide anonymous
querying, but this is not recommended by LDAP vendors. 

The SearchUserDN and SearchUserPassword should be set to the credentials of the
desired service user. If anonymous queries are allowed and preferred, the DN
must be set to the anon DN, but the password may remain blank.

#### UserDNMapAttr

The attribute to use as the login name for CouchDB. On Active Directory, you 
might use:

- `sAMAccountName`, e.g. jsmith
- `userPrincipalName`, e.g. jsmith@example.com<br/>
  NOTE: if you use userPrincipalName, be sure to URL-encode the username when using basic auth.<br/>
  e.g. `http://jsmith%40example.com:password@example.com:5984`

Any attribute could be used, though.

#### GroupDNMapAttr

The same as UserDNMapAttr, but for groups. Most LDAP software has a `name`
attribute on group objects.

#### SystemAdminRoleName

If you're using system admin delegation, this is the name of the role that will
be promoted to `_admin`, aka the system admin.
