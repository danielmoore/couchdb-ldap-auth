# Changelog

## v2.0.0

### Fixes

- Issue #2: handle_admin_role is now functional.

### Enhancements

- Issue #7: All groups are now lower-cased. **Potentially backwards-incompatible**
- Issue #3: The `LdapServer` config has been replaced with `LdapServers`, which accepts a comma-separated list of servers to try. **Backwards-incompatible**

## v1.0.0

Initial version. Supports authenticating users and groups against a specified LDAP server.