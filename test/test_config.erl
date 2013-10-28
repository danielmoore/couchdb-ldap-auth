-module(test_config).

-export([get_config/3]).

get_config("ldap_auth", "UseSsl", _) -> "false";
get_config("ldap_auth", "LdapServer", _) -> "atlas.northhorizon.local";
get_config("ldap_auth", "BaseDN", _) -> "DC=northhorizon,DC=local";
get_config("ldap_auth", "SearchUserDN", _) -> "CN=ldapsearch,CN=Users,DC=northhorizon,DC=local";
get_config("ldap_auth", "SearchUserPassword", _) -> "Welcome1";
get_config("ldap_auth", "UserDNMapAttr", _) -> "sAMAccountName";
get_config("ldap_auth", "GroupDNMapAttr", _) -> "name";
get_config("ldap_auth", _, NotFound) -> NotFound.
