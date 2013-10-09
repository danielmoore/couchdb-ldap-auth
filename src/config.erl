%%%-------------------------------------------------------------------
%%% @author dmoore
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 08. Oct 2013 10:25 PM
%%%-------------------------------------------------------------------
-module(config).
-author("dmoore").

%% API
-export([get_config/1]).

get_config([]) -> [];
get_config([Key|Rem]) ->
  [case Key of
    "UseSsl" -> false;
    "LdapServer" -> "atlas.northhorizon.local";
     "BaseDN" -> "DC=northhorizon,DC=local";
     "SearchUserDN" -> "CN=ldapsearch,CN=Users,DC=northhorizon,DC=local";
     "SearchUserPassword" -> "Welcome1";
     "UserDNMapAttr" -> "userPrincipalName";
     "GroupDNMapAttr" -> "name"
  end | get_config(Rem)].
