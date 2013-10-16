%%%-------------------------------------------------------------------
%%% @author dmoore
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 08. Oct 2013 10:25 PM
%%%-------------------------------------------------------------------
-module(ldap_auth_config).
-author("dmoore").

%% API
-export([get_config/1]).
-include("couch_db.hrl").

get_config([]) -> [];
get_config([Key|Rem]) ->
  [case couch_config:get("ldap_auth", Key, undefined) of
    undefined -> throw({config_key_not_found, "Key not found in [ldap_auth] section of config: " ++ Key});
    Value -> Value
  end | get_config(Rem)].
