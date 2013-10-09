%%%-------------------------------------------------------------------
%%% @author dmoore
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 08. Oct 2013 10:21 PM
%%%-------------------------------------------------------------------
-module(ldap_integration).
-author("dmoore").

-include_lib("eldap/include/eldap.hrl").

%% API
-export([connect/0, authenticate/3, get_group_memberships/2]).

-import(config, [get_config/1]).

authenticate(LdapConnection, User, Password) ->
  [UserDNMapAttr] = get_config(["UserDNMapAttr"]),

  case query(LdapConnection, "person", eldap:equalityMatch(UserDNMapAttr, User)) of
    [] -> throw({ invalid_credentials });
    [#eldap_entry{ object_name = UserDN } | _] ->
      % attempt to connect as UserDN and if it doesn't throw, immediately disconnect.
      eldap:close(connect(UserDN, Password)),

      UserDN
  end.

connect() ->
  [SearchUserDN, SearchUserPassword] = get_config(["SearchUserDN", "SearchUserPassword"]),
  io:format("Connecting with ~s / ~s\n", [SearchUserDN, SearchUserPassword]),
  connect(SearchUserDN, SearchUserPassword).

connect(DN, Password) ->
  [LdapServer, UseSsl] = get_config(["LdapServer", "UseSsl"]),
  case eldap:open([LdapServer], [{ssl, UseSsl}]) of
    {error, Reason} -> throw({ ldap_connection_error, Reason });
    {ok, LdapConnection} ->
      case eldap:simple_bind(LdapConnection, DN, Password) of
        {error, _} ->
          eldap:close(LdapConnection),
          throw({ invalid_credentials });
        ok -> LdapConnection
      end
  end.

query(LdapConnection, Type, Filter) ->
  [BaseDN] = get_config(["BaseDN"]),
  TypedFilter = eldap:'and'([eldap:equalityMatch("objectClass", Type), Filter]),
  case eldap:search(LdapConnection, [{ base, BaseDN }, { filter, TypedFilter }]) of
    {error, Reason} -> throw({search, Reason});
    {ok, #eldap_search_result{ entries = Result }} -> Result
  end.

get_group_memberships(LdapConnection, UserDN) ->
  Memberships = get_group_memberships(LdapConnection, sets:new(), UserDN),
  [ element(2, T) || T <- sets:to_list(Memberships) ].

get_group_memberships(LdapConnection, Memberships, DN) ->
  [GroupDNMapAttr] = get_config(["GroupDNMapAttr"]),
  case query(LdapConnection, "group", eldap:equalityMatch("member", DN)) of
    [] -> Memberships;
    Entries ->
      ParentGroupDNs = [
        case element(2, lists:keyfind(GroupDNMapAttr, 1, X#eldap_entry.attributes)) of
          [Value|_] -> {X#eldap_entry.object_name, Value};
          _ -> throw({no_value})
        end || X <- Entries
      ],
      S = sets:subtract(sets:from_list(ParentGroupDNs), Memberships),
      case sets:size(S) of
        0 -> Memberships;
        _ -> sets:fold(fun ({N, _}, P) -> get_group_memberships(LdapConnection, P, N) end, sets:union(Memberships, S), S)
      end
  end.
