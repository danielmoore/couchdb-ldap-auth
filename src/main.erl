%%%-------------------------------------------------------------------
%%% @author dmoore
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 06. Oct 2013 3:05 PM
%%%-------------------------------------------------------------------
-module(main).

-export([start/0]).

-define(USE_SSL, false).
-define(LDAP_SERVER, "atlas.northhorizon.local").
-define(BASE_DN, "DC=northhorizon,DC=local").
-define(SEARCH_USER_DN, "CN=ldapsearch,CN=Users,DC=northhorizon,DC=local").
-define(SEARCH_USER_PASSWORD, "Welcome1").
-define(USER_DN_MAP_ATTR, "userPrincipalName").
-define(GROUP_DN_MAP_ATTR, "name").

-define(TEST_USER, "test@northhorizon.local").
-define(TEST_USER_PASSWORD, "Welcome1").

-define(b2l(V), binary_to_list(V)).
-define(l2b(V), list_to_binary(V)).

-define(LOG_DEBUG(Format, Args), io:format(Format, Args)).
-define(LOG_INFO(Format, Args) , io:format(Format, Args)).
-define(LOG_ERROR(Format, Args), io:format(Format, Args)).

-include_lib("eldap/include/eldap.hrl").

start() ->
%%   User = string:strip(io:get_line("User: "), right, $\n),
%%   Password = string:strip(io:get_line("Password: "), right, $\n),
%%
%%   authenticate(User, Password).
  authenticate(?TEST_USER, ?TEST_USER_PASSWORD).


authenticate(User, Password) ->
  LdapConnection = connect(?SEARCH_USER_DN, ?SEARCH_USER_PASSWORD),
  case query(LdapConnection, "person", eldap:equalityMatch(?USER_DN_MAP_ATTR, User)) of
    [] -> throw({ invalid_credentials });
    [#eldap_entry{ object_name = UserDN } | _] ->
      % attempt to connect as UserDN and if it doesn't throw, immediately disconnect.
      eldap:close(connect(UserDN, Password)),

      % If we're here, auth succeeded.

      io:format("user: ~p\n", [UserDN]),
      Groups = get_group_memberships(LdapConnection, UserDN),
      io:format("groups: ~p", [Groups])
  end,
  eldap:close(LdapConnection).

connect(DN, Password) ->
  case eldap:open([?LDAP_SERVER], [{ssl, ?USE_SSL}]) of
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
  TypedFilter = eldap:'and'([eldap:equalityMatch("objectClass", Type), Filter]),
  case eldap:search(LdapConnection, [{ base, ?BASE_DN }, { filter, TypedFilter }]) of
    {error, Reason} -> throw({search, Reason});
    {ok, #eldap_search_result{ entries = Result }} -> io:format("found ~p\n", [Result]), Result
  end.

get_group_memberships(LdapConnection, UserDN) ->
  Memberships = get_group_memberships(LdapConnection, sets:new(), UserDN),
  sets:to_list(Memberships).

get_group_memberships(LdapConnection, Memberships, DN) ->
  case query(LdapConnection, "group", eldap:equalityMatch("member", DN)) of
    [] -> Memberships;
    Entries ->
      ParentGroupDNs = [ {X#eldap_entry.object_name, get_record_value(X, ?GROUP_DN_MAP_ATTR)} || X <- Entries ],
      S = sets:subtract(sets:from_list(ParentGroupDNs), Memberships),
      case sets:size(S) of
        0 -> Memberships;
        _ -> sets:fold(fun (N, P) -> get_group_memberships(LdapConnection, P, N) end, sets:union(Memberships, S), S)
      end
  end.

get_record_value(Record, Field) ->
  FieldAtom = string_to_atom(Field)
  lists:filter(fun ({FieldAtom})
