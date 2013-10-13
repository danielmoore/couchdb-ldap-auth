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

-define(TEST_USER, "test@northhorizon.local").
-define(TEST_USER_PASSWORD, "Welcome1").

-define(b2l(V), binary_to_list(V)).
-define(l2b(V), list_to_binary(V)).

-define(LOG_DEBUG(Format, Args), io:format(Format, Args)).
-define(LOG_INFO(Format, Args) , io:format(Format, Args)).
-define(LOG_ERROR(Format, Args), io:format(Format, Args)).

-include_lib("eldap/include/eldap.hrl").

-import(ldap_auth_gateway, [connect/0, authenticate/3, get_group_memberships/2]).

start() ->
%%   User = string:strip(io:get_line("User: "), right, $\n),
%%   Password = string:strip(io:get_line("Password: "), right, $\n),
%%
%%   authenticate(User, Password).
  LdapConnection = connect(),
  UserDN = authenticate(LdapConnection, ?TEST_USER, ?TEST_USER_PASSWORD),
  Groups = get_group_memberships(LdapConnection, UserDN),

  io:format("user: ~p\ngroups: ~p\n", [UserDN, Groups]).

