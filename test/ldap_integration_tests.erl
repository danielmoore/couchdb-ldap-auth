%%%-------------------------------------------------------------------
%%% @author dmoore
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 19. Oct 2013 7:45 PM
%%%-------------------------------------------------------------------
-module(ldap_integration_tests).
-author("dmoore").

-include("couch_db.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(TEST_USER, "test.npm").
-define(TEST_USER_PASSWORD, "T32!11pm").

integration_test_() ->   io:format("Testing...", []),  run([fun () ->
  {ok, LdapConnection} = ldap_auth_gateway:connect(),
  io:format("Connect OK"),
  {ok, UserDN} = ldap_auth_gateway:authenticate(LdapConnection, ?TEST_USER, ?TEST_USER_PASSWORD),
  io:format("UserDN=~p\n", [UserDN]),
  Groups = ldap_auth_gateway:get_group_memberships(LdapConnection, UserDN),
  io:format("Groups=~p\n", [Groups]),
  eldap:close(LdapConnection)
  end]).

run(Tests) ->
  {
    setup,
    fun () ->
      meck:new(couch_config, [non_strict]),
      meck:expect(couch_config, get, fun test_config:get_config/3)
    end,
    fun (_) -> meck:unload(couch_config) end,
    fun (_) -> Tests end
  }.