%%%-------------------------------------------------------------------
%%% @author dmoore
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 13. Oct 2013 6:09 PM
%%%-------------------------------------------------------------------
-module(ldap_auth).
-author("dmoore").
-include("couch_db.hrl").

%% API
-export([handle_req/1]).

-import(ldap_auth_gateway, [connect/0, authenticate/3, get_group_memberships/2]).

handle_req(#httpd{ method='GET' } = Req) ->
  case basic_name_pw(Req) of
    {User, Password} ->
      LdapConnection = connect(),
      UserDN = authenticate(LdapConnection, User, Password),
      Groups = get_group_memberships(LdapConnection, UserDN),
      eldap:close(LdapConnection),
      Req#httpd{
        user_ctx = #user_ctx{
          name = ?l2b(User),
          roles = Groups
        }
      };
    nil -> Req
  end;

handle_req(Req) ->
  couch_httpd:send_method_not_allowed(Req, "GET").


% taken from https://github.com/davisp/couchdb/blob/5d4ef93048f4aca24bef00fb5b2c13c54c2bbbb3/src/couchdb/couch_httpd_auth.erl#L46-L62
basic_name_pw(Req) ->
  AuthorizationHeader = couch_httpd:header_value(Req, "Authorization"),
  case AuthorizationHeader of
    "Basic " ++ Base64Value ->
      case re:split(base64:decode(Base64Value), ":",
        [{return, list}, {parts, 2}]) of
        ["_", "_"] ->
          % special name and pass to be logged out
          nil;
        [User, Pass] ->
          {User, Pass};
        _ ->
          nil
      end;
    _ ->
      nil
  end.