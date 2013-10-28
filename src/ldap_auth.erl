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

-define(replace(L, K, V), lists:keystore(K, 1, L, {K, V})).

%% API
-export([handle_basic_auth_req/1, handle_cookie_auth_req/1, handle_admin_role/1]).
-export([handle_session_req/1]).

-import(couch_httpd, [header_value/2, send_json/2,send_json/4, send_method_not_allowed/2]).

-import(ldap_auth_config, [get_config/1]).
-import(ldap_auth_gateway, [connect/0, authenticate/3, get_user_dn/2, get_group_memberships/2]).

% many functions in here are taken from or based on things here:
% https://github.com/davisp/couchdb/blob/5d4ef93048f4aca24bef00fb5b2c13c54c2bbbb3/src/couchdb/couch_httpd_auth.erl

handle_basic_auth_req(Req) ->
  case basic_name_pw(Req) of
    {UserName, Password} ->
      case authenticate_user(UserName, Password) of
        {ok, Roles} ->
          Req#httpd{
            user_ctx = #user_ctx {
              name = ?l2b(UserName),
              roles = Roles
            }
          };
        _ -> Req
      end;
    nil ->
      Req
  end.

handle_admin_role(#httpd{ user_ctx = #user_ctx{ roles = Roles } = UserCtx } = Req) when size(Roles) > 0 ->
  [SystemAdminRoleName] = get_config(["SystemAdminRoleName"]),
  case lists:member(SystemAdminRoleName, Roles) of
    true -> Req#httpd{ user_ctx = UserCtx#user_ctx{ roles = [<<"_admin">>|Roles] } };
    _ -> Req
  end;
handle_admin_role(Req) -> Req.

handle_cookie_auth_req(#httpd{mochi_req=MochiReq}=Req) ->
  case MochiReq:get_cookie_value("AuthSession") of
    undefined -> Req;
    [] -> Req;
    Cookie ->
      [User, TimeStr, HashStr] = begin
        AuthSession = couch_util:decodeBase64Url(Cookie),
        case re:split(?b2l(AuthSession), ":", [{return, list}, {parts, 3}]) of
          [_, _, _] = Parts -> Parts;
          _ ->
            Reason = <<"Malformed AuthSession cookie. Please clear your cookies.">>,
            throw({bad_request, Reason})
        end
      end,
      % Verify expiry and hash
      CurrentTime = make_cookie_time(),
      case couch_config:get("couch_httpd_auth", "secret", nil) of
        nil ->
          ?LOG_DEBUG("cookie auth secret is not set",[]),
          Req;
        SecretStr ->
          Secret = ?l2b(SecretStr),
          case couch_auth_cache:get_user_creds(User) of
            nil -> Req;
            UserProps ->
              ?LOG_INFO("Got user creds: ~p", [UserProps]),
              UserSalt = couch_util:get_value(<<"salt">>, UserProps, <<"">>),
              FullSecret = <<Secret/binary, UserSalt/binary>>,
              ExpectedHash = crypto:hmac(sha, FullSecret, User ++ ":" ++ TimeStr),
              Hash = ?l2b(HashStr),
              Timeout = list_to_integer(
                couch_config:get("couch_httpd_auth", "timeout", "600")),
              ?LOG_DEBUG("timeout ~p", [Timeout]),
              ?LOG_INFO("Now: ~p, Cut off: ~p", [CurrentTime, list_to_integer(TimeStr, 16) + Timeout]),
              case {(catch list_to_integer(TimeStr, 16)), couch_passwords:verify(ExpectedHash, Hash)} of
                {TimeStamp, true} when CurrentTime < TimeStamp + Timeout ->
                  case get_user_roles(User) of
                    {error, _} -> Req;
                    {ok, Roles} ->
                      TimeLeft = TimeStamp + Timeout - CurrentTime,
                      ?LOG_DEBUG("Successful cookie auth as: ~p", [User]),
                      Req#httpd{
                        user_ctx = #user_ctx{
                          name = ?l2b(User),
                          roles = Roles
                        },
                        auth = { FullSecret, TimeLeft < Timeout * 0.9 }
                      }
                  end;
                V ->
                  ?LOG_INFO("Result: ~p", [V]),
                  Req
              end
          end
      end
  end.

% session handlers
% Login handler with user db
handle_session_req(#httpd{method='POST', mochi_req=MochiReq}=Req) ->
  {UserName, Password} = get_req_credentials(Req),
  ?LOG_DEBUG("Attempt Login: ~s",[UserName]),
  User = case couch_auth_cache:get_user_creds(UserName) of
           nil -> [];
           Result -> Result
         end,
  UserSalt = couch_util:get_value(<<"salt">>, User, <<>>),
  case authenticate_user(UserName, Password) of
    {ok, Roles} ->
      set_user_roles(UserName, Roles),

      % setup the session cookie
      Secret = ?l2b(ensure_cookie_auth_secret()),
      CurrentTime = make_cookie_time(),
      Cookie = cookie_auth_cookie(Req, ?b2l(UserName), <<Secret/binary, UserSalt/binary>>, CurrentTime),
      % TODO document the "next" feature in Futon
      {Code, Headers} = redirect_or_default(Req, "next", {200, [Cookie]}),
      send_json(Req#httpd{req_body=MochiReq:recv_body()}, Code, Headers,
        {[
          {ok, true},
          {name, UserName},
          {roles, Roles}
        ]});
    _Else ->
      % clear the session
      Cookie = mochiweb_cookies:cookie("AuthSession", "", [{path, "/"}] ++ cookie_scheme(Req)),
      {Code, Headers} = redirect_or_default(Req, "fail", {401, [Cookie]}),
      send_json(Req, Code, Headers, {[{error, <<"unauthorized">>},{reason, <<"Name or password is incorrect.">>}]})
  end;
% get user info
% GET /_session
handle_session_req(#httpd{method='GET', user_ctx=UserCtx}=Req) ->
  Name = UserCtx#user_ctx.name,
  ForceLogin = couch_httpd:qs_value(Req, "basic", "false"),
  case {Name, ForceLogin} of
    {null, "true"} ->
      throw({unauthorized, <<"Please login.">>});
    {Name, _} ->
      send_json(Req, {[
        % remove this ok
        {ok, true},
        {<<"userCtx">>, {[
          {name, Name},
          {roles, UserCtx#user_ctx.roles}
        ]}},
        {info, {get_auth_info(Req)}}
      ]})
  end;
% logout by deleting the session
handle_session_req(#httpd{method='DELETE'}=Req) ->
  Cookie = mochiweb_cookies:cookie("AuthSession", "", [{path, "/"}] ++ cookie_scheme(Req)),
  {Code, Headers} = redirect_or_default(Req, "next", {200, [Cookie]}),
  send_json(Req, Code, Headers, {[{ok, true}]});
handle_session_req(Req) ->
  send_method_not_allowed(Req, "GET,HEAD,POST,DELETE").

auth_name(String) when is_list(String) ->
  [_,_,_,_,_,Name|_] = re:split(String, "[\\W_]", [{return, list}]),
  ?l2b(Name).

redirect_or_default(Req, RedirectHeaderKey, {_DefaultCode, DefaultHeaders} = Default) ->
  case couch_httpd:qs_value(Req, RedirectHeaderKey, nil) of
    nil -> Default;
    Redirect ->
      {302, DefaultHeaders ++ {"Location", couch_httpd:absolute_uri(Req, Redirect)}}
  end.

ensure_cookie_auth_secret() ->
  case couch_config:get("couch_httpd_auth", "secret", nil) of
    nil ->
      NewSecret = ?b2l(couch_uuids:random()),
      couch_config:set("couch_httpd_auth", "secret", NewSecret),
      NewSecret;
    Secret -> Secret
  end.

make_cookie_time() ->
  {NowMS, NowS, _} = erlang:now(),
  NowMS * 1000000 + NowS.

cookie_scheme(#httpd{mochi_req=MochiReq}) ->
  [{http_only, true}] ++
  case MochiReq:get(scheme) of
    http -> [];
    https -> [{secure, true}]
  end.

cookie_auth_cookie(Req, User, Secret, TimeStamp) ->
  SessionData = User ++ ":" ++ erlang:integer_to_list(TimeStamp, 16),
  Hash = crypto:hmac(sha, Secret, SessionData),
  mochiweb_cookies:cookie("AuthSession",
    couch_util:encodeBase64Url(SessionData ++ ":" ++ ?b2l(Hash)),
    [{path, "/"}] ++ cookie_scheme(Req) ++ max_age()).

max_age() ->
  case couch_config:get("couch_httpd_auth", "allow_persistent_cookies", "false") of
    "false" ->
      [];
    "true" ->
      Timeout = list_to_integer(
        couch_config:get("couch_httpd_auth", "timeout", "600")),
      [{max_age, Timeout}]
  end.

get_auth_info(#httpd{ user_ctx = #user_ctx { handler = Handler } }) ->
  [
    {authentication_db, ?l2b(couch_config:get("couch_httpd_auth", "authentication_db"))},
    {authentication_handlers, [auth_name(H) || H <- couch_httpd:make_fun_spec_strs(
      couch_config:get("httpd", "authentication_handlers"))]}
  ] ++
  case Handler of
    undefined -> [];
    Handler -> [{ authenticated, auth_name(?b2l(Handler)) }]
  end.

get_req_credentials(#httpd{method='POST', mochi_req=MochiReq}) ->
  ReqBody = MochiReq:recv_body(),
  Form = case MochiReq:get_primary_header_value("content-type") of
           % content type should be json
           "application/x-www-form-urlencoded" ++ _ ->
             mochiweb_util:parse_qs(ReqBody);
           "application/json" ++ _ ->
             {Pairs} = ?JSON_DECODE(ReqBody),
             [{?b2l(Key), ?b2l(Value)} || {Key, Value} <- Pairs];
           _ ->
             []
         end,
  UserName = ?l2b(couch_util:get_value("name", Form, "")),
  Password = ?l2b(couch_util:get_value("password", Form, "")),
  {UserName, Password}.

set_user_roles(UserName, Roles) ->
  ?LOG_INFO("Assigning user ~s roles: ~p", [UserName, Roles]),

  DbName = ?l2b(couch_config:get("couch_httpd_auth", "authentication_db")),
  DbOptions = [{user_ctx, #user_ctx{roles = [<<"_admin">>]}}],
  {ok, AuthDb} = couch_db:open_int(DbName, DbOptions),

  DocId =  <<<<"org.couchdb.user:">>/binary, UserName/binary>>,
  Doc = case couch_db:open_doc(AuthDb, DocId, [ejson_body]) of
          {ok, OldDoc = #doc{body = {DocBody}}} ->
            OldDoc#doc{
              body = {?replace(DocBody, <<"roles">>, Roles)}
            };
          {not_found, _} ->
            #doc{
              id = DocId,
              body = {[
                {'_id', DocId},
                {type, <<"user">>},
                {name, UserName},
                {salt, couch_uuids:random()},
                {roles, Roles}
              ]}
            }
        end,

  ?LOG_INFO("Assigning _users/~s roles ~p", [DocId, Roles]),

  % disable validation so we can put _admin in the _users db.
  case couch_db:update_doc(AuthDb#db{ validate_doc_funs=[] }, Doc, []) of
    {ok, _} -> ok;
    {error, _} = Error -> throw(Error)
  end.

get_user_roles(User) when User =/= "" ->
  case connect() of
    {error, _} = Error -> Error;
    {ok, LdapConnection} ->
      case get_user_dn(LdapConnection, User) of
        {error, _} = Error ->
          eldap:close(LdapConnection),
          Error;
        {ok, UserDN} ->
          Roles = get_group_memberships(LdapConnection, UserDN),
          eldap:close(LdapConnection),
          {ok, [ ?l2b(R) || R <- Roles ]}
      end
  end.

authenticate_user(_UserName, _Password) when _UserName == <<"">>; _Password == <<"">> ->
  {error, missing_user_name_or_password};
authenticate_user(UserName, Password) ->
  ?LOG_INFO("Authenticating user: ~p", [UserName]),
  case connect() of
    {error, Reason} = Error ->
      ?LOG_ERROR("Could not connect to LDAP. Reason: ~p", [Reason]),
      Error;
    {ok, LdapConnection} ->
      case authenticate(LdapConnection, UserName, Password) of
        {error, Reason} = Error ->
          ?LOG_ERROR("Could not authenticate user ~p over LDAP. Reason: ~p", [UserName, Reason]),
          Error;
        {ok, UserDN} ->
          Groups = get_group_memberships(LdapConnection, UserDN),
          eldap:close(LdapConnection),
          {ok, [ ?l2b(G) || G <- Groups ]}
      end
  end.

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
      ?LOG_INFO("Could not recognize auth header ~p", [AuthorizationHeader]),
      nil
  end.