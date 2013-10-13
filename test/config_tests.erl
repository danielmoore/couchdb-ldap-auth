-module(config_tests).

-include_lib("eunit/include/eunit.hrl").
-import(ldap_auth_config, [get_config/1]).

found_1_test_() -> run([
  ?_assertEqual(get_config(["foo"]), ["oof"]),
  ?_assertEqual(get_config(["bar"]), ["rab"])
]).

not_found_1_test_() -> run([
  ?_assertThrow({config_key_not_found, _}, get_config(["does_not_exist"]))
]).

found_2_test_() -> run([
  ?_assertEqual(get_config(["foo", "bar"]), ["oof", "rab"]),
  ?_assertEqual(get_config(["bar", "foo"]), ["rab", "oof"])
]).

not_found_2_test_() -> run([
  ?_assertThrow({config_key_not_found, _}, get_config(["does_not_exist", "foo", "bar"])),
  ?_assertThrow({config_key_not_found, _}, get_config(["foo", "does_not_exist", "bar"])),
  ?_assertThrow({config_key_not_found, _}, get_config(["foo", "bar", "does_not_exist"]))
]).

run(Tests) ->
  {
    setup,
    fun () ->
      meck:new(couch_config),
      meck:expect(couch_config, get,
        fun ("ldap_auth", "foo", _) -> "oof";
            ("ldap_auth", "bar", _) -> "rab";
            ("ldap_auth", _, NotFound) -> NotFound
        end)
    end,
    fun (_) -> meck:unload(couch_config) end,
    fun (_) -> Tests end
  }.