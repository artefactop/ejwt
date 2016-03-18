-module(ejwt_tests).
-include_lib("eunit/include/eunit.hrl").

decode_dont_check_signature_test() ->
  Expected = [{<<"sub">>,<<"1234567890">>},{<<"name">>,<<"John Doe">>},{<<"admin">>,true}],
  JWT = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9."
  "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ">>,
  ?assertEqual(Expected, ejwt:decode(JWT)).

decode_test() ->
  Expected = [{<<"sub">>,<<"1234567890">>},{<<"name">>,<<"John Doe">>},{<<"admin">>,true}],
  JWT = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9."
  "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ">>,
  ?assertEqual(Expected, ejwt:decode(JWT, <<"secret">>)).

encode_test() ->
  Expected = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9."
  "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ">>,
  Payload = [{<<"sub">>,<<"1234567890">>},{<<"name">>,<<"John Doe">>},{<<"admin">>,true}],
  ?assertEqual(Expected, ejwt:encode(Payload, <<"secret">>)).