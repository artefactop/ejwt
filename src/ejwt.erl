%%%-------------------------------------------------------------------
%%% File        : ejwt.erl
%%% Author      : Jose Luis Navarro <pepe@yuilop.com>
%%% Description : encode/decode library for jwt
%%%-------------------------------------------------------------------

-module(ejwt).

-define(HS265, <<"HS265">>).
-define(HS384, <<"HS384">>).
-define(HS512, <<"HS512">>).

-export([encode/2, encode/3, decode/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

-spec encode(Payload::list(), Key::list()) -> binary().

encode(Payload, Key) ->
    encode(Payload, Key, ?HS265).

-spec encode(Payload::list(), Key::list(), Algorithm::binary()) -> binary().

encode(Payload, Key, Algorithm) ->
	Header = [{<<"typ">>, <<"JWT">>}, {<<"alg">>, Algorithm}],
	Hjson = jsx:encode(Header),
	Pjson = jsx:encode(Payload), 
	Hb = base64url:encode(Hjson),
	Pb = base64url:encode(Pjson),
	Data = <<Hb/binary, ".", Pb/binary>>,
	Signing = base64url:encode(get_mac(Key, Data, Algorithm)),
    <<Data/binary, ".", Signing/binary>>.

-spec get_mac(Key::list(), Data::binary(), Method::binary()) -> binary().

get_mac(Key, Data, ?HS265) ->
	hmac:hmac256(Key, Data);
get_mac(Key, Data, ?HS384) ->
	hmac:hmac256(Key, Data);
get_mac(Key, Data, ?HS512) ->
	hmac:hmac256(Key, Data).

-spec decode(JWT::binary()) -> term().

decode(JWT) ->
    [Header, Data] = binary:split(JWT, <<".">>),
    [Payload, Signing] = binary:split(Data, <<".">>),
    _Hjson = jsx:decode(base64url:decode(Header)),
    Pjson = jsx:decode(base64url:decode(Payload)),
    Pjson.

