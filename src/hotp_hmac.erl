-module(hotp_hmac).

-export_type(
    [ hash_algo/0
    ]).

-export(
    [ cons/3
    , hash_algos_supported/0
    ]).

-type hash_algo() ::
      sha
    | sha256
    | sha512
    .

-spec cons(hash_algo(), binary(), binary()) ->
    binary().
cons(HashAlgo, <<Secret/binary>>, <<Data/binary>>) ->
    crypto:hmac(HashAlgo, Secret, Data).

-spec hash_algos_supported() ->
    [hash_algo()].
hash_algos_supported() ->
    [ sha
    , sha256
    , sha512
    ].
