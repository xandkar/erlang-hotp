-module(hotp).

-include("hotp_extra_params.hrl").

-export_type(
    [ extra_params/0
    ]).

-export(
    [ cons/2
    , cons/3
    ]).

-type extra_params() ::
    #hotp_extra_params{}.

-spec cons(binary(), integer()) ->
    integer().
cons(<<Secret/binary>>, Count) ->
    cons(Secret, Count, #hotp_extra_params{}).

-spec cons(binary(), integer(), extra_params()) ->
    integer().
cons(<<Secret/binary>>, Count, #hotp_extra_params
    { hash_algo = HashAlgo
    , length    = Length
    }
) ->
    CountBin = count_to_bin(Count),
    Digest = hotp_hmac:cons(HashAlgo, Secret, CountBin),
    Number = digest_truncate(Digest),
    int_truncate(Number, Length).

-spec count_to_bin(integer()) ->
    binary().
count_to_bin(Count) ->
    <<Count:64/integer>>.

-spec digest_truncate(binary()) ->
    integer().
digest_truncate(Digest) ->
    Offset1 = byte_size(Digest) - 1,
    <<_:Offset1/bytes, _:4/bits,               Offset2:4/integer >> = Digest,
    <<_:Offset2/bytes, _:1/bits, P:31/integer,         _/binary  >> = Digest,
    P.

int_truncate(Number, Length) ->
    Number rem trunc(math:pow(10, Length)).

%% ============================================================================
%% Tests from RFC 4226 (https://tools.ietf.org/html/rfc4226#appendix-D)
%% ============================================================================

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-record(test_case,
    { secret           :: binary()
    , count            :: integer()
    , digest_full_hex  :: binary()
    , digest_trunc_hex :: binary()
    , digest_trunc_dec :: integer()
    , hotp             :: integer()
    }).

all_test_() ->
    Test =
        fun(HashAlgo, Length) ->
            Secret1 = hotp_secret:new(HashAlgo),
            Secret2 = hotp_secret:new(HashAlgo),
            Count1 = 1,
            Count2 = 2,
            Extra = #hotp_extra_params
                { hash_algo = HashAlgo
                , length    = Length
                },
            HOTP = hotp:cons(Secret1, Count1, Extra),
            Title =
                fun(Name) ->
                    lists:flatten(io_lib:format(
                        "~s. HashAlgo: ~p, Length: ~b, HOTP: ~b",
                        [Name, HashAlgo, Length, HOTP]
                    ))
                end,
            [
                {
                    Title("Same secret, same count"),
                    ?_assertEqual(HOTP, hotp:cons(Secret1, Count1, Extra))
                },
                {
                    Title("Same secret, diff count"),
                    ?_assertNotEqual(HOTP, hotp:cons(Secret1, Count2, Extra))
                },
                {
                    Title("Diff secret, same count"),
                    ?_assertNotEqual(HOTP, hotp:cons(Secret2, Count1, Extra))
                },
                {
                    Title("Diff secret, diff count"),
                    ?_assertNotEqual(HOTP, hotp:cons(Secret2, Count2, Extra))
                },
                {
                    Title("Length"),
                    % Possible leading zeros will reduce the length
                    ?_assert(Length >= length(integer_to_list(HOTP)))
                }
            ]
        end,
    Tests =
        [
            [
                Test(HashAlgo, Length)
            ||
                HashAlgo <- hotp_hmac:hash_algos_supported(),
                Length <- lists:seq(6, 100)
            ]
        |
            tests_rfc4226()
        ]
        ++
        [
            {
                "count_to_bin bit_size",
                ?_assertEqual(64, bit_size(count_to_bin(1)))
            }
        ]
        ++
        [
            ?_assertEqual(123456  , int_truncate( 10123456  , 6)),
            ?_assertEqual(12345678, int_truncate( 1012345678, 8)),
            ?_assertEqual(1234567 , int_truncate( 101234567 , 8)),
            ?_assertEqual(123456  , int_truncate(100123456  , 8)),
            ?_assertEqual(12345   , int_truncate(100012345  , 8)),
            ?_assertEqual(1234567 , int_truncate(1001234567 , 8)),
            ?_assertEqual(12345678, int_truncate(1000000000000012345678, 8))
        ],
    {inparallel, Tests}.

tests_rfc4226() ->
    lists:map(fun test_case_make/1, test_cases_from_rfc4226()).

test_case_make(#test_case
    { secret           = Secret
    , count            = Count
    , digest_full_hex  = DigestFullHex
    , digest_trunc_hex = _DigestTruncHex
    , digest_trunc_dec = DigestTruncDec
    , hotp             = HOTP
    }
) ->
    CountBin = count_to_bin(Count),
    Digest = hotp_hmac:cons(sha, Secret, CountBin),
    <<DigestFullDec:160/integer>> = Digest,
    [
        ?_assertEqual(64, bit_size(CountBin)),
        ?_assertEqual(160, bit_size(Digest)),
        ?_assertEqual(DigestFullHex, list_to_binary(io_lib:format("~40.16.0b", [DigestFullDec]))),
        ?_assertEqual(DigestTruncDec, digest_truncate(Digest)),
        ?_assertEqual(HOTP, int_truncate(DigestTruncDec, 6)),
        ?_assertEqual(HOTP, cons(Secret, Count))
    ].

test_cases_from_rfc4226() ->
    Secret = <<"12345678901234567890">>,
    [ #test_case{secret = Secret, count = 0, digest_full_hex = <<"cc93cf18508d94934c64b65d8ba7667fb7cde4b0">> , digest_trunc_hex = <<"4c93cf18">> , digest_trunc_dec = 1284755224 , hotp = 755224}
    , #test_case{secret = Secret, count = 1, digest_full_hex = <<"75a48a19d4cbe100644e8ac1397eea747a2d33ab">> , digest_trunc_hex = <<"41397eea">> , digest_trunc_dec = 1094287082 , hotp = 287082}
    , #test_case{secret = Secret, count = 2, digest_full_hex = <<"0bacb7fa082fef30782211938bc1c5e70416ff44">> , digest_trunc_hex = <<"82fef30">>  , digest_trunc_dec = 137359152  , hotp = 359152}
    , #test_case{secret = Secret, count = 3, digest_full_hex = <<"66c28227d03a2d5529262ff016a1e6ef76557ece">> , digest_trunc_hex = <<"66ef7655">> , digest_trunc_dec = 1726969429 , hotp = 969429}
    , #test_case{secret = Secret, count = 4, digest_full_hex = <<"a904c900a64b35909874b33e61c5938a8e15ed1c">> , digest_trunc_hex = <<"61c5938a">> , digest_trunc_dec = 1640338314 , hotp = 338314}
    , #test_case{secret = Secret, count = 5, digest_full_hex = <<"a37e783d7b7233c083d4f62926c7a25f238d0316">> , digest_trunc_hex = <<"33c083d4">> , digest_trunc_dec = 868254676  , hotp = 254676}
    , #test_case{secret = Secret, count = 6, digest_full_hex = <<"bc9cd28561042c83f219324d3c607256c03272ae">> , digest_trunc_hex = <<"7256c032">> , digest_trunc_dec = 1918287922 , hotp = 287922}
    , #test_case{secret = Secret, count = 7, digest_full_hex = <<"a4fb960c0bc06e1eabb804e5b397cdc4b45596fa">> , digest_trunc_hex = <<"4e5b397">>  , digest_trunc_dec = 82162583   , hotp = 162583}
    , #test_case{secret = Secret, count = 8, digest_full_hex = <<"1b3c89f65e6c9e883012052823443f048b4332db">> , digest_trunc_hex = <<"2823443f">> , digest_trunc_dec = 673399871  , hotp = 399871}
    , #test_case{secret = Secret, count = 9, digest_full_hex = <<"1637409809a679dc698207310c8c7fc07290d9e5">> , digest_trunc_hex = <<"2679dc69">> , digest_trunc_dec = 645520489  , hotp = 520489}
    ].

-endif.
