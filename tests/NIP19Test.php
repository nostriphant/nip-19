<?php

use nostriphant\NIP19\Bech32;

it('converts between bech32 and hexidecimal', function () {

    $public_key_hex = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';
    $public_key_bech32 = 'npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg';
    $private_key_hex = '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa';
    $private_key_bech32 = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5';

    expect(Bech32::fromNpub($public_key_bech32))->toBe($public_key_hex);
    expect(Bech32::toNpub($public_key_hex))->toBe($public_key_bech32);

    expect(Bech32::fromNsec($private_key_bech32))->toBe($private_key_hex);
    expect(Bech32::toNsec($private_key_hex))->toBe($private_key_bech32);
});
//;
//import { test, expect, describe } from 'bun:test';
//import { generateSecretKey, getPublicKey } from './pure.ts';
//import {
//  decode,
//  naddrEncode,
//  Bech32::decode,
//  npubEncode,
//  nsecEncode,
//  neventEncode,
//  type AddressPointer,
//  type ProfilePointer,
//  EventPointer,
//  NostrTypeGuard,
//} from './nip19.ts';

it('encodes and decodes nsec', function () {
    $private_key_hex = '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa';
    $nsec = Bech32::toNsec($private_key_hex);
    $bech32 = Bech32::decode($nsec);
    expect('' . $bech32)->toMatch('/nsec1\w+/');
    expect($bech32->type)->toEqual('nsec');
    expect($bech32->data[0])->toEqual($private_key_hex);
});

it('encodes and decodes npub', function () {
    $public_key_hex = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';
    $npub = Bech32::toNpub($public_key_hex);
    $bech32 = Bech32::decode($npub);
    expect('' . $bech32)->toMatch('/npub1\w+/');
        expect($bech32->type)->toEqual('npub');
    expect($bech32->data[0])->toEqual($public_key_hex);
});

it('encodes and decodes nprofile', function () {

    $public_key_hex = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';
    $relays = ['wss://relay.nostr.example.mydomain.example.com', 'wss://nostr.banana.com'];
    $bech32 = new Bech32('nprofile', pubkey: $public_key_hex, relays: $relays);
    expect('' . $bech32)->toMatch('/nprofile1\w+/');
        expect($bech32->type)->toEqual('nprofile');
    expect($bech32->data['pubkey'])->toEqual($public_key_hex);
    expect($bech32->data['relays'])->toContain('wss://relay.nostr.example.mydomain.example.com');
    expect($bech32->data['relays'])->toContain('wss://nostr.banana.com');
});

it('decodes nprofile without relays', function () {
    $public_key_hex = '97c70a44366a6535c145b333f973ea86dfdc2d7a99da618c40c64705ad98e322';
    $relays = [];
    $bech32 = new Bech32('nprofile', pubkey: $public_key_hex, relays: $relays);
    expect('' . $bech32)->toMatch('/nprofile1\w+/');
    expect($bech32->type)->toEqual('nprofile');
    expect($bech32->data['pubkey'])->toEqual($public_key_hex);
    expect($bech32->data['relays'])->toBeEmpty();
});

it('encode and decode naddr', function () {

    $public_key_hex = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';
    $relays = ['wss://relay.nostr.example.mydomain.example.com', 'wss://nostr.banana.com'];
    $bech32 = new Bech32('naddr',
            pubkey: $public_key_hex,
            relays: $relays,
            kind: 30023,
            identifier: 'banana'
    );
    expect('' . $bech32)->toMatch('/naddr1\w+/');
        expect($bech32->type)->toEqual('naddr');
    expect($bech32->data['pubkey'])->toEqual($public_key_hex);
    expect($bech32->data['relays'])->toContain($relays[0]);
    expect($bech32->data['relays'])->toContain($relays[1]);
    expect($bech32->data['kind'])->toEqual(30023);
    expect($bech32->data['identifier'])->toEqual('banana');
});

it('encode and decode nevent', function () {

    $public_key_hex = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';
    $relays = ['wss://relay.nostr.example.mydomain.example.com', 'wss://nostr.banana.com'];
    $bech32 = new Bech32('nevent',
            id: $public_key_hex,
            relays: $relays,
            kind: 30023,
    );
    expect('' . $bech32)->toMatch('/nevent1\w+/');
    expect($bech32->type)->toEqual('nevent');
    expect($bech32->data['id'])->toEqual($public_key_hex);
    expect($bech32->data['relays'])->toContain($relays[0]);
    expect($bech32->data['kind'])->toEqual(30023);
});

it('encode and decode nevent with kind 0', function () {

    $public_key_hex = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';
    $relays = ['wss://relay.nostr.example.mydomain.example.com', 'wss://nostr.banana.com'];
    $bech32 = new Bech32('nevent',
            id: $public_key_hex,
            relays: $relays,
            kind: 0,
    );
    expect('' . $bech32)->toMatch('/nevent1\w+/');
    expect($bech32->type)->toEqual('nevent');
    expect($bech32->data['id'])->toEqual($public_key_hex);
    expect($bech32->data['relays'])->toContain($relays[0]);
    expect($bech32->data['kind'])->toEqual(0);
});

it('encode and decode naddr with empty "d"', function () {

    $public_key_hex = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';
    $relays = ['wss://relay.nostr.example.mydomain.example.com', 'wss://nostr.banana.com'];
    $bech32 = new Bech32('naddr',
            identifier: '',
            pubkey: $public_key_hex,
            relays: $relays,
            kind: 3,
    );
    expect('' . $bech32)->toMatch('/naddr\w+/');
    expect($bech32->type)->toEqual('naddr');
    expect($bech32->data['identifier'])->toEqual('');
    expect($bech32->data['relays'])->toContain('wss://relay.nostr.example.mydomain.example.com');
    expect($bech32->data['kind'])->toEqual(3);
    expect($bech32->data['pubkey'])->toEqual($public_key_hex);
});

it('decode naddr from habla.news', function () {

    $bech32 = Bech32::decode(
            'naddr1qq98yetxv4ex2mnrv4esygrl54h466tz4v0re4pyuavvxqptsejl0vxcmnhfl60z3rth2xkpjspsgqqqw4rsf34vl5',
    );
    expect($bech32->type)->toEqual('naddr');
    expect($bech32->data['pubkey'])->toEqual('7fa56f5d6962ab1e3cd424e758c3002b8665f7b0d8dcee9fe9e288d7751ac194');
    expect($bech32->data['kind'])->toEqual(30023);
    expect($bech32->data['identifier'])->toEqual('references');
});

it('decode naddr from go-nostr with different TLV ordering', function () {

    $bech32 = Bech32::decode(
            'naddr1qqrxyctwv9hxzq3q80cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsxpqqqp65wqfwwaehxw309aex2mrp0yhxummnw3ezuetcv9khqmr99ekhjer0d4skjm3wv4uxzmtsd3jjucm0d5q3vamnwvaz7tmwdaehgu3wvfskuctwvyhxxmmd0zfmwx',
    );

    expect($bech32->type)->toEqual('naddr');
    expect($bech32->data['pubkey'])->toEqual('3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d');
    expect($bech32->data['relays'])->toContain('wss://relay.nostr.example.mydomain.example.com');
    expect($bech32->data['relays'])->toContain('wss://nostr.banana.com');
    expect($bech32->data['kind'])->toEqual(30023);
    expect($bech32->data['identifier'])->toEqual('banana');
});

//it('is valid Bech32', function (string $method, string $bech32, bool $expected) {
//    expect(Bech32::$method($bech32))->toBe($expected, $method . ': ' . $bech32);
//})->with([
//    ['isValidNProfile', 'nprofile1qqsvc6ulagpn7kwrcwdqgp797xl7usumqa6s3kgcelwq6m75x8fe8yc5usxdg', true],
//    ['isValidNProfile', 'nprofile1qqsvc6ulagpn7kwrcwdqgp797xl7usumqa6s3kgcelwq6m75x8fe8yc5usxãg', false],
//    ['isValidNProfile', 'nsec1lqw6zqyanj9mz8gwhdam6tqge42vptz4zg93qsfej440xm5h5esqya0juv', false],
//    ['isValidNEvent', 'nevent1qqst8cujky046negxgwwm5ynqwn53t8aqjr6afd8g59nfqwxpdhylpcpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mg8arnc9', true],
//    ['isValidNEvent', 'nevent1qqst8cujky046negxgwwm5ynqwn53t8aqjr6afd8g59nfqwxpdhylpcpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mg8ãrnc9', false],
//    ['isValidNEvent', 'nprofile1qqsvc6ulagpn7kwrcwdqgp797xl7usumqa6s3kgcelwq6m75x8fe8yc5usxdg', false],
//    ['isValidNAddress', 'naddr1qqxnzdesxqmnxvpexqunzvpcqyt8wumn8ghj7un9d3shjtnwdaehgu3wvfskueqzypve7elhmamff3sr5mgxxms4a0rppkmhmn7504h96pfcdkpplvl2jqcyqqq823cnmhuld', true],
//    ['isValidNAddress', 'nsec1lqw6zqyanj9mz8gwhdam6tqge42vptz4zg93qsfej440xm5h5esqya0juv', false],
//    ['isValidNSec', 'nsec1lqw6zqyanj9mz8gwhdam6tqge42vptz4zg93qsfej440xm5h5esqya0juv', true],
//    ['isValidNSec', 'nsec1lqw6zqyanj9mz8gwhdam6tqge42vptz4zg93qsfej440xm5h5esqya0juã', false],
//    ['isValidNSec', 'nprofile1qqsvc6ulagpn7kwrcwdqgp797xl7usumqa6s3kgcelwq6m75x8fe8yc5usxdg', false],
//    ['isValidNPub', 'npub1jz5mdljkmffmqjshpyjgqgrhdkuxd9ztzasv8xeh5q92fv33sjgqy4pats', true],
//    ['isValidNPub', 'npub1jz5mdljkmffmqjshpyjgqgrhdkuxd9ztzãsv8xeh5q92fv33sjgqy4pats', false],
//    ['isValidNPub', 'nsec1lqw6zqyanj9mz8gwhdam6tqge42vptz4zg93qsfej440xm5h5esqya0juv', false],
//    ['isValidNote', 'note1gmtnz6q2m55epmlpe3semjdcq987av3jvx4emmjsa8g3s9x7tg4sclreky', true],
//    ['isValidNote', 'note1gmtnz6q2m55epmlpe3semjdcq987av3jvx4emmjsa8g3s9x7tg4sçlreky', false],
//    ['isValidNote', 'npub1jz5mdljkmffmqjshpyjgqgrhdkuxd9ztzasv8xeh5q92fv33sjgqy4pats', false],
//    ['isValidNCryptSec', 'ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p', true],
//    ['isValidNCryptSec', 'ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsã8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p', false],
//    ['isValidNCryptSec', 'note1gmtnz6q2m55epmlpe3semjdcq987av3jvx4emmjsa8g3s9x7tg4sçlreky', false]
//]);
