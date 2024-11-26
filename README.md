# nip19
Bech32 implementation in PHP

## Usage

```
use nostriphant\NIP19\Bech32;

$bech32 = new Bech32('npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg');
$public_key_hex = $bech32();
$public_key_bech32 = (string) (Bech32::npub($public_key_hex));

$bech32 = new Bech32('nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5');
$private_key_hex = $bech32();
$private_key_bech32 = (string) (Bech32::nsec($private_key_hex));

$public_key_hex = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';
$relays = ['wss://relay.nostr.example.mydomain.example.com', 'wss://nostr.banana.com'];

$bech32 = Bech32::nprofile(pubkey: $public_key_hex, relays: $relays);

$bech32 = Bech32::naddr(
        pubkey: $public_key_hex,
        relays: $relays,
        kind: 30023,
        identifier: 'banana'
);

$bech32 = Bech32::nevent(
        id: $public_key_hex,
        relays: $relays,
        kind: 30023,
);
```
