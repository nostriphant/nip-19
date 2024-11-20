# nip19
Bech32 implementation in PHP

## Usage

```
use nostriphant\NIP19\Bech32;

$public_key_hex = Bech32::fromNpub('npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg');
$public_key_bech32 = Bech32::toNpub($public_key_hex);

$private_key_hex = Bech32::fromNsec('nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5');
$private_key_bech32 = Bech32::toNsec($private_key_hex);
```
