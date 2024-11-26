# nip19
Bech32 implementation in PHP

## Usage

```
use nostriphant\NIP19\Bech32;

$bech32 = Bech32::npub('npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg');
$public_key_hex = $bech32();
$public_key_bech32 = (string) (new Bech32($public_key_hex));

$bech32 = Bech32::nsec('nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5');
$private_key_hex = $bech32();
$private_key_bech32 = (string) (new Bech32($private_key_hex));
```
