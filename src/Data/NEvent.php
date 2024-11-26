<?php

namespace nostriphant\NIP19\Data;

use nostriphant\NIP19\Data;
use nostriphant\NIP19\Bech32;

readonly class NEvent implements Data {

    public string $id;
    public array $relays;
    public ?string $author;
    public ?int $kind;

    #[\Override]
    public function __construct(array $bytes) {
        $tlv = Bech32::parseTLV($bytes);
        $this->id = Bech32::fromBytesToHex($tlv[0][0]);
        $this->relays = Bech32::parseTLVRelays($tlv);
        $this->author = Bech32::parseTLVAuthor($tlv);
        $this->kind = Bech32::parseTLVKind($tlv);
    }

    #[\Override]
    static function toBytes(mixed ...$data): array {
        return Bech32::encodeTLV(
                        [Bech32::fromHexToBytes($data['id'])],
                        Bech32::fromRelaysToBytes($data['relays'] ?? []),
                        isset($data['author']) ? [Bech32::fromHexToBytes($data['author'])] : [],
                        [Bech32::fromIntegerToBytes($data['kind'])],
                );
    }
}
