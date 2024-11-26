<?php

namespace nostriphant\NIP19\Data;

use nostriphant\NIP19\Data;
use nostriphant\NIP19\Bech32;

readonly class NAddr implements Data {

    public string $identifier;
    public string $pubkey;
    public int $kind;
    public array $relays;

    #[\Override]
    public function __construct(array $bytes) {
        $tlv = Bech32::parseTLV($bytes);
        $this->identifier = Bech32::fromBytesToUTF8($tlv[0][0]);
        $this->pubkey = Bech32::parseTLVAuthor($tlv);
        $this->kind = Bech32::parseTLVKind($tlv);
        $this->relays = Bech32::parseTLVRelays($tlv);
    }

    #[\Override]
    public function __invoke() {
        return $this;
    }

    #[\Override]
    static function toBytes(mixed ...$data): array {
        return Bech32::encodeTLV(
                        [Bech32::fromUTF8ToBytes($data['identifier'])],
                        Bech32::fromRelaysToBytes($data['relays'] ?? []),
                        [Bech32::fromHexToBytes($data['pubkey'])],
                        [Bech32::fromIntegerToBytes($data['kind'])],
                );
    }
}
