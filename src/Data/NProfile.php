<?php

namespace nostriphant\NIP19\Data;

use nostriphant\NIP19\Data;
use nostriphant\NIP19\Bech32;

readonly class NProfile implements Data {

    public string $pubkey;
    public array $relays;

    #[\Override]
    public function __construct(array $bytes) {
        $tlv = Bech32::parseTLV($bytes);
        if (!isset($tlv[0]) || !isset($tlv[0][0])) {
            throw new \Exception('missing TLV 0 for nprofile');
        }
        if (count($tlv[0][0]) !== 32) {
            throw new \Exception('TLV 0 should be 32 bytes');
        }

        $this->pubkey = Bech32::fromBytesToHex($tlv[0][0]);
        $this->relays = Bech32::parseTLVRelays($tlv);
    }

    #[\Override]
    static function toBytes(mixed ...$data): array {
        return Bech32::encodeTLV(
                        [Bech32::fromHexToBytes($data['pubkey'])],
                        Bech32::fromRelaysToBytes($data['relays'] ?? [])
                );
    }
}
