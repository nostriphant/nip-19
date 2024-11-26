<?php

namespace nostriphant\NIP19\Data;

use nostriphant\NIP19\Data;
use nostriphant\NIP19\Bech32;

readonly class NSec implements Data {

    public string $data;

    #[\Override]
    public function __construct(array $bytes) {
        $this->data = Bech32::fromBytesToHex($bytes);
    }

    #[\Override]
    public function __invoke() {
        return $this->data;
    }

    #[\Override]
    static function toBytes(mixed ...$data): array {
        return Bech32::fromHexToBytes($data[0]);
    }
}
