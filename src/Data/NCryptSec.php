<?php

namespace nostriphant\NIP19\Data;

use nostriphant\NIP19\Data;
use nostriphant\NIP19\Bech32;

readonly class NCryptSec implements Data {

    public string $data;

    #[\Override]
    public function __construct(array $bytes) {
        $this->data = Bech32::fromBytesToUTF8($bytes);
    }

    #[\Override]
    static function toBytes(mixed ...$data): array {
        return Bech32::fromUTF8ToBytes($data[0]);
    }
}
