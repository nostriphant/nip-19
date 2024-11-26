<?php

namespace nostriphant\NIP19;

readonly class Checksum {

    const CHECKSUM_LENGTH = 6;

    public function __construct(private string $hrp, private array $words) {
        
    }

    public function __invoke(callable $encoder, int $length = self::CHECKSUM_LENGTH): string {
        $polyMod = new PolyMod($this->hrp, $this->words);
        $polyModChecksum = PolyMod::createChecksumFor($polyMod, $length)() ^ 1;
        $results = [];
        for ($i = 0; $i < $length; $i++) {
            $results[$i] = ($polyModChecksum >> 5 * (5 - $i)) & 31;
        }

        return "{$this->hrp}1" . array_reduce(array_merge($this->words, $results), $encoder, '');
    }

    static function validate(string $hrp, array $data, int $length = self::CHECKSUM_LENGTH) {
        if ((new PolyMod($hrp, $data))() !== 1) {
            return false;
        }
        return array_slice($data, 0, -$length);
    }
}
