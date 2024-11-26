<?php

namespace nostriphant\NIP19;

readonly class PolyMod {

    const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    public function __construct(private string $hrp, private array $convertedDataChars) {
        
    }

    static function hrpExpand(string $hrp) {
        $hrpLen = strlen($hrp);
        $expand1 = [];
        $expand2 = [];
        for ($i = 0; $i < $hrpLen; $i++) {
            $o = \ord($hrp[$i]);
            $expand1[] = $o >> 5;
            $expand2[] = $o & 31;
        }
        return \array_merge($expand1, [0], $expand2);
    }

    static function createChecksumFor(PolyMod $polyMod, int $length): self {
        return new self($polyMod->hrp, array_merge($polyMod->convertedDataChars, array_fill(0, $length, 0)));
    }

    public function __invoke() {
        $values = array_merge(self::hrpExpand($this->hrp), $this->convertedDataChars);

        $numValues = count($values);
        $chk = 1;
        for ($i = 0; $i < $numValues; $i++) {
            $top = $chk >> 25;
            $chk = ($chk & 0x1ffffff) << 5 ^ $values[$i];

            for ($j = 0; $j < count(self::GENERATOR); $j++) {
                $value = (($top >> $j) & 1) ? self::GENERATOR[$j] : 0;
                $chk ^= $value;
            }
        }

        return $chk;
    }
}
