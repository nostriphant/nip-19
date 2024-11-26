<?php

namespace nostriphant\NIP19;

readonly class PolyMod {

    const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    private array $values;

    public function __construct(string $hrp, array $convertedDataChars) {
        $this->values = array_merge(self::hrpExpand($hrp), $convertedDataChars);
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

    public function __invoke() {
        $numValues = count($this->values);
        $chk = 1;
        for ($i = 0; $i < $numValues; $i++) {
            $top = $chk >> 25;
            $chk = ($chk & 0x1ffffff) << 5 ^ $this->values[$i];

            for ($j = 0; $j < count(self::GENERATOR); $j++) {
                $value = (($top >> $j) & 1) ? self::GENERATOR[$j] : 0;
                $chk ^= $value;
            }
        }

        return $chk;
    }
}
