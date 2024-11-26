<?php


namespace nostriphant\NIP19;

class Bits {

    static function encode(array $data): array {
        return self::convert($data, 8, 5, true);
    }

    static function decode(array $data): array {
        return self::convert($data, 5, 8, false);
    }

    static function convert(array $data, int $fromBits, int $toBits, bool $pad = true): array {
        $inLen = count($data);
        $acc = 0;
        $bits = 0;
        $ret = [];
        $maxv = (1 << $toBits) - 1;
        $maxacc = (1 << ($fromBits + $toBits - 1)) - 1;

        for ($i = 0; $i < $inLen; $i++) {
            $value = $data[$i];
            if ($value < 0 || $value >> $fromBits) {
                throw new \Exception('Invalid value for convert bits');
            }

            $acc = (($acc << $fromBits) | $value) & $maxacc;
            $bits += $fromBits;

            while ($bits >= $toBits) {
                $bits -= $toBits;
                $ret[] = (($acc >> $bits) & $maxv);
            }
        }

        if ($pad) {
            if ($bits) {
                $ret[] = ($acc << $toBits - $bits) & $maxv;
            }
        } elseif ($bits >= $fromBits || ((($acc << ($toBits - $bits))) & $maxv)) {
            throw new \Exception('Invalid data');
        }

        return $ret;
    }
}
