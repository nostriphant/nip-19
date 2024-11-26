<?php

namespace nostriphant\NIP19;

readonly class Bech32 {

    public Data $data;

    const TYPE_MAP = [
        'nsec' => Data\NSec::class,
        'npub' => Data\NPub::class,
        'note' => Data\Note::class,
        'nprofile' => Data\NProfile::class,
        'naddr' => Data\NAddr::class,
        'ncryptsec' => Data\NCryptSec::class,
        'nevent' => Data\NEvent::class
    ];

    public function __construct(private string $bech32) {
        $this->data = self::decodeRaw($this->bech32, 5000);
    }

    public function __get(string $name): mixed {
        if ($name === 'type') {
            $class = get_class($this->data);
            return strtolower(substr($class, strrpos($class, '\\') + 1));
        }
    }

    static function __callStatic(string $name, array $arguments): self {
        $bytes = call_user_func_array([self::TYPE_MAP[$name], 'toBytes'], $arguments);
        return new self(self::encodeRaw($name, $bytes));
    }

    public function __toString(): string {
        return $this->bech32;
    }

    static function array_entries(array $array) {
        return array_map(fn(mixed $key, mixed $value) => [$key, $value], array_keys($array), array_values($array));
    }

    static function parseTLVRelays(array $tlv): array {
        return isset($tlv[1]) ? array_map([self::class, 'fromBytesToUTF8'], $tlv[1]) : [];
    }

    static function parseTLVKind(array $tlv): ?int {
        return isset($tlv[3][0]) ? self::fromBytesToInteger($tlv[3][0]) : null;
    }

    static function parseTLVAuthor(array $tlv): ?string {
        return isset($tlv[2][0]) ? self::fromBytesToHex($tlv[2][0]) : null;
    }

    static function parseTLV(array $bytes): array {
        $result = [];
        $rest = $bytes;
        while (count($rest) > 0) {
            $type = array_shift($rest);
            $length = array_shift($rest);
            $value = array_slice($rest, 0, $length);
            if (count($value) < $length) {
                throw new \Exception('not enough data to read on TLV ' . $type);
            }
            $rest = array_slice($rest, $length);
            $result[$type] = $result[$type] ?? [];
            $result[$type][] = $value;
        }
        return $result;
    }

    static function encodeTLV(array ...$tlv): array {
        return array_reduce(self::array_entries($tlv), function (array $carry, array $tlv_entry): array {
            return array_reduce($tlv_entry[1], function (array $carry, array $value) use ($tlv_entry): array {
                return array_merge($carry, [$tlv_entry[0], count($value)], $value);
            }, $carry);
        }, []);
    }

    static function fromBytesToHex(array $bytes): string {
        return array_reduce($bytes, fn(string $hex, int $item) => $hex .= str_pad(dechex($item), 2, '0', STR_PAD_LEFT), '');
    }

    static function fromBytesToInteger(array $bytes): int {
        return hexdec(self::fromBytesToHex($bytes));
    }

    static function fromBytesToUTF8(array $bytes): string {
        return array_reduce($bytes, fn(string $utf8, int $item) => $utf8 .= chr($item), '');
    }

    static function fromHexToBytes(#[\SensitiveParameter] string $hex_key): array {
        return array_map('hexdec', str_split($hex_key, 2));
    }

    static function fromUTF8ToBytes(string $utf8): array {
        return array_map('ord', mb_str_split($utf8));
    }

    static function fromRelaysToBytes(array $relays): array {
        return array_map([self::class, 'fromUTF8ToBytes'], $relays);
    }

    static function fromIntegerToBytes(int $integer): array {
        // Create a Uint8Array with enough space to hold a 32-bit integer (4 bytes).
        $uint8Array = [];

        // Use bitwise operations to extract the bytes.
        $uint8Array[0] = ($integer >> 24) & 0xff; // Most significant byte (MSB)
        $uint8Array[1] = ($integer >> 16) & 0xff;
        $uint8Array[2] = ($integer >> 8) & 0xff;
        $uint8Array[3] = $integer & 0xff; // Least significant byte (LSB)

        return $uint8Array;
    }

    static function toNpub(string $hex) {
        return self::convertHexToBech32($hex, 'npub');
    }

    static function fromNpub(string $npub) {
        return self::convertBech32ToHex($npub, 'npub');
    }


    static function toNsec(#[\SensitiveParameter] string $hex): string {
        return self::convertHexToBech32($hex, 'nsec');
    }

    static function fromNsec(#[\SensitiveParameter] string $nsec): string {
        return self::convertBech32ToHex($nsec, 'nsec');
    }

    private static function convertHexToBech32(#[\SensitiveParameter] string $hex_key, string $prefix) {
        try {
            return self::encodeRaw($prefix, self::fromHexToBytes($hex_key));
        } catch (\Exception) {
            return '';
        }
    }

    private static function convertBech32ToHex(#[\SensitiveParameter] string $bech32_key): string {
        try {
            return (new self($bech32_key))->data->data;
        } catch (\Exception) {
            return '';
        }
    }

    static function isValid(string $expected_type, string $bech32) {
        try {
            $decoded = new self($bech32);
            return $decoded->type === $expected_type;
        } catch (\Exception $ex) {
            
        }
        return false;
    }

    static function isValidNProfile(string $bech32): bool {
        return self::isValid('nprofile', $bech32);
    }

    static function isValidNAddress(string $bech32): bool {
        return self::isValid('naddr', $bech32);
    }

    static function isValidNSec(string $bech32): bool {
        return self::isValid('nsec', $bech32);
    }

    static function isValidNPub(string $bech32): bool {
        return self::isValid('npub', $bech32);
    }

    static function isValidNote(string $bech32): bool {
        return self::isValid('note', $bech32);
    }

    static function isValidNCryptSec(string $bech32): bool {
        return self::isValid('ncryptsec', $bech32);
    }

    static function isValidNEvent(string $bech32): bool {
        return self::isValid('nevent', $bech32);
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

    static function convertBits(array $data, int $fromBits, int $toBits, bool $pad = true): array {
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
        } else if ($bits >= $fromBits || ((($acc << ($toBits - $bits))) & $maxv)) {
            throw new \Exception('Invalid data');
        }

        return $ret;
    }

    static function createChecksum(string $hrp, array $convertedDataChars): array {
        $values = array_merge(self::hrpExpand($hrp, strlen($hrp)), $convertedDataChars);
        $polyMod = PolyMod::calculate(array_merge($values, [0, 0, 0, 0, 0, 0])) ^ 1;
        $results = [];
        for ($i = 0; $i < 6; $i++) {
            $results[$i] = ($polyMod >> 5 * (5 - $i)) & 31;
        }

        return $results;
    }

    static function verifyChecksum(string $hrp, array $convertedDataChars): bool {
        $expandHrp = self::hrpExpand($hrp);
        $r = array_merge($expandHrp, $convertedDataChars);
        return PolyMod::calculate($r) === 1;
    }

    const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

    static function encodeRaw(string $hrp, array $bytes): string {
        $words = self::convertBits($bytes, 8, 5, true);
        $checksum = self::createChecksum($hrp, $words);
        $characters = array_merge($words, $checksum);

        $encoded = [];
        for ($i = 0, $n = count($characters); $i < $n; $i++) {
            $encoded[$i] = self::CHARSET[$characters[$i]];
        }

        return "{$hrp}1" . implode('', $encoded);
    }

    const CHARKEY_KEY = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
        1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
        1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1
    ];

    static function decodeRaw(string $sBech, int $limit = 90): Data {
        $length = strlen($sBech);

        if ($length < 8 || $length > $limit) {
            throw new \Exception("invalid string length: $length ($sBech). Expected (8..$limit)");
        }

        $chars = array_values(unpack('C*', $sBech));

        $haveUpper = false;
        $haveLower = false;
        $positionOne = -1;

        for ($i = 0; $i < $length; $i++) {
            $x = $chars[$i];
            if ($x < 33 || $x > 126) {
                throw new \Exception('Out of range character in bech32 string');
            }

            if ($x >= 0x61 && $x <= 0x7a) {
                $haveLower = true;
            }

            if ($x >= 0x41 && $x <= 0x5a) {
                $haveUpper = true;
                $x = $chars[$i] = $x + 0x20;
            }

            // find location of last '1' character
            if ($x === 0x31) {
                $positionOne = $i;
            }
        }

        if ($haveUpper && $haveLower) {
            throw new \Exception('Data contains mixture of higher/lower case characters');
        }

        if ($positionOne === -1) {
            throw new \Exception("Missing separator character");
        }

        if ($positionOne < 1) {
            throw new \Exception("Empty HRP");
        }

        if (($positionOne + 7) > $length) {
            throw new \Exception('Too short checksum');
        }

        $hrp = \pack("C*", ...\array_slice($chars, 0, $positionOne));

        $data = [];
        for ($i = $positionOne + 1; $i < $length; $i++) {
            $data[] = ($chars[$i] & 0x80) ? -1 : self::CHARKEY_KEY[$chars[$i]];
        }

        if (!self::verifyChecksum($hrp, $data)) {
            throw new \Exception('Invalid bech32 checksum');
        }

        return new (self::TYPE_MAP[$hrp])(self::convertBits(array_slice($data, 0, -6), 5, 8, false));
    }
}
