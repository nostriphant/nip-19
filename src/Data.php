<?php

namespace nostriphant\NIP19;


interface Data {
    public function __construct(array $bytes);

    static function toBytes(mixed ...$data);
}
