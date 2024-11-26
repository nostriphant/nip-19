<?php

namespace nostriphant\NIP19;


interface Data {
    public function __construct(array $bytes);

    public function __invoke();

    static function toBytes(mixed ...$data);
}
