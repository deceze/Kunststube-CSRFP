<?php

namespace Kunststube\CSRFP;


interface ICryptoProvider {

    public function getRandomHexString($length);
    public function hash($data, $secret);

}