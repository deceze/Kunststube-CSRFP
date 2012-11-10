<?php

namespace Kunststube\CSRFP;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'ICryptoProvider.php';


class CryptoProvider implements ICryptoProvider {

    public function getRandomHexString($length) {
        try {
            return $this->getRandomHexStringFromDevRandom($length);
        } catch (\RuntimeException $e) {
            trigger_error($e->getMessage() . ' Falling back to internal generator.', E_USER_NOTICE);
            return $this->getRandomHexStringFromMtRand($length);
        }
    }

    protected function getRandomHexStringFromDevRandom($length) {
        static $sources = array('/dev/urandom', '/dev/random');

        foreach ($sources as $source) {
            if (is_readable($source)) {
                return bin2hex(file_get_contents($source, false, null, -1, $length / 2));
            }
        }

        throw new \RuntimeException('No system source for randomness available.');
    }

    protected function getRandomHexStringFromMtRand($length) {
        $hex = null;
        for ($i = 0; $i < $length; $i++) {
            $hex .= base_convert(mt_rand(0, 15), 10, 16);
        }
        return $hex;
    }

    public function hash($data, $secret) {
        return hash_hmac('sha512', $data, $secret);
    }

}