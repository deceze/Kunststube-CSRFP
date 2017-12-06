<?php

namespace Kunststube\CSRFP;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'ICryptoProvider.php';


class CryptoProvider implements ICryptoProvider {

    public function getRandomHexString($length) {
        // `random_bytes()` is available in PHP 7+. more performant and platform independent than subsequent generators
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes($length / 2));
        }
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
            if (@is_readable($source)) {
                // NOTE: the following line produces an error in PHP 7+ related to the offset value. reference
                // documentation notes that remote files cannot seek, so it seems that since PHP 7.0, `/dev/urandom`
                // is considered a remote file.
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
