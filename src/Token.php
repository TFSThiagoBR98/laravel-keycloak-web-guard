<?php

namespace TFSThiagoBR98\LaravelKeycloak;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;

class Token
{
    /**
     * Decode a JWT token
     *
     * @param  string  $token
     * @param  string  $publicKey
     * @return stdClass|null
     */
    public static function decode(string $token = null, string $publicKey, int $leeway = 0): ?stdClass
    {
        JWT::$leeway = $leeway;
        $publicKey = self::buildPublicKey($publicKey);

        return $token ? JWT::decode($token, new Key($publicKey, 'RS256')) : null;
    }

    /**
     * Build a valid public key from a string
     *
     * @param  string  $key
     * @return string
     */
    private static function buildPublicKey(string $key): string
    {
        return "-----BEGIN PUBLIC KEY-----\n".wordwrap($key, 64, "\n", true)."\n-----END PUBLIC KEY-----";
    }
}