<?php

namespace Ndinhbang\LaravelEncrypter\Support;

use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\Util;
use SodiumException;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Uid\UuidV7;

final class Key
{
    /**
     * @throws SodiumException
     */
    public static function exportKey(#[\SensitiveParameter] SymmetricKey $key, bool $hasKeyId = true): string
    {
        return self::header()
            . ($hasKeyId ? ('.' . self::generateKeyId()) : '')
            . '.' . $key->encode();
    }

    public static function generateKeyId(): string
    {
        return Uuid::v7()->toBase58();
    }

    public static function header(): string
    {
        return Version4::header();
    }

    /**
     * @return array{0: SymmetricKey, 1: string}|SymmetricKey
     *
     * @throws InvalidVersionException
     * @throws PasetoException
     * @throws SodiumException
     */
    public static function parseKey(#[\SensitiveParameter] string $key, bool $hasKeyId = true): array|SymmetricKey
    {
        if ($hasKeyId) {
            [$version, $keyId, $base64Key] = explode('.', $key);
        } else {
            [$version, $base64Key] = explode('.', $key);
        }

        $key = SymmetricKey::fromEncodedString(
            $base64Key,
            ProtocolCollection::protocolFromHeaderPart($version)
        );

        Util::wipe($base64Key);

        if ($hasKeyId) {
            return [$key, $keyId];
        }

        return $key;
    }

    /**
     * @throws SodiumException
     */
    public static function extractKeyId(string $payload): string
    {
        $keyId = Util::extractFooter($payload);
        if (! empty($keyId)) {
            return UuidV7::fromBinary($keyId)->toBase58();
        }

        return '';
    }

    public static function getKeyIdRaw(string $keyId): string
    {
        if (! empty($keyId)) {
            return UuidV7::fromBase58($keyId)->toBinary();
        }

        return '';
    }
}
