<?php

namespace Ndinhbang\LaravelEncrypter;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Ndinhbang\LaravelEncrypter\Support\Key;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version4;
use Random\RandomException;
use RuntimeException;
use SodiumException;

class Encrypter implements EncrypterContract, StringEncrypter
{
    /**
     * The encryption key.
     */
    protected SymmetricKey $key;

    /**
     * The identifier of encryption key.
     */
    protected string $keyId;

    /**
     * The identifier of encryption key in binary format.
     */
    protected string $keyIdRaw;

    /**
     * The previous / legacy encryption keys.
     */
    protected array $previousKeys = [];

    public function __construct(#[\SensitiveParameter] SymmetricKey $key, string $keyId = '')
    {
        $this->key = $key;
        $this->keyId = $keyId;
        $this->keyIdRaw = Key::getKeyIdRaw($keyId);
    }

    /**
     * @throws PasetoException
     * @throws RandomException
     */
    public static function generateKey(): SymmetricKey
    {
        return Version4::generateSymmetricKey();
    }

    /**
     * Encrypt the given value.
     *
     * @param  mixed  $value
     * @param  bool  $serialize
     *
     * @throws EncryptException
     */
    public function encrypt(#[\SensitiveParameter] $value, $serialize = true): string
    {
        try {
            return Version4::encrypt($serialize ? serialize($value) : $value, $this->key, $this->keyIdRaw);
        } catch (\Exception $ex) {
            throw new EncryptException($ex->getMessage());
        }
    }

    /**
     * Encrypt a string without serialization.
     *
     * @param  string  $value
     *
     * @throws EncryptException
     */
    public function encryptString(#[\SensitiveParameter] $value): string
    {
        return $this->encrypt($value, false);
    }

    /**
     * Decrypt the given value.
     *
     * @param  string  $payload
     * @param  bool  $unserialize
     *
     * @throws DecryptException
     */
    public function decrypt($payload, $unserialize = true): mixed
    {
        try {
            $decrypted = Version4::decrypt($payload, $this->getKeyById(Key::extractKeyId($payload)));

            return $unserialize ? unserialize($decrypted) : $decrypted;
        } catch (\Exception $ex) {
            throw new DecryptException($ex->getMessage());
        }
    }

    /**
     * Decrypt the given string without unserialization.
     *
     * @param  string  $payload
     *
     * @throws DecryptException
     */
    public function decryptString($payload): string
    {
        return $this->decrypt($payload, false);
    }

    /**
     * Get the encryption key that the encrypter is currently using.
     */
    public function getKey(): SymmetricKey
    {
        return $this->key;
    }

    /**
     * Get the current encryption key and all previous encryption keys.
     */
    public function getAllKeys(): array
    {
        return [$this->key, ...array_values($this->previousKeys)];
    }

    /**
     * Get the previous encryption keys.
     *
     * @return array<string, SymmetricKey>
     */
    public function getPreviousKeys(): array
    {
        return $this->previousKeys;
    }

    /**
     * Set the previous / legacy encryption keys that should be utilized if decryption fails.
     *
     * @return $this
     *
     * @throws PasetoException
     * @throws SodiumException
     * @throws InvalidVersionException
     */
    public function previousKeys(array $keys): static
    {
        foreach ($keys as $key) {
            [$key, $keyId] = Key::parseKey($key);
            $this->previousKeys[$keyId] = $key;
        }

        return $this;
    }

    protected function getKeyById(string $keyId): SymmetricKey
    {
        if (empty($keyId) || $keyId === $this->keyId) {
            return $this->key;
        }

        if (! empty($this->previousKeys[$keyId])) {
            return $this->previousKeys[$keyId];
        }

        throw new RuntimeException(
            'Encryption key was not found.'
        );
    }
}
