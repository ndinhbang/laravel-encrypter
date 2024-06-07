<?php

namespace Ndinhbang\LaravelEncrypter;

use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Encryption\EncryptionServiceProvider;
use Illuminate\Encryption\MissingAppKeyException;
use Laravel\SerializableClosure\SerializableClosure;
use Ndinhbang\LaravelEncrypter\Commands\EnvironmentDecryptCommand;
use Ndinhbang\LaravelEncrypter\Commands\EnvironmentEncryptCommand;
use Ndinhbang\LaravelEncrypter\Commands\KeyGenerateCommand;
use Ndinhbang\LaravelEncrypter\Support\Key;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use SodiumException;

class EncrypterServiceProvider extends EncryptionServiceProvider
{
    /**
     * Bootstrap the application services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/encrypter.php' => config_path('encrypter.php'),
            ]);

            $this->commands([
                KeyGenerateCommand::class,
                EnvironmentDecryptCommand::class,
                EnvironmentEncryptCommand::class,
            ]);
        }
    }

    /**
     * Register the application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/encrypter.php', 'encrypter');

        $this->registerEncrypter();
        $this->registerSerializableClosureSecurityKey();
    }

    /**
     * Register the encrypter.
     */
    protected function registerEncrypter(): void
    {
        $this->app->singleton('encrypter', function ($app) {
            $config = $app->make('config')->get('app');

            [$key, $keyId] = $this->parseKey($config);

            return (new Encrypter($key, $keyId))
                ->previousKeys($config['previous_keys'] ?? []);
        });
    }

    /**
     * Parse the encryption key.
     * @return array{0: SymmetricKey, 1: string}
     * @throws InvalidVersionException
     * @throws PasetoException
     * @throws SodiumException
     */
    protected function parseKey(#[\SensitiveParameter] array $config): array
    {
        return Key::parseKey($this->key($config));
    }

    /**
     * Extract the encryption key from the given configuration.
     *
     * @throws MissingAppKeyException
     */
    protected function key(#[\SensitiveParameter] array $config): string
    {
        return tap($config['key'], function (#[\SensitiveParameter] $key) {
            if (empty($key)) {
                throw new MissingAppKeyException;
            }
        });
    }

    /**
     * Configure Serializable Closure signing for security.
     *
     * @throws BindingResolutionException
     * @throws InvalidVersionException
     * @throws PasetoException
     * @throws SodiumException
     */
    protected function registerSerializableClosureSecurityKey(): void
    {
        $config = $this->app->make('config')->get('app');

        if (! class_exists(SerializableClosure::class) || empty($config['key'])) {
            return;
        }

        [$key, ] = $this->parseKey($config);

        SerializableClosure::setSecretKey($key->raw());
    }
}
