<?php

namespace Ndinhbang\LaravelEncrypter\Commands;

use Illuminate\Console\Command;
use Illuminate\Console\ConfirmableTrait;
use Illuminate\Support\Str;
use Ndinhbang\LaravelEncrypter\Encrypter;
use Ndinhbang\LaravelEncrypter\Support\Key;
use ParagonIE\Paseto\Exception\PasetoException;
use Random\RandomException;
use SodiumException;

class KeyGenerateCommand extends Command
{
    use ConfirmableTrait;

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'key:generate
                    {--show : Display the key instead of modifying files}
                    {--force : Force the operation to run when in production}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Set the application key';

    /**
     * Execute the console command.
     *
     * @throws PasetoException
     * @throws RandomException
     * @throws SodiumException
     */
    public function handle(): int
    {
        $key = $this->generateRandomKey();

        if ($this->option('show')) {
            $this->line('<comment>' . $key . '</comment>');
            return self::SUCCESS;
        }

        $currentKey = $this->laravel['config']['app.key'];

        if (strlen($currentKey) !== 0 && (!$this->confirmToProceed())) {
            return false;
        }

        // Next, we will replace the application key in the environment file so it is
        // automatically setup for this developer. This key gets generated using a
        // secure random byte generator and is later base64 encoded for storage.
        if (!$this->setKeyInEnvironmentFile($key)) {
            return self::FAILURE;
        }

        $this->setPreviousKeyInEnvironmentFile($currentKey);

        $this->laravel['config']['app.key'] = $key;

        if ($this->laravel->configurationIsCached()) {
            $this->call('config:cache');
        }

        $this->components->info('Application key set successfully.');

        return self::SUCCESS;
    }

    /**
     * Generate a random key for the application.
     *
     * @throws SodiumException
     * @throws PasetoException
     * @throws RandomException
     */
    protected function generateRandomKey(): string
    {
        return Key::exportKey(Encrypter::generateKey());
    }

    /**
     * Set the application key in the environment file.
     *
     * @param string $key
     * @return bool
     */
    protected function setKeyInEnvironmentFile(#[\SensitiveParameter] string $key): bool
    {
        if (!$this->writeNewEnvironmentFileWith('APP_KEY', $key)) {
            return false;
        }

        return true;
    }

    /**
     * Write a new environment file with the given key.
     */
    protected function writeNewEnvironmentFileWith(string $variable, #[\SensitiveParameter] string $value): bool
    {
        $input = file_get_contents($this->laravel->environmentFilePath());

        if ($this->hasEnvironmentVariable($input, $variable)) {

            $variablePreviousValue = $this->getEnvironmentVariable($input, $variable);

            $replaced = preg_replace(
                $this->getKeyReplacementPattern($variable, $variablePreviousValue),
                "{$variable}=" . $value,
                $input
            );

            if ($replaced === $input || $replaced === null) {
                $this->error("Unable to set {$variable} variable in the .env file.");

                return false;
            }
        } else {
            $replaced = $this->appendEnvironmentVariable($input, $variable, $value);
        }

        file_put_contents($this->laravel->environmentFilePath(), $replaced);

        return true;
    }

    protected function hasEnvironmentVariable(#[\SensitiveParameter] string $input, string $variable): bool
    {
        return Str::of($input)->isMatch("/^{$variable}=(.*)/m");
    }

    protected function getEnvironmentVariable(#[\SensitiveParameter] string $input, string $variable): string
    {
        return Str::of($input)->match("/^{$variable}=(.*)/m");
    }

    /**
     * Get a regex pattern that will match env APP_KEY with any random key.
     */
    protected function getKeyReplacementPattern(string $key, #[\SensitiveParameter] string $value): string
    {
        $escaped = preg_quote('=' . $value, '/');

        return "/^{$key}{$escaped}/m";
    }

    protected function appendEnvironmentVariable(#[\SensitiveParameter] string $input, string $variable, #[\SensitiveParameter] string $value): string
    {
        return $input . PHP_EOL . "{$variable}={$value}" . PHP_EOL;
    }

    /**
     * Set the previous application keys in the environment file.
     */
    protected function setPreviousKeyInEnvironmentFile(#[\SensitiveParameter] string $key): bool
    {
        $newKeys = collect($this->laravel['config']['app.previous_keys'])
            ->push($key)
            ->filter()
            ->all();

        if (! $this->writeNewEnvironmentFileWith('APP_PREVIOUS_KEYS', $this->serializeKeys($newKeys))) {
            return false;
        }

        $this->laravel['config']['app.previous_keys'] = $newKeys;

        return true;
    }

    protected function serializeKeys(#[\SensitiveParameter] array $keys): string
    {
        if (!empty($keys)) {
            return implode(',', $keys);
        }

        return '';
    }
}
