<?php

namespace Ndinhbang\LaravelEncrypter\Commands;

use Exception;
use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;
use Ndinhbang\LaravelEncrypter\Encrypter;
use Ndinhbang\LaravelEncrypter\Support\Key;
use ParagonIE\Paseto\Exception\PasetoException;
use Random\RandomException;
use SodiumException;

class EnvironmentEncryptCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'env:encrypt
                    {--key= : The encryption key}
                    {--env= : The environment to be encrypted}
                    {--prune : Delete the original environment file}
                    {--force : Overwrite the existing encrypted environment file}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Encrypt an environment file';

    /**
     * The filesystem instance.
     *
     * @var Filesystem
     */
    protected Filesystem $files;

    /**
     * Create a new command instance.
     *
     * @param Filesystem $files
     * @return void
     */
    public function __construct(Filesystem $files)
    {
        parent::__construct();

        $this->files = $files;
    }

    /**
     * Execute the console command.
     *
     * @return int
     * @throws PasetoException
     * @throws RandomException
     * @throws SodiumException
     */
    public function handle(): int
    {
        $key = $this->option('key');

        $keyPassed = $key !== null;

        $environmentFile = $this->option('env')
                            ? Str::finish(dirname($this->laravel->environmentFilePath()), DIRECTORY_SEPARATOR).'.env.'.$this->option('env')
                            : $this->laravel->environmentFilePath();

        $encryptedFile = $environmentFile.'.encrypted';

        if (! $keyPassed) {
            $key = Key::exportKey(Encrypter::generateKey(), false);
        }

        if (! $this->files->exists($environmentFile)) {
            $this->components->error('Environment file not found.');

            return Command::FAILURE;
        }

        if ($this->files->exists($encryptedFile) && ! $this->option('force')) {
            $this->components->error('Encrypted environment file already exists.');

            return Command::FAILURE;
        }

        try {
            $encrypter = new Encrypter(Key::parseKey($key, false));

            $this->files->put(
                $encryptedFile,
                $encrypter->encrypt($this->files->get($environmentFile))
            );
        } catch (Exception $e) {
            $this->components->error($e->getMessage());

            return Command::FAILURE;
        }

        if ($this->option('prune')) {
            $this->files->delete($environmentFile);
        }

        $this->components->info('Environment successfully encrypted.');

        $this->components->twoColumnDetail('Key', $key);
        $this->components->twoColumnDetail('Encrypted file', $encryptedFile);

        $this->newLine();

        return Command::SUCCESS;
    }
}
