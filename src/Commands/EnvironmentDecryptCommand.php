<?php

namespace Ndinhbang\LaravelEncrypter\Commands;

use Exception;
use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Env;
use Illuminate\Support\Str;
use Ndinhbang\LaravelEncrypter\Encrypter;
use Ndinhbang\LaravelEncrypter\Support\Key;

class EnvironmentDecryptCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'env:decrypt
                    {--key= : The encryption key}
                    {--env= : The environment to be decrypted}
                    {--force : Overwrite the existing environment file}
                    {--path= : Path to write the decrypted file}
                    {--filename= : Filename of the decrypted file}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Decrypt an environment file';

    /**
     * The filesystem instance.
     *
     * @var \Illuminate\Filesystem\Filesystem
     */
    protected Filesystem $files;

    /**
     * Create a new command instance.
     *
     * @param  \Illuminate\Filesystem\Filesystem  $files
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
     * @throws \ParagonIE\Paseto\Exception\InvalidVersionException
     * @throws \ParagonIE\Paseto\Exception\PasetoException
     * @throws \SodiumException
     */
    public function handle(): int
    {
        $key = $this->option('key') ?: Env::get('LARAVEL_ENV_ENCRYPTION_KEY');

        if (! $key) {
            $this->components->error('A decryption key is required.');

            return Command::FAILURE;
        }

        $encryptedFile = ($this->option('env')
                    ? Str::finish(dirname($this->laravel->environmentFilePath()), DIRECTORY_SEPARATOR).'.env.'.$this->option('env')
                    : $this->laravel->environmentFilePath()).'.encrypted';

        $outputFile = $this->outputFilePath();

        if (Str::endsWith($outputFile, '.encrypted')) {
            $this->components->error('Invalid filename.');

            return Command::FAILURE;
        }

        if (! $this->files->exists($encryptedFile)) {
            $this->components->error('Encrypted environment file not found.');

            return Command::FAILURE;
        }

        if ($this->files->exists($outputFile) && ! $this->option('force')) {
            $this->components->error('Environment file already exists.');

            return Command::FAILURE;
        }

        try {
            $encrypter = new Encrypter(Key::parseKey($key, false));

            $this->files->put(
                $outputFile,
                $encrypter->decrypt($this->files->get($encryptedFile))
            );
        } catch (Exception $e) {
            $this->components->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->components->info('Environment successfully decrypted.');

        $this->components->twoColumnDetail('Decrypted file', $outputFile);

        $this->newLine();

        return Command::SUCCESS;
    }

    /**
     * Get the output file path that should be used for the command.
     *
     * @return string
     */
    protected function outputFilePath(): string
    {
        $path = Str::finish($this->option('path') ?: dirname($this->laravel->environmentFilePath()), DIRECTORY_SEPARATOR);

        $outputFile = $this->option('filename') ?: ('.env'.($this->option('env') ? '.'.$this->option('env') : ''));
        $outputFile = ltrim($outputFile, DIRECTORY_SEPARATOR);

        return $path.$outputFile;
    }
}
