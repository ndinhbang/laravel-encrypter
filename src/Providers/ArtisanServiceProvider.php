<?php

namespace Ndinhbang\LaravelEncrypter\Providers;

use Illuminate\Foundation\Console\EnvironmentDecryptCommand;
use Illuminate\Foundation\Console\EnvironmentEncryptCommand;
use Illuminate\Foundation\Console\KeyGenerateCommand;

class ArtisanServiceProvider extends \Illuminate\Foundation\Providers\ArtisanServiceProvider
{
    protected function registerKeyGenerateCommand(): void
    {
        $this->app->singleton(KeyGenerateCommand::class, function () {
            return new \Ndinhbang\LaravelEncrypter\Commands\KeyGenerateCommand;
        });
    }

    protected function registerEnvironmentEncryptCommand(): void
    {
        $this->app->singleton(EnvironmentEncryptCommand::class, function ($app) {
            return new \Ndinhbang\LaravelEncrypter\Commands\EnvironmentEncryptCommand($app['files']);
        });
    }

    protected function registerEnvironmentDecryptCommand(): void
    {
        $this->app->singleton(EnvironmentDecryptCommand::class, function ($app) {
            return new \Ndinhbang\LaravelEncrypter\Commands\EnvironmentDecryptCommand($app['files']);
        });
    }
}
