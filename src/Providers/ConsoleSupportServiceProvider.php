<?php

namespace Ndinhbang\LaravelEncrypter\Providers;

use Illuminate\Database\MigrationServiceProvider;
use Illuminate\Foundation\Providers\ComposerServiceProvider;

class ConsoleSupportServiceProvider extends \Illuminate\Foundation\Providers\ConsoleSupportServiceProvider
{
    /**
     * The provider class names.
     *
     * @var string[]
     */
    protected $providers = [
        ArtisanServiceProvider::class,
        MigrationServiceProvider::class,
        ComposerServiceProvider::class,
    ];
}
