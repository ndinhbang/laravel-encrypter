<?php

namespace Ndinhbang\LaravelEncrypter\Middleware;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken as Middleware;

class ValidateCsrfToken extends Middleware
{
    /**
     * Get the CSRF token from the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string|null
     */
    protected function getTokenFromRequest($request): ?string
    {
        $token = $request->input('_token') ?: $request->header('X-CSRF-TOKEN');

        if (! $token && $header = $request->header('X-XSRF-TOKEN')) {
            try {
                $token = $this->encrypter->decrypt($header, static::serialized());
            } catch (DecryptException) {
                $token = '';
            }
        }

        return $token;
    }
}
