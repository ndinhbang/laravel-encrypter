<?php

namespace Ndinhbang\LaravelEncrypter\Middleware;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Cookie\Middleware\EncryptCookies as Middleware;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class EncryptCookies extends Middleware
{
    protected static $neverEncrypt = [
        'XDEBUG_SESSION'
    ];

    /**
     * Decrypt the cookies on the request.
     */
    protected function decrypt(Request $request): Request
    {
        foreach ($request->cookies as $key => $cookie) {
            if ($this->isDisabled($key)) {
                continue;
            }

            try {
                $request->cookies->set($key, $this->decryptCookie($key, $cookie));
            } catch (DecryptException) {
                $request->cookies->set($key, null);
            }
        }

        return $request;
    }

    /**
     * Encrypt the cookies on an outgoing response.
     */
    protected function encrypt(Response $response): Response
    {
        foreach ($response->headers->getCookies() as $cookie) {
            if ($this->isDisabled($cookie->getName())) {
                continue;
            }

            $response->headers->setCookie($this->duplicate(
                $cookie,
                $this->encrypter->encrypt(
                    $cookie->getValue(),
                    static::serialized($cookie->getName())
                )
            ));
        }

        return $response;
    }
}
