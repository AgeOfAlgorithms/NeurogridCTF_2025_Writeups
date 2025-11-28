<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    /**
     * URIs that should be excluded from CSRF verification. For easier sending of requests. This is not a vulnerability in this case, it is intended.
     */
    protected $except = [
        '/register',
        '/login',
        '/api/messages'
    ];
}
