<?php

use App\Http\Middleware\RoleMiddleware;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // Add/merge your aliases here
        $middleware->alias([
            'role' => RoleMiddleware::class, // <-- this line registers "role"
        ]);

        // (You can also alias others here if you add any later)
    })
    ->withExceptions(function ($exceptions) {
        //
    })->create();
