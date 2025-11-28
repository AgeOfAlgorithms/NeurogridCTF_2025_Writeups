<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class RoleMiddleware
{
    // Use as: ->middleware('role:admin') or 'role:admin,user'
    public function handle(Request $request, Closure $next, ...$roles)
    {
        $user = $request->user();
        if (!$user) {
            abort(401);
        }

        // allow comma-separated list
        if (count($roles) === 1 && str_contains($roles[0], ',')) {
            $roles = array_map('trim', explode(',', $roles[0]));
        }

        if (!in_array($user->role, $roles, true)) {
            abort(403, 'You are not authorized to access this resource.');
        }

        return $next($request);
    }
}
