<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\URL;

class AppServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $forwardedPrefix = $this->app['request']->headers->get('x-forwarded-prefix', '');
        $forwardedPort = $this->app['request']->headers->get('X-Forwarded-Port');
        
        $root = $this->app['request']->getScheme() . '://' . $this->app['request']->getHost();
        
        if ($forwardedPort) {
            $root .= ':' . $forwardedPort;
        }
        
        if (!empty($forwardedPrefix)) {
            $root .= rtrim($forwardedPrefix, '/');

        } else {
            $base = rtrim($this->app['request']->getBaseUrl(), '/');
            
            if ($base !== '') {
                $root .= $base;
            }
        }

        URL::forceRootUrl($root);
        URL::forceScheme($this->app['request']->isSecure() ? 'https' : 'http');
        
        if (config('database.default') === 'sqlite') {
            DB::statement('PRAGMA foreign_keys = ON;');
            DB::statement('PRAGMA journal_mode = WAL;');
        }
    }
    
}
