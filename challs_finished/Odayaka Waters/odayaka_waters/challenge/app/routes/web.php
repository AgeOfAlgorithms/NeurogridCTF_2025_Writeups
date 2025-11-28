<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\ChatController;
use App\Http\Controllers\Admin\LogController;
use Illuminate\Support\Facades\Route;
use App\Http\Middleware\VerifyCsrfToken;

/*
|--------------------------------------------------------------------------
| Entry
|--------------------------------------------------------------------------
| Root goes to Login (as requested).
*/
Route::get('/', function () {
    return redirect()->route('login');
})->name('root');

/*
|--------------------------------------------------------------------------
| Auth (guest-only)
|--------------------------------------------------------------------------
*/
Route::middleware('guest')->group(function () {
    Route::get('/register', [AuthController::class, 'showRegister'])->name('register');
    Route::post('/register', [AuthController::class, 'register'])->withoutMiddleware([VerifyCsrfToken::class]);
    Route::get('/login',    [AuthController::class, 'showLogin'])->name('login');
    Route::post('/login',   [AuthController::class, 'login'])->middleware('throttle:5,1')->withoutMiddleware([VerifyCsrfToken::class]); // 5/min
});

/*
|--------------------------------------------------------------------------
| Admin (auth + role)
|--------------------------------------------------------------------------
*/
Route::middleware(['auth', 'role:admin'])->group(function () {
    Route::get('/admin/logs', [LogController::class, 'index'])->name('admin.logs');
    Route::get('/admin/logs/chunk', [LogController::class, 'chunk'])->name('admin.logs.chunk');
});
/*
|--------------------------------------------------------------------------
| App (auth)
|--------------------------------------------------------------------------
| /waters will be the chat screen for all authenticated users (user/admin).
*/
Route::middleware('auth')->group(function () {
    Route::get('/waters', [ChatController::class, 'index'])->name('waters');

    // chat API
    Route::get('/api/messages', [ChatController::class, 'list'])->name('chat.list');
    Route::post('/api/messages', [ChatController::class, 'store'])
        ->middleware('throttle:30,1') // 30 requests/min as a network guard
        ->name('chat.store');

    Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
});