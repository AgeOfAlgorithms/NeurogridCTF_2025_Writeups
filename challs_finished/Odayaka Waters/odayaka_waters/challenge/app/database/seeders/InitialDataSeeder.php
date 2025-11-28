<?php

namespace Database\Seeders;

use App\Models\User;
use App\Models\Message;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class InitialDataSeeder extends Seeder
{
    public function run(): void
    {
        // Admin from env (with safe defaults)
        $adminEmail = env('ADMIN_EMAIL', 'hashira@odayaka.htb');
        $adminPass  = env('ADMIN_PASSWORD', 'a-very-strong-password');

        $admin = User::updateOrCreate(
            ['email' => $adminEmail],
            [
                'name'              => 'Administrator',
                'password'          => Hash::make($adminPass),
                'role'              => 'admin',
                'remember_token'    => Str::random(10),
            ]
        );

        // Some demo users
        $users = collect([
            ['name' => 'Alice',   'email' => 'alice@odayaka.htb'],
            ['name' => 'Bob',     'email' => 'bob@odayaka.htb'],
            ['name' => 'Charlie', 'email' => 'charlie@odayaka.htb'],
        ])->map(function ($u) {
            return User::updateOrCreate(
                ['email' => $u['email']],
                [
                    'name'              => $u['name'],
                    'password'          => Hash::make('a-very-strong-password'),
                    'role'              => 'user',
                    'remember_token'    => Str::random(10),
                ]
            );
        });

        // Seed messages for each user (including admin)
        $allUsers = collect([$admin])->merge($users);

        foreach ($allUsers as $user) {
            // only create if none exist yet for idempotency
            if ($user->messages()->count() === 0) {
                Message::create([
                    'user_id'    => $user->id,
                    'body'       => "Hi, I'm {$user->name}.",
                    'is_deleted' => false,
                ]);
                Message::create([
                    'user_id'    => $user->id,
                    'body'       => "This is a sample message for {$user->email}.",
                    'is_deleted' => false,
                ]);
                Message::create([
                    'user_id'    => $user->id,
                    'body'       => 'Old message (soft-deleted).',
                    'is_deleted' => true,
                ]);
            }
        }
    }
}
