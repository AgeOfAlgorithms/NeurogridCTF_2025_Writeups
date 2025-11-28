<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('users', function (Blueprint $t) {
            $t->id();
            $t->string('name', 80);
            $t->string('email')->unique();
            $t->string('password');                 // Argon2id hashed
            $t->enum('role', ['user','admin'])->default('user');
            $t->rememberToken();
            $t->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
