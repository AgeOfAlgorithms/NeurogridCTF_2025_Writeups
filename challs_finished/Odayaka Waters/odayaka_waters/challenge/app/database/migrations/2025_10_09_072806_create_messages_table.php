<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('messages', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')
                  ->constrained()
                  ->cascadeOnDelete(); // if a user is deleted, remove their messages
            $table->string('body', 400);  // keep it short & indexable
            $table->boolean('is_deleted')->default(false)->index();
            $table->timestamps();

            // Helpful indexes for polling by id/time
            $table->index(['id']);              // fast "after_id" queries
            $table->index(['created_at']);      // general sorting/filtering
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('messages');
    }
};
