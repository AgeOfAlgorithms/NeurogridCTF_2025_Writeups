<?php

namespace Database\Factories;

use App\Models\Message;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

class MessageFactory extends Factory
{
    protected $model = Message::class;

    public function definition(): array
    {
        return [
            'user_id'    => User::factory(),
            'body'       => fake()->sentence(8),
            'is_deleted' => false,
        ];
    }
}
