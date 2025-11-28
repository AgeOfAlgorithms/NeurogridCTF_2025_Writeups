<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class User extends Authenticatable
{
    use Notifiable;
    use HasFactory;

    protected $fillable = ['name','email','password','role'];
    protected $hidden   = ['password','remember_token'];

    public function messages(): HasMany
    {
        return $this->hasMany(Message::class);
    }
}