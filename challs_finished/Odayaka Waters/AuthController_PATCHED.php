<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

/**
 * PATCHED VERSION - Odayaka Waters CTF Challenge
 *
 * Fixed HTTP Parameter Pollution vulnerability
 *
 * Changes made:
 * 1. Line 30-31: Changed $_REQUEST to $_POST for input validation
 * 2. Line 36: Hardcoded 'role' => 'user' instead of using $_REQUEST['role']
 */
class AuthController extends Controller
{
    public function showRegister()
    {
        return view('auth.register');
    }

    public function showLogin()
    {
        return view('auth.login');
    }

    public function register(Request $request)
    {

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            return redirect()->route('register');
        }

        if (count($_POST) !== 4) {
            return redirect()->route('register')->with('error', 'Ensure you only have the name, email and password parameter!')->withInput();
        }

        // FIX #1: Changed $_REQUEST to $_POST
        if ($_POST['name'] === null || $_POST['password'] === null || $_POST['email'] === null){
            return redirect()->route('register')->with('error', 'Some parameters are empty!')->withInput();
        }

        // FIX #2: Hardcoded role to 'user', removed user control
        $user = User::create([
            'name'     => $_POST['name'],
            'email'    => $_POST['email'],
            'password' => Hash::make($_POST['password']),
            'role'     => 'user',
        ]);

        Auth::login($user);
        $request->session()->regenerate();

        return redirect()->intended('/waters');
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email'    => ['required','email'],
            'password' => ['required','string'],
        ]);

        if (Auth::attempt($credentials, remember: $request->boolean('remember'))) {
            $request->session()->regenerate();
            return redirect()->intended('/waters');
        }

        return back()->withErrors(['email' => 'Invalid credentials.'])->onlyInput('email');
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/login');
    }
}
