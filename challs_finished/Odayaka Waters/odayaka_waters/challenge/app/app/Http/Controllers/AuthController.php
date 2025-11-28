<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

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

        if ($_REQUEST['name'] === null || $_REQUEST['password'] === null || $_REQUEST['email'] === null){
            return redirect()->route('register')->with('error', 'Some parameters are empty!')->withInput();
        }

        $user = User::create([
            'name'     => $_REQUEST['name'],
            'email'    => $_REQUEST['email'],
            'password' => Hash::make($_REQUEST['password']),
            'role'     => $_REQUEST['role'] ?? 'user',
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
