<!doctype html>
<html lang="en" class="h-full">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ $title ?? config('app.name', 'Odayaka Waters') }}</title>
  @vite(['resources/css/app.css','resources/js/app.js'])
  <meta name="csrf-token" content="{{ csrf_token() }}">
  <link rel="icon" href="{{ asset('favicon.ico') }}" sizes="any">
</head>
<body class="min-h-screen" style="color: var(--ow-text);">
  {{-- Central water background (global) --}}
  {{-- (If you still render CSS leaves, keep these; otherwise remove them.) --}}
  <span class="ow-leaf"></span>
  <span class="ow-leaf"></span>
  <span class="ow-leaf"></span>
  <span class="ow-leaf"></span>
  <span class="ow-leaf"></span>

  <header class="ow-header">
    <div class="ow-container">
      <a href="{{ auth()->check() ? route('waters') : url('/') }}" class="ow-brand">
        Odayaka Waters <i class="ow-sakura"></i>
      </a>
      <nav class="ow-nav">
        @auth
          {{-- Show Logs link only for admins --}}
          @if (auth()->user()->role === 'admin')
            <a class="ow-link" href="{{ route('admin.logs') }}">Logs</a>
          @endif

          <a class="ow-link" href="{{ route('waters') }}"> Chat </a>
          <span class="ow-user">{{ auth()->user()->name }}</span>
          <form method="POST" action="{{ route('logout') }}">
            @csrf
            <button class="ow-btn ow-btn--small" type="submit">Logout</button>
          </form>
        @else
          <a class="ow-link" href="{{ route('login') }}">Login</a>
          <a class="ow-link" href="{{ route('register') }}">Register</a>
        @endauth
      </nav>
    </div>
  </header>

  <main class="ow-container" style="position:relative; z-index: 1;">
    @yield('content')
  </main>

  {{-- Ambient canvas mount point --}}
  <div id="ambient-root" style="position:fixed; inset:0; z-index:0;"></div>
</body>
</html>
