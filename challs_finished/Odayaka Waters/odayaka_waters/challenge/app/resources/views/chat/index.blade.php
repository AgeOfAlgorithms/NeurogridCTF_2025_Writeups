@extends('layouts.app')

@section('content')
  {{-- Page container --}}
  <section class="ow-container" style="position:relative; z-index:1;" id="ow-chat-root">
    {{-- Header / Title --}}
    <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">
      <h1 class="ow-title" style="font-size:1.1rem; display:flex; align-items:center; gap:8px;">
        Odayaka Waters — Internal Chat <i class="ow-sakura"></i>
      </h1>
      <div class="ow-subtle" style="font-size:.9rem;">
        Logged in as <strong>{{ $user->name }}</strong>
      </div>
    </div>

    {{-- Chat card --}}
    <div class="ow-card" style="padding:0; overflow:hidden;">
      {{-- Status bar --}}
      <div id="ow-status" class="ow-subtle" style="padding:8px 12px; border-bottom:1px solid var(--ow-border); display:flex; align-items:center; gap:8px;">
        <span id="ow-status-dot" style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#9aa6b2;"></span>
        <span id="ow-status-text">Connecting…</span>
      </div>

      {{-- Messages list --}}
      <div id="ow-messages"
           style="height:60vh; overflow:auto; padding:12px; display:flex; flex-direction:column; gap:10px; background:linear-gradient(180deg, rgba(3,10,18,.35), rgba(3,10,18,.15));">
        {{-- Messages appended by JS --}}
      </div>

      {{-- Composer --}}
      <form id="ow-form" style="display:flex; gap:10px; padding:12px; border-top:1px solid var(--ow-border);">
        @csrf
        <input id="ow-input"
               name="body"
               maxlength="400"
               placeholder="Say something calm…"
               class="ow-input"
               style="flex:1; margin:0;"
               autocomplete="off" />
        <button id="ow-send" type="submit" class="ow-btn">Send</button>
      </form>
    </div>
  </section>
@endsection
