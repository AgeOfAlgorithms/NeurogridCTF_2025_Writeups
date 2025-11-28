@extends('layouts.app')

@section('content')
  <div class="grid lg:grid-cols-3 gap-6">
    {{-- Ambient panel --}}
    <section class="lg:col-span-2 relative rounded-xl overflow-hidden border border-white/10">
      <div id="ambient-root" class="ambient-root">
        {{-- Canvas injected by JS --}}
        <div class="ambient-overlay">
          <div class="controls">
            <button id="aw-play" class="btn">Play</button>
            <input id="aw-volume" type="range" min="0" max="100" value="25" aria-label="Volume" />
            <label class="quality">
              <span>Visuals:</span>
              <select id="aw-quality">
                <option value="standard" selected>Standard</option>
                <option value="low">Low</option>
                <option value="ultra">Ultra</option>
              </select>
            </label>
          </div>
        </div>
      </div>
    </section>

    {{-- Placeholder column (chat will live here later) --}}
    <aside class="rounded-xl p-4 bg-slate-900/40 border border-white/10">
      <h2 class="font-semibold mb-2">Odayaka Waters</h2>
      <p class="opacity-80 text-sm">
        Ambient water & drifting leaves. Play the track and relax.
      </p>
    </aside>
  </div>
@endsection
