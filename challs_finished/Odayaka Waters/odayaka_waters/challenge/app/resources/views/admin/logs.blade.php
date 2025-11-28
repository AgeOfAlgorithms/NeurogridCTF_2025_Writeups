@extends('layouts.app')

@section('content')
  {{-- Wider admin container --}}
  <section class="ow-container ow-container--wide" style="position:relative; z-index:1;" id="ow-logs-root">
    <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">
      <h1 class="ow-title" style="font-size:1.1rem; display:flex; align-items:center; gap:8px;">
        Server Logs <i class="ow-sakura"></i>
      </h1>
      <div class="ow-subtle" style="font-size:.9rem;">Read-only</div>
    </div>

    <div class="ow-card" style="padding:0; overflow:hidden;">
      <div style="display:flex; align-items:center; gap:10px; padding:10px 12px; border-bottom:1px solid var(--ow-border);">
        <button id="ow-logs-refresh" class="ow-btn ow-btn--small" type="button">Refresh</button>
        <button id="ow-logs-older" class="ow-btn ow-btn--small" type="button">Load older</button>
        <div class="ow-subtle" id="ow-logs-meta" style="margin-left:auto;">—</div>
      </div>

      <pre id="ow-logs-view"
           style="height:72vh; overflow:auto; margin:0; padding:14px 16px; background:rgba(2,8,23,.45); color:var(--ow-text); white-space:pre-wrap; word-break:break-word; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;"></pre>
    </div>
  </section>
@endsection
