<?php

namespace App\Http\Controllers;

use App\Models\Message;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;

class ChatController extends Controller
{
    public function index()
    {
        return view('chat.index', [
            'title' => 'Odayaka Waters',
            'user'  => Auth::user(),
        ]);
    }

    public function list(Request $request): JsonResponse
    {
        $request->validate([
            'after_id' => ['nullable', 'integer', 'min:0'],
            'limit'    => ['nullable', 'integer', 'min:1', 'max:200'],
        ]);

        $afterId = (int) $request->integer('after_id', 0);
        $limit   = (int) $request->integer('limit', 50);
        $limit   = max(1, min(200, $limit));

        $query = Message::query()
            ->where('is_deleted', false)
            ->with(['user:id,name'])
            ->orderBy('id', 'desc')
            ->limit($limit);

        if ($afterId > 0) {
            $query->where('id', '>', $afterId);
        }

        $rows = $query->get()->sortBy('id')->values();

        $messages = $rows->map(function (Message $m) {
            return [
                'id'         => $m->id,
                'body'       => $m->body,
                'created_at' => $m->created_at?->toIso8601String(),
                'user'       => [
                    'id'   => $m->user_id,
                    'name' => $m->user?->name ?? 'Unknown',
                ],
            ];
        });

        return response()->json([
            'messages' => $messages,
            'now'      => Carbon::now()->toIso8601String(),
        ]);
    }

    public function store(Request $request, RateLimiter $limiter): JsonResponse
    {
        $user = Auth::user();

        $key = 'msg:' . $user->id;
        if (! $limiter->attempt($key, $perMinute = 10, function () {
        })) {
            $seconds = $limiter->availableIn($key);
            return response()->json([
                'error'   => 'Too many messages. Please wait a bit.',
                'retryIn' => $seconds,
            ], 429);
        }

        $validated = $request->validate([
            'body' => ['required', 'string', 'min:1', 'max:400'],
        ]);

        $body = trim(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/u', '', $validated['body']));

        if ($body === '') {
            return response()->json(['error' => 'Empty message.'], 422);
        }

        $msg = new Message();
        $msg->user_id    = $user->id;
        $msg->body       = $body;
        $msg->is_deleted = false;
        $msg->save();

        return response()->json([
            'id'         => $msg->id,
            'body'       => $msg->body,
            'created_at' => $msg->created_at?->toIso8601String(),
            'user'       => [
                'id'   => $user->id,
                'name' => $user->name,
            ],
        ], 201);
    }

    public function destroy(Message $message): JsonResponse
    {
        $message->is_deleted = true;
        $message->save();

        return response()->json(['ok' => true]);
    }
}
