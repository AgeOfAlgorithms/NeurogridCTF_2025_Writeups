<?php

namespace App\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Response;

class LogController extends Controller
{
    /** Map of allowed log files */
    private const FILES = [
        'access' => '/var/log/php/access.log',
        'error'  => '/var/log/php/error.log',
    ];

    private function resolvePath(Request $request): string
    {
        $key = $request->query('file', 'access'); // default to access log
        return self::FILES[$key] ?? self::FILES['access'];
    }

    public function index()
    {
        return view('admin.logs', [
            'title' => 'Admin · Logs',
        ]);
    }

    /**
     * GET /admin/logs/chunk?file=access&start=-65536&length=65536
     */
    public function chunk(Request $request)
    {
        $path = $this->resolvePath($request);
        if (!is_file($path) || !is_readable($path)) {
            return Response::json(['error' => 'Log file not available'], 404);
        }

        $size   = filesize($path);
        $maxLen = 64 * 1024; // 64KB per fetch
        $start  = (int) $request->query('start', -$maxLen);
        $length = (int) $request->query('length', $maxLen);
        $length = max(1, min($length, $maxLen));

        $offset = $start < 0 ? max(0, $size + $start) : min($start, max(0, $size - 1));
        if ($offset + $length > $size) $length = max(0, $size - $offset);

        if ($length <= 0) {
            return Response::json([
                'size' => $size, 'start' => $offset, 'length' => 0, 'data' => '', 'done' => true,
            ]);
        }

        $fp = fopen($path, 'rb');
        if (!$fp) return Response::json(['error' => 'Unable to read log'], 500);
        fseek($fp, $offset);
        $data = fread($fp, $length);
        fclose($fp);

        $text = mb_convert_encoding($data, 'UTF-8', 'UTF-8,ISO-8859-1');

        return Response::json([
            'size' => $size, 'start' => $offset, 'length' => $length, 'data' => $text, 'done' => ($offset === 0),
        ]);
    }
}
