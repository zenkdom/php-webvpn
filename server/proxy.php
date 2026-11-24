<?php
/**
 * PHP-WebVPN Backend Server
 * -------------------------------------------------------------
 * Deploy this script to any PHP web hosting environment (shared hosting, cPanel, VPS).
 * Receives encapsulated requests from the client, executes them via cURL
 * from the hosting server's IP address, and relays the response back.
 *
 * Disguises as a standard Apache 404 Not Found error for unauthorized requests.
 *
 * @license MIT
 * @link https://github.com
 */

// Disable error display to prevent malforming JSON payloads
ini_set('display_errors', '0');
error_reporting(0);

// Optimize execution limits when permitted by the hosting provider
@ini_set('memory_limit', '256M');
@set_time_limit(120);

// =============================================================
// SERVER CONFIGURATION
// =============================================================
$CONFIG = [
    // Secret authorization key. IMPORTANT: Change this to your own strong secret!
    // Must match the "secret_key" configured in the client config.json.
    'secret_key'  => 'ChangeThisSecretKey',

    // Allow GET test requests (?test=1&key=...) for health-checking
    'allow_test'  => true,

    // Maximum cURL request execution timeout (in seconds)
    'max_timeout' => 60,

    // Target SSL certificate verification (false ensures maximum proxy compatibility)
    'verify_ssl'  => false,
];

/**
 * Return an authentic Apache 404 Not Found decoy page.
 * Masks the endpoint from web scanners, crawlers, and censors.
 */
function return_decoy() {
    http_response_code(404);
    header("Content-Type: text/html; charset=UTF-8");
    echo "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n";
    echo "<html><head><title>404 Not Found</title></head><body>\n";
    echo "<h1>Not Found</h1>\n";
    echo "<p>The requested URL was not found on this server.</p>\n";
    echo "<hr><address>Apache Server</address>\n";
    echo "</body></html>";
    exit;
}

// -------------------------------------------------------------
// 1. Authorization Verification
// -------------------------------------------------------------
$client_key = '';

if (isset($_SERVER['HTTP_X_PROXY_KEY'])) {
    $client_key = $_SERVER['HTTP_X_PROXY_KEY'];
} elseif (isset($_GET['key'])) {
    $client_key = $_GET['key'];
}

// -------------------------------------------------------------
// 2. Health-Check / Diagnostic Mode (GET ?test=1&key=...)
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (isset($_GET['test']) && $CONFIG['allow_test']) {
        if (empty($client_key) || !hash_equals($CONFIG['secret_key'], $client_key)) {
            return_decoy();
        }

        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'status'        => 'ok',
            'message'       => 'PHP-WebVPN Backend is operational and ready!',
            'php_version'   => PHP_VERSION,
            'curl_loaded'   => extension_loaded('curl'),
            'curl_version'  => function_exists('curl_version') ? curl_version()['version'] : null,
            'gzip_enabled'  => function_exists('gzencode'),
            'server_ip'     => $_SERVER['SERVER_ADDR'] ?? ($_SERVER['LOCAL_ADDR'] ?? gethostbyname(gethostname())),
            'timestamp'     => time(),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

    // Default for unauthorized or standard GET requests
    return_decoy();
}

// -------------------------------------------------------------
// 3. Process Proxy Request (POST only)
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    return_decoy();
}

$input_raw = file_get_contents('php://input');

// Decompress client gzip payload if compressed
if (isset($_SERVER['HTTP_CONTENT_ENCODING']) && strtolower($_SERVER['HTTP_CONTENT_ENCODING']) === 'gzip') {
    if (function_exists('gzdecode')) {
        $decompressed = @gzdecode($input_raw);
        if ($decompressed !== false) {
            $input_raw = $decompressed;
        }
    }
}

$data = json_decode($input_raw, true);

// Fallback: Check body for authorization key if omitted from HTTP headers
if (empty($client_key) && is_array($data) && isset($data['key'])) {
    $client_key = $data['key'];
}

// Authenticate request key with timing-attack resistant comparison
if (empty($client_key) || !hash_equals($CONFIG['secret_key'], $client_key)) {
    return_decoy();
}

if (!is_array($data) || empty($data['url'])) {
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => true, 'message' => 'Missing or invalid "url" in payload']);
    exit;
}

$target_url = trim($data['url']);
if (!preg_match('#^https?://#i', $target_url)) {
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => true, 'message' => 'URL scheme must be http or https']);
    exit;
}

// Translate IPv6 addresses to IPv4 fallbacks (shared hosting typically lacks IPv6 cURL routing)
$parsed_h = parse_url($target_url, PHP_URL_HOST);
if ($parsed_h) {
    $clean_h = strtolower(trim($parsed_h, '[]'));
    if (strpos($clean_h, ':') !== false) {
        $ipv4_h = null;
        if (strpos($clean_h, 'f001') !== false) $ipv4_h = '149.154.175.50';
        elseif (strpos($clean_h, 'f002') !== false) $ipv4_h = '149.154.167.50';
        elseif (strpos($clean_h, 'f003') !== false) $ipv4_h = '149.154.175.100';
        elseif (strpos($clean_h, 'f004') !== false) $ipv4_h = '149.154.167.91';
        elseif (strpos($clean_h, 'f005') !== false) $ipv4_h = '91.108.56.170';
        elseif (strpos($clean_h, '2001:67c:4e8') !== false || strpos($clean_h, '2001:b28:f23f') !== false) $ipv4_h = '149.154.167.50';

        if ($ipv4_h) {
            $target_url = str_replace($parsed_h, $ipv4_h, $target_url);
        }
    }
}

$method = strtoupper($data['method'] ?? 'GET');
$req_headers_raw = $data['headers'] ?? [];
$body_base64 = $data['body'] ?? null;
$body_raw = $body_base64 ? base64_decode($body_base64) : null;
$req_timeout = isset($data['timeout']) ? min((int)$data['timeout'], $CONFIG['max_timeout']) : 30;

// -------------------------------------------------------------
// 4. Header Sanitization and Preparation
// -------------------------------------------------------------
$hop_by_hop = [
    'proxy-connection', 'connection', 'keep-alive',
    'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade',
    'content-length' // cURL calculates Content-Length automatically
];

$curl_headers = [];
$target_host = parse_url($target_url, PHP_URL_HOST);
$target_port = parse_url($target_url, PHP_URL_PORT);
$has_host_header = false;

if (is_array($req_headers_raw)) {
    foreach ($req_headers_raw as $item) {
        $k = '';
        $v = '';
        if (is_array($item) && count($item) >= 2) {
            $k = trim($item[0]);
            $v = trim($item[1]);
        } elseif (is_string($item)) {
            $parts = explode(':', $item, 2);
            $k = trim($parts[0]);
            $v = trim($parts[1] ?? '');
        }

        if ($k === '') continue;

        $lower_k = strtolower($k);
        if (in_array($lower_k, $hop_by_hop, true)) {
            continue;
        }

        if ($lower_k === 'host') {
            $has_host_header = true;
        }

        $curl_headers[] = "$k: $v";
    }
}

// Add Host header if missing
if (!$has_host_header && !empty($target_host)) {
    $host_val = $target_host;
    if ($target_port && !in_array($target_port, [80, 443])) {
        $host_val .= ':' . $target_port;
    }
    $curl_headers[] = "Host: $host_val";
}

// -------------------------------------------------------------
// 5. Execute Remote Request via cURL
// -------------------------------------------------------------
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => $target_url,
    CURLOPT_CUSTOMREQUEST  => $method,
    CURLOPT_HTTPHEADER     => $curl_headers,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER         => true,
    CURLOPT_FOLLOWLOCATION => false, // Client browser handles 301/302 redirects directly
    CURLOPT_AUTOREFERER    => false,
    CURLOPT_SSL_VERIFYPEER => $CONFIG['verify_ssl'],
    CURLOPT_SSL_VERIFYHOST => $CONFIG['verify_ssl'] ? 2 : 0,
    CURLOPT_CONNECTTIMEOUT => 15,
    CURLOPT_TIMEOUT        => $req_timeout,
    CURLOPT_IPRESOLVE      => 1, // CURL_IPRESOLVE_V4 (force IPv4)
]);

if ($body_raw !== null && strlen($body_raw) > 0) {
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body_raw);
}

$raw_response = curl_exec($ch);

if ($raw_response === false) {
    $err_code = curl_errno($ch);
    $err_msg = curl_error($ch);
    curl_close($ch);

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'error'   => true,
        'status'  => 502,
        'message' => "cURL error ($err_code): $err_msg",
    ]);
    exit;
}

$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$http_code   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$header_text   = substr($raw_response, 0, $header_size);
$resp_body_raw = substr($raw_response, $header_size);

// -------------------------------------------------------------
// 6. Parse Response Headers
// -------------------------------------------------------------
$header_blocks = preg_split("/\r?\n\r?\n/", trim($header_text));
$last_block = '';
for ($i = count($header_blocks) - 1; $i >= 0; $i--) {
    $block = trim($header_blocks[$i]);
    if (!empty($block)) {
        $last_block = $block;
        break;
    }
}

$lines = explode("\n", $last_block);
$resp_headers = [];

foreach ($lines as $idx => $line) {
    $line = trim($line);
    if ($idx === 0 || empty($line)) {
        continue; // Skip HTTP status line
    }

    $colon_pos = strpos($line, ':');
    if ($colon_pos !== false) {
        $hname = trim(substr($line, 0, $colon_pos));
        $hval = trim(substr($line, $colon_pos + 1));
        $lower_name = strtolower($hname);

        // Filter hop-by-hop response headers
        if (in_array($lower_name, ['connection', 'transfer-encoding', 'proxy-connection', 'keep-alive'])) {
            continue;
        }

        $resp_headers[] = [$hname, $hval];
    }
}

// -------------------------------------------------------------
// 7. Relay Response to Client (with Gzip compression if supported)
// -------------------------------------------------------------
$response_payload = json_encode([
    'status'  => $http_code,
    'headers' => $resp_headers,
    'body'    => base64_encode($resp_body_raw),
]);

if (isset($_SERVER['HTTP_ACCEPT_ENCODING']) && strpos($_SERVER['HTTP_ACCEPT_ENCODING'], 'gzip') !== false && function_exists('gzencode')) {
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Encoding: gzip');
    echo gzencode($response_payload, 6);
} else {
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Length: ' . strlen($response_payload));
    echo $response_payload;
}
