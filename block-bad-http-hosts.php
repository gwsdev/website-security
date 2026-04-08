<?php
/**
 * Basic WordPress hardening against known malicious outbound hosts
 * and suspicious injected files/code.
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ------------------------------------------------------------
 * SETTINGS
 * ------------------------------------------------------------
 */
function mm_security_blocked_hosts() {
    return [
        'analytics.essentialplugin.com',
        '0x295bae89192c32.com',
        'ethereum-rpc.publicnode.com',
    ];
}

function mm_security_suspicious_strings() {
    return [
        'analytics.essentialplugin.com',
        '0x295bae89192c32.com',
        'ethereum-rpc.publicnode.com',
        'base64_decode(',
        'eval(',
        'gzinflate(',
        'str_rot13(',
        'shell_exec(',
        'system(',
        'assert(',
        'create_function(',
        'wp-comments-posts.php',
        'Googlebot',
        'pages.',
        'links.',
    ];
}

function mm_security_suspicious_filenames() {
    return [
        'wp-comments-posts.php',
        'wp-admins.php',
        'wp-loads.php',
        'wp-settingss.php',
        'wp-blog-headers.php',
        'class.wp.php',
        'wp-activate1.php',
    ];
}

/**
 * ------------------------------------------------------------
 * 1) BLOCK OUTBOUND REQUESTS VIA WORDPRESS HTTP API
 * ------------------------------------------------------------
 */
add_filter('pre_http_request', function ($preempt, $args, $url) {
    $blocked_hosts = mm_security_blocked_hosts();
    $host = wp_parse_url($url, PHP_URL_HOST);

    if ($host) {
        $host = strtolower($host);

        foreach ($blocked_hosts as $blocked) {
            if ($host === $blocked || substr($host, -strlen('.' . $blocked)) === '.' . $blocked) {
                error_log('[MM SECURITY] Blocked outbound request to: ' . $host . ' URL: ' . $url);
                return new WP_Error('blocked_host', 'Blocked outbound request to disallowed host.');
            }
        }
    }

    return $preempt;
}, 10, 3);

/**
 * ------------------------------------------------------------
 * 2) BLOCK KNOWN MALICIOUS FILE ACCESS
 * ------------------------------------------------------------
 */
add_action('init', function () {
    $request_uri = $_SERVER['REQUEST_URI'] ?? '';
    $basename = basename(parse_url($request_uri, PHP_URL_PATH));

    if (in_array($basename, mm_security_suspicious_filenames(), true)) {
        status_header(403);
        exit('Forbidden');
    }
}, 1);

/**
 * ------------------------------------------------------------
 * 3) ADMIN NOTICE IF KNOWN SUSPICIOUS FILE EXISTS
 * ------------------------------------------------------------
 */
add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) {
        return;
    }

    $root = ABSPATH;
    $suspicious_files = [];

    foreach (mm_security_suspicious_filenames() as $file) {
        $path = $root . $file;
        if (file_exists($path)) {
            $suspicious_files[] = $path;
        }
    }

    /*if (!empty($suspicious_files)) {
        echo '<div class="notice notice-error"><p><strong>Security Warning:</strong> Suspicious file(s) detected:</p><ul>';
        foreach ($suspicious_files as $file) {
            echo '<li><code>' . esc_html($file) . '</code></li>';
        }
        echo '</ul><p>Please review and remove if malicious.</p></div>';
    }*/
});

/**
 * ------------------------------------------------------------
 * 4) LIGHTWEIGHT PLUGIN/THEME FILE SCAN (ADMIN ONLY)
 * ------------------------------------------------------------
 * Scans recently modified PHP files in plugins/themes for suspicious strings.
 * This avoids scanning everything on every request.
 */
add_action('admin_init', function () {
    if (!current_user_can('manage_options')) {
        return;
    }

    if (get_transient('mm_security_scan_lock')) {
        return;
    }

    set_transient('mm_security_scan_lock', 1, 10 * MINUTE_IN_SECONDS);

    $dirs = [
        WP_CONTENT_DIR . '/plugins',
        WP_CONTENT_DIR . '/themes',
        WP_CONTENT_DIR . '/mu-plugins',
    ];

    $suspects = [];
    $now = time();
    $max_files = 300; // safety cap
    $checked = 0;

    foreach ($dirs as $dir) {
        if (!is_dir($dir)) {
            continue;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($checked >= $max_files) {
                break 2;
            }

            if (!$file->isFile()) {
                continue;
            }

            if (strtolower($file->getExtension()) !== 'php') {
                continue;
            }

            $path = $file->getPathname();

            // Only inspect files modified in the last 30 days to reduce load
            if (($now - $file->getMTime()) > (30 * DAY_IN_SECONDS)) {
                continue;
            }

            $content = @file_get_contents($path);
            if ($content === false) {
                continue;
            }

            foreach (mm_security_suspicious_strings() as $needle) {
                if (stripos($content, $needle) !== false) {
                    $suspects[] = $path . ' [matched: ' . $needle . ']';
                    break;
                }
            }

            $checked++;
        }
    }

    if (!empty($suspects)) {
        update_option('mm_security_suspect_files', $suspects, false);
    } else {
        delete_option('mm_security_suspect_files');
    }
});

/**
 * ------------------------------------------------------------
 * 5) SHOW SUSPECT FILES IN ADMIN NOTICE
 * ------------------------------------------------------------
 */
add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) {
        return;
    }

    $suspects = get_option('mm_security_suspect_files', []);

    /*if (!empty($suspects) && is_array($suspects)) {
        echo '<div class="notice notice-warning"><p><strong>Security Scan Notice:</strong> Suspicious PHP file patterns found:</p><ul>';
        foreach (array_slice($suspects, 0, 20) as $file) {
            echo '<li><code>' . esc_html($file) . '</code></li>';
        }
        if (count($suspects) > 20) {
            echo '<li><em>...and more</em></li>';
        }
        echo '</ul><p>Please inspect these files. Some may be false positives, but unexpected matches should be reviewed immediately.</p></div>';
    }*/
});

/**
 * ------------------------------------------------------------
 * 6) OPTIONAL: LOG UNKNOWN PHP FILES IN UPLOADS
 * ------------------------------------------------------------
 */
add_action('admin_init', function () {
    if (!current_user_can('manage_options')) {
        return;
    }

    $uploads = WP_CONTENT_DIR . '/uploads';
    if (!is_dir($uploads)) {
        return;
    }

    $found = [];
    $max_files = 100;

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($uploads, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($iterator as $file) {
        if (count($found) >= $max_files) {
            break;
        }

        if ($file->isFile()) {
            $ext = strtolower($file->getExtension());
            if (in_array($ext, ['php', 'phtml', 'phar'], true)) {
                $found[] = $file->getPathname();
            }
        }
    }

    if (!empty($found)) {
        update_option('mm_security_upload_php_files', $found, false);
    } else {
        delete_option('mm_security_upload_php_files');
    }
});

/**
 * ------------------------------------------------------------
 * 7) SHOW UPLOADS PHP FILE ALERT
 * ------------------------------------------------------------
 */
add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) {
        return;
    }

    $found = get_option('mm_security_upload_php_files', []);

    /*if (!empty($found) && is_array($found)) {
        echo '<div class="notice notice-error"><p><strong>Security Alert:</strong> PHP-like files found inside uploads folder:</p><ul>';
        foreach (array_slice($found, 0, 20) as $file) {
            echo '<li><code>' . esc_html($file) . '</code></li>';
        }
        if (count($found) > 20) {
            echo '<li><em>...and more</em></li>';
        }
        echo '</ul><p>Uploads should normally not contain executable PHP files. Review immediately.</p></div>';
    }*/
});