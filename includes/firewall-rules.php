<?php
/**
 * CAS Antivirus Pro - Módulo de Firewall Completo
 * 
 * Gestiona los bloqueos en el .htaccess y las protecciones de PHP en tiempo de ejecución.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Evita el acceso directo
}

/**
 * 1. GESTIÓN DE REGLAS EN EL .htaccess (Bloqueos a nivel de servidor)
 */
if ( ! function_exists( 'ssp_manage_firewall_htaccess' ) ) {
    function ssp_manage_firewall_htaccess() {
        $htaccess_path = ABSPATH . '.htaccess';
        
        $block_sqli        = get_option( 'fw_sqli', 0 );
        $block_xss         = get_option( 'fw_xss', 0 );
        $block_lfi_rfi     = get_option( 'fw_lfi', 0 );
        $block_traversal   = get_option( 'fw_path', 0 );
        $block_urls        = get_option( 'fw_url', 0 );
        $block_agents      = get_option( 'fw_useragent', 0 );
        $block_scans       = get_option( 'fw_scan', 0 );

        $begin_marker = '# BEGIN CAS Advanced Firewall';
        $end_marker   = '# END CAS Advanced Firewall';

        $firewall_rules  = "{$begin_marker}\n";
        $firewall_rules .= "<IfModule mod_rewrite.c>\n";
        $firewall_rules .= "    RewriteEngine On\n\n";

        // 1. User-Agent
        if ( $block_agents == 1 || $block_scans == 1 ) {
            $firewall_rules .= "    # User-Agent y Escaneos: Bloquear bots maliciosos\n";
            $firewall_rules .= "    RewriteCond %{HTTP_USER_AGENT} (libwww-perl|wget|ZmEu|nikto|sqlmap|acunetix|nessus|nmap|dirbuster) [NC]\n";
            $firewall_rules .= "    RewriteRule .* - [F,L]\n\n";
        }

        // 2. Path Traversal
        if ( $block_traversal == 1 ) {
            $firewall_rules .= "    # Path Traversal: Impedir acceso a archivos protegidos\n";
            $firewall_rules .= "    RewriteCond %{QUERY_STRING} (\\.\\./|\\.\\.) [NC,OR]\n";
            $firewall_rules .= "    RewriteCond %{QUERY_STRING} (boot\\.ini|etc/passwd|self/environ) [NC]\n";
            $firewall_rules .= "    RewriteRule .* - [F,L]\n\n";
        }

        // 3. LFI / RFI
        if ( $block_lfi_rfi == 1 ) {
            $firewall_rules .= "    # LFI / RFI: Proteger archivos del servidor\n";
            $firewall_rules .= "    RewriteCond %{QUERY_STRING} (http|https|ftp):\\/\\/ [NC,OR]\n";
            $firewall_rules .= "    RewriteCond %{QUERY_STRING} (_vti_bin|\\.exe|\\.dll|\\.sh|\\.bak) [NC]\n";
            $firewall_rules .= "    RewriteRule .* - [F,L]\n\n";
        }

        // 4. Cross-Site Scripting (XSS)
        if ( $block_xss == 1 ) {
            $firewall_rules .= "    # Cross-Site Scripting (XSS): Bloquear código malicioso\n";
            $firewall_rules .= "    RewriteCond %{QUERY_STRING} (<|%3C).*script.*(>|%3E) [NC,OR]\n";
            $firewall_rules .= "    RewriteCond %{QUERY_STRING} GLOBALS(=|\\[|\\%[0-9A-Z]{0,2}) [NC,OR]\n";
            $firewall_rules .= "    RewriteCond %{QUERY_STRING} _REQUEST(=|\\[|\\%[0-9A-Z]{0,2}) [NC]\n";
            $firewall_rules .= "    RewriteRule .* - [F,L]\n\n";
        }

        // 5. SQL Injection
        if ( $block_sqli == 1 ) {
            $firewall_rules .= "    # SQL Injection: Bloquear ataques contra la base de datos\n";
            $firewall_rules .= "    RewriteCond %{QUERY_STRING} union.*select [NC,OR]\n";
            $firewall_rules .= "    RewriteCond %{QUERY_STRING} cast\\(.*as.*char\\) [NC]\n";
            $firewall_rules .= "    RewriteRule .* - [F,L]\n";
        }

        $firewall_rules .= "</IfModule>\n";
        $firewall_rules .= "{$end_marker}";

        // Escritura limpia y nativa con WordPress
        if ( function_exists( 'insert_with_markers' ) && file_exists( $htaccess_path ) ) {
            // Pasamos un array de líneas limpio al marcador
            $lines = explode( "\n", str_replace( "\r", "", $firewall_rules ) );
            // Quitamos los marcadores individuales del array ya que insert_with_markers los añade solo
            $lines_to_insert = array_slice( $lines, 1, count( $lines ) - 2 );
            insert_with_markers( $htaccess_path, 'CAS Advanced Firewall', $lines_to_insert );
        }
    }
}


// Hook automático para actualizar el .htaccess cuando se guarden las opciones
foreach ( array( 'fw_sqli', 'fw_xss', 'fw_lfi', 'fw_path', 'fw_url', 'fw_useragent', 'fw_scan' ) as $opt ) {
    add_action( "update_option_{$opt}", 'ssp_manage_firewall_htaccess' );
    add_action( "add_option_{$opt}", 'ssp_manage_firewall_htaccess' );
}

/**
 * 2. COMPROBACIÓN GENERAL DE IP BANEADA
 */
if ( ! function_exists( 'ssp_firewall_check_banned_ip' ) ) {
    function ssp_firewall_check_banned_ip() {
        if ( get_option( 'fw_tempblock', 0 ) != 1 ) {
            return;
        }

        // Nunca bloquear la administración por IP temporal
        if ( is_admin() ) {
            return;
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $ban_transient = 'ssp_banned_ip_' . md5( $ip );

        if ( get_transient( $ban_transient ) ) {
            status_header( 403 );
            wp_die( 
                '<h1>Acceso Bloqueado Temporalmente</h1><p>Tu dirección IP ha sido bloqueada temporalmente debido a actividades sospechosas o exceso de solicitudes.</p>', 
                'IP Bloqueada', 
                array( 'response' => 403 ) 
            );
        }
    }
    add_action( 'init', 'ssp_firewall_check_banned_ip', 0 );
}

/**
 * 3. FUERZA BRUTA
 */
if ( ! function_exists( 'ssp_firewall_brute_force_check' ) ) {
    function ssp_firewall_brute_force_check( $user, $username, $password ) {
        if ( get_option( 'fw_bruteforce', 0 ) != 1 ) {
            return $user;
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $transient_name = 'ssp_bf_' . md5( $ip );
        $attempts = get_transient( $transient_name ) ?: 0;

        if ( $attempts >= 5 ) {
            if ( get_option( 'fw_tempblock', 0 ) == 1 ) {
                set_transient( 'ssp_banned_ip_' . md5( $ip ), true, 15 * MINUTE_IN_SECONDS );
            }

            wp_die( 
                '<h1>Acceso Bloqueado</h1><p>Has superado el límite de intentos de inicio de sesión. Por seguridad, tu IP ha sido bloqueada temporalmente.</p>', 
                'Fuerza Bruta Detectada', 
                array( 'response' => 403 ) 
            );
        }

        return $user;
    }
    add_filter( 'authenticate', 'ssp_firewall_brute_force_check', 30, 3 );
}

if ( ! function_exists( 'ssp_firewall_login_failed' ) ) {
    function ssp_firewall_login_failed( $username ) {
        if ( get_option( 'fw_bruteforce', 0 ) != 1 ) {
            return;
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $transient_name = 'ssp_bf_' . md5( $ip );
        $attempts = get_transient( $transient_name ) ?: 0;

        set_transient( $transient_name, $attempts + 1, 15 * MINUTE_IN_SECONDS );
    }
    add_action( 'wp_login_failed', 'ssp_firewall_login_failed' );
}

/**
 * 4. RATE LIMITING
 */
if ( ! function_exists( 'ssp_firewall_rate_limit' ) ) {
    function ssp_firewall_rate_limit() {
        if ( get_option( 'fw_rate', 0 ) != 1 ) {
            return;
        }

        if ( is_admin() ) {
            return;
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $transient_name = 'ssp_rl_' . md5( $ip );
        $requests = get_transient( $transient_name ) ?: 0;

        if ( $requests > 30 ) {
            if ( get_option( 'fw_tempblock', 0 ) == 1 ) {
                set_transient( 'ssp_banned_ip_' . md5( $ip ), true, 10 * MINUTE_IN_SECONDS );
            }

            status_header( 429 );
            wp_die( 
                '<h1>Demasiadas solicitudes</h1><p>Has superado el límite de solicitudes permitidas. Tu dirección IP ha sido limitada temporalmente.</p>', 
                'Rate Limit Exceeded', 
                array( 'response' => 429 ) 
            );
        }

        set_transient( $transient_name, $requests + 1, MINUTE_IN_SECONDS );
    }
    add_action( 'init', 'ssp_firewall_rate_limit', 1 );
}