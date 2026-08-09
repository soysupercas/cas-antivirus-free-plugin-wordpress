<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Crear las tablas del plugin
 */
function buen_inf_create_security_tables() {

    global $wpdb;

    $charset_collate = $wpdb->get_charset_collate();

    $table_logs     = $wpdb->prefix . 'buen_inf_login_logs';
    $table_success  = $wpdb->prefix . 'buen_inf_log_success';
    $table_blocked  = $wpdb->prefix . 'buen_inf_blocked_ips';

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';

    // Tabla de intentos fallidos
    $sql_logs = "CREATE TABLE {$table_logs} (
        id MEDIUMINT(9) NOT NULL AUTO_INCREMENT,
        time DATETIME NOT NULL,
        ip VARCHAR(100) NOT NULL,
        username VARCHAR(100) NOT NULL,
        status VARCHAR(50) NOT NULL,
        PRIMARY KEY (id)
    ) {$charset_collate};";

    // Tabla de accesos correctos
    $sql_success = "CREATE TABLE {$table_success} (
        id MEDIUMINT(9) NOT NULL AUTO_INCREMENT,
        time DATETIME NOT NULL,
        ip VARCHAR(100) NOT NULL,
        username VARCHAR(100) NOT NULL,
        status VARCHAR(50) NOT NULL,
        PRIMARY KEY (id)
    ) {$charset_collate};";

    // Tabla de IPs bloqueadas
    $sql_blocked = "CREATE TABLE {$table_blocked} (
        id MEDIUMINT(9) NOT NULL AUTO_INCREMENT,
        ip VARCHAR(100) NOT NULL,
        reason VARCHAR(255) NOT NULL DEFAULT 'Bloqueo manual',
        created DATETIME NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY ip (ip)
    ) {$charset_collate};";

    dbDelta( $sql_logs );
    dbDelta( $sql_success );
    dbDelta( $sql_blocked );
}

add_action( 'admin_init', 'buen_inf_create_security_tables' );


function buen_inf_log_failed_login( $username ) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'buen_inf_login_logs';

    $wpdb->insert(
        $table_name,
        array(
            'time'     => current_time( 'mysql' ),
            'ip'       => sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? '' ),
            'username' => sanitize_user( $username ),
            'status'   => 'Acceso fallido' // Texto estándar para la BD
        ),
        array( '%s', '%s', '%s', '%s' )
    );
}
add_action( 'wp_login_failed', 'buen_inf_log_failed_login' );

function buen_inf_log_successful_login( $user_login, $user ) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'buen_inf_log_success';

    $wpdb->insert(
        $table_name,
        array(
            'time'     => current_time( 'mysql' ),
            'ip'       => sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? '' ),
            'username' => sanitize_user( $user_login ),
            'status'   => 'Acceso correcto' // Texto estándar para la BD
        ),
        array( '%s', '%s', '%s', '%s' )
    );
}
add_action( 'wp_login', 'buen_inf_log_successful_login', 10, 2 );



/// BOTÓN BLOQUEAR IP
function buen_inf_manual_block_ip() {

    if ( ! is_admin() ) {
        return;
    }

    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    if ( empty( $_GET['manual_quick_block'] ) ) {
        return;
    }

    check_admin_referer( 'manual_quick_block' );

    $ip = sanitize_text_field( $_GET['manual_quick_block'] );

    $blocked_ips = get_option( 'buen_inf_manually_blocked_ips', array() );

    if ( ! in_array( $ip, $blocked_ips, true ) ) {
        $blocked_ips[] = $ip;
        update_option( 'buen_inf_manually_blocked_ips', $blocked_ips );
    }

    wp_safe_redirect(
        remove_query_arg(
            array(
                'manual_quick_block',
                '_wpnonce'
            )
        )
    );

    exit;
}

add_action( 'admin_init', 'buen_inf_manual_block_ip' );


/**
 * Comprobar si la IP está bloqueada
 */
function buen_inf_check_blocked_ip() {

    // Permitir acceso al administrador dentro del panel
    if ( is_admin() ) {
        return;
    }

    $ip = sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? '' );

    if ( empty( $ip ) ) {
        return;
    }

    $blocked_ips = get_option( 'buen_inf_manually_blocked_ips', array() );

    if ( ! in_array( $ip, $blocked_ips, true ) ) {
        return;
    }

    status_header( 403 );
    nocache_headers();

    exit(
        '<!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>403 - Acceso denegado</title>
        </head>
        <body style="font-family: Arial; text-align:center; padding-top:100px;">
            <h1>403 - Acceso denegado</h1>
            <p>Tu dirección IP ha sido bloqueada por el administrador.</p>
        </body>
        </html>'
    );
}

add_action( 'init', 'buen_inf_check_blocked_ip', 1 );