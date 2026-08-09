<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Bloqueo automático tras 5 intentos fallidos en 15 minutos.
 */
function buen_inf_auto_block_after_failures( $username ) {

    global $wpdb;

    $table = $wpdb->prefix . 'buen_inf_login_logs';

    $ip = sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? '' );

    if ( empty( $ip ) ) {
        return;
    }

    // Contar intentos fallidos de esta IP en los últimos 15 minutos
    $failed_attempts = (int) $wpdb->get_var(
        $wpdb->prepare(
            "SELECT COUNT(*)
             FROM {$table}
             WHERE ip = %s
             AND status = %s
             AND time >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)",
            $ip,
            'Acceso fallido'
        )
    );

    // Si todavía no ha llegado al límite, salir
    if ( $failed_attempts < 5 ) {
        return;
    }

    // Obtener IPs bloqueadas
    $blocked_ips = get_option( 'buen_inf_manually_blocked_ips', array() );

    // Añadir solo si no existe
    if ( ! in_array( $ip, $blocked_ips, true ) ) {

        $blocked_ips[] = $ip;

        update_option(
            'buen_inf_manually_blocked_ips',
            $blocked_ips
        );

        // Opcional: registrar el bloqueo automático
        error_log( 'CAS: IP bloqueada automáticamente -> ' . $ip );
    }
}

add_action( 'wp_login_failed', 'buen_inf_auto_block_after_failures', 20 );