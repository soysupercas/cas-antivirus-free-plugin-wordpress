<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

require_once plugin_dir_path( __FILE__ ) . '../libs/phpqrcode/qrlib.php';

/**
 * ==========================================================
 * Motor 2FA
 * ==========================================================
 */

/**
 * Decodifica Base32
 */
function cas_base32_decode( $sec ) {

    if ( empty( $sec ) ) {
        return false;
    }

    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    $sec = strtoupper( $sec );

    $buffer = '';

    for ( $i = 0; $i < strlen( $sec ); $i++ ) {

        $val = strpos( $chars, $sec[$i] );

        if ( $val === false ) {
            continue;
        }

        $buffer .= str_pad(
            decbin( $val ),
            5,
            '0',
            STR_PAD_LEFT
        );

    }

    $output = '';

    for ( $i = 0; $i + 8 <= strlen( $buffer ); $i += 8 ) {

        $output .= chr(
            bindec(
                substr(
                    $buffer,
                    $i,
                    8
                )
            )
        );

    }

    return $output;

}

/**
 * Calcula un código TOTP
 */
function cas_calculate_code( $binary_secret, $time_slice ) {

    $time =
        chr(0) .
        chr(0) .
        chr(0) .
        chr(0) .
        pack(
            'N*',
            $time_slice
        );

    $hm = hash_hmac(
        'sha1',
        $time,
        $binary_secret,
        true
    );

    $offset =
        ord(
            substr(
                $hm,
                -1
            )
        ) & 0x0F;

    $hashpart = substr(
        $hm,
        $offset,
        4
    );

    $value = unpack(
        'N',
        $hashpart
    );

    $value = $value[1];

    $value &= 0x7FFFFFFF;

    return str_pad(
        $value % 1000000,
        6,
        '0',
        STR_PAD_LEFT
    );

}

/**
 * Verifica un código
 */
function cas_verify_totp_code(
    $secret,
    $code,
    $discrepancy = 1
) {

    $decoded = cas_base32_decode(
        $secret
    );

    if ( ! $decoded ) {
        return false;
    }

    $slice = floor(
        time() / 30
    );

    for (
        $i = -$discrepancy;
        $i <= $discrepancy;
        $i++
    ) {

        $generated = cas_calculate_code(
            $decoded,
            $slice + $i
        );

        if (
            hash_equals(
                (string) $generated,
                str_pad(
                    (string) $code,
                    6,
                    '0',
                    STR_PAD_LEFT
                )
            )
        ) {
            return true;
        }

    }

    return false;

}

/**
 * Genera una clave secreta Base32 para Google Authenticator
 */
function cas_generate_base32_secret() {

    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    $secret = '';

    for ( $i = 0; $i < 16; $i++ ) {

        $secret .= $chars[
            wp_rand(
                0,
                strlen( $chars ) - 1
            )
        ];

    }

    return $secret;
}

/**
 * Genera una clave secreta
 */
function cas_generate_qr( $text, $user_id ) {

    $upload_dir = wp_upload_dir();

    $folder = $upload_dir['basedir'] . '/cas-antivirus';

    if ( ! file_exists( $folder ) ) {
        wp_mkdir_p( $folder );
    }

    $filename = 'cas-2fa-' . $user_id . '.png';

    $file = $folder . '/' . $filename;

    QRcode::png(
        $text,
        $file,
        QR_ECLEVEL_M,
        6,
        2
    );

    if ( ! file_exists( $file ) ) {
        return '';
    }

    return $upload_dir['baseurl'] . '/cas-antivirus/' . $filename;
}

/**
 * ==========================================================
 * Guardar configuración desde el plugin
 * ==========================================================
 */
add_action( 'admin_init', 'cas_handle_plugin_2fa_save' );

function cas_handle_plugin_2fa_save() {

    // ¿Se ha enviado el formulario?
    if ( empty( $_POST['cas_2fa_nonce'] ) ) {
        return;
    }

    // Verificar nonce
    if ( ! wp_verify_nonce( $_POST['cas_2fa_nonce'], 'cas_save_2fa_action' ) ) {
        return;
    }

    // Solo administradores
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    $user_id = get_current_user_id();

    // Generar clave si aún no existe
    $secret = get_user_meta( $user_id, 'cas_2fa_secret', true );

    if ( empty( $secret ) ) {

        $secret = cas_generate_base32_secret();

        update_user_meta(
            $user_id,
            'cas_2fa_secret',
            $secret
        );

    }

    $enable = isset( $_POST['cas_enable_2fa'] );

    $code = '';

    if ( isset( $_POST['cas_2fa_code'] ) ) {

        $code = sanitize_text_field(
            $_POST['cas_2fa_code']
        );

    }

   /**
     * ACTIVAR
     */
    if ( $enable ) {

        if ( empty( $code ) ) {

            add_settings_error(
                'cas_notices',
                'cas_2fa_empty',
                ssp_get_text( '2fa_empty_code' ),
                'error'
            );

            return;

        }

        if ( ! cas_verify_totp_code( $secret, $code ) ) {

            add_settings_error(
                'cas_notices',
                'cas_2fa_invalid',
                ssp_get_text( '2fa_invalid_code' ),
                'error'
            );

            return;

        }

        update_user_meta(
            $user_id,
            'cas_2fa_enabled',
            '1'
        );

        add_settings_error(
            'cas_notices',
            'cas_2fa_enabled',
            ssp_get_text( '2fa_enabled_notice' ),
            'updated'
        );

    }

    /**
     * DESACTIVAR
     */
    else {

        delete_user_meta(
            $user_id,
            'cas_2fa_enabled'
        );

        add_settings_error(
            'cas_notices',
            'cas_2fa_disabled',
            ssp_get_text( '2fa_disabled_notice' ),
            'updated'
        );

    }

}

/**
 * ==========================================================
 * Añadir campo 2FA al formulario de login
 * ==========================================================
 */
add_action( 'login_form', 'cas_render_2fa_login_field' );

function cas_render_2fa_login_field() {

    $admins = get_users( array(
        'role'       => 'administrator',
        'meta_key'   => 'cas_2fa_enabled',
        'meta_value' => '1',
        'number'     => 1,
        'fields'     => 'ID',
    ) );

    if ( empty( $admins ) ) {
        return;
    }

    ?>
    <p>
        <label for="cas_2fa_code">
            Código de autenticación
            <input
                type="text"
                name="cas_2fa_code"
                id="cas_2fa_code"
                class="input"
                maxlength="6"
                autocomplete="one-time-code"
            />
        </label>
    </p>
    <?php
}

/**
 * ==========================================================
 * Verificar código 2FA durante el login
 * ==========================================================
 */
add_filter( 'authenticate', 'cas_verify_login_2fa', 50, 3 );

function cas_verify_login_2fa( $user, $username, $password ) {

    // Si ya hay un error previo (usuario o contraseña incorrectos)
    if ( is_wp_error( $user ) ) {
        return $user;
    }

    // Si no es un usuario válido
    if ( ! ( $user instanceof WP_User ) ) {
        return $user;
    }

    // ¿Tiene el 2FA activado?
    $enabled = get_user_meta(
        $user->ID,
        'cas_2fa_enabled',
        true
    );

    if ( $enabled !== '1' ) {
        return $user;
    }

    // Obtener la clave secreta
    $secret = get_user_meta(
        $user->ID,
        'cas_2fa_secret',
        true
    );

    // Código introducido
    $code = '';

    if ( isset( $_POST['cas_2fa_code'] ) ) {
        $code = sanitize_text_field( $_POST['cas_2fa_code'] );
    }

    if ( empty( $code ) ) {

        return new WP_Error(
            'cas_2fa_required',
            '<strong>Error:</strong> Debes introducir el código de autenticación.'
        );

    }

    if ( ! cas_verify_totp_code( $secret, $code ) ) {

        return new WP_Error(
            'cas_2fa_invalid',
            '<strong>Error:</strong> El código de autenticación no es válido.'
        );

    }

    return $user;

}