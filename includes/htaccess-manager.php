<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Ruta al archivo .htaccess
 */
if ( ! function_exists( 'ssp_get_htaccess_path' ) ) {
    function ssp_get_htaccess_path() {
        return ABSPATH . '.htaccess';
    }
}

/**
 * Comprueba si el servidor es compatible
 */
if ( ! function_exists( 'ssp_htaccess_supported' ) ) {
    function ssp_htaccess_supported() {

        if ( empty( $_SERVER['SERVER_SOFTWARE'] ) ) {
            return false;
        }

        $server = strtolower( $_SERVER['SERVER_SOFTWARE'] );

        return (
            strpos( $server, 'apache' ) !== false ||
            strpos( $server, 'litespeed' ) !== false
        );
    }
}

/**
 * Genera todas las reglas del plugin
 */
if ( ! function_exists( 'ssp_generate_htaccess_rules' ) ) {
    function ssp_generate_htaccess_rules() {

        $rules = array();

        /*
        |--------------------------------------------------------------------------
        | Bloquear PHP en wp-includes
        |--------------------------------------------------------------------------
        */

        if ( get_option( 'ssp_protect_wp_includes', 'no' ) === 'yes' ) {

            $rules[] = '<IfModule mod_rewrite.c>';
            $rules[] = 'RewriteRule ^wp-includes/.*\.php$ - [F,L]';
            $rules[] = '</IfModule>';
            $rules[] = '';

        }
		

        /*
        |--------------------------------------------------------------------------
        | Proteger archivos sensibles
        |--------------------------------------------------------------------------
        */

        if ( get_option( 'ssp_protect_sensitive_files', 'no' ) === 'yes' ) {

            $rules[] = '<FilesMatch "^(readme\.html|license\.txt|composer\.(json|lock)|package(-lock)?\.json|phpunit\.xml(\.dist)?|wp-config-sample\.php)$">';
            $rules[] = 'Require all denied';
            $rules[] = '</FilesMatch>';
            $rules[] = '';

        }

        return $rules;
    }
}

/**
 /**
 * Escribe el bloque CAS Security en .htaccess
 */
if ( ! function_exists( 'ssp_update_htaccess' ) ) {
    function ssp_update_htaccess() {

        if ( ! ssp_htaccess_supported() ) {
            return;
        }

        $file = ssp_get_htaccess_path();

        if ( ! file_exists( $file ) ) {
            return;
        }

        if ( ! is_writable( $file ) ) {
            return;
        }

        // Crear copia de seguridad del .htaccess antes de modificarlo
        @copy( $file, $file . '.cas-backup' );

        $contents = file_get_contents( $file );

        if ( $contents === false ) {
            return;
        }

        $rules = ssp_generate_htaccess_rules();

        $block = '';

        if ( ! empty( $rules ) ) {

            $block  = "# BEGIN CAS Security\n";
            $block .= implode( "\n", $rules );
            $block .= "\n# END CAS Security\n";

        }

        $pattern = '/\# BEGIN CAS Security.*?\# END CAS Security\s*/is';

        $contents = preg_replace(
            $pattern,
            '',
            $contents
        );

        $contents = rtrim( $contents ) . "\n\n";

        if ( ! empty( $block ) ) {
            $contents .= $block;
        }

        file_put_contents(
            $file,
            $contents,
            LOCK_EX
        );

    }
}

add_action( 'update_option_ssp_protect_wp_includes', 'ssp_update_htaccess' );

add_action(
    'update_option_ssp_protect_sensitive_files',
    'ssp_update_htaccess'
);