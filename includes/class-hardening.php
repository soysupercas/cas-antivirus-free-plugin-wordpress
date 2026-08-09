<?php

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Comprueba si el servidor es compatible con .htaccess (Apache o LiteSpeed)
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
 * Genera de forma dinámica las reglas del .htaccess según las opciones activas
 */
if ( ! function_exists( 'ssp_generate_hardening_rules' ) ) {
    function ssp_generate_hardening_rules() {
        $blocks = array();

        // 1. Protección de archivos sensibles
        if ( get_option( 'ssp_protect_sensitive_files', 'yes' ) === 'yes' ) {
            $sensitive_block  = "# BEGIN CAS Sensitive Files\n";
            $sensitive_block .= "<FilesMatch \"^(readme\.html|license\.txt|composer\.(json|lock)|package\.json|phpunit\.xml|error_log)$\">\n";
            $sensitive_block .= "    Require all denied\n";
            $sensitive_block .= "</FilesMatch>\n";
            $sensitive_block .= "# END CAS Sensitive Files";
            $blocks[] = $sensitive_block;
        }

        // 2. Protección de wp-includes
        if ( get_option( 'ssp_protect_wp_includes', 'yes' ) === 'yes' ) {
            $includes_block  = "# BEGIN CAS Protect wp-includes\n";
            $includes_block .= "RewriteEngine On\n";
            $includes_block .= "RewriteRule !^wp-includes/ - [S=3]\n";
            $includes_block .= "RewriteRule ^wp-includes/[^/]+\\.php$ - [F,L]\n";
            $includes_block .= "RewriteRule ^wp-includes/js/tinymce/langs/.+\\.php - [F,L]\n";
            $includes_block .= "RewriteRule ^wp-includes/theme-compat/ - [F,L]\n";
            $includes_block .= "# END CAS Protect wp-includes";
            $blocks[] = $includes_block;
        }

        // 3. Bloqueo de XML-RPC
        if ( get_option( 'ssp_block_xmlrpc', 'yes' ) === 'yes' ) {
            $xmlrpc_block  = "# BEGIN CAS Block XML-RPC\n";
            $xmlrpc_block .= "<Files xmlrpc.php>\n";
            $xmlrpc_block .= "    Require all denied\n";
            $xmlrpc_block .= "</Files>\n";
            $xmlrpc_block .= "# END CAS Block XML-RPC";
            $blocks[] = $xmlrpc_block;
        }

        return $blocks;
    }
}

/**
 * Actualiza el archivo .htaccess principal limpiando lo antiguo y aplicando lo nuevo
 */
if ( ! function_exists( 'ssp_update_main_htaccess' ) ) {
    function ssp_update_main_htaccess() {
        if ( ! ssp_htaccess_supported() ) {
            return;
        }

        $file = ABSPATH . '.htaccess';

        if ( ! file_exists( $file ) ) {
            if ( ! is_writable( ABSPATH ) ) {
                return;
            }
            file_put_contents( $file, '' );
        }

        if ( ! is_writable( $file ) ) {
            return;
        }

        // Crear copia de seguridad preventiva
        @copy( $file, $file . '.cas-backup' );

        $contents = file_get_contents( $file );
        if ( $contents === false ) {
            return;
        }

        // Limpiar bloques antiguos de CAS para evitar duplicidades
        $contents = preg_replace( '/\# BEGIN CAS Sensitive Files.*?\# END CAS Sensitive Files\s*/is', '', $contents );
        $contents = preg_replace( '/\# BEGIN CAS Protect wp-includes.*?\# END CAS Protect wp-includes\s*/is', '', $contents );
        $contents = preg_replace( '/\# BEGIN CAS Block XML-RPC.*?\# END CAS Block XML-RPC\s*/is', '', $contents );

        // Obtener los bloques actuales según las opciones marcadas
        $new_blocks = ssp_generate_hardening_rules();

        $contents = rtrim( $contents );

        // Añadir los bloques activos al final del archivo
        if ( ! empty( $new_blocks ) ) {
            $contents .= "\n\n" . implode( "\n\n", $new_blocks ) . "\n";
        } else {
            $contents .= "\n";
        }

        // Guardar cambios de forma segura
        file_put_contents( $file, $contents, LOCK_EX );
    }
}

/**
 * Gestiona el bloqueo de PHP en la carpeta uploads mediante su propio .htaccess
 */
if ( ! function_exists( 'ssp_manage_php_uploads_htaccess' ) ) {
    function ssp_manage_php_uploads_htaccess() {
        $upload = wp_upload_dir();
        if ( empty( $upload['basedir'] ) ) {
            return;
        }

        $htaccess = trailingslashit( $upload['basedir'] ) . '.htaccess';
        $status = get_option( 'ssp_block_php_uploads', 'yes' );

        // Inicializar WP_Filesystem de forma segura
        global $wp_filesystem;
        if ( empty( $wp_filesystem ) ) {
            require_once ABSPATH . '/wp-admin/includes/file.php';
            WP_Filesystem();
        }

        if ( $status === 'yes' ) {
            $rules  = "# BEGIN CAS Block PHP Uploads\n";
            $rules .= "<FilesMatch \"\.(php|php3|php4|php5|phtml|phar)$\">\n";
            $rules .= "    Require all denied\n";
            $rules .= "</FilesMatch>\n";
            $rules .= "# END CAS Block PHP Uploads\n";

            // Usamos el sistema de ficheros de WP en lugar de file_put_contents directo
            if ( $wp_filesystem ) {
                $wp_filesystem->put_contents( $htaccess, $rules, FS_CHMOD_FILE );
            }
        } else {
            if ( $wp_filesystem && $wp_filesystem->exists( $htaccess ) ) {
                $content = $wp_filesystem->get_contents( $htaccess );
                if ( $content !== false && strpos( $content, 'CAS Block PHP Uploads' ) !== false ) {
                    $wp_filesystem->delete( $htaccess );
                }
            }
        }
    }
}

/**
 * Función envolvente que ejecuta las actualizaciones
 */
if ( ! function_exists( 'ssp_apply_hardening_rules' ) ) {
    function ssp_apply_hardening_rules() {
        ssp_update_main_htaccess();
        ssp_manage_php_uploads_htaccess();
    }
}

// Enganchar a la actualización de las opciones específicas
add_action( 'update_option_ssp_protect_sensitive_files', 'ssp_apply_hardening_rules' );
add_action( 'update_option_ssp_protect_wp_includes', 'ssp_apply_hardening_rules' );
add_action( 'update_option_ssp_block_php_uploads', 'ssp_apply_hardening_rules' );
add_action( 'update_option_ssp_block_xmlrpc', 'ssp_apply_hardening_rules' );

// Asegurar que se aplique si se registran por primera vez
add_action( 'added_option_ssp_protect_sensitive_files', 'ssp_apply_hardening_rules' );
add_action( 'added_option_ssp_protect_wp_includes', 'ssp_apply_hardening_rules' );
add_action( 'added_option_ssp_block_php_uploads', 'ssp_apply_hardening_rules' );
add_action( 'added_option_ssp_block_xmlrpc', 'ssp_apply_hardening_rules' );