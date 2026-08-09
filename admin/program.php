<?php

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}


if ( ! function_exists( 'ssp_add_security_headers' ) ) {
    function ssp_add_security_headers() {
        if ( is_admin() ) {
            return;
        }

        $x_frame = get_option( 'ssp_x_frame_options', 'DENY' );
        if ( $x_frame !== 'disabled' ) {
            header( 'X-Frame-Options: ' . sanitize_text_field( $x_frame ) );
        }

        if ( get_option( 'ssp_x_content_type', 'yes' ) === 'yes' ) {
            header( 'X-Content-Type-Options: nosniff' );
        }

        if ( get_option( 'ssp_hsts', 'yes' ) === 'yes' ) {
            header( 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' );
        }

        $referrer = get_option( 'ssp_referrer_policy', 'strict-origin-when-cross-origin' );
        if ( $referrer !== 'disabled' ) {
            header( 'Referrer-Policy: ' . sanitize_text_field( $referrer ) );
        }

        $csp = get_option( 'ssp_csp', 'default' );
        if ( $csp !== 'disabled' ) {
            header( "Content-Security-Policy: upgrade-insecure-requests" );
        }

        if ( get_option( 'ssp_permissions_policy', 'yes' ) === 'yes' ) {
            header( 'Permissions-Policy: accelerometer=(), camera=(), display-capture=(), geolocation=(), microphone=()' );
        }

        header( 'X-XSS-Protection: 0' );
        header( 'Cross-Origin-Resource-Policy: cross-origin' );
    }
    add_action( 'send_headers', 'ssp_add_security_headers' );
}


// ==========================================
// 2. FUNCIONES DE ENDURECIMIENTO Y PRIVACIDAD
// ==========================================


// Bloquear el editor de archivos
if ( get_option( 'ssp_disable_file_edit', 'yes' ) === 'yes' && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
    define( 'DISALLOW_FILE_EDIT', true );
}

// Bloquear XML-RPC
if ( get_option( 'ssp_block_xmlrpc', 'yes' ) === 'yes' ) {
    add_filter( 'xmlrpc_enabled', '__return_false' );
}

// Ocultar versión de WordPress
if ( get_option( 'ssp_hide_wp_version', 'yes' ) === 'yes' ) {
    remove_action( 'wp_head', 'wp_generator' );
}

// Bloquear enumeración de usuarios
if ( get_option( 'ssp_block_user_enumeration', 'yes' ) === 'yes' ) {

    function ssp_bloquear_enumeracion_usuarios() {

        if ( ! is_admin() && isset( $_GET['author'] ) ) {
            wp_die(
                'Access Denied: User enumeration blocked.',
                'Security Core',
                array( 'response' => 403 )
            );
        }

        add_filter( 'rest_endpoints', function( $endpoints ) {

            if ( ! is_user_logged_in() && isset( $endpoints['/wp/v2/users'] ) ) {
                unset( $endpoints['/wp/v2/users'] );
            }

            if ( ! is_user_logged_in() && isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
                unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
            }

            return $endpoints;

        } );

    }

    add_action( 'init', 'ssp_bloquear_enumeracion_usuarios' );

}

// Desactivar Pingbacks
if ( get_option( 'ssp_disable_pingbacks', 'yes' ) === 'yes' ) {

    add_filter( 'xmlrpc_methods', function( $methods ) {

        unset( $methods['pingback.ping'] );
        unset( $methods['pingback.extensions.getPingbacks'] );

        return $methods;

    } );

}

// Eliminar cabecera X-Pingback
if ( get_option( 'ssp_remove_x_pingback', 'yes' ) === 'yes' ) {

    add_filter( 'wp_headers', function( $headers ) {

        if ( isset( $headers['X-Pingback'] ) ) {
            unset( $headers['X-Pingback'] );
        }

        return $headers;

    } );

}

// Ocultar versiones de CSS y JavaScript
if ( get_option( 'ssp_hide_script_versions', 'yes' ) === 'yes' ) {

    function ssp_remove_version_query( $src ) {

        if ( strpos( $src, 'ver=' ) !== false ) {
            $src = remove_query_arg( 'ver', $src );
        }

        return $src;

    }

    add_filter( 'style_loader_src', 'ssp_remove_version_query', 9999 );
    add_filter( 'script_loader_src', 'ssp_remove_version_query', 9999 );

}

// Eliminar Really Simple Discovery (RSD)
if ( get_option( 'ssp_disable_rsd', 'yes' ) === 'yes' ) {

    remove_action( 'wp_head', 'rsd_link' );

}

// Eliminar Windows Live Writer
if ( get_option( 'ssp_disable_wlwmanifest', 'yes' ) === 'yes' ) {

    remove_action( 'wp_head', 'wlwmanifest_link' );

}

if ( get_option( 'ssp_protect_sensitive_files', 'yes' ) === 'yes' ) {
    // Proteger readme.html, license.txt, composer.json, etc.
}

if ( get_option( 'ssp_block_php_uploads', 'yes' ) === 'yes' ) {
    // Impedir la ejecución de PHP dentro de wp-content/uploads
}




// ==========================================
// 3. CONFIGURACIÓN DEL PANEL Y MENÚS
// ==========================================
if ( ! function_exists( 'ssp_add_admin_menu' ) ) {
    function ssp_add_admin_menu() {

        $plugin_menu = ssp_get_text( 'plugin_menu' );

        add_menu_page(
            $plugin_menu,
            $plugin_menu,
            'manage_options',
            'secure-headers',
            'ssp_options_page_html',
			'dashicons-shield-alt',
            3
        );
    }
    add_action( 'admin_menu', 'ssp_add_admin_menu' );
}

if ( ! function_exists( 'ssp_add_admin_bar_node' ) ) {
    function ssp_add_admin_bar_node( $wp_admin_bar ) {
        // Comprobar que el usuario tenga permisos de administración
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $plugin_menu = ssp_get_text( 'plugin_menu' );

        $wp_admin_bar->add_node( array(
            'id'    => 'ssp-top-bar-icon',
            'title' => '<span class="ab-icon dashicons dashicons-shield-alt" style="margin-top: 3px;"></span><span class="ab-label">' . esc_html( $plugin_menu ) . '</span>',
            'href'  => admin_url( 'admin.php?page=secure-headers' ),
            'meta'  => array(
                'title' => $plugin_menu,
            ),
        ) );
    }
    add_action( 'admin_bar_menu', 'ssp_add_admin_bar_node', 100 );
}



if ( ! function_exists( 'ssp_register_settings' ) ) {
    function ssp_register_settings() {

        register_setting( 'ssp_settings_group', 'ssp_x_frame_options' );
        register_setting( 'ssp_settings_group', 'ssp_x_content_type' );
        register_setting( 'ssp_settings_group', 'ssp_hsts' );
        register_setting( 'ssp_settings_group', 'ssp_referrer_policy' );
        register_setting( 'ssp_settings_group', 'ssp_csp' );
        register_setting( 'ssp_settings_group', 'ssp_permissions_policy' );

        // Hardening
        register_setting( 'ssp_hardening_group', 'ssp_disable_file_edit' );
        register_setting( 'ssp_hardening_group', 'ssp_block_xmlrpc' );
        register_setting( 'ssp_hardening_group', 'ssp_hide_wp_version' );
        register_setting( 'ssp_hardening_group', 'ssp_block_user_enumeration' );

        // Nuevos escudos
        register_setting( 'ssp_hardening_group', 'ssp_disable_pingbacks' );
        register_setting( 'ssp_hardening_group', 'ssp_remove_x_pingback' );
        register_setting( 'ssp_hardening_group', 'ssp_hide_script_versions' );
        register_setting( 'ssp_hardening_group', 'ssp_disable_rsd' );
        register_setting( 'ssp_hardening_group', 'ssp_disable_wlwmanifest' );
        register_setting( 'ssp_hardening_group', 'ssp_protect_sensitive_files' );
        register_setting( 'ssp_hardening_group', 'ssp_block_php_uploads' );
        register_setting( 'ssp_general_settings_group', 'ssp_language' );
		register_setting( 'ssp_hardening_group', 'ssp_protect_wp_includes' );

    }
    add_action( 'admin_init', 'ssp_register_settings' );
}


if ( ! function_exists( 'ssp_sql_escape_value' ) ) {
    function ssp_sql_escape_value( $value ) {

        if ( is_null( $value ) ) {
            return 'NULL';
        }

        if ( is_bool( $value ) ) {
            return $value ? '1' : '0';
        }

        if ( is_int( $value ) || is_float( $value ) ) {
            return (string) $value;
        }

        return "'" . addslashes( (string) $value ) . "'";
    }
}

// 4. Copia de seguridad SQL
if ( ! function_exists( 'ssp_handle_backup_download' ) ) {

    function ssp_handle_backup_download() {

        if ( ! isset( $_GET['ssp_download_backup'] ) || 'true' !== sanitize_text_field( wp_unslash( $_GET['ssp_download_backup'] ) ) ) {
            return;
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Access denied.', 'cas-antivirus' ) );
        }

        check_admin_referer( 'ssp_download_backup' );

        global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Required to retrieve all database tables for SQL backup generation.
		$tables = $wpdb->get_results(
			'SHOW TABLES',
			ARRAY_N
		);

        if ( empty( $tables ) ) {
            wp_die( esc_html__( 'No tables found.', 'cas-antivirus' ) );
        }

        $sql_dump  = '-- CAS Database Backup - ' . get_bloginfo( 'name' ) . "\n";
        $sql_dump .= '-- Date: ' . current_time( 'mysql' ) . "\n\n";
        $sql_dump .= "SET FOREIGN_KEY_CHECKS = 0;\n\n";

        foreach ( $tables as $table_row ) {

            if ( empty( $table_row[0] ) ) {
                continue;
            }

            $table = esc_sql( $table_row[0] );

			// Validar nombre de tabla antes de usarlo como identificador SQL.
			if ( ! preg_match( '/^[a-zA-Z0-9_]+$/', $table ) ) {
			continue;
		}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Required to export database structure during SQL backup generation.
			$create_table = $wpdb->get_row(
				"SHOW CREATE TABLE `" . esc_sql( $table ) . "`",
				ARRAY_N
			);

            if ( empty( $create_table[1] ) ) {
                continue;
            }

            $sql_dump .= "DROP TABLE IF EXISTS `{$table}`;\n";
            $sql_dump .= $create_table[1] . ";\n\n";

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Required to export table contents.
            $rows = $wpdb->get_results(
                "SELECT * FROM `{$table}`",
                ARRAY_A
            );

            if ( ! empty( $rows ) ) {

                foreach ( $rows as $row ) {

                    $fields = array();
                    $values = array();

                    foreach ( $row as $field => $value ) {

                        $fields[] = '`' . esc_sql( $field ) . '`';
                        $values[] = ssp_sql_escape_value( $value );

                    }

                    $sql_dump .= sprintf(
                        "INSERT INTO `%s` (%s) VALUES (%s);\n",
                        esc_sql( $table ),
                        implode( ', ', $fields ),
                        implode( ', ', $values )
                    );
                }

                $sql_dump .= "\n";
            }
        }

        $sql_dump .= "SET FOREIGN_KEY_CHECKS = 1;\n";

        $filename = sprintf(
            'cas-backup-%s-%s.sql',
            sanitize_title( get_bloginfo( 'name' ) ),
            gmdate( 'Y-m-d' )
        );

        nocache_headers();

        header( 'Content-Type: application/octet-stream' );
        header( 'Content-Transfer-Encoding: binary' );
        header( 'Content-Disposition: attachment; filename="' . sanitize_file_name( $filename ) . '"' );
        header( 'Content-Length: ' . strlen( $sql_dump ) );

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Generated SQL file download.
        echo $sql_dump;

        exit;
    }

    add_action( 'admin_init', 'ssp_handle_backup_download' );
}

// 5. Acciones de limpieza
if ( ! function_exists( 'ssp_handle_cleanup_actions' ) ) {

    function ssp_handle_cleanup_actions() {

        if (
            ! isset( $_POST['ssp_run_cleanup'] ) ||
            ! check_admin_referer( 'ssp_cleanup_action', 'ssp_cleanup_nonce' )
        ) {
            return;
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        global $wpdb;

        $action_type = isset( $_POST['ssp_cleanup_type'] )
            ? sanitize_text_field( wp_unslash( $_POST['ssp_cleanup_type'] ) )
            : '';

        $deleted = 0;
        $message = '';

        switch ( $action_type ) {

            // Revisiones
            case 'revisions':

                $ids = get_posts(
                    array(
                        'post_type'      => 'revision',
                        'post_status'    => 'inherit',
                        'posts_per_page' => -1,
                        'fields'         => 'ids',
                    )
                );

                foreach ( $ids as $id ) {
                    if ( wp_delete_post( $id, true ) ) {
                        $deleted++;
                    }
                }

                $message = sprintf( ssp_get_text( 'cleanup_revisions_notice' ), $deleted );

            break;

            // Borradores automáticos
            case 'auto_drafts':

                $ids = get_posts(
                    array(
                        'post_status'    => 'auto-draft',
                        'posts_per_page' => -1,
                        'fields'         => 'ids',
                    )
                );

                foreach ( $ids as $id ) {
                    if ( wp_delete_post( $id, true ) ) {
                        $deleted++;
                    }
                }

                $message = sprintf( ssp_get_text( 'cleanup_autodrafts_notice' ), $deleted );

            break;

            // Papelera
            case 'trash_posts':

                $ids = get_posts(
                    array(
                        'post_status'    => 'trash',
                        'posts_per_page' => -1,
                        'fields'         => 'ids',
                    )
                );

                foreach ( $ids as $id ) {
                    if ( wp_delete_post( $id, true ) ) {
                        $deleted++;
                    }
                }

                $message = sprintf( ssp_get_text( 'cleanup_trashposts_notice' ), $deleted );

            break;

            // Comentarios spam
            case 'spam':

                $comments = get_comments(
                    array(
                        'status' => 'spam',
                        'fields' => 'ids',
                        'number' => 0,
                    )
                );

                foreach ( $comments as $id ) {
                    if ( wp_delete_comment( $id, true ) ) {
                        $deleted++;
                    }
                }

                $message = sprintf( ssp_get_text( 'cleanup_spam_notice' ), $deleted );

            break;

            // Comentarios en papelera
            case 'trash_comments':

                $comments = get_comments(
                    array(
                        'status' => 'trash',
                        'fields' => 'ids',
                        'number' => 0,
                    )
                );

                foreach ( $comments as $id ) {
                    if ( wp_delete_comment( $id, true ) ) {
                        $deleted++;
                    }
                }

                $message = sprintf( ssp_get_text( 'cleanup_trashcomments_notice' ), $deleted );

            break;

            // Pingbacks
            case 'pingbacks':

                $comments = get_comments(
                    array(
                        'type'   => 'pingback',
                        'fields' => 'ids',
                        'number' => 0,
                    )
                );

               foreach ( $comments as $id ) {
				$comment_id = absint( $id );

				if ( $comment_id && wp_delete_comment( $comment_id, true ) ) {
					$deleted++;
				}
			}

			$message = sprintf( ssp_get_text( 'cleanup_pingbacks_notice' ), $deleted );

            break;

				// Transients
				case 'transients':

					$deleted = $wpdb->query(
						"DELETE FROM {$wpdb->options}
						WHERE option_name LIKE '_transient_%'
						OR option_name LIKE '_site_transient_%'"
					);

					$message = sprintf(
						ssp_get_text( 'cleanup_transients_notice' ),
						intval( $deleted )
					);

				break;
        }

        wp_safe_redirect(
            add_query_arg(
                array(
                    'page'    => 'secure-headers',
                    'tab'     => 'cleanup',
                    'cleaned' => rawurlencode( $message ),
                ),
                admin_url( 'admin.php' )
            )
        );

        exit;
    }

    add_action( 'admin_init', 'ssp_handle_cleanup_actions' );
}

/// 6. Cambio de prefijo BASE DE DATOS ///
if ( ! function_exists( 'ssp_handle_prefix_change' ) ) {

    function ssp_handle_prefix_change() {

        if (
            ! isset( $_POST['ssp_submit_prefix'] ) ||
            ! isset( $_POST['ssp_change_prefix_nonce'] )
        ) {
            return;
        }

        if (
            ! wp_verify_nonce(
                sanitize_text_field( wp_unslash( $_POST['ssp_change_prefix_nonce'] ) ),
                'ssp_prefix_action'
            )
        ) {
            return;
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        global $wpdb;


        /*
         * Obtener nuevo prefijo
         */
        $new_prefix = isset( $_POST['ssp_new_prefix'] )
            ? sanitize_key( wp_unslash( $_POST['ssp_new_prefix'] ) )
            : '';


        if ( empty( $new_prefix ) ) {
            wp_die( 'El prefijo introducido no es válido.' );
        }


        if ( ! preg_match( '/^[a-z0-9_]+$/', $new_prefix ) ) {
            wp_die( 'El prefijo introducido contiene caracteres no permitidos.' );
        }


        if ( substr( $new_prefix, -1 ) !== '_' ) {
            $new_prefix .= '_';
        }


        $old_prefix = $wpdb->prefix;


        if ( $new_prefix === $old_prefix ) {

            wp_safe_redirect(
                admin_url( 'admin.php?page=secure-headers&tab=database' )
            );

            exit;
        }



        /*
         * Comprobar que el nuevo prefijo no exista
         */
        $exists = $wpdb->get_var(
            $wpdb->prepare(
                "SHOW TABLES LIKE %s",
                $new_prefix . '%'
            )
        );


        if ( $exists ) {
            wp_die( 'Ya existen tablas con ese prefijo.' );
        }



        /*
         * Obtener tablas actuales
         */
        $tables = $wpdb->get_col(
            $wpdb->prepare(
                "SHOW TABLES LIKE %s",
                $old_prefix . '%'
            )
        );


        if ( empty( $tables ) ) {
            wp_die( 'No se encontraron tablas para renombrar.' );
        }



        /*
         * Renombrar tablas
         */
        foreach ( $tables as $table_name ) {


            $new_table = preg_replace(
                '/^' . preg_quote( $old_prefix, '/' ) . '/',
                $new_prefix,
                $table_name
            );


            if (
                ! preg_match( '/^[a-zA-Z0-9_]+$/', $table_name ) ||
                ! preg_match( '/^[a-zA-Z0-9_]+$/', $new_table )
            ) {
                continue;
            }


			// Validar nombres de tablas antes de ejecutar SQL dinámico
			if (
				! preg_match( '/^[a-zA-Z0-9_]+$/', $table_name ) ||
				! preg_match( '/^[a-zA-Z0-9_]+$/', $new_table )
			) {
				continue;
			}

			$result = $wpdb->query(
				"RENAME TABLE `" . esc_sql( $table_name ) . "` TO `" . esc_sql( $new_table ) . "`"
			);


            if ( $result === false ) {

                wp_die(
                    'Error renombrando la tabla:<br><br>' .
                    esc_html( $table_name ) .
                    '<br><br>' .
                    esc_html( $wpdb->last_error )
                );
            }
        }


/*
 * Actualizar meta_keys de usermeta
 */
		$new_usermeta_table = $new_prefix . 'usermeta';

		if ( ! preg_match( '/^[a-zA-Z0-9_]+$/', $new_usermeta_table ) ) {
			wp_die( 'Nombre de tabla no válido.' );
		}

		$wpdb->query(
			$wpdb->prepare(
				"UPDATE `" . esc_sql( $new_usermeta_table ) . "`
				 SET meta_key = REPLACE(meta_key,%s,%s)
				 WHERE meta_key LIKE %s",
				$old_prefix,
				$new_prefix,
				$wpdb->esc_like( $old_prefix ) . '%'
			)
		);



        /*
         * Corregir user_roles
         */
        $wpdb->update(
            $new_prefix . 'options',
            array(
                'option_name' => $new_prefix . 'user_roles'
            ),
            array(
                'option_name' => $old_prefix . 'user_roles'
            )
        );



        /*
         * Actualizar objeto wpdb
         */
        $wpdb->set_prefix( $new_prefix );



        /*
         * Actualizar wp-config.php
         */
        $config_file = file_exists( ABSPATH . 'wp-config.php' )
            ? ABSPATH . 'wp-config.php'
            : dirname( ABSPATH ) . '/wp-config.php';


        if ( ! file_exists( $config_file ) ) {
            wp_die( 'No se encontró el archivo wp-config.php.' );
        }


        if ( ! is_writable( $config_file ) ) {
            wp_die( 'No se puede escribir en wp-config.php.' );
        }


        $config = file_get_contents( $config_file );


        if ( $config === false ) {
            wp_die( 'No se pudo leer wp-config.php.' );
        }


        $config = preg_replace(
            "/\\\$table_prefix\s*=\\s*['\"].*?['\"]\\s*;/",
            "\$table_prefix = '{$new_prefix}';",
            $config
        );


        if ( file_put_contents( $config_file, $config ) === false ) {
            wp_die( 'No se pudo actualizar wp-config.php.' );
        }



        /*
         * Limpieza final
         */
        wp_cache_flush();

        wp_set_current_user( get_current_user_id() );

        wp_set_auth_cookie(
            get_current_user_id(),
            is_user_logged_in()
        );


        if ( function_exists( 'session_write_close' ) ) {
            @session_write_close();
        }


        while ( ob_get_level() ) {
            ob_end_clean();
        }


        if ( function_exists( 'opcache_reset' ) ) {
            @opcache_reset();
        }


        wp_safe_redirect(
            admin_url( 'admin.php?page=secure-headers&tab=database&prefix_changed=true' )
        );

        exit;

    }

    add_action( 'admin_init', 'ssp_handle_prefix_change' );

}

// ==========================================
// 7. FUNCIONES AUXILIARES FIM (CORE INTEGRITY) & RESTAURACIÓN
// ==========================================

function ssp_get_core_checksums_data() {
    global $wp_version;
    $locale = get_locale();
    
    $url = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}";
    $response = wp_remote_get( $url, array( 'timeout' => 15 ) );
    
    if ( is_wp_error( $response ) ) {
        return false;
    }
    
    $body = wp_remote_retrieve_body( $response );
    $data = json_decode( $body, true );
    
    if ( isset( $data['checksums'] ) && is_array( $data['checksums'] ) ) {
        return $data['checksums'];
    }
    
    // Fallback a en_US si falla el locale local
    $url_en = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale=en_US";
    $response_en = wp_remote_get( $url_en, array( 'timeout' => 15 ) );
    if ( ! is_wp_error( $response_en ) ) {
        $data_en = json_decode( wp_remote_retrieve_body( $response_en ), true );
        if ( isset( $data_en['checksums'] ) && is_array( $data_en['checksums'] ) ) {
            return $data_en['checksums'];
        }
    }
    
    return false;
}

function ssp_run_fim_scan() {
    $checksums = ssp_get_core_checksums_data();
    if ( ! $checksums ) {
        return array( 'error' => 'No se pudo conectar con la API de WordPress.org para obtener los checksums.' );
    }
    
    $results = array(
        'modified' => array(),
        'missing'  => array(),
    );
	
   // Archivos del núcleo que se pueden omitir de forma segura si no existen
    $ignored_files = array(
        'readme.html',
        'license.txt',
    );

    foreach ( $checksums as $file => $expected_hashes ) {
        if ( $file === 'wp-content' || strpos( $file, 'wp-content/' ) === 0 || $file === 'wp-includes/version.php' ) {
            continue; 
        }
        
        // --- AQUÍ ESTÁ EL CAMBIO CLAVE ---
        // Limpiamos la barra inicial por si la API devuelve '/readme.html'
        $clean_file = ltrim( $file, '/' );

        // Si está en la lista de ignorados, nos saltamos la comprobación por completo
        if ( in_array( $clean_file, $ignored_files, true ) ) {
            continue;
        }
        // ---------------------------------
        
        $full_path = ABSPATH . $clean_file;
        if ( ! file_exists( $full_path ) ) {
            $results['missing'][] = $file;
        } else {
            $actual_hash = md5_file( $full_path );
            $valid_hashes = (array) $expected_hashes;
            
            if ( ! in_array( $actual_hash, $valid_hashes, true ) ) {
                $results['modified'][] = $file;
            }
        }
    }
    return $results;
}

// Función auxiliar para copiar carpetas recursivamente en PHP puro[cite: 1]
function ssp_recursive_copy( $source, $destination ) {
    if ( ! is_dir( $destination ) ) {
        mkdir( $destination, 0755, true );
    }
    $dir = opendir( $source );
    while ( ( $file = readdir( $dir ) ) !== false ) {
        if ( $file == '.' || $file == '..' ) {
            continue;
        }
        if ( is_dir( $source . '/' . $file ) ) {
            ssp_recursive_copy( $source . '/' . $file, $destination . '/' . $file );
        } else {
            copy( $source . '/' . $file, $destination . '/' . $file );
        }
    }
    closedir( $dir );
}

// Endpoint AJAX para la restauración por pasos con barra de progreso[cite: 1]
function ssp_ajax_restore_step() {
    check_ajax_referer( 'prueba_restore_nonce', 'security' );

    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'No tienes permisos suficientes.' );
    }

    global $wp_version;
    require_once ABSPATH . 'wp-admin/includes/file.php';
    WP_Filesystem();
    global $wp_filesystem;

    $step = isset( $_POST['step'] ) ? sanitize_text_field( $_POST['step'] ) : '';
    $upload_dir = wp_upload_dir();
    $extract_dir = $upload_dir['basedir'] . '/prueba-core-temp';

    if ( $step === 'download' ) {
        $zip_url = 'https://downloads.wordpress.org/release/wordpress-' . $wp_version . '.zip';
        $temp_file = download_url( $zip_url );

        if ( is_wp_error( $temp_file ) ) {
            wp_send_json_error( 'Error al descargar: ' . $temp_file->get_error_message() );
        }

        if ( is_dir( $extract_dir ) ) {
            $wp_filesystem->delete( $extract_dir, true );
        }

        unzip_file( $temp_file, $extract_dir );
        @unlink( $temp_file );

        if ( ! is_dir( $extract_dir . '/wordpress' ) ) {
            wp_send_json_error( 'Error al descomprimir los archivos oficiales.' );
        }

        wp_send_json_success( array( 'message' => 'Paquete descargado y descomprimido correctamente.', 'next_step' => 'copy_core' ) );
    } 
    elseif ( $step === 'copy_core' ) {
        $source = $extract_dir . '/wordpress';

        if ( ! is_dir( $source ) ) {
            wp_send_json_error( 'No se encuentra el directorio temporal de origen.' );
        }

        ssp_recursive_copy( $source . '/wp-admin', ABSPATH . 'wp-admin' );
        ssp_recursive_copy( $source . '/wp-includes', ABSPATH . 'wp-includes' );

        wp_send_json_success( array( 'message' => 'Directorios wp-admin y wp-includes actualizados.', 'next_step' => 'copy_root' ) );
    } 
    elseif ( $step === 'copy_root' ) {
        $source = $extract_dir . '/wordpress';

        if ( ! is_dir( $source ) ) {
            wp_send_json_error( 'No se encuentra el directorio temporal de origen.' );
        }

        $root_files = glob( $source . '/*.php' );
        foreach ( $root_files as $file ) {
            $filename = basename( $file );
            if ( $filename !== 'wp-config.php' ) {
                copy( $file, ABSPATH . $filename );
            }
        }

        $wp_filesystem->delete( $extract_dir, true );

        wp_send_json_success( array( 'message' => '¡Núcleo de WordPress restaurado con éxito!', 'next_step' => 'done' ) );
    }

    wp_send_json_error( 'Paso desconocido.' );
}
add_action( 'wp_ajax_ssp_restore_step', 'ssp_ajax_restore_step' );

///

// Lógica corregida y optimizada para la redirección de la URL de login

