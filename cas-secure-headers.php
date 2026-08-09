<?php
/**
 * Plugin Name: CAS Antivirus - Versión esencial.
 * Plugin URI: https://bueninformatico.com/wordpress/plugins
 * Description: Protege tu WordPress con 6 cabeceras HTTP de seguridad esenciales, un potente escáner de integridad del núcleo (FIM) con restauración automática de archivos, autenticación en dos pasos (2FA), protección de la base de datos, herramientas de mantenimiento y optimización, monitorización de accesos, personalización de la URL de inicio de sesión y página 404 personalizada. Seguridad avanzada en una interfaz clara, rápida y fácil de usar.
 * Version: 3.1
 * Author: Buen Informático
 * Author URI: https://bueninformatico.com/wordpress/plugins
 * Text Domain: cas-antivirus-esencial
 */
 
 if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'cas_antivirus_plugin_action_links' );

function cas_antivirus_plugin_action_links( $links ) {

    $pro_link = '<a href="https://bueninformatico.com/wordpress/plugins/" target="_blank" style="color:#7c3aed;font-weight:600;">'
        . '⭐ ' . ssp_get_text( 'upgrade_link' ) .
    '</a>';

    array_unshift( $links, $pro_link );

    return $links;
}

require_once plugin_dir_path(__FILE__) . 'logs/login_security.php';
require_once plugin_dir_path(__FILE__) . 'languages/languages.php';
require_once plugin_dir_path(__FILE__) . 'admin/program.php';
require_once plugin_dir_path( __FILE__ ) . 'logs/auto_block.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/cas-error404.php';
require_once plugin_dir_path(__FILE__) . 'includes/error404.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/htaccess-manager.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/cas-firewall.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-hardening.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/firewall-rules.php';
require_once plugin_dir_path( __FILE__ ) . '2fa/2fa-cas.php';



// Renderizado del Panel HTML 
if ( ! function_exists( 'ssp_options_page_html' ) ) {
    function ssp_options_page_html() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        if ( isset( $_GET['prefix_changed'] ) && $_GET['prefix_changed'] === 'true' ) {
            echo '<div class="notice notice-success is-dismissible" style="border-left-color: #7c3aed;"><p><strong>' . esc_html( ssp_get_text('prefix_changed_success') ) . '</strong></p></div>';
        }

        if ( isset( $_GET['cleaned'] ) ) {
            echo '<div class="notice notice-success is-dismissible" style="border-left-color: #7c3aed;"><p><strong>' . esc_html( ssp_get_text('operation_completed') ) . '</strong> ' . esc_html( $_GET['cleaned'] ) . '</p></div>';
        }

        if ( isset( $_GET['fim_restored'] ) && $_GET['fim_restored'] === 'true' ) {
            echo '<div class="notice notice-success is-dismissible" style="border-left-color: #7c3aed;"><p><strong>' . esc_html( ssp_get_text('fim_restored_success') ) . '</strong></p></div>';
        }

        $active_layers = 0;
        if ( get_option( 'ssp_x_frame_options', 'DENY' ) !== 'disabled' ) $active_layers++;
        if ( get_option( 'ssp_x_content_type', 'yes' ) === 'yes' ) $active_layers++;
        if ( get_option( 'ssp_hsts', 'yes' ) === 'yes' ) $active_layers++;
        if ( get_option( 'ssp_referrer_policy', 'strict-origin-when-cross-origin' ) !== 'disabled' ) $active_layers++;
        if ( get_option( 'ssp_csp', 'default' ) !== 'disabled' ) $active_layers++;
        if ( get_option( 'ssp_permissions_policy', 'yes' ) === 'yes' ) $active_layers++;

        $protection_percent = round( ( $active_layers / 6 ) * 100 );
        $status_color = ($protection_percent == 100) ? '#059669' : (($protection_percent >= 50) ? '#d97706' : '#dc2626');

        $active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'headers';
        ?>
        <div class="wrap cas-bubble-wrap">
            <h1 class="cas-title"><?php echo ssp_get_text('plugin_title'); ?></h1>

            <style>
                /* ========================================================== */
                /* CSS */
                /* ========================================================== */
				.cas-bubble-wrap {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
                    color: #1e293b;
                    max-width: auto !important;
                    background-color: #7299e6; /* Fondo general suave para destacar burbujas */
                    padding: 20px;
                    border-radius: 16px;
                    border: 1px solid #e2e8f0;
                    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05);
                    margin-top: 20px;
                }
                .cas-title {
                    font-size: 24px !important;
                    font-weight: 800 !important;
                    color: #0f172a;
                    letter-spacing: -0.025em;
                    margin-bottom: 24px !important;
                    text-transform: uppercase;
                    border-bottom: 2px solid #e2e8f0;
                    padding-bottom: 12px;
                }

                /* Barra de Estado Global (Burbuja contenedora principal) */
                .cas-status-bubble {
                    background: #ffffff;
                    border: 1px solid #cbd5e1;
                    border-radius: 12px;
                    padding: 18px 24px;
                    margin-bottom: 24px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.04);
                }
                .cas-status-text {
                    font-size: 14px;
                    font-weight: 700;
                    letter-spacing: 0.02em;
                }
                .cas-progress-track {
                    background: #f1f5f9;
                    border-radius: 6px;
                    height: 10px;
                    width: 260px;
                    overflow: hidden;
                    border: 1px solid #cbd5e1;
                }
                .cas-progress-fill {
                    height: 100%;
                    transition: width 0.5s ease;
                }

                /* Pestañas de navegación en formato burbuja superior */
                .cas-bubble-wrap .nav-tab-wrapper {
                    border-bottom: none !important;
                    padding-bottom: 0 !important;
                    margin-bottom: 24px !important;
                    display: flex;
                    gap: 8px;
                    flex-wrap: wrap;
                }
                .cas-bubble-wrap .nav-tab {
                    background: #ffffff !important;
                    color: #475569 !important;
                    border: 1px solid #cbd5e1 !important;
                    padding: 10px 18px !important;
                    font-size: 13px !important;
                    font-weight: 600 !important;
                    border-radius: 10px !important;
                    margin-right: 0 !important;
                    text-decoration: none !important;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.02);
                    transition: all 0.2s ease;
                }
                .cas-bubble-wrap .nav-tab:hover {
                    background: #9763eb !important;
                    color: #ffffff !important;
                    border-color: #c4b5fd !important;
                }
                .cas-bubble-wrap .nav-tab-active,
                .cas-bubble-wrap .nav-tab-active:hover {
                    background: #9763eb!important;
                    color: #ffffff !important;
                    border-color: #8139f3 !important;
                }

                /* Burbujas Contenedoras de Secciones */
				.cas-bubble-card {
					background: #d8e5ff;
					border: 0px solid #cbd5e1;
					border-radius: 14px;
					padding: 20px; /* Padding generoso para escritorio */
					margin-bottom: 24px;
					box-shadow: 0 6px 16px rgba(0, 0, 0, 0.04);
				}
				/* Ajuste específico para móviles */
				@media screen and (max-width: 768px) {
					.cas-bubble-card {
						padding: 14px 15px !important;
						margin-left: 6px !important;
						margin-right: 0px !important;
						margin-left: 0px !important;
				}	
		}

				.cas-bubble-card h2 {
					font-size: 16px !important;
					font-weight: 700 !important;
					color: #0f172a !important;
					margin-top: 0 !important;
					margin-bottom: 10px !important;
					text-transform: uppercase;
					letter-spacing: 0.03em;
				}

				.cas-bubble-card p, .cas-desc {
					color: #475569 !important;
					font-size: 13px !important;
					line-height: 1.6;
				}
    }
}

                /* Tablas y elementos internos */
                .form-table th {
                    width: 280px !important;
                    padding: 18px 10px 18px 0 !important;
                    color: #1e293b;
                    font-weight: 600;
                }
                .form-table td {
                    padding: 18px 0 !important;
                }
                .cas-border-top {
                    border-top: 1px solid #f1f5f9;
                }

                /* Controles estilizados */
                .cas-bubble-wrap select, 
                .cas-bubble-wrap input[type="text"], 
                .cas-bubble-wrap input[type="number"] {
                    background: #f8fafc !important;
                    border: 1px solid #cbd5e1 !important;
                    color: #0f172a !important;
                    border-radius: 8px !important;
                    padding: 8px 14px !important;
                    font-size: 16px !important;
					font-weight: 600;
                }
                .cas-bubble-wrap select:focus, 
                .cas-bubble-wrap input[type="text"]:focus, 
                .cas-bubble-wrap input[type="number"]:focus {
                    border-color: #7c3aed !important;
                    box-shadow: 0 0 0 3px rgba(124, 58, 237, 0.15) !important;
                    background: #ffffff !important;
                }

                .cas-bubble-wrap .button-primary:hover
				.cas-bubble-wrap input[type="submit"].button-primary {
                    background: #6d28d9 !important;
                }
				
				.cas-bubble-wrap .button-secondary, 
				.cas-bubble-wrap .button {
				background: #34429c !important;
				border-color: #000000 !important;
				color: #ffffff !important;
				border-radius: 8px !important;
				font-size: 13px !important;
				display: inline-flex !important;
				align-items: center !important;
				justify-content: center !important;
				
				/* Padding vertical reducido (primer valor: arriba/abajo, segundo: izquierda/derecha) */
				padding: 4px 12px !important; 
				
				/* Altura de línea más compacta (por defecto suele ser 1.4 o 1.5) */
				line-height: 1.2 !important; 
				
				text-transform: uppercase;
				height: auto;
				max-width: 100% !important;
				width: auto !important;
				box-sizing: border-box !important;
				white-space: normal !important;
				word-wrap: break-word !important;
				}
				.cas-bubble-wrap .button-secondary:hover, 
				.cas-bubble-wrap .button:hover {				
				background: #7299E6 !important;
				color: #ffffff !important;
				}
				
                .cas-bubble-wrap .button-primary:hover {
                 background: #7299E6 !important;
                }	

                /* Alertas y cajas informativas */
                .cas-alert-box {
                    background: #fef2f2;
                    border: 1px solid #fecaca;
                    color: #991b1b;
                    padding: 12px 16px;
                    border-radius: 8px;
                    font-size: 12px;
                    margin-top: 10px;
                }
                .cas-info-bubble {
                    background: #f8fafc;
                    border: 1px solid #cbd5e1;
                    border-left: 4px solid #7c3aed;
                    padding: 18px;
                    border-radius: 8px;
                    margin: 18px 0;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
					height: auto;
                }

                /* Tablas de registros (Logs) dentro de burbujas */
                .cas-bubble-wrap .wp-list-table {
                    background: #ffffff !important;
                    border: 1px solid #cbd5e1 !important;
                    border-radius: 10px !important;
                    box-shadow: none !important;
                }
                .cas-bubble-wrap .wp-list-table thead th {
                    background: #f8fafc !important;
                    color: #0f172a !important;
                    border-bottom: 1px solid #cbd5e1 !important;
                    font-size: 12px !important;
                }
                .cas-bubble-wrap .wp-list-table tbody td {
                    border-bottom: 1px solid #f1f5f9 !important;
                    color: #334155 !important;
                    font-size: 12px !important;
                }

                /* Etiquetas distintivas */
                .cas-tag {
                    font-size: 10px;
                    text-transform: uppercase;
                    padding: 4px 8px;
                    border-radius: 6px;
                    font-weight: 700;
                    background: #e2e8f0;
                    color: #475569;
                    display: inline-block;
                    margin-bottom: 6px;
                }
                .cas-tag-pro { background: #ede9fe; color: #6d28d9; }
                .cas-tag-danger { background: #fee2e2; color: #991b1b; }

                @media (max-width: 782px) {
                    .cas-status-bubble { flex-direction: column; align-items: flex-start; gap: 12px; }
                    .cas-progress-track { width: 100%; }
                }
								
				input.buttonblock {
					border-radius: 8px !important;
					font-size: 16px !important;
					padding: 6px 14px !important;
					text-transform: uppercase !important;
					font-family: inherit !important;
					font-weight: 600 !important;
					border-style: solid !important;
					border-width: 1px !important;
					display: block !important;
					margin-top: 10px !important;
				}
				
					input.buttonblock:hover {
					background-color: #dc2626 !important; 
					color: #ffffff !important;
					border-color: #b91c1c !important;
				}
				.button.button-small {
					/* Activa Flexbox para centrar el contenido automáticamente */
					display: inline-flex !important;
					align-items: center !important;
					justify-content: center !important;
					
					/* Asegura que ocupe el espacio correcto y no deforme el texto */
					text-align: center !important;
					box-sizing: border-box !important;
					
					/* Control opcional de altura y espacios si los necesitas en móvil */
					min-height: 32px !important;
					line-height: normal !important;
				}
				@media screen and (max-width: 768px) {
					.nav-tab-wrapper {
						display: flex !important;
						flex-direction: column !important; /* Las coloca una debajo de otra */
						gap: 8px !important; /* Espacio limpio entre pestañas */
					}

					.nav-tab-wrapper .nav-tab {
						width: 100% !important;
						box-sizing: border-box !important;
						text-align: center !important;
						margin: 0 !important;
						display: block !important;
					}
				}
				
						.cas-upgrade-box{
						text-align:center;
						padding:60px 40px;
					}

					.cas-upgrade-icon{
						font-size:70px;
						margin-bottom:50px;
						animation:casStar 1.5s infinite;
					}

					@keyframes casStar{
						0%{transform:scale(1);}
						50%{transform:scale(1.08);}
						100%{transform:scale(1);}
					}

					.cas-upgrade-box h2{
						margin:0 0 20px;
						font-size:34px;
						color:#1e293b;
					}

					.cas-upgrade-text{
						max-width:700px;
						margin:0 auto 35px;
						font-size:16px;
						line-height:1.8;
						color:#64748b;
					}

					.cas-upgrade-btn{
						display:inline-block;
						padding:16px 36px;
						background:#7c3aed;
						color:#fff;
						text-decoration:none;
						border-radius:10px;
						font-size:17px;
						font-weight:700;
						transition:all .30s ease;
						box-shadow:0 10px 25px rgba(124,58,237,.25);
					}

					.cas-upgrade-btn:hover{
						background:#6d28d9;
						color:#fff;
						transform:translateY(-5px) scale(1.05);
						box-shadow:0 20px 40px rgba(124,58,237,.45);
					}

					.cas-upgrade-btn:active{
						transform:scale(.97);
					}
				
			/* Corrección definitiva para la sección de cambio de URL en móviles */
				@media screen and (max-width: 768px) {
					/* Apila el contenedor principal del input en columna vertical */
					.cas-bubble-card form div[style*="display: flex"] {
						display: flex !important;
						flex-direction: column !important;
						align-items: stretch !important;
						gap: 8px !important;
						width: 100% !important;
						box-sizing: border-box !important;
					}
					
					/* Hace que la etiqueta de la URL base ocupe todo el ancho y rompa el texto si es muy largo */
					.cas-bubble-card form code {
						display: block !important;
						width: 100% !important;
						max-width: 100% !important;
						box-sizing: border-box !important;
						word-break: break-all !important;
						overflow-wrap: break-word !important;
					}

					/* Hace que el campo de texto se adapte al 100% exacto de la pantalla sin desbordar */
					.cas-bubble-card form .regular-text,
					.cas-bubble-card form input[type="text"] {
						width: 100% !important;
						max-width: 100% !important;
						box-sizing: border-box !important;
						margin: 0 !important;
					}
					
					/* Ajuste final para que la caja informativa inferior no sobresalga en móviles */
				@media screen and (max-width: 768px) {
					.cas-bubble-card div[style*="border-left: 4px solid"] {
						max-width: 100% !important;
						box-sizing: border-box !important;
						word-break: break-all !important;
						overflow-wrap: break-word !important;
						margin-left: 0 !important;
						margin-right: 0 !important;
					}

				@media screen and (max-width: 768px) {
					.cas-url-mobile-container {
						flex-direction: column !important;
						align-items: stretch !important;
					}
					.cas-url-mobile-container code {
						display: block !important;
						width: 100% !important;
						box-sizing: border-box !important;
					}
				}
			
				
            </style>

            
            <div class="cas-status-bubble">
                <div class="cas-status-text" style="color: <?php echo $status_color; ?>;">
                    <?php printf( ssp_get_text('protected_status'), $active_layers ); ?>
                </div>
                <div class="cas-progress-track">
                    <div class="cas-progress-fill" style="background: <?php echo $status_color; ?>; width: <?php echo $protection_percent; ?>%;"></div>
                </div>
            </div>

            <h2 class="nav-tab-wrapper">
                <a href="?page=secure-headers&tab=headers" class="nav-tab <?php echo $active_tab == 'headers' ? 'nav-tab-active' : ''; ?>"><?php echo ssp_get_text('tab_headers'); ?></a>
                <a href="?page=secure-headers&tab=fim" class="nav-tab <?php echo $active_tab == 'fim' ? 'nav-tab-active' : ''; ?>"><?php echo ssp_get_text('tab_fim'); ?></a>
			    <a href="?page=secure-headers&tab=database" class="nav-tab <?php echo $active_tab == 'database' ? 'nav-tab-active' : ''; ?>"><?php echo ssp_get_text('tab_database'); ?></a>
                <a href="?page=secure-headers&tab=cleanup" class="nav-tab <?php echo $active_tab == 'cleanup' ? 'nav-tab-active' : ''; ?>"><?php echo ssp_get_text('tab_cleanup'); ?></a>
                <a href="?page=secure-headers&tab=login_security" class="nav-tab <?php echo $active_tab == 'login_security' ? 'nav-tab-active' : ''; ?>"><?php echo ssp_get_text('tab_login_security'); ?></a>
                <a href="?page=secure-headers&tab=cambiourl" class="nav-tab <?php echo $active_tab == 'cambiourl' ? 'nav-tab-active' : ''; ?>"><?php echo ssp_get_text('tab_cambiourl'); ?></a>
                <a href="?page=secure-headers&tab=error404" class="nav-tab <?php echo $active_tab == 'error404' ? 'nav-tab-active' : ''; ?>"><?php echo ssp_get_text('tab_error404'); ?></a>               
			    <a href="?page=secure-headers&tab=2fa" class="nav-tab <?php echo $active_tab == '2fa' ? 'nav-tab-active' : ''; ?>"><?php echo ssp_get_text('2fa_title'); ?></a>
				<a href="?page=secure-headers&tab=hardening" class="nav-tab <?php echo $active_tab == 'hardening' ? 'nav-tab-active' : ''; ?>"><?php echo ssp_get_text('tab_hardening'); ?></a>
			   <a href="?page=secure-headers&tab=firewall" class="nav-tab <?php echo $active_tab == 'firewall' ? 'nav-tab-active' : ''; ?>"><?php echo ssp_get_text('firewall'); ?></a>
				<a href="?page=secure-headers&tab=settings" class="nav-tab <?php echo $active_tab == 'settings' ? 'nav-tab-active' : ''; ?>"><?php echo ssp_get_text('tab_settings'); ?></a>		
			</h2>

            <?php settings_errors( 'ssp_messages' ); ?>


            <?php if ( $active_tab == 'login_security' ) : ?>
                <?php 
                global $wpdb;
                $table_name = $wpdb->prefix . 'buen_inf_login_logs';
                $success_table_name = $wpdb->prefix . 'buen_inf_log_success';

                if (isset($_POST['manual_block_ip']) && check_admin_referer('buen_inf_manual_block_nonce')) {
                    $ip_to_block = sanitize_text_field($_POST['target_ip']);
                    if (!empty($ip_to_block)) {
                        $blocked_ips = get_option('buen_inf_manually_blocked_ips', array());
                        if ( ! in_array( $ip_to_block, $blocked_ips, true ) ) {
                            $blocked_ips[] = $ip_to_block;
                            update_option('buen_inf_manually_blocked_ips', $blocked_ips);
                        }
                        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html(ssp_get_text('ip_blocked_success')) . '</p></div>';
                    }
                }

                if (isset($_GET['unblock_ip']) && check_admin_referer('buen_inf_unblock_ip_' . $_GET['unblock_ip'])) {
                    $ip_to_unblock = sanitize_text_field($_GET['unblock_ip']);
                    $blocked_ips = get_option('buen_inf_manually_blocked_ips', array());
                    $blocked_ips = array_diff($blocked_ips, array($ip_to_unblock));
                    update_option('buen_inf_manually_blocked_ips', $blocked_ips);
                    delete_transient('buen_inf_lockout_' . md5($ip_to_unblock));
                    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html(ssp_get_text('ip_unblocked_success')) . '</p></div>';
                }

                if (isset($_POST['clear_logs']) && check_admin_referer('buen_inf_clear_logs_nonce')) {
                    $wpdb->query("TRUNCATE TABLE $table_name");
                    $wpdb->query("TRUNCATE TABLE $success_table_name");
                    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html(ssp_get_text('login_logs_cleared')) . '</p></div>';
                }

                if (isset($_POST['save_login_security']) && check_admin_referer('buen_inf_login_sec_nonce')) {
                    update_option('buen_inf_max_login_attempts', intval($_POST['max_attempts']));
                    update_option('buen_inf_lockout_duration', intval($_POST['lockout_duration']));
                    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html(ssp_get_text('login_settings_saved')) . '</p></div>';
                }
                
                $max_attempts = get_option('buen_inf_max_login_attempts', 5);
                $lockout_time = get_option('buen_inf_lockout_duration', 15);
                $manually_blocked = get_option('buen_inf_manually_blocked_ips', array());
                ?>

                <div class="cas-bubble-card">
                    <h2><?php echo esc_html(ssp_get_text('login_sec_heading')); ?></h2>
                    
                    <form method="post" action="">
                        <?php wp_nonce_field('buen_inf_login_sec_nonce'); ?>
                        <table class="form-table">
                            <tr>
                                <th scope="row"><label for="max_attempts"><?php echo esc_html(ssp_get_text('login_max_attempts')); ?></label></th>
                                <td>
                                    <input type="number" id="max_attempts" name="max_attempts" value="<?php echo esc_attr($max_attempts); ?>" min="1" max="20" class="small-text" />
                                    <p class="cas-desc"><?php echo esc_html(ssp_get_text('login_max_desc')); ?></p>
                                </td>
                            </tr>
                            <tr class="cas-border-top">
                                <th scope="row"><label for="lockout_duration"><?php echo esc_html(ssp_get_text('login_lockout_duration')); ?></label></th>
                                <td>
                                    <input type="number" id="lockout_duration" name="lockout_duration" value="<?php echo esc_attr($lockout_time); ?>" min="1" max="1440" class="small-text" />
                                    <p class="cas-desc"><?php echo esc_html(ssp_get_text('login_lockout_desc')); ?></p>
                                </td>
                            </tr>
                        </table>
                        <?php submit_button( ssp_get_text('save_changes'), 'primary', 'save_login_security' ); ?>
                    </form>

                    <div style="margin: 30px 0; border-top: 1px solid #e2e8f0;"></div>

                    <h3 style="font-size: 14px; text-transform: uppercase; color: #0f172a; font-weight: 700; margin-bottom: 6px;"><?php echo esc_html(ssp_get_text('login_manual_block_heading')); ?></h3>
                    <p class="cas-desc"><?php echo esc_html(ssp_get_text('login_manual_block_desc')); ?></p>
                    
                    <form method="post" action="" style="margin-bottom: 20px;">
                        <?php wp_nonce_field('buen_inf_manual_block_nonce'); ?>
                        <input type="text" name="target_ip" placeholder="<?php echo esc_attr(ssp_get_text('login_manual_ip_placeholder')); ?>" style="width: 220px;" required />
                        <input type="submit" name="manual_block_ip" class="buttonblock" value="<?php echo esc_attr(ssp_get_text('login_manual_block_btn')); ?>" style="background: #fee2e2; color: #991b1b; border-color: #fecaca;" />
                    </form>

                    <h4 style="font-size: 13px; text-transform: uppercase; color: #334155; margin-bottom: 10px;"><?php echo esc_html(ssp_get_text('login_blocked_list_heading')); ?></h4>
                    <table class="wp-list-table widefat fixed striped" style="margin-bottom: 30px;">
                        <thead>
                            <tr>
                                <th style="width: 70%;"><?php echo esc_html(ssp_get_text('login_th_ip_addr')); ?></th>
                                <th style="width: 30%;"><?php echo esc_html(ssp_get_text('login_th_status')); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            if (!empty($manually_blocked)) {
                                foreach ($manually_blocked as $b_ip) {
                                    $unblock_url = wp_nonce_url(admin_url('admin.php?page=secure-headers&tab=login_security&unblock_ip=' . $b_ip), 'buen_inf_unblock_ip_' . $b_ip);
                                    echo '<tr>';
                                    echo '<td><code>' . esc_html($b_ip) . '</code></td>';
                                    echo '<td><a href="' . esc_url($unblock_url) . '" class="button button-small" style="background: #d1fae5; color: #065f46; border-color: #a7f3d0; text-decoration: none;">' . esc_html(ssp_get_text('login_unblock_btn')) . '</a></td>';
                                    echo '</tr>';
                                }
                            } else {
                                echo '<tr><td colspan="2">' . esc_html(ssp_get_text('login_no_blocked_ips')) . '</td></tr>';
                            }
                            ?>
                        </tbody>
                    </table>

                    <div style="margin: 30px 0; border-top: 1px solid #e2e8f0;"></div>

                    <h3 style="font-size: 14px; text-transform: uppercase; color: #0f172a; font-weight: 700; margin-bottom: 12px;"><?php echo esc_html(ssp_get_text('login_logs_heading')); ?></h3>
                    
                    <form method="post" style="margin-bottom: 15px;">
                        <?php wp_nonce_field('buen_inf_clear_logs_nonce'); ?>
                        <input type="submit" name="clear_logs" class="button button-secondary" value="<?php echo esc_attr(ssp_get_text('login_clear_btn')); ?>" onclick="return confirm('<?php echo esc_js(ssp_get_text('login_confirm_msg')); ?>');" />
                    </form>

<!-- TABLA DE INTENTOS FALLIDOS CON SCROLL HORIZONTAL Y BOTÓN PROTEGIDO -->
<?php
$logs = $wpdb->get_results("SELECT * FROM $table_name ORDER BY id DESC LIMIT 50");

if ($logs) {
    echo '<div style="overflow-x: auto; width: 100%; margin-bottom: 30px;">';
    echo '<table class="wp-list-table widefat striped" style="width: 100%; white-space: nowrap;">';
    echo '<thead>';
    echo '<tr>';
    echo '<th>' . esc_html(ssp_get_text('login_th_date')) . '</th>';
    echo '<th>' . esc_html(ssp_get_text('login_th_ip')) . '</th>';
    echo '<th>' . esc_html(ssp_get_text('login_th_user')) . '</th>';
    echo '<th>' . esc_html(ssp_get_text('login_th_status')) . '</th>';
    echo '<th style="width:1%;">Acciones</th>';
    echo '</tr>';
    echo '</thead>';
    echo '<tbody>';

    foreach ($logs as $log) {

        $block_url = wp_nonce_url(
            admin_url(
                'admin.php?page=secure-headers&tab=login_security&manual_quick_block=' . urlencode($log->ip)
            ),
            'manual_quick_block'
        );

        echo '<tr>';
        echo '<td>' . esc_html($log->time) . '</td>';
        echo '<td><code>' . esc_html($log->ip) . '</code></td>';
        echo '<td>' . esc_html($log->username) . '</td>';
        // TRADUCCIÓN DINÁMICA DEL ESTADO FALLIDO
        echo '<td><span style="color:#dc2626;font-weight:600;">' . esc_html(ssp_get_text('login_status_failed')) . '</span></td>';
        echo '<td style="width:1%;"><a href="' . esc_url($block_url) . '" class="button button-small" style="background:#fee2e2;color:#991b1b;border-color:#fecaca;text-decoration:none;display:inline-block;">' . esc_html(ssp_get_text('login_action_block_btn')) . '</a></td>';
        echo '</tr>';
    }

    echo '</tbody>';
    echo '</table>';
    echo '</div>';

} else {

    echo '<p style="margin-bottom:30px;">' . esc_html(ssp_get_text('login_no_logs')) . '</p>';

}
?>

<h3 style="font-size: 14px; text-transform: uppercase; color: #0f172a; font-weight: 700; margin-bottom: 12px;"><?php echo esc_html(ssp_get_text('login_success_heading')); ?></h3>
                    
<!-- TABLA DE ACCESOS EXITOSOS CON SCROLL HORIZONTAL -->
<?php
$success_logs = $wpdb->get_results("SELECT * FROM $success_table_name ORDER BY id DESC LIMIT 50");
if ($success_logs) {
    echo '<div style="overflow-x: auto; width: 100%;">';
    echo '<table class="wp-list-table widefat striped" style="width: 100%; white-space: nowrap;">';
    echo '<thead>';
    echo '<tr>';
    echo '<th>' . esc_html(ssp_get_text('login_th_date')) . '</th>';
    echo '<th>' . esc_html(ssp_get_text('login_th_ip')) . '</th>';
    echo '<th>' . esc_html(ssp_get_text('login_th_user')) . '</th>';
    echo '<th>' . esc_html(ssp_get_text('login_th_status')) . '</th>';
    echo '</tr>';
    echo '</thead>';
    echo '<tbody>';
    
    foreach ($success_logs as $s_log) {
        echo '<tr>';
        echo '<td>' . esc_html($s_log->time) . '</td>';
        echo '<td><code>' . esc_html($s_log->ip) . '</code></td>';
        echo '<td>' . esc_html($s_log->username) . '</td>';
        // TRADUCCIÓN DINÁMICA DEL ESTADO EXITOSO
        echo '<td><span style="color: #059669; font-weight: 600;">' . esc_html(ssp_get_text('login_status_success')) . '</span></td>';
        echo '</tr>';
    }
    
    echo '</tbody>';
    echo '</table>';
    echo '</div>';
} else {
    echo '<p>' . esc_html(ssp_get_text('login_no_logs')) . '</p>';
}
?>


    <?php 
    // Forzar la carga de los scripts del footer (incluido el modo oscuro) antes de salir
    do_action('admin_footer');
    
    exit; 
    endif; 
    ?>

            <?php if ( $active_tab == 'fim' ) : ?>
                <div class="cas-bubble-card">
                    <h2><?php echo esc_html( ssp_get_text('fim_heading') ); ?></h2>
                    <p class="cas-desc" style="margin-top: 0; margin-bottom: 24px;">
                        <?php echo esc_html( ssp_get_text('fim_intro') ); ?>
                    </p>

                    

                    


<?php
if ( ( isset( $_POST['ssp_run_fim_scan'] ) && check_admin_referer( 'ssp_fim_scan_action', 'ssp_fim_scan_nonce' ) ) || isset( $_GET['fim_scanned'] ) ) {
    $scan_results = ssp_run_fim_scan();
    
    if ( isset( $scan_results['error'] ) ) {
        echo '<div class="cas-alert-box">' . esc_html( $scan_results['error'] ) . '</div>';
    } else {
        $modified_files = isset( $scan_results['modified'] ) ? $scan_results['modified'] : array();
        $missing_files  = isset( $scan_results['missing'] ) ? $scan_results['missing'] : array();

        if ( empty( $modified_files ) && empty( $missing_files ) ) {
            echo '<div class="cas-info-bubble" style="border-left-color: #059669; background: #ecfdf5;"><p style="margin: 0; color: #065f46; font-weight: 600;">' . esc_html( ssp_get_text('fim_status_clean') ) . '</p></div>';
        } else {
            $total_issues = count( $modified_files ) + count( $missing_files );
            
            // Usamos sprintf para concatenar el número de archivos y la palabra traducida de forma limpia
            $msg_format = ssp_get_text('fim_status_modified_count'); // Ej: "%d archivos con incidencias" o "%d files with issues"
            $alert_text = sprintf( $msg_format, $total_issues );

            echo '<div class="cas-alert-box" style="margin-bottom: 16px;"><strong>' . esc_html( $alert_text ) . '</strong></div>';
            
            echo '<div style="overflow-x: auto; width: 100%;">';
            echo '<table class="wp-list-table widefat striped" style="width: 100%;">';
            echo '<thead>';
            echo '<tr>';
            echo '<th>' . esc_html( ssp_get_text('fim_file_col') ) . '</th>';
            echo '<th>' . esc_html( ssp_get_text('fim_status_col') ) . '</th>';
            echo '<th>' . esc_html( ssp_get_text('fim_action_col') ) . '</th>';
            echo '</tr>';
            echo '</thead>';
            echo '<tbody>';
            
            foreach ( $modified_files as $file ) {
                echo '<tr>';
                echo '<td><code>' . esc_html( $file ) . '</code></td>';
                echo '<td><span style="color: #d97706; font-weight: 600;">' . esc_html( ssp_get_text('fim_status_modified_label') ) . '</span></td>';
                echo '<td>' . esc_html( ssp_get_text('fim_action_restore_text') ) . '</td>';
                echo '</tr>';
            }

            foreach ( $missing_files as $file ) {
                echo '<tr>';
                echo '<td><code>' . esc_html( $file ) . '</code></td>';
                echo '<td><span style="color: #dc2626; font-weight: 600;">' . esc_html( ssp_get_text('fim_status_missing_label') ) . '</span></td>';
                echo '<td>' . esc_html( ssp_get_text('fim_action_restore_text') ) . '</td>';
                echo '</tr>';
            }
            
            echo '</tbody>';
            echo '</table>';
            echo '</div>';
        }
    }
}
?>



<div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-top: 15px;">
    <form method="post" action="" id="fim-scan-form">
        <?php wp_nonce_field( 'ssp_fim_scan_action', 'ssp_fim_scan_nonce' ); ?>
        <input type="hidden" name="ssp_run_fim_scan" value="1">
        <button type="submit" id="fim-scan-btn" class="button button-primary cas-custom-btn cas-btn-scan"><?php echo esc_html( ssp_get_text('fim_scan_btn') ); ?></button>
    </form>

    <button type="button" id="start-restore-btn" class="button cas-custom-btn cas-btn-restore"><?php echo esc_html( ssp_get_text('fim_restore_btn') ); ?></button>
</div>

<div id="restore-progress-container" style="display: none; background: #fff; border: 1px solid #ccd0d4; padding: 15px; border-radius: 4px; margin-top: 15px;">
    <p id="restore-status-text" style="font-weight: bold; margin-bottom: 8px; color: #1d2327;">Iniciando proceso...</p>
    <div style="background: #f0f0f1; border-radius: 4px; overflow: hidden; height: 24px; width: 100%; border: 1px solid #dcdcde;">
        <div id="restore-progress-bar" style="background: #2271b1; width: 0%; height: 100%; text-align: center; color: #fff; font-size: 12px; line-height: 24px; transition: width 0.4s ease;">0%</div>
    </div>
</div>




<script>
document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('fim-scan-form');
    const scanBtn = document.getElementById('fim-scan-btn');
    
    // Obtenemos la traducción directamente desde tu sistema PHP
    const scanningText = "<?php echo esc_js( ssp_get_text('scanning_files') ); ?>";

    // Indicador visual al pulsar el botón de escaneo
    if (scanForm && scanBtn) {
        scanForm.addEventListener('submit', function() {
            scanBtn.style.opacity = '0.7';
            scanBtn.style.cursor = 'wait';
            scanBtn.innerText = scanningText;
            scanBtn.disabled = true;
        });
    }
});
</script>

<script>
jQuery(document).ready(function($) {
    // Textos traducidos desde PHP para el script de restauración
    const tRest = {
        confirm: "<?php echo esc_js( ssp_get_text('restore_confirm') ); ?>",
        stepDownload: "<?php echo esc_js( ssp_get_text('restore_step_download') ); ?>",
        successNotice: "<?php echo esc_js( ssp_get_text('restore_success_notice') ); ?>",
        stepCopyCore: "<?php echo esc_js( ssp_get_text('restore_step_copy_core') ); ?>",
        stepCopyRoot: "<?php echo esc_js( ssp_get_text('restore_step_copy_root') ); ?>",
        errorPrefix: "<?php echo esc_js( ssp_get_text('restore_error_prefix') ); ?>",
        errorUnknown: "<?php echo esc_js( ssp_get_text('restore_error_unknown') ); ?>",
        errorCritical: "<?php echo esc_js( ssp_get_text('restore_error_critical') ); ?>"
    };

    $('#start-restore-btn').on('click', function() {
        if (!confirm(tRest.confirm)) {
            return;
        }

        $('#start-restore-btn').prop('disabled', true);
        $('#restore-progress-container').show();
        
        updateProgress(0, tRest.stepDownload, 'download');
    });

    function updateProgress(percent, text, step) {
        $('#restore-progress-bar').css('width', percent + '%').text(percent + '%');
        $('#restore-status-text').text(text);

        if (step === 'done') {
            $('#start-restore-btn').prop('disabled', false);
            
            $('#restore-progress-container').after(
                '<div class="notice notice-success is-dismissible" style="margin-top: 15px; padding: 12px; border-left-color: #00a32a;"><p><strong>' + tRest.successNotice + '</strong></p></div>'
            );

            setTimeout(function() {
                location.reload();
            }, 2000);
            return;
        }

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'ssp_restore_step',
                security: '<?php echo wp_create_nonce( "prueba_restore_nonce" ); ?>',
                step: step
            },
            success: function(response) {
                if (response.success) {
                    if (step === 'download') {
                        updateProgress(35, tRest.stepCopyCore, response.data.next_step);
                    } else if (step === 'copy_core') {
                        updateProgress(75, tRest.stepCopyRoot, response.data.next_step);
                    } else if (step === 'copy_root') {
                        updateProgress(100, response.data.message, 'done');
                    }
                } else {
                    $('#restore-status-text').css('color', '#d63638').text(tRest.errorPrefix + (response.data || tRest.errorUnknown));
                    $('#start-restore-btn').prop('disabled', false);
                }
            },
            error: function() {
                $('#restore-status-text').css('color', '#d63638').text(tRest.errorCritical);
                $('#start-restore-btn').prop('disabled', false);
            }
        });
    }
});
</script>






            <?php elseif 
			// ==========================================
            // CONTENIDO SECCIONES
			// ==========================================
				( $active_tab == 'headers' ) : ?>
                <div class="cas-bubble-card">
                    <p class="cas-desc" style="margin-top: 0; margin-bottom: 24px;">
                        <?php echo ssp_get_text('headers_intro'); ?>
                    </p>

                    <form action="options.php" method="post">
                        <?php settings_fields( 'ssp_settings_group' ); ?>
                        
                        <table class="form-table">
                            <tr>
                                <th scope="row">
                                    <span class="cas-tag">Capa 01</span><br>
                                    <label for="ssp_x_frame_options"><?php echo ssp_get_text('layer_5_title'); ?></label>
                                </th>
                                <td><select name="ssp_csp" id="ssp_csp" style="width: 300px;">
                                        <option value="default" <?php selected( get_option( 'ssp_csp', 'default' ), 'default' ); ?>><?php echo ssp_get_text('layer_5_mode'); ?></option>
                                        <option value="disabled" <?php selected( get_option( 'ssp_csp' ), 'disabled' ); ?>><?php echo ssp_get_text('opt_disabled'); ?></option>
                                    </select>
                                    
                                    <p class="cas-desc"><?php echo ssp_get_text('layer_5_desc'); ?></p>
                                </td>
                            </tr>

                            <tr class="cas-border-top">
                                <th scope="row">
                                    <span class="cas-tag">Capa 02</span><br>
                                    <?php echo ssp_get_text('layer_2_title'); ?>
                                </th>
                                <td>
                                    <label style="color: #1e293b; font-size: 13px; font-weight: 500;">
                                        <input type="checkbox" name="ssp_x_content_type" value="yes" <?php checked( get_option( 'ssp_x_content_type', 'yes' ), 'yes' ); ?>>
                                        <?php echo ssp_get_text('layer_2_label'); ?>
                                    </label>
                                    <p class="cas-desc"><?php echo ssp_get_text('layer_2_desc'); ?></p>
                                </td>
                            </tr>

                            <tr class="cas-border-top">
                                <th scope="row">
                                    <span class="cas-tag">Capa 03</span><br>
                                    <?php echo ssp_get_text('layer_3_title'); ?>
                                </th>
                                <td>
                                    <label style="color: #1e293b; font-size: 13px; font-weight: 500;">
                                        <input type="checkbox" name="ssp_hsts" value="yes" <?php checked( get_option( 'ssp_hsts', 'yes' ), 'yes' ); ?>>
                                        <?php echo ssp_get_text('layer_3_label'); ?>
                                    </label>
                                    <p class="cas-desc"><?php echo ssp_get_text('layer_3_desc'); ?></p>
                                </td>
                            </tr>

                            <tr class="cas-border-top">
                                <th scope="row">
                                    <span class="cas-tag">Capa 04</span><br>
                                    <label for="ssp_referrer_policy"><?php echo ssp_get_text('layer_4_title'); ?></label>
                                </th>
                                <td>
                                    <select name="ssp_referrer_policy" id="ssp_referrer_policy" style="width: 300px;">
                                        <option value="no-referrer" <?php selected( get_option( 'ssp_referrer_policy', 'no-referrer' ), 'no-referrer' ); ?>><?php echo ssp_get_text('opt_noreferrer'); ?></option>
                                        <option value="strict-origin-when-cross-origin" <?php selected( get_option( 'ssp_referrer_policy' ), 'strict-origin-when-cross-origin' ); ?>><?php echo ssp_get_text('opt_balanced'); ?></option>
                                        <option value="disabled" <?php selected( get_option( 'ssp_referrer_policy' ), 'disabled' ); ?>><?php echo ssp_get_text('opt_disabled'); ?></option>
                                    </select>
                                    <p class="cas-desc"><?php echo ssp_get_text('layer_4_desc'); ?></p>
                                </td>
                            </tr>

                            <tr class="cas-border-top">
                                <th scope="row">
                                    <span class="cas-tag cas-tag-pro">Capa 05 (A+)</span><br>
                                    <label for="ssp_csp"><?php echo ssp_get_text('layer_1_title'); ?></label>
                                </th>
                                <td>
                                    <select name="ssp_x_frame_options" id="ssp_x_frame_options" style="width: 300px;">
                                        <option value="DENY" <?php selected( get_option( 'ssp_x_frame_options', 'DENY' ), 'DENY' ); ?>><?php echo ssp_get_text('opt_deny'); ?></option>
                                        <option value="SAMEORIGIN" <?php selected( get_option( 'ssp_x_frame_options' ), 'SAMEORIGIN' ); ?>><?php echo ssp_get_text('opt_sameorigin'); ?></option>
                                        <option value="disabled" <?php selected( get_option( 'ssp_x_frame_options' ), 'disabled' ); ?>><?php echo ssp_get_text('opt_disabled'); ?></option>
                                    </select>
									<p class="cas-desc">
                                        <?php echo ssp_get_text('layer_1_desc'); ?><br>
                                        <span class="cas-alert-box" style="display: block; margin-top: 10px;">
                                            <?php echo ssp_get_text('csp_warning'); ?>
                                        </span>
                                    </p>
                                </td>
                            </tr>

                            <tr class="cas-border-top">
                                <th scope="row">
                                    <span class="cas-tag cas-tag-danger">Extra</span><br>
                                    <?php echo ssp_get_text('layer_extra_title'); ?>
                                </th>
                                <td>
                                    <label style="color: #1e293b; font-size: 13px; font-weight: 500;">
                                        <input type="checkbox" name="ssp_permissions_policy" value="yes" <?php checked( get_option( 'ssp_permissions_policy', 'yes' ), 'yes' ); ?>>
                                        <?php echo ssp_get_text('layer_extra_label'); ?>
                                    </label>
                                    <p class="cas-desc"><?php echo ssp_get_text('layer_extra_desc'); ?></p>
                                </td>
                            </tr>
                        </table>
                        
                        <?php submit_button( ssp_get_text('save_changes') ); ?>
                    </form>
                </div>
						

  <?php elseif ( $active_tab == 'hardening' ) : ?>

<div class="cas-bubble-card">

    <div class="cas-upgrade-box">

        <div class="cas-upgrade-icon">⭐</div>

        <h2><?php echo ssp_get_text( 'upgrade_title' ); ?></h2>

        <p class="cas-upgrade-text">
            <?php echo ssp_get_text( 'upgrade_hardening' ); ?>
        </p>

        <a href="https://bueninformatico.com/wordpress/plugins/" class="cas-upgrade-btn" target="_blank">
            ⭐ <?php echo ssp_get_text( 'upgrade_button' ); ?>
        </a>

    </div>

</div>          

            <?php elseif ( $active_tab == 'database' ) : ?>
                <div class="cas-bubble-card">
                    <h2><?php echo ssp_get_text('db_heading'); ?></h2>
                    <p class="cas-desc"><?php echo ssp_get_text('db_intro'); ?></p>

                    <?php 
                    global $wpdb;
                    $current_prefix = $wpdb->prefix;
                    $backup_url = admin_url( 'admin.php?page=secure-headers&tab=database&ssp_download_backup=true' );
                    ?>

                    <div class="cas-info-bubble">
                        <div>
                            <p style="margin: 0; font-size: 13px; color: #1e293b;">
                                <strong><?php echo ssp_get_text('db_current_label'); ?></strong> 
                                <span style="background: #ffffff; padding: 4px 10px; border: 1px solid #cbd5e1; border-radius: 6px; color: #7c3aed; font-weight: bold;"><?php echo esc_html( $current_prefix ); ?></span>
                            </p>
                        </div>
                        <div>
                            <a href="<?php echo esc_url( $backup_url ); ?>" class="button button-secondary" style="text-decoration: none;">
                                <?php echo ssp_get_text('db_download_btn'); ?>
                            </a>
                        </div>
                    </div>

                    <form method="post" action="">
                        <?php wp_nonce_field( 'ssp_prefix_action', 'ssp_change_prefix_nonce' ); ?>
                        
                        <table class="form-table">
                            <tr>
                                <th scope="row"><label for="ssp_new_prefix"><?php echo ssp_get_text('db_new_label'); ?></label></th>
                                <td>
                                    <input type="text" name="ssp_new_prefix" id="ssp_new_prefix" value="cas_" style="width: 220px;" required />
                                    <p class="cas-desc"><?php echo ssp_get_text('db_new_desc'); ?></p>
                                </td>
                            </tr>
                        </table>

                        <p class="cas-alert-box" style="margin: 20px 0;">
                            <strong><?php echo ssp_get_text('db_tip'); ?></strong>
                        </p>

                        <?php submit_button( ssp_get_text('db_submit_btn'), 'primary', 'ssp_submit_prefix', true, array('onclick' => 'return confirm("' . ssp_get_text('db_confirm_msg') . '");') ); ?>
                    </form>
                </div>

            <?php elseif ( $active_tab == 'cleanup' ) : ?>
                <div class="cas-bubble-card">
                    <h2><?php echo ssp_get_text('cleanup_heading'); ?></h2>
                    <p class="cas-desc"><?php echo ssp_get_text('cleanup_intro'); ?></p>

                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php echo ssp_get_text('clean_rev_title'); ?></th>
                            <td>
                                <form method="post" action="">
                                    <?php wp_nonce_field( 'ssp_cleanup_action', 'ssp_cleanup_nonce' ); ?>
                                    <input type="hidden" name="ssp_cleanup_type" value="revisions">
                                    <p class="cas-desc" style="margin-bottom: 8px;"><?php echo ssp_get_text('clean_rev_desc'); ?></p>
                                    <?php submit_button( ssp_get_text('clean_rev_btn'), 'secondary', 'ssp_run_cleanup', false ); ?>
                                </form>
                            </td>
                        </tr>

                        <tr class="cas-border-top">
                            <th scope="row"><?php echo ssp_get_text('clean_spam_title'); ?></th>
                            <td>
                                <form method="post" action="">
                                    <?php wp_nonce_field( 'ssp_cleanup_action', 'ssp_cleanup_nonce' ); ?>
                                    <input type="hidden" name="ssp_cleanup_type" value="spam">
                                    <p class="cas-desc" style="margin-bottom: 8px;"><?php echo ssp_get_text('clean_spam_desc'); ?></p>
                                    <?php submit_button( ssp_get_text('clean_spam_btn'), 'secondary', 'ssp_run_cleanup', false ); ?>
                                </form>
                            </td>
                        </tr>

                        <tr class="cas-border-top">
                            <th scope="row"><?php echo ssp_get_text('clean_trans_title'); ?></th>
                            <td>
                                <form method="post" action="">
                                    <?php wp_nonce_field( 'ssp_cleanup_action', 'ssp_cleanup_nonce' ); ?>
                                    <input type="hidden" name="ssp_cleanup_type" value="transients">
                                    <p class="cas-desc" style="margin-bottom: 8px;"><?php echo ssp_get_text('clean_trans_desc'); ?></p>
                                    <?php submit_button( ssp_get_text('clean_trans_btn'), 'secondary', 'ssp_run_cleanup', false ); ?>
                                </form>
                            </td>
                        </tr>
                    </table>
                </div>
				
				
				
				<?php elseif ( $active_tab == 'error404' ) : ?>
								<div class="cas-bubble-card">
									<h2><?php echo ssp_get_text('f404_heading'); ?></h2>
									<p class="cas-desc"><?php echo ssp_get_text('f404_intro'); ?></p>
									<form action="options.php" method="post">
										<?php settings_fields( 'ssp_error404_group' ); ?>
											<table class="form-table">
												<tr>
													<th scope="row">
														<?php echo ssp_get_text('f404_enable_label'); ?>
													</th>
													<td>
														<label>
															<input
																type="checkbox"
																name="ssp_404_enabled"
																value="1"
																<?php checked( get_option( 'ssp_404_enabled', 0 ), 1 ); ?>
															>
															<?php echo ssp_get_text('f404_enable_desc'); ?>
														</label>
													</td>
												</tr>
											</table>	
											
										<table class="form-table">
											<tr>
												<th scope="row"><label for="ssp_404_title"><?php echo ssp_get_text('f404_title_label'); ?></label></th>
												<td>
													<input type="text" id="ssp_404_title" name="ssp_404_title" value="<?php echo esc_attr( get_option( 'ssp_404_title', '' ) ); ?>" class="regular-text" />
													<p class="cas-desc"><?php echo ssp_get_text('f404_title_desc'); ?></p>
												</td>
											</tr>

											<tr class="cas-border-top">
												<th scope="row"><label for="ssp_404_text"><?php echo ssp_get_text('f404_text_label'); ?></label></th>
												<td>
													<textarea id="ssp_404_text" name="ssp_404_text" rows="5" class="large-text"><?php echo esc_textarea( get_option( 'ssp_404_text', '' ) ); ?></textarea>
													<p class="cas-desc"><?php echo ssp_get_text('f404_text_desc'); ?></p>
												</td>
											</tr>

											<tr class="cas-border-top">
												<th scope="row"><label for="ssp_404_image"><?php echo ssp_get_text('f404_img_label'); ?></label></th>
												<td>
													<div class="cas-image-upload">

														<input 
															type="text" 
															id="ssp_404_image" 
															name="ssp_404_image" 
															value="<?php echo esc_url( get_option( 'ssp_404_image', '' ) ); ?>" 
															class="regular-text" 
														/>

														<button 
															type="button" 
															class="button cas-upload-404-image">
															<?php echo ssp_get_text('f404_upimagen'); ?>
														</button>

														<button 
															type="button" 
															class="button cas-remove-404-image">
															<?php echo ssp_get_text('f404_remove_image'); ?>
														</button>


												<div style="margin-top:15px;" id="ssp_404_image_preview">
															<?php 
															$image = get_option('ssp_404_image', '');
															if ( $image ) :
															?>
																<img 
																	src="<?php echo esc_url($image); ?>" 
																	style="max-width:200px;height:auto;border-radius:8px;"
																>
															<?php endif; ?>
														</div>
														

													</div>
												</td>
											</tr>
										</table>

										<?php submit_button( ssp_get_text('save_error404') ); ?>
									</form>
								</div>	

				<?php elseif ( $active_tab == '2fa' ) : ?>
    <?php

// Mostrar avisos generados por el motor
settings_errors( 'cas_notices' );

// Datos para la vista
$current_user_id = get_current_user_id();
$user            = get_userdata( $current_user_id );

$secret = get_user_meta( $current_user_id, 'cas_2fa_secret', true );

if ( empty( $secret ) ) {
    $secret = cas_generate_base32_secret();
    update_user_meta( $current_user_id, 'cas_2fa_secret', $secret );
}

$is_enabled = get_user_meta( $current_user_id, 'cas_2fa_enabled', true );

$site_name  = get_bloginfo( 'name' );
$user_email = $user->user_email;

$otpauth = sprintf(
    'otpauth://totp/%s:%s?secret=%s&issuer=%s',
    rawurlencode( $site_name ),
    rawurlencode( $user_email ),
    $secret,
    rawurlencode( $site_name )
);

$qr_url = cas_generate_qr(
    $otpauth,
    $current_user_id
);

?>

<div class="cas-bubble-card">

    <h2><?php echo ssp_get_text( '2fa_heading' ); ?></h2>

    <p class="cas-desc">
        <?php echo ssp_get_text( '2fa_intro' ); ?>
    </p>

    <form method="post">

        <?php wp_nonce_field( 'cas_save_2fa_action', 'cas_2fa_nonce' ); ?>

        <table class="form-table">

            <tr>

                <th scope="row">
                    <?php echo ssp_get_text( '2fa_enable_label' ); ?>
                </th>

                <td>

                    <label>

                        <input
                            type="checkbox"
                            name="cas_enable_2fa"
                            value="1"
                            <?php checked( $is_enabled, '1' ); ?>
                        >

                        <?php echo ssp_get_text( '2fa_enable_desc' ); ?>

                    </label>

                </td>

            </tr>

        </table>

        <table class="form-table">

            <tr class="cas-border-top">

                <th scope="row">

                    <label>
                        <?php echo ssp_get_text( '2fa_app_config_label' ); ?>
                    </label>

                </th>

                <td>

                    <p>

                        <?php echo ssp_get_text( '2fa_scan_qr_text' ); ?>

                        <strong>Google Authenticator</strong>,
                        <strong>Microsoft Authenticator</strong>,
                        <strong>Authy</strong>

                    </p>

                    <p>

                        <img
                            src="<?php echo esc_url( $qr_url ); ?>"
                            alt="QR 2FA"
                            width="180"
                            height="180"
                            style="border:4px solid #fff;box-shadow:0 1px 3px rgba(0,0,0,.2);"
                        >

                    </p>

                    <p>

                        <?php echo ssp_get_text( '2fa_manual_key_text' ); ?>

                        <code><?php echo esc_html( $secret ); ?></code>

                    </p>

                </td>

            </tr>

            <tr class="cas-border-top">

                <th scope="row">

                    <label for="cas_2fa_code">

                        <?php echo ssp_get_text( '2fa_verify_code_label' ); ?>

                    </label>

                </th>

                <td>

                    <input
                        type="text"
                        id="cas_2fa_code"
                        name="cas_2fa_code"
                        class="regular-text"
                        maxlength="6"
                        autocomplete="one-time-code"
                        placeholder="<?php echo esc_attr( ssp_get_text( '2fa_code_placeholder' ) ); ?>"
                    >

                    <p class="cas-desc">

                        <?php echo ssp_get_text( '2fa_verify_code_desc' ); ?>

                    </p>

                </td>

            </tr>

        </table>

        <?php submit_button( ssp_get_text( 'save_2fa' ) ); ?>

    </form>

</div>

						
				
							<?php elseif ( $active_tab == 'cambiourl' ) : ?>
        <div class="cas-bubble-card">
            <h2><?php echo ssp_get_text('cambiourl_heading'); ?></h2>
            <p class="cas-desc"><?php echo ssp_get_text('cambiourl_intro'); ?></p>

            <form method="post" action="">
                <?php
                    settings_fields( 'cas_cambiourl_group' );
                    do_settings_sections( 'cas_cambiourl_group' );
                ?>
                
                <div style="margin-top: 20px;">
                    <label for="cas_login_slug" style="display: block; font-weight: 600; margin-bottom: 8px; color: #1e293b;">
                        <?php echo ssp_get_text('cambiourl_label'); ?>
                    </label>
                    
                    <!-- Contenedor adaptativo sin tablas -->
                    <div class="cas-url-mobile-container" style="display: flex; align-items: center; flex-wrap: wrap; gap: 8px; width: 100%; box-sizing: border-box;">
                        <code style="padding: 8px 12px; background: #e0e0e0; border-radius: 4px; font-size: 13px; word-break: break-all; max-width: 100%;"><?php echo home_url( '/' ); ?></code>
                        <input type="text" id="cas_login_slug" name="cas_login_slug" value="<?php echo esc_attr( get_option( 'cas_login_slug', 'mi-login-secreto' ) ); ?>" class="regular-text" style="margin: 0; width: 100%; max-width: 100%; box-sizing: border-box;" />
                    </div>
                    
                    <p class="description" style="margin-top: 8px;"><?php echo ssp_get_text('cambiourl_desc'); ?></p>

                    <?php
                    $slug_actual = get_option( 'cas_login_slug', 'mi-login-secreto' );
                    $url_completa = ! empty( $slug_actual ) ? home_url( '/' . trim( $slug_actual, '/' ) ) : home_url( '/wp-login.php' );
                    ?>

                    <div style="background: #fff; border-left: 4px solid #2271b1; padding: 10px 15px; margin-top: 15px; box-shadow: 0 1px 1px rgba(0,0,0,.04); width: 100%; box-sizing: border-box; word-break: break-all; overflow-wrap: break-word;">
                        <p style="margin: 0; font-size: 13px; color: #1d2327;">
                            <strong><?php echo ssp_get_text('cambiourl_current'); ?></strong> 
                            <a href="<?php echo esc_url( $url_completa ); ?>" target="_blank" style="font-family: monospace; font-weight: bold; color: #2271b1; word-break: break-all;"><?php echo esc_url( $url_completa ); ?></a>
                        </p>
                    </div>
                </div>

                <p class="submit" style="margin-top: 20px;">
                    <button type="submit" name="submit" id="submit" class="button button-primary"><?php echo ssp_get_text('save_settings'); ?></button>
                </p>
            </form>
        </div>

	<?php elseif ( $active_tab == 'firewall' ) : ?>

<div class="cas-bubble-card">

    <div class="cas-upgrade-box">

        <div class="cas-upgrade-icon">⭐</div>

        <h2><?php echo ssp_get_text( 'upgrade_title' ); ?></h2>

        <p class="cas-upgrade-text">
            <?php echo ssp_get_text( 'upgrade_firewall' ); ?>
        </p>

        <a href="https://bueninformatico.com/wordpress/plugins/" class="cas-upgrade-btn" target="_blank">
            ⭐ <?php echo ssp_get_text( 'upgrade_button' ); ?>
        </a>

    </div>

</div>


												
			
				<?php else : ?>
                <div class="cas-bubble-card">
                    <h2> <?php echo ssp_get_text('tab_settings'); ?></h2>

                    <!-- Botones de modo oscuro bien ubicados -->
                    <div class="cas-mode-buttons" style="margin-bottom: 20px;">
					<button id="cas-light-btn" type="button" class="button button-secondary"><?php echo esc_html( ssp_get_text( 'light_mode' ) ); ?></button>
					<button id="cas-dark-btn" type="button" class="button button-secondary"><?php echo esc_html( ssp_get_text( 'dark_mode' ) ); ?></button>
                    </div>

                    
                </div>
				
				
				
            <?php endif; ?>
        </div>
        <?php
		
		
    }
}

// Guardar el slug personalizado
function cas_guardar_cambiourl_setting() {
    if ( isset( $_POST['cas_login_slug'] ) && isset( $_GET['tab'] ) && $_GET['tab'] === 'cambiourl' ) {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        
        $nuevo_slug = sanitize_text_field( $_POST['cas_login_slug'] );
        update_option( 'cas_login_slug', trim( $nuevo_slug, '/' ) );
        
        wp_safe_redirect( admin_url( 'admin.php?page=secure-headers&tab=cambiourl&updated=true' ) );
        exit;
    }
}
add_action( 'admin_init', 'cas_guardar_cambiourl_setting' );

// Mostrar el aviso verde de éxito al guardar
function cas_aviso_actualizacion_login() {
    if ( isset( $_GET['page'] ) && $_GET['page'] === 'secure-headers' && isset( $_GET['tab'] ) && $_GET['tab'] === 'cambiourl' && isset( $_GET['updated'] ) ) {
        echo '<div class="notice notice-success is-dismissible" style="margin-top: 15px;"><p><strong>' . esc_html( ssp_get_text('cambiourl_success_notice') ) . '</strong></p></div>';
    }
}
add_action( 'admin_notices', 'cas_aviso_actualizacion_login' );

// 2. Interceptar directamente la petición mediante la URL (Corregido para permitir envío POST de login y errores)
function cas_interceptar_url_login_directa() {
    if ( ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
        return;
    }

    $slug_personalizado = trim( get_option( 'cas_login_slug', '' ), '/' );
    if ( empty( $slug_personalizado ) ) {
        return;
    }

    $request_uri = $_SERVER['REQUEST_URI'];
    $is_wp_login = ( strpos( $request_uri, 'wp-login.php' ) !== false );

    // A. Bloquear el wp-login.php clásico SOLO si es una petición normal (GET) de entrada directa
    if ( $is_wp_login && ! is_user_logged_in() ) {
        $action  = isset( $_GET['action'] ) ? $_GET['action'] : '';
        $is_post = ( $_SERVER['REQUEST_METHOD'] === 'POST' );
        
        if ( !$is_post && $action !== 'logout' && $action !== 'postpass' ) {
            wp_safe_redirect( home_url( '404' ) );
            exit;
        }
    }

  // B. Detectar si la URL solicitada contiene el slug personalizado de forma segura
		$request_path = trim( parse_url( $request_uri, PHP_URL_PATH ), '/' );

		// Comprobamos si el final de la ruta coincide con nuestro slug (válido para raíz o subcarpetas)
		if ( $request_path === $slug_personalizado || substr( $request_path, -strlen( '/' . $slug_personalizado ) ) === '/' . $slug_personalizado ) {

			if ( ! is_user_logged_in() ) {

				global $pagenow, $user_login, $error;

				$pagenow = 'wp-login.php';

				$user_login = isset( $_POST['log'] ) ? sanitize_user( wp_unslash( $_POST['log'] ) ) : '';

				$error = '';

				if ( file_exists( ABSPATH . 'wp-login.php' ) ) {
					require_once ABSPATH . 'wp-login.php';
					exit;
				}

			} else {

				wp_safe_redirect( admin_url() );
				exit;

			}
		}
}
add_action( 'init', 'cas_interceptar_url_login_directa', 1 );

/**
 * ==========================================================
 * Redirigir logout después de ocultar wp-login.php
 * ==========================================================
 */
function cas_redirect_logout_custom() {

    if ( isset( $_GET['action'] ) && $_GET['action'] === 'logout' ) {

        wp_logout();

        wp_safe_redirect( home_url() );

        exit;

    }

}
add_action( 'login_init', 'cas_redirect_logout_custom', 1 );


function cas_sistema_modo_oscuro_completo() {
    ?>
    <!-- 1. Estilos CSS del Modo Oscuro con tus reglas exactas pero encapsuladas -->
    <style>
        /* Fondo general de la página solo cuando estás dentro de tu plugin */
        html.cas-dark-mode body:has(.cas-bubble-wrap) {
            background-color: #0b0f19 !important;
        }

        /* Contenedor principal */
        html.cas-dark-mode .cas-bubble-wrap,
        html.cas-dark-mode .wrap:has(.cas-bubble-wrap) {
            background-color: #0f172a !important;
            color: #f8fafc !important;
        }

        /* Tarjetas o cajas */
        html.cas-dark-mode .cas-bubble-wrap .cas-bubble-card,
        html.cas-dark-mode .cas-bubble-wrap .card,
        html.cas-dark-mode .cas-bubble-wrap .postbox {
            background-color: #1e293b !important;
            color: #f8fafc !important;
            border-color: #334155 !important;
        }

        /* ESTILOS PARA LAS TABLAS */
        html.cas-dark-mode .cas-bubble-wrap .wp-list-table.widefat,
        html.cas-dark-mode .cas-bubble-wrap .wp-list-table,
        html.cas-dark-mode .cas-bubble-wrap .widefat,
        html.cas-dark-mode .cas-bubble-wrap .striped {
            background-color: #1e293b !important;
            color: #f8fafc !important;
            border-color: #334155 !important;
        }

        html.cas-dark-mode .cas-bubble-wrap .wp-list-table.widefat th, 
        html.cas-dark-mode .cas-bubble-wrap .wp-list-table.widefat td,
        html.cas-dark-mode .cas-bubble-wrap .form-table th,
        html.cas-dark-mode .cas-bubble-wrap .form-table td {
            color: #f8fafc !important;
            border-color: #334155 !important;
        }

        /* Filas alternas de la clase striped y efectos al pasar el ratón */
        html.cas-dark-mode .cas-bubble-wrap .wp-list-table.widefat.striped tbody tr:nth-child(odd),
        html.cas-dark-mode .cas-bubble-wrap .wp-list-table.widefat tr:nth-child(odd) {
            background-color: #151e2d !important;
        }
        
        html.cas-dark-mode .cas-bubble-wrap .cas-alert-box {
            background: #000000 !important;
            border: 1px solid #fecaca !important;
            color: #f1f1f1 !important;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 12px;
            margin-top: 10px;
        }

        /* CAJAS / INPUTS Y CONTENEDORES DE CONFIGURACIÓN */
        html.cas-dark-mode .cas-bubble-wrap input[type="text"],
        html.cas-dark-mode .cas-bubble-wrap input[type="number"],
        html.cas-dark-mode .cas-bubble-wrap input[type="search"],
        html.cas-dark-mode .cas-bubble-wrap select,
        html.cas-dark-mode .cas-bubble-wrap textarea {
            background-color: #1e293b !important;
            color: #f8fafc !important;
            border-color: #334155 !important;
        }

        html.cas-dark-mode .cas-bubble-wrap .inside,
        html.cas-dark-mode .cas-bubble-wrap .handlediv + .inside,
        html.cas-dark-mode .cas-bubble-wrap div:not([class]) > div {
            background-color: #1e293b !important;
            color: #f8fafc !important;
            border-color: #334155 !important;
        }

        html.cas-dark-mode .cas-bubble-wrap .wp-list-table.widefat tbody tr:hover {
            background-color: #253348 !important;
        }

        /* Textos, títulos y etiquetas generales dentro del plugin */
        html.cas-dark-mode .cas-bubble-wrap h1, 
        html.cas-dark-mode .cas-bubble-wrap h2, 
        html.cas-dark-mode .cas-bubble-wrap h3, 
        html.cas-dark-mode .cas-bubble-wrap h4, 
        html.cas-dark-mode .cas-bubble-wrap p, 
        html.cas-dark-mode .cas-bubble-wrap label,
        html.cas-dark-mode .cas-bubble-wrap span {
            color: #f8fafc !important;
        }

        html.cas-dark-mode .cas-bubble-wrap .wp-list-table,
        html.cas-dark-mode .cas-bubble-wrap table.wp-list-table,
        html.cas-dark-mode .cas-bubble-wrap div.wp-list-table {
            background-color: #1e293b !important;
            color: #f8fafc !important;
        }

        html.cas-dark-mode .cas-bubble-wrap .wp-list-table.widefat tr,
        html.cas-dark-mode .cas-bubble-wrap .wp-list-table.widefat td,
        html.cas-dark-mode .cas-bubble-wrap .wp-list-table.widefat th {
            background-color: transparent !important;
            color: #f8fafc !important;
            border-color: #334155 !important;
        }

        html.cas-dark-mode .cas-bubble-wrap div:has(> .wp-list-table),
        html.cas-dark-mode .cas-bubble-wrap .inside {
            background-color: #0f172a !important;
            color: #f8fafc !important;
        }
        
        html.cas-dark-mode .cas-bubble-wrap .cas-tag {
            font-size: 10px;
            text-transform: uppercase;
            padding: 4px 8px;
            border-radius: 6px;
            font-weight: 700;
            display: inline-block;
            margin-bottom: 6px;
            background: #010109;
            color: #f8fafc !important;
        }

        html.cas-dark-mode .cas-bubble-wrap .form-table th {
            vertical-align: top;
            text-align: left;
            padding: 20px 10px 20px 0;
            width: 200px;
            line-height: 1.3;
            font-weight: 600;
            color: white !important;
        }

        html.cas-dark-mode .cas-bubble-wrap .cas-info-bubble {
            background: #000000;
            border-left: 4px solid #7c3aed;
            padding: 18px;
            border-radius: 8px;
            margin: 18px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            height: auto;
            color: #f8fafc !important;
        }
        
        html.cas-dark-mode .cas-bubble-wrap span[style*="background"],
        html.cas-dark-mode .cas-bubble-wrap code,
        html.cas-dark-mode .cas-bubble-wrap div[style*="background"],
        html.cas-dark-mode .cas-bubble-wrap span {
            background-color: #1e293b !important;
            color: #f8fafc !important;
        }
		
		/* Avisos de WordPress (notice-success, etc.) en modo oscuro */
        html.cas-dark-mode .cas-bubble-wrap .notice.notice-success,
        html.cas-dark-mode .cas-bubble-wrap .notice,
        html.cas-dark-mode .cas-bubble-wrap .updated,
        html.cas-dark-mode .cas-bubble-wrap .error {
            background-color: #000000 !important;
            color: #ffffff !important;
            border-color: #334155 !important;
            box-shadow: 0 1px 4px rgba(0,0,0,0.5);
        }

        html.cas-dark-mode .cas-bubble-wrap .notice.notice-success p,
        html.cas-dark-mode .cas-bubble-wrap .notice p,
        html.cas-dark-mode .cas-bubble-wrap .updated p,
        html.cas-dark-mode .cas-bubble-wrap .error p {
            color: #ffffff !important;
        }

        html.cas-dark-mode .cas-bubble-wrap .notice .notice-dismiss::before {
            color: #ffffff !important;
        }
    </style>

    <!-- 2. Script preventivo para cargar en oscuro al instante sin parpadeos -->
    <script>
    if (localStorage.getItem('cas_dark_mode') === 'enabled') {
        document.documentElement.classList.add('cas-dark-mode');
    }
    </script>

    <!-- 3. Control de los botones y restricción automática fuera del plugin -->
    <script>
    document.addEventListener('click', function(event) {
        const rootElement = document.documentElement;

        if (event.target.closest('#cas-light-btn')) {
            rootElement.classList.remove('cas-dark-mode');
            localStorage.setItem('cas_dark_mode', 'disabled');
        }

        if (event.target.closest('#cas-dark-btn')) {
            rootElement.classList.add('cas-dark-mode');
            localStorage.setItem('cas_dark_mode', 'enabled');
        }
    });

    document.addEventListener('DOMContentLoaded', function() {
        // Si no estamos en la página del plugin, desactivamos la clase global para proteger el resto de WordPress
        if (!document.querySelector('.cas-bubble-wrap')) {
            document.documentElement.classList.remove('cas-dark-mode');
            return;
        }

        if (localStorage.getItem('cas_dark_mode') === 'enabled') {
            document.documentElement.classList.add('cas-dark-mode');
        }
    });
    </script>
    <?php
}
add_action('admin_footer', 'cas_sistema_modo_oscuro_completo');

add_action('admin_enqueue_scripts', 'ssp_error404_media_scripts');

function ssp_error404_media_scripts($hook) {


    if (
        isset($_GET['page']) &&
        $_GET['page'] == 'secure-headers' &&
        isset($_GET['tab']) &&
        $_GET['tab'] == 'error404'
    ) {


        wp_enqueue_media();


        wp_enqueue_script(
            'ssp-error404-media',
            plugin_dir_url(__FILE__) . 'js/error404-media.js',
            array('jquery'),
            '1.0',
            true
        );

    }

}



// ==========================================
// FIN CONTENIDO SECCIONES
// ==========================================



