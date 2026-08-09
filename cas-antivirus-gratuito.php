<?php
/**
 * Plugin Name: Cas Antivirus Gratuito
 * Plugin URI: https://bueninformatico.com/wordpress/plugins
 * Description: Protege tu WordPress gratis con 6 cabeceras HTTP de seguridad esenciales, un potente escáner de integridad del núcleo (FIM) con restauración automática de archivos y autenticación en dos pasos (2FA). Seguridad avanzada en una interfaz clara, rápida y fácil de usar.
 * Version: 3.1
 * Author: Buen Informático
 * Author URI: https://bueninformatico.com/wordpress/plugins
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: cas-antivirus-gratuito
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



require_once plugin_dir_path(__FILE__) . 'languages/languages.php';
require_once plugin_dir_path(__FILE__) . 'admin/program.php';
require_once plugin_dir_path(__FILE__) . 'admin/program.php';
require_once plugin_dir_path( __FILE__ ) . '2fa/2fa-cas.php';

        if ( ! function_exists( 'ssp_options_page_html' ) ) {
            function ssp_options_page_html() {
                if ( ! current_user_can( 'manage_options' ) ) {
                    return;
                }

                if ( isset( $_GET['prefix_changed'] ) && $_GET['prefix_changed'] === 'true' ) {
                    echo '<div class="notice notice-success is-dismissible" style="border-left-color: #7c3aed;"><p><strong>Prefijo actualizado con éxito.</strong></p></div>';
                }

                if ( isset( $_GET['cleaned'] ) ) {
                    $cleaned_msg = sanitize_text_field( wp_unslash( $_GET['cleaned'] ) );
                    echo '<div class="notice notice-success is-dismissible" style="border-left-color: #7c3aed;"><p><strong>Operación completada:</strong> ' . esc_html( $cleaned_msg ) . '</p></div>';
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

		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'headers';
        ?>
         <div class="wrap cas-bubble-wrap">
		<h1 class="cas-title"><?php echo esc_html( ssp_get_text('plugin_title') ); ?></h1>
            <style>
                /* ========================================================== */
                /* CSS */
                /* ========================================================== */
					.cas-bubble-wrap {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
                    color: #1e293b;
                    max-width: 100% !important;
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
					
            </style>

            
				<div class="cas-status-bubble">
               <div class="cas-status-text" style="color: <?php echo esc_attr( $status_color ); ?>;">
        <?php 
        // printf con cadenas y variables traducidas y escapadas de forma segura
        printf( 
            esc_html( ssp_get_text('protected_status') ), 
            esc_html( $active_layers ) 
        ); 
        ?>
    </div>
    <div class="cas-progress-track">
        <div class="cas-progress-fill" style="background: <?php echo esc_attr( $status_color ); ?>; width: <?php echo esc_attr( $protection_percent ); ?>%;"></div>
    </div>
</div>

		<h2 class="nav-tab-wrapper">
			<a href="?page=secure-headers&tab=headers" class="nav-tab <?php echo $active_tab == 'headers' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( ssp_get_text('tab_headers') ); ?></a>
			<a href="?page=secure-headers&tab=fim" class="nav-tab <?php echo $active_tab == 'fim' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( ssp_get_text('tab_fim') ); ?></a>
			<a href="?page=secure-headers&tab=2fa" class="nav-tab <?php echo $active_tab == '2fa' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( ssp_get_text('2fa_title') ); ?></a>                
			<a href="?page=secure-headers&tab=database" class="nav-tab <?php echo $active_tab == 'database' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( ssp_get_text('tab_database') ); ?></a>
			<a href="?page=secure-headers&tab=cleanup" class="nav-tab <?php echo $active_tab == 'cleanup' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( ssp_get_text('tab_cleanup') ); ?></a>
			<a href="?page=secure-headers&tab=login_security" class="nav-tab <?php echo $active_tab == 'login_security' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( ssp_get_text('tab_login_security') ); ?></a>
			<a href="?page=secure-headers&tab=cambiourl" class="nav-tab <?php echo $active_tab == 'cambiourl' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( ssp_get_text('tab_cambiourl') ); ?></a>
			<a href="?page=secure-headers&tab=error404" class="nav-tab <?php echo $active_tab == 'error404' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( ssp_get_text('tab_error404') ); ?></a>                
			<a href="?page=secure-headers&tab=hardening" class="nav-tab <?php echo $active_tab == 'hardening' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( ssp_get_text('tab_hardening') ); ?></a>
			<a href="?page=secure-headers&tab=firewall" class="nav-tab <?php echo $active_tab == 'firewall' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( ssp_get_text('firewall') ); ?></a>
			<a href="?page=secure-headers&tab=settings" class="nav-tab <?php echo $active_tab == 'settings' ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( ssp_get_text('tab_settings') ); ?></a>     
		</h2>

            <?php settings_errors( 'ssp_messages' ); ?>

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
                                $msg_format = ssp_get_text('fim_status_modified_count');
                                $alert_text = sprintf( $msg_format, $total_issues );

                                echo '<div class="cas-alert-box" style="margin-bottom: 16px;"><strong>' . esc_html( $alert_text ) . '</strong></div>';
                                echo '<div style="overflow-x: auto; width: 100%;">';
                                echo '<table class="wp-list-table widefat striped" style="width: 100%;">';
                                echo '<thead><tr>';
                                echo '<th>' . esc_html( ssp_get_text('fim_file_col') ) . '</th>';
                                echo '<th>' . esc_html( ssp_get_text('fim_status_col') ) . '</th>';
                                echo '<th>' . esc_html( ssp_get_text('fim_action_col') ) . '</th>';
                                echo '</tr></thead><tbody>';
                                
                                foreach ( $modified_files as $file ) {
                                    echo '<tr><td><code>' . esc_html( $file ) . '</code></td>';
                                    echo '<td><span style="color: #d97706; font-weight: 600;">' . esc_html( ssp_get_text('fim_status_modified_label') ) . '</span></td>';
                                    echo '<td>' . esc_html( ssp_get_text('fim_action_restore_text') ) . '</td></tr>';
                                }

                                foreach ( $missing_files as $file ) {
                                    echo '<tr><td><code>' . esc_html( $file ) . '</code></td>';
                                    echo '<td><span style="color: #dc2626; font-weight: 600;">' . esc_html( ssp_get_text('fim_status_missing_label') ) . '</span></td>';
                                    echo '<td>' . esc_html( ssp_get_text('fim_action_restore_text') ) . '</td></tr>';
                                }
                                echo '</tbody></table></div>';
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
                </div>




				<script>
                document.addEventListener('DOMContentLoaded', function() {
                    const scanForm = document.getElementById('fim-scan-form');
                    const scanBtn = document.getElementById('fim-scan-btn');
                    const scanningText = "<?php echo esc_js( ssp_get_text('scanning_files') ); ?>";

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
							security: '<?php echo esc_attr( wp_create_nonce( "prueba_restore_nonce" ) ); ?>',
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


           <?php elseif ( $active_tab == 'headers' ) : ?>
                <div class="cas-bubble-card">
                    <p class="cas-desc" style="margin-top: 0; margin-bottom: 24px;">
                   <?php echo esc_html( ssp_get_text('headers_intro') ); ?>
                    </p>
                    <form action="options.php" method="post">
                        <?php settings_fields( 'ssp_settings_group' ); ?>
                        <table class="form-table">
                            <tr>
                                <th scope="row">
                                    <span class="cas-tag">Capa 01</span><br>
                                    <label for="ssp_csp"><?php echo esc_html( ssp_get_text('layer_5_title') ); ?></label>
                                </th>
                                <td>
                                    <select name="ssp_csp" id="ssp_csp" style="width: 300px;">
                                        <option value="default" <?php selected( get_option( 'ssp_csp', 'default' ), 'default' ); ?>><?php echo esc_html( ssp_get_text('layer_5_mode') ); ?></option>
                                        <option value="disabled" <?php selected( get_option( 'ssp_csp' ), 'disabled' ); ?>><?php echo esc_html( ssp_get_text('opt_disabled') ); ?></option>
                                    </select>
                                    <p class="cas-desc"><?php echo esc_html( ssp_get_text('layer_5_desc') ); ?></p>
                                </td>
                            </tr>
                            <tr class="cas-border-top">
                                <th scope="row">
                                    <span class="cas-tag">Capa 02</span><br>
                                    <?php echo esc_html( ssp_get_text('layer_2_title') ); ?>
                                </th>
                                <td>
                                    <label style="color: #1e293b; font-size: 13px; font-weight: 500;">
                                        <input type="checkbox" name="ssp_x_content_type" value="yes" <?php checked( get_option( 'ssp_x_content_type', 'yes' ), 'yes' ); ?>>
                                        <?php echo esc_html( ssp_get_text('layer_2_label') ); ?>
                                    </label>
                                    <p class="cas-desc"><?php echo esc_html( ssp_get_text('layer_2_desc') ); ?></p>
                                </td>
                            </tr>
                            <tr class="cas-border-top">
                                <th scope="row">
                                    <span class="cas-tag">Capa 03</span><br>
                                    <?php echo esc_html( ssp_get_text('layer_3_title') ); ?>
                                </th>
                                <td>
                                    <label style="color: #1e293b; font-size: 13px; font-weight: 500;">
                                        <input type="checkbox" name="ssp_hsts" value="yes" <?php checked( get_option( 'ssp_hsts', 'yes' ), 'yes' ); ?>>
                                        <?php echo esc_html( ssp_get_text('layer_3_label') ); ?>
                                    </label>
                                    <p class="cas-desc"><?php echo esc_html( ssp_get_text('layer_3_desc') ); ?></p>
                                </td>
                            </tr>
                            <tr class="cas-border-top">
                                <th scope="row">
                                    <span class="cas-tag">Capa 04</span><br>
                                    <label for="ssp_referrer_policy"><?php echo esc_html( ssp_get_text('layer_4_title') ); ?></label>
                                </th>
                                <td>
                                    <select name="ssp_referrer_policy" id="ssp_referrer_policy" style="width: 300px;">
                                        <option value="no-referrer" <?php selected( get_option( 'ssp_referrer_policy', 'no-referrer' ), 'no-referrer' ); ?>><?php echo esc_html( ssp_get_text('opt_noreferrer') ); ?></option>
                                        <option value="strict-origin-when-cross-origin" <?php selected( get_option( 'ssp_referrer_policy' ), 'strict-origin-when-cross-origin' ); ?>><?php echo esc_html( ssp_get_text('opt_balanced') ); ?></option>
                                        <option value="disabled" <?php selected( get_option( 'ssp_referrer_policy' ), 'disabled' ); ?>><?php echo esc_html( ssp_get_text('opt_disabled') ); ?></option>
                                    </select>
                                    <p class="cas-desc"><?php echo esc_html( ssp_get_text('layer_4_desc') ); ?></p>
                                </td>
                            </tr>
                            <tr class="cas-border-top">
                                <th scope="row">
                                    <span class="cas-tag cas-tag-pro">Capa 05 (A+)</span><br>
                                    <label for="ssp_x_frame_options"><?php echo esc_html( ssp_get_text('layer_1_title') ); ?></label>
                                </th>
                                <td>
                                    <select name="ssp_x_frame_options" id="ssp_x_frame_options" style="width: 300px;">
                                        <option value="DENY" <?php selected( get_option( 'ssp_x_frame_options', 'DENY' ), 'DENY' ); ?>><?php echo esc_html( ssp_get_text('opt_deny') ); ?></option>
                                        <option value="SAMEORIGIN" <?php selected( get_option( 'ssp_x_frame_options' ), 'SAMEORIGIN' ); ?>><?php echo esc_html( ssp_get_text('opt_sameorigin') ); ?></option>
                                        <option value="disabled" <?php selected( get_option( 'ssp_x_frame_options' ), 'disabled' ); ?>><?php echo esc_html( ssp_get_text('opt_disabled') ); ?></option>
                                    </select>
                                    <p class="cas-desc">
                                        <?php echo esc_html( ssp_get_text('layer_1_desc') ); ?><br>
                                        <span class="cas-alert-box" style="display: block; margin-top: 10px;">
                                            <?php echo esc_html( ssp_get_text('csp_warning') ); ?>
                                        </span>
                                    </p>
                                </td>
                            </tr>
                            <tr class="cas-border-top">
                                <th scope="row">
                                    <span class="cas-tag cas-tag-danger">Extra</span><br>
                                    <?php echo esc_html( ssp_get_text('layer_extra_title') ); ?>
                                </th>
                                <td>
                                    <label style="color: #1e293b; font-size: 13px; font-weight: 500;">
                                        <input type="checkbox" name="ssp_permissions_policy" value="yes" <?php checked( get_option( 'ssp_permissions_policy', 'yes' ), 'yes' ); ?>>
                                        <?php echo esc_html( ssp_get_text('layer_extra_label') ); ?>
                                    </label>
                                    <p class="cas-desc"><?php echo esc_html( ssp_get_text('layer_extra_desc') ); ?></p>
                                </td>
                            </tr>
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
									<h2><?php echo esc_html( ssp_get_text( 'upgrade_title' ) ); ?></h2>
									<p class="cas-upgrade-text">
										<?php echo esc_html( ssp_get_text( 'upgrade_hardening' ) ); ?>
									</p>
									<a href="https://bueninformatico.com/wordpress/plugins/" class="cas-upgrade-btn" target="_blank" rel="noopener">
										⭐<?php echo esc_html( ssp_get_text( 'upgrade_button' ) ); ?>
									</a>
								</div>
							</div>

							<?php elseif ( $active_tab == 'login_security' ) : ?>
							<div class="cas-bubble-card">
								<div class="cas-upgrade-box">
									<div class="cas-upgrade-icon">⭐</div>
									<h2><?php echo esc_html( ssp_get_text( 'upgrade_title' ) ); ?></h2>
									<p class="cas-upgrade-text">
										<?php echo esc_html( ssp_get_text( 'upgrade_security' ) ); ?>
									</p>
									<a href="https://bueninformatico.com/wordpress/plugins/" class="cas-upgrade-btn" target="_blank" rel="noopener">
										⭐ <?php echo esc_html( ssp_get_text( 'upgrade_button' ) ); ?>
									</a>
								</div>
							</div>

							<?php elseif ( $active_tab == 'database' ) : ?>
							<div class="cas-bubble-card">
								<div class="cas-upgrade-box">
									<div class="cas-upgrade-icon">⭐</div>
									<h2><?php echo esc_html( ssp_get_text( 'upgrade_title' ) ); ?></h2>
									<p class="cas-upgrade-text">
										<?php echo esc_html( ssp_get_text( 'upgrade_database' ) ); ?>
									</p>
									<a href="https://bueninformatico.com/wordpress/plugins/" class="cas-upgrade-btn" target="_blank" rel="noopener">
										⭐ <?php echo esc_html( ssp_get_text( 'upgrade_button' ) ); ?>
									</a>
								</div>
							</div>

							<?php elseif ( $active_tab == 'error404' ) : ?>
							<div class="cas-bubble-card">
								<div class="cas-upgrade-box">
									<div class="cas-upgrade-icon">⭐</div>
									<h2><?php echo esc_html( ssp_get_text( 'upgrade_title' ) ); ?></h2>
									<p class="cas-upgrade-text">
										<?php echo esc_html( ssp_get_text( 'upgrade_404' ) ); ?>
									</p>
									<a href="https://bueninformatico.com/wordpress/plugins/" class="cas-upgrade-btn" target="_blank" rel="noopener">
										⭐ <?php echo esc_html( ssp_get_text( 'upgrade_button' ) ); ?>
									</a>
								</div>
							</div>

							<?php elseif ( $active_tab == 'cambiourl' ) : ?>
							<div class="cas-bubble-card">
								<div class="cas-upgrade-box">
									<div class="cas-upgrade-icon">⭐</div>
									<h2><?php echo esc_html( ssp_get_text( 'upgrade_title' ) ); ?></h2>
									<p class="cas-upgrade-text">
										<?php echo esc_html( ssp_get_text( 'upgrade_cambiourl' ) ); ?>
									</p>
									<a href="https://bueninformatico.com/wordpress/plugins/" class="cas-upgrade-btn" target="_blank" rel="noopener">
										⭐<?php echo esc_html( ssp_get_text( 'upgrade_button' ) ); ?>
									</a>
								</div>
							</div>

							<?php elseif ( $active_tab == 'cleanup' ) : ?>
							<div class="cas-bubble-card">
								<div class="cas-upgrade-box">
									<div class="cas-upgrade-icon">⭐</div>
									<h2><?php echo esc_html( ssp_get_text( 'upgrade_title' ) ); ?></h2>
									<p class="cas-upgrade-text">
										<?php echo esc_html( ssp_get_text( 'upgrade_cleanup' ) ); ?>
									</p>
									<a href="https://bueninformatico.com/wordpress/plugins/" class="cas-upgrade-btn" target="_blank" rel="noopener">
										⭐ <?php echo esc_html( ssp_get_text( 'upgrade_button' ) ); ?>
									</a>
								</div>
							</div>


				<?php elseif ( $active_tab == '2fa' ) : ?>
				<?php

				settings_errors( 'cas_notices' );
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
						<h2><?php echo esc_html( ssp_get_text( '2fa_heading' ) ); ?></h2>
						<p class="cas-desc">
							<?php echo esc_html( ssp_get_text( '2fa_intro' ) ); ?>
						</p>

						<form method="post">
							<?php wp_nonce_field( 'cas_save_2fa_action', 'cas_2fa_nonce' ); ?>
							<table class="form-table">
								<tr>
									<th scope="row">
										<?php echo esc_html( ssp_get_text( '2fa_enable_label' ) ); ?>
									</th>
									<td>
										<label>
											<input
												type="checkbox"
												name="cas_enable_2fa"
												value="1"
												<?php checked( $is_enabled, '1' ); ?>
											>
											<?php echo esc_html( ssp_get_text( '2fa_enable_desc' ) ); ?>
										</label>
									</td>
								</tr>
							</table>
							<table class="form-table">
								<tr class="cas-border-top">
									<th scope="row">
										<label>
											<?php echo esc_html( ssp_get_text( '2fa_app_config_label' ) ); ?>
										</label>
									</th>
									<td>
										<p>
											<?php echo esc_html( ssp_get_text( '2fa_scan_qr_text' ) ); ?>

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
											<?php echo esc_html( ssp_get_text( '2fa_manual_key_text' ) ); ?>
											<code><?php echo esc_html( $secret ); ?></code>
										</p>
									</td>
								</tr>
								<tr class="cas-border-top">
									<th scope="row">
										<label for="cas_2fa_code">
											<?php echo esc_html( ssp_get_text( '2fa_verify_code_label' ) ); ?>
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
											<?php echo esc_html( ssp_get_text( '2fa_verify_code_desc' ) ); ?>
										</p>
									</td>
								</tr>
							</table>
							<?php submit_button( ssp_get_text( 'save_2fa' ) ); ?>
						</form>
					</div>


	<?php elseif ( $active_tab == 'firewall' ) : ?>
    <div class="cas-bubble-card">
        <div class="cas-upgrade-box">
            <div class="cas-upgrade-icon">⭐</div>
            <h2><?php echo esc_html( ssp_get_text( 'upgrade_title' ) ); ?></h2>
            <p class="cas-upgrade-text">
                <?php echo esc_html( ssp_get_text( 'upgrade_firewall' ) ); ?>
            </p>
            <a href="https://bueninformatico.com/wordpress/plugins/" class="cas-upgrade-btn" target="_blank" rel="noopener">
                ⭐ <?php echo esc_html( ssp_get_text( 'upgrade_button' ) ); ?>
            </a>
        </div>
    </div>

		<?php else : ?>
				<div class="cas-bubble-card">
					<h2><?php echo esc_html( ssp_get_text( 'tab_settings' ) ); ?></h2>

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

function cas_sistema_modo_oscuro_completo() {
    ?>
   
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



    <script>
    if (localStorage.getItem('cas_dark_mode') === 'enabled') {
        document.documentElement.classList.add('cas-dark-mode');
    }
    </script>

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