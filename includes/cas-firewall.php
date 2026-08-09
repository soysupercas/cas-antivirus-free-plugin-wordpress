<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

function cas_firewall_register_settings() {
    $firewall_options = array( 
        'fw_sqli', 
        'fw_xss', 
        'fw_lfi', 
        'fw_path', 
        'fw_url', 
        'fw_useragent', 
        'fw_scan', 
        'fw_rate', 
        'fw_bruteforce', 
        'fw_tempblock' 
    );

    foreach ( $firewall_options as $opt ) {
        register_setting( 'cas_firewall_group', $opt );
    }
}
add_action( 'admin_init', 'cas_firewall_register_settings' );