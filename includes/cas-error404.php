<?php

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

add_action('admin_init', 'ssp_register_error404_settings');

function ssp_register_error404_settings() {

    register_setting(
        'ssp_error404_group',
        'ssp_404_title'
    );

    register_setting(
        'ssp_error404_group',
        'ssp_404_text'
    );

    register_setting(
        'ssp_error404_group',
        'ssp_404_image'
    );

	register_setting(
		'ssp_error404_group',
		'ssp_404_enabled'
	);
}