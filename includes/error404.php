<?php

if ( ! defined('ABSPATH') ) {
    exit;
}

if ( ! get_option( 'ssp_404_enabled', 0 ) ) {
    return;
}

add_action('template_redirect', 'ssp_custom_404_page');


function ssp_custom_404_page() {


    if ( ! is_404() ) {
        return;
    }


    $title = get_option(
        'ssp_404_title',
        'Página no encontrada'
    );


    $text = get_option(
        'ssp_404_text',
        'Lo sentimos, la página que buscas no existe o ha sido movida.'
    );


    $image = get_option(
        'ssp_404_image',
        ''
    );


status_header(404);

nocache_headers();

wp_enqueue_style(
    'ssp-error404-style',
    plugin_dir_url(__FILE__) . 'error404.css',
    array(),
    '1.0'
);;

include plugin_dir_path(__FILE__) . '404-template.php';

exit;

}