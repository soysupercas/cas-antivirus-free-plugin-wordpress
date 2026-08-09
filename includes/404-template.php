<?php

if ( ! defined('ABSPATH') ) {
    exit;
}

?>

<link rel="stylesheet" href="<?php echo esc_url(plugin_dir_url(__FILE__) . 'error404.css'); ?>">


<div class="cas-404-page">


    <?php if ( ! empty($image) ) : ?>

        <img 
        src="<?php echo esc_url($image); ?>" 
        alt="Error 404">

    <?php endif; ?>


    <h1>
        <?php echo esc_html($title); ?>
    </h1>


    <p>
        <?php echo esc_html($text); ?>
    </p>


    <a href="<?php echo esc_url(home_url()); ?>">
        Volver al inicio
    </a>


</div>