jQuery(document).ready(function($){

    $('.cas-upload-404-image').on('click', function(e){

        e.preventDefault();

        let frame = wp.media({
            title: 'Seleccionar imagen 404',
            button: {
                text: 'Usar imagen'
            },
            multiple: false
        });


        frame.on('select', function(){

            let attachment = frame
                .state()
                .get('selection')
                .first()
                .toJSON();


            $('#ssp_404_image').val(attachment.url);


            $('#ssp_404_image_preview').html(
                '<img src="' + attachment.url + '" style="max-width:200px;height:auto;border-radius:8px;">'
            );

        });


        frame.open();

    });

$('.cas-remove-404-image').on('click', function(e){

    e.preventDefault();

    $('#ssp_404_image').val('');

    $('#ssp_404_image_preview').html('');

});

});