console.log("movemovemoemove");
$(function(){
    $('.table-clickable-row').on('click', function(){
        console.log($(this).data('href'));
        window.location = $(this).data('href');
    });
});
