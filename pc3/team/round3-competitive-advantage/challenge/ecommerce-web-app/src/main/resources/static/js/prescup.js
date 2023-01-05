$(document).ready(function(){

  	// This is for checking out
	$( "#checkout" ).click(function() {
		window.location.href = "/checkout";
	});
	
	// This is for adding a single item to cart from the item detail page.
	$("#addSingleItem").submit(function(e)
	{
		e.preventDefault();
		var form = this;
		data = objectifyForm( $(this).serializeArray() );
		console.log( data );
		$.ajax( '/rest/cart', { data: JSON.stringify(data), contentType: 'application/json', type: 'POST', success: function(d){console.log(d);} });
	});
});

function objectifyForm( formArray )
{
    //serialize data function
    var returnArray = {};
    for( var i = 0; i < formArray.length; i++ )
	{
    	returnArray[formArray[i]['name']] = formArray[i]['value'];
    }

	// add in required fields
	returnArray['FSTAT'] = '039';
	returnArray['csrfToken'] = $('meta[name="_csrf"]').attr('content');
    return returnArray;
}