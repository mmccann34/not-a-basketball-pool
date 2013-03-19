$(document).ready( function () {
  $("#usersimilarity").tablesorter({sortList: [[0,0]], widgets: ['zebra']});
  

	var oTable = $('#usersimilarity').dataTable( {
		"sDom": 'RCfrtip',
		"bPaginate": false,
		"sSortable":true
		
	} );

	$.extend( $.fn.dataTableExt.oStdClasses, {
    	"sSortAsc": "header headerSortDown",
    	"sSortDesc": "header headerSortUp",
    	"sSortable": "header"
	} )
  	
  
});