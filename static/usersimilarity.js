$(document).ready( function () {
  $("#usersimilarity").tablesorter({sortList: [[0,0]], widgets: ['zebra']});
  

	var oTable = $('#usersimilarity').dataTable( {
		"sDom": 'RCfrtip',
		"bPaginate": false,
		"sSortable":true,
		"oColVis": {
            "aiExclude": [ 0 ]
		}
	} );

	$.extend( $.fn.dataTableExt.oStdClasses, {
    	"sSortAsc": "header headerSortDown",
    	"sSortDesc": "header headerSortUp",
    	"sSortable": "header"
	} )
  	
  
});