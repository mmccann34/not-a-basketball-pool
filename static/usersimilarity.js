$(document).ready( function () {
  $("#usersimilarity").tablesorter({sortList: [[0,0]], widgets: ['zebra']});
  

	var oTable = $('#usersimilarity').dataTable( {
		"sDom": 'Rlfrtip'
	} );
  
});