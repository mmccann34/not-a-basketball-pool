$(function() {
  // do stuff when DOM is ready
  $(".team").click(function() {
    if ($(this).text())
    {
      var game = $(this).attr('id').split('_')[1];
      setWinner(Math.round(game/2), $(this).text());
    }
  });

  $(".winner").click(function() {
    if ($(this).val())
    {
      var game = $(this).attr('name').split('_')[1];
      setWinner(Math.round(game/2) + 32, $(this).val());
    }
  });
});

function setWinner(game, value)
{
  var winner = $('input[name=winner_' + game + ']');
  var prevWinner = winner.val();
  if (prevWinner)
  {
    do
    {
      winner.val(value);

      game = Math.round(game/2) + 32;
      winner = $('input[name=winner_' + game + ']');
    }
    while (winner.val() == prevWinner);
  }
  else
  {
    winner.val(value);
  }
}