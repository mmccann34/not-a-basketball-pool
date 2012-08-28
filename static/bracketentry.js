$(function() {
  // do stuff when DOM is ready
  $(".team").click(function() {
    if ($(this).text())
    {
      var team = parseInt($(this).attr('id').split('_')[1]);
      setWinner(Math.round(team/2), $(this).text());

      $(this).css("font-weight","bold");

      var opponent;
      if (team % 2 == 0)
      {
        opponent = team - 1;
      }
      else
      {
        opponent = team + 1;
      }

      $('#team_' + opponent).css("font-weight","normal");
    }
  });

  $(".winner").click(function() {
    if ($(this).val())
    {
      var game = parseInt($(this).attr('name').split('_')[1]);
      setWinner(Math.round(game/2) + 32, $(this).val());

      $(this).css("font-weight","bold");

      var opponent;
      if (game % 2 == 0)
      {
        opponent = game - 1;
      }
      else
      {
        opponent = game + 1;
      }

      $('input[name=winner_' + opponent + ']').css("font-weight","normal");
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

function validateInputs()
{
  var returnval = true;

  $('input.winner').each(function (i) {
    if (!$(this).val()) {
      alert("A winner must be picked for all games");
      returnval = false;
    }
    return returnval;
  });

  if (returnval)
  {
    var final_score_val = $('input[name=final_score]').val();
    var final_score = parseInt(final_score_val);

    if (isNaN(final_score) || final_score != final_score || final_score_val <= 0)
    {
      alert('Final Score Sum must be a valid, positive number');
      returnval = false;
    }
  }

  return returnval;
}