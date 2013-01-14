$(function() {
  // do stuff when DOM is ready
  $.ajaxSetup({cache: false});

  $('.team').click(function() {
    locked = $('#form_bracket').data('locked');
    if (locked != 'True' && $(this).text())
    {
      var team = parseInt($(this).attr('id').split('_')[1]);
      setWinner(Math.round(team/2), $(this).text());

      // $(this).css('font-weight','bold');

      // var opponent;
      // if (team % 2 == 0)
      // {
      //   opponent = team - 1;
      // }
      // else
      // {
      //   opponent = team + 1;  
      // }

      // $('#team_' + opponent).css('font-weight','normal');
    }
  });

  $('.winner').click(function() {
    locked = $('#form_bracket').data('locked');
    if (locked != 'True' && $(this).val())
    {
      var game = parseInt($(this).attr('name').split('_')[1]);
      setWinner(Math.round(game/2) + 32, $(this).val());

      // $(this).css('font-weight','bold');

      // var opponent;
      // if (game % 2 == 0)
      // {
      //   opponent = game - 1;
      // }
      // else
      // {
      //   opponent = game + 1;
      // }

      // $('input[name=winner_' + opponent + ']').css('font-weight','normal');
    }
  });

  // Randomize the picks
  $(document).bind('keydown', 'alt+ctrl+r', function() {
    for (i=1; i<64; i+=2)
    {
      $('#team_' + (i + Math.round(Math.random()))).click();
    }

    for (i=1; i<63; i+=2)
    {
      $('input[name=winner_' + (i + Math.round(Math.random())) + ']').click();
    }

    $('input[name=final_score]').val(Math.floor((Math.random()*101)+100));
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
  try
  {
    if ($('#form_bracket').data('master') == 'True')
    {
      $('#form_bracket').submit()
      return;
    }

    var returnval = true;

    $('input.winner').each(function (i) {
      if (!$(this).val()) {
        alert('A winner must be picked for all games');
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

    if (returnval)
    {
      var entry_name = $('input[name=entry_name]')
      if (entry_name.length)
      {
        var name = entry_name.val()
        if (!name)
        {
          alert('Entry must have a name');
          returnval = false;
        }
        else
        {
        $.getJSON('/validate/entry', { entry_name: name }, 
          function(response) { 
            var result = response;
            if (!result)
            {
              alert('That Entry name is already in use')
              returnval = false;
            }
            else
            {
              $('#form_bracket').submit()
            }
          });
        }
      }
      else
      {
        $('#form_bracket').submit()
      }
    }
    return returnval;
  }
  catch(err)
  {
    return false;
  }
}