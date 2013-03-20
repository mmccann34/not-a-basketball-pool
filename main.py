#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import random
import hashlib
import hmac
import csv
import string
import StringIO
import math
import json
import itertools
from datetime import datetime
from datetime import timedelta
from operator import attrgetter

import webapp2
from webapp2_extras import sessions
import jinja2

from google.appengine.ext import db
from google.appengine.ext import deferred
from google.appengine.api import mail

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
  t = jinja_env.get_template(template)
  return t.render(params)

secret = 'poqieurjfads'
def make_secure_val(val):
  return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
  val = secure_val.split('|')[0]
  if secure_val == make_secure_val(val):
      return val

class BaseHandler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)
      
  def render_str(self, template, **params):
    params['user'] = self.user
    
    # Set the flash message
    flash = self.session.get_flashes()
    if flash:
      params['flash_message'] = flash[0][0]
      if len(flash[0]) > 1:
        params['flash_status'] = flash[0][1]

    if 'locked' not in params:
      params['locked'] = self.locked
    return render_str(template, **params)
      
  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

  def set_secure_cookie(self, name, val):
    cookie_val = make_secure_val(val)
    self.response.headers.add_header(
        'Set-Cookie',
        '%s=%s; Path=/' % (name, cookie_val))

  def read_secure_cookie(self, name):
    cookie_val = self.request.cookies.get(name)
    return cookie_val and check_secure_val(cookie_val)

  def login(self, user):
    self.set_secure_cookie('user_id', str(user.id))

  def logout(self):
    self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

  def require_login(self):
    self.redirect('/login?return-url=' + self.request.path_qs)

  def add_flash(self, message, status=None):
    self.session.add_flash(message, status)
      
  def initialize(self, *a, **kw):
    webapp2.RequestHandler.initialize(self, *a, **kw)
    
    uid = self.read_secure_cookie('user_id')
    self.user = uid and User.by_id(int(uid))
    
    a = Admin.get_current()
    self.locked = a and datetime.today() > a.lock_date

    self.dev = os.environ['SERVER_SOFTWARE'].startswith('Development')
    if self.dev:
      self.base_url = "http://localhost:8080"
    else:
      self.base_url = "notabasketballpool.appspot.com"

  def dispatch(self):
    # Get a session store for this request.
    self.session_store = sessions.get_store(request=self.request)

    try:
      # Dispatch the request.
      webapp2.RequestHandler.dispatch(self)
    finally:
      # Save all sessions.
      self.session_store.save_sessions(self.response)

  @webapp2.cached_property
  def session(self):
    # Returns a session using the default cookie key.
    return self.session_store.get_session()

####User####
def make_salt(length = 5):
  return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(pw, name=None, salt=None):
  if not salt:
      salt = make_salt()
  if not name:
    h = hashlib.sha256(pw + salt).hexdigest()
  else:
    h = hashlib.sha256(name + pw + salt).hexdigest()
  return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
  salt = h.split(',')[0]
  return h == make_pw_hash(password, name.strip(), salt)

##Token Stuff##
def make_reset_token(length = 20):
  rand = random.SystemRandom()
  return ''.join(rand.choice(string.ascii_letters + string.digits) for x in xrange(length))

def valid_token(token, h):
  salt = h.split(',')[0]
  return h == make_pw_hash(token, salt=salt)

def look_for_token(token):
  result = None
  for u in User.all().filter('reset_token !=', None).run(batch_size=1000):
    if valid_token(token, u.reset_token):
      result = u
      break
  return result

def users_key(group = 'default'):
  return db.Key.from_path('users', group)

class User(db.Model):
  name = db.StringProperty(required = True)
  name_search = db.StringProperty(required = True)
  pw_hash = db.StringProperty(required = True)
  email = db.StringProperty()
  admin = db.BooleanProperty(required = True)
  reset_token = db.StringProperty()
  reset_expiration = db.DateTimeProperty()

  @property
  def id(self):
    return self.key().id()

  @classmethod
  def by_id(cls, uid):
    return User.get_by_id(uid, parent = users_key())

  @classmethod
  def by_name(cls, name):
    u = User.all().filter('name_search =', name.strip().upper()).ancestor(users_key()).get()
    return u

  @classmethod
  def register(cls, name, pw, email = None):
    name = name.strip()
    pw_hash = make_pw_hash(pw, name)
    u = User(parent = users_key(),
              name = name,
              name_search = name.upper(),
              pw_hash = pw_hash,
              email = email,
              admin = False)
    u.put()
    return u

  @classmethod
  def login(cls, name, pw):
    u = cls.by_name(name)
    if u and valid_pw(name, pw, u.pw_hash):
      return u

  def delete_account(self):
    db.delete(Entry.all().filter("user =", self).ancestor(entries_key()).run(batch_size=1000, keys_only=True))
    for p in Pool.all().filter("users =", self.id).ancestor(pools_key()).run(batch_size=1000):
      p.users.remove(self.id)
      if p.admin_user.id == self.id:
        p.admin_user = None
      p.put()
    self.delete()

  def get_entries(self):
    return Entry.all().filter("user =", self).filter("year =", datetime.now().year).order("name").ancestor(entries_key()).run(batch_size=1000)

  def get_pools(self):
    return Pool.all().filter("users =", self.id).filter("year =", datetime.now().year).order("name").ancestor(pools_key()).run(batch_size=1000)

  def prepare_reset_token(self):
    done = False
    while not done:
      token = make_reset_token()
      if not look_for_token(token):
        done = True
    self.reset_token = make_pw_hash(token)
    self.reset_expiration = datetime.now() + timedelta(hours=2)
    self.put()
    return token

####Team####
def teams_key(group = 'default'):
  return db.Key.from_path('teams', group)

class Team(db.Model):
  name = db.StringProperty(required = True)
  year = db.IntegerProperty(required = True)
  seed = db.IntegerProperty(required = True)
  bracket_position = db.IntegerProperty(required = True)
  eliminated = db.BooleanProperty()

  @property
  def id(self):
    return self.key().id()

  @classmethod
  def submit(cls, name, year, seed, bracket_position):
    t = Team(parent = pools_key(),
              year = year,
              name = name,
              seed = seed,
              bracket_position = bracket_position)
    t.put()
    return t

  def update(self, name, year, seed, bracket_position):
    self.name = name
    self.year = year
    self.seed = seed
    self.bracket_position = bracket_position
    self.put()

  @classmethod
  def by_year(cls, year = datetime.now().year):
    return Team.all().filter('year = ', year).ancestor(pools_key()).fetch(limit=64)

  @classmethod
  def get_teams_dict(cls, year = datetime.now().year):
    teams = dict()
    for team in Team.all().filter('year = ', year).ancestor(pools_key()).fetch(limit=64):
      teams[team.id] = team
    return teams

####Pool####
def pools_key(group = 'default'):
  return db.Key.from_path('pools', group)

class Pool(db.Model):
  name = db.StringProperty(required = True)
  name_search = db.StringProperty(required = True)
  pw_hash = db.StringProperty(required = True)
  year = db.IntegerProperty(required = True)
  admin_user = db.ReferenceProperty(User)
  users = db.ListProperty(int, required = True)
  paid = db.ListProperty(int, required = True)
  points = db.ListProperty(float, required = True)
  bonus = db.StringProperty()

  @property
  def id(self):
    return self.key().id()

  @classmethod
  def submit(cls, name, pw, points, bonus, user):
    name = name.strip()
    pw_hash = make_pw_hash(pw, name)
    p = Pool(parent = pools_key(),
              name = name,
              name_search = name.upper(),
              pw_hash = pw_hash,
              points = points,
              bonus = bonus,
              admin_user = user,
              users = [user.id],
              paid = [],
              year = datetime.now().year)
    p.put()
    return p

  @classmethod
  def by_name(cls, name, year = datetime.now().year):
    p = Pool.all().filter('name_search =', name.strip().upper()).filter('year =', year).ancestor(pools_key()).get()
    return p

  @classmethod
  def by_year(cls, year):
    return Pool.all().filter('year =', year).ancestor(pools_key()).run(batch_size=1000)

  @classmethod
  def by_id(cls, pid):
    return Pool.get_by_id(pid, parent = pools_key())

  def remove_entries(self, user_id):
    for e in Entry.all().filter('user =', db.Key.from_path('User', user_id, parent = users_key())).filter('pools =', self.id).run(batch_size=1000):
      e.pools.remove(self.id)
      e.put()

# ####PoolSetting####
# def poolsetting_key(group = 'default'):
#   return db.Key.from_path('poolsetting', group)

# class PoolSetting(db.Model):
#   type = db.StringProperty(required = True)
#   value = db.StringProperty(required = True)
#   description = db.StringProperty()
#   notes = db.StringProperty()
#   order = db.IntegerProperty()

#   @property
#   def id(self):
#     return self.key().id()

#   @classmethod
#   def by_type(cls, type):
#     ps = PoolSetting.all().filter('type =', type).order("order").ancestor(poolsetting_key()).run(batch_size=1000)
#     return ps

###Game###
def games_key(group = 'default'):
  return db.Key.from_path('games', group)

class Game(db.Model):
  game_id = db.IntegerProperty(required = True)
  year = db.IntegerProperty(required = True)
  game_day = db.IntegerProperty()
  team_1 = db.ReferenceProperty(Team, collection_name = 'game_set_1')
  team_1_potentials = db.ListProperty(int)
  team_1_lowest_potential_seed = db.IntegerProperty()
  team_2 = db.ReferenceProperty(Team, collection_name = 'game_set_2')
  team_2_potentials = db.ListProperty(int)
  team_2_lowest_potential_seed = db.IntegerProperty()
  winning_team = db.IntegerProperty()
  losing_team = db.IntegerProperty()
  next_game = db.IntegerProperty()

  @classmethod
  def submit(cls, game_id, team_1, team_2, next_game = None, year = datetime.now().year):
    game = Game(game_id = game_id, team_1 = team_1, team_2 = team_2, next_game = next_game, year = year, parent = games_key())
    game.put()

  @classmethod
  def by_game_id(cls, game_id, year = datetime.now().year):
    return Game.all().filter("game_id =", game_id).filter("year =", year).ancestor(games_key()).get()

  @classmethod
  def by_year(cls, year):
    return Game.all().filter('year = ', year).ancestor(games_key()).order('game_id').fetch(limit=63)

  @classmethod
  def get_current(cls):
    return cls.by_year(datetime.now().year)

  @classmethod
  def create_games(cls, year):
    ##Delete old games
    old_games = Game.by_year(year)
    db.delete(old_games)

    teams = sorted(Team.by_year(year), key=attrgetter('bracket_position'))

    ##Create first round games
    i = 0
    game_id = 1
    while i + 1 < len(teams):
      Game.submit(game_id, teams[i], teams[i + 1], int(round(game_id/2.0)) + 32)
      game_id += 1
      i += 2

    ##Create remaining games
    while game_id < len(teams):
      if game_id == len(teams) - 1:
        Game.submit(game_id, None, None, None)
      else:
        Game.submit(game_id, None, None, int(round(game_id/2.0)) + 32)
      game_id += 1

    Game.update_games()

  @classmethod
  def update_games(cls):
    games = Game.get_current()
    all_teams = Team.get_teams_dict()
    game_id = 32
    master = Entry.get_master()
    eliminated_teams = []

    ## For each game, update the results/potentials for the next game
    for i, game in enumerate(games):
      winning_team = None
      if master:
        master_pick = master.picks[i]
        if master_pick != -1:
          winning_team = all_teams[master_pick]
          game.winning_team = winning_team.id
          if winning_team.id == game.team_1.id:
            game.losing_team = game.team_2.id
            eliminated_teams.append(game.team_2.id)
          else:
            game.losing_team = game.team_1.id
            eliminated_teams.append(game.team_1.id)
        else:
          game.winning_team = None
          game.losing_team = None

      game.put()
      
      if game.next_game:
        potentials = []
        lowest_potential_seed = None
        ## If a winner has been picked, that team moves on. Otherwise aggregate the potential teams.
        if not winning_team:
          if game.team_1 != None:
            potentials.append(game.team_1.id)
            lowest_potential_seed = game.team_1.seed
          else:
            potentials.extend(game.team_1_potentials)
            lowest_potential_seed = game.team_1_lowest_potential_seed

          if game.team_2 != None:
            potentials.append(game.team_2.id)
            lowest_potential_seed = min(lowest_potential_seed, game.team_2.seed)
          else:
            potentials.extend(game.team_2_potentials)
            lowest_potential_seed = min(lowest_potential_seed, game.team_2_lowest_potential_seed)

        ## Update Team 1 in the next game if even game otherwise update Team 2
        next_game = games[game.next_game - 1]
        if i % 2 == 0:
          next_game.team_1 = winning_team
          next_game.team_1_potentials = potentials
          next_game.team_1_lowest_potential_seed = lowest_potential_seed
        else:
          next_game.team_2 = winning_team
          next_game.team_2_potentials = potentials
          next_game.team_2_lowest_potential_seed = lowest_potential_seed

    ## Update teams with whether or not they have been eliminated
    for team in all_teams.values():
      if team.id in eliminated_teams:
        team.eliminated = True
      else:
        team.eliminated = False
      team.put()

####GameDay####
def gameday_key(group = 'default'):
  return db.Key.from_path('gamedays', group)

class GameDay(db.Model):
  date = db.DateTimeProperty()
  name = db.StringProperty()

####Entry####
def entries_key(group = 'default'):
  return db.Key.from_path('entries', group)

class Entry(db.Model):
  name = db.StringProperty(required = True)
  name_search = db.StringProperty(required = True)
  picks = db.ListProperty(int, required = True)
  losers = db.ListProperty(int, required = True)
  final_score = db.IntegerProperty(required = True)
  user = db.ReferenceProperty(User)
  pools = db.ListProperty(int)
  year = db.IntegerProperty(required = True)

  @property
  def id(self):
    return self.key().id()

  @classmethod
  def submit(cls, name, picks, losers, final_score, user, pool_id):
    e = Entry(parent = entries_key(),
              name = name.strip(),
              name_search = name.strip().upper(),
              picks = picks,
              losers = losers,
              final_score = final_score,
              year = datetime.now().year)
    if user:
      e.user = user
    if pool_id:
      e.pools = [pool_id]
    else:
      e.pools = []
    e.put()
    if pool_id:
      Standings.add_new(e.id, pool_id)
      ##Put a task on the queue to calc standings so we can return to user quickly
      deferred.defer(calculate_standings)
    return e

  def update(self, picks, losers, final_score):
    self.picks = picks
    self.losers = losers
    self.final_score = final_score
    self.put()
    ##Put a task on the queue to calc standings so we can return to user quickly
    deferred.defer(calculate_standings)

  @classmethod
  def by_id(cls, eid):
    return Entry.get_by_id(eid, parent = entries_key())

  @classmethod
  def by_name(cls, name, year = datetime.now().year):
    return Entry.all().filter('name_search =', name.strip().upper()).filter('year =', year).ancestor(entries_key()).get()

  @classmethod
  def get_master(cls):
    return cls.by_name('Master Bracket')

  @classmethod
  def by_pool(cls, pool_id):
    return Entry.all().filter("pools =", pool_id).ancestor(entries_key()).run(batch_size=1000)

  @classmethod
  def by_year(cls, year):
    return Entry.all().filter('year =', year).ancestor(entries_key()).run(batch_size=1000)

####Standings####
def standings_key(group = 'default'):
  return db.Key.from_path('standings', group)

class Standings(db.Model):
  round = db.IntegerProperty(required = True)
  day = db.IntegerProperty()
  entry_id = db.IntegerProperty(required = True)
  pool_id = db.IntegerProperty(required = True)
  points = db.ListProperty(float, required = True)
  total = db.FloatProperty()
  rank = db.IntegerProperty()
  prev_rank = db.IntegerProperty()
  change_rank = db.IntegerProperty()
  max_score = db.FloatProperty()
  max_score_rank = db.IntegerProperty()
  year = db.IntegerProperty(required = True)

  @classmethod
  def add_new(cls, entry_id, pool_id):
    s = Standings(parent = standings_key(),
                round = 0,
                entry_id = entry_id, 
                pool_id = pool_id,
                points = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
                year = datetime.now().year)
    s.put()
    return s

  def reset(self):
    self.points = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

  @classmethod
  def get(cls, entry_id, pool_id):
    return Standings.all().filter('entry_id =', entry_id).filter('pool_id =', pool_id).ancestor(standings_key()).get()

  @classmethod
  def by_year(cls, year):
    return Standings.all().filter('year =', year).ancestor(standings_key()).run(batch_size = 1000)

  @classmethod
  def current(cls):
    return cls.by_year(datetime.now().year)

  @classmethod
  def by_entry(cls, entry_id):
    return Standings.all().filter('entry_id =', entry_id).ancestor(standings_key()).run(batch_size=1000)

  @classmethod
  def by_pool(cls, pool_id):
    standings = dict()
    for s in Standings.all().filter('pool_id =', pool_id).ancestor(standings_key()).run(batch_size=1000):
      standings[s.entry_id] = s
    return standings

####Admin####
def admins_key(group = 'default'):
  return db.Key.from_path('admins', group)

class Admin(db.Model):
  year = db.IntegerProperty(required = True)
  lock_date = db.DateTimeProperty(required = True)
  regions = db.ListProperty(str)

  @classmethod
  def submit(cls, lock_date):
    year = datetime.now().year
    a = Admin.all().filter('year =', year).get()
    if not a:
      a = Admin(year = year,
                lock_date = lock_date)
    else:
      a.lock_date = lock_date
    a.put()
    return a

  @classmethod
  def get_current(cls):
    a = Admin.all().filter('year =', datetime.now().year).get()
    return a;

  @classmethod
  def update_regions(cls, regions):
    a = cls.get_current()
    a.regions = regions
    a.put();

class Front(BaseHandler):
  def get(self):
    self.render('front.html')

USER_RE = re.compile(r"^.{3,20}$")
USERNAME_ERROR = "3 to 20 characters"
def valid_username(username):
  return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
PASSWORD_ERROR = "3 to 20 characters"
def valid_password(password):
  return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
  return not email or EMAIL_RE.match(email)

class Signup(BaseHandler):
  def get(self):
    return_url = self.request.get('return-url')
    if return_url:
      return_url = '?return-url=' + return_url
    self.render("signup-form.html", return_url = return_url)

  def post(self):
    have_error = False
    username = self.request.get('username')
    password = self.request.get('password')
    verify = self.request.get('verify')
    email = self.request.get('email')

    params = dict(username = username, email = email)

    if not valid_username(username):
      params['message_username'] = USERNAME_ERROR
      params['status_username'] = "error"
      have_error = True

    if not valid_password(password):
      params['message_password'] = PASSWORD_ERROR
      params['status_password'] = "error"
      have_error = True
    elif password != verify:
      params['message_verify'] = "Your passwords didn't match."
      params['status_verify'] = "error"
      have_error = True

    if not valid_email(email):
      params['message_email'] = "That's not a valid email."
      params['status_email'] = "error"
      have_error = True

    if have_error:
      self.render('signup-form.html', **params)
    else:
      user = User.by_name(username)
      if not user:
        u = User.register(username, password, email)
        self.login(u)
        return_url = self.request.get('return-url')
        if return_url:
          self.redirect(return_url)
        else:
          self.redirect('/')
      else:   
        params['message_username'] = "That username is taken"
        params['status_username'] = "info"
        self.render('signup-form.html', **params)

class Login(BaseHandler):
  def get(self):
    params = dict()
    return_url = self.request.get('return-url')
    if return_url:
      return_url = '?return-url=' + return_url
      params['return_url'] = return_url

    if self.request.get('password_reset') == "true":
      params['flash_message_info'] = "You will receive an email with instructions about how to reset your password in a few minutes."

    self.render('login-form.html', **params)

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')

    u = User.login(username, password)
    if u:
      self.login(u)
      return_url = self.request.get('return-url')
      if return_url:
        self.redirect(return_url)
      else:
        self.redirect('/')
    else:
      params = dict(username = username, error_login = 'Invalid login')
      self.render('login-form.html', **params)

class Logout(BaseHandler):
  def get(self):
    self.logout()
    self.redirect('/login')

POOL_RE = re.compile(r"^.{1,50}$")
def valid_poolname(name):
    return name and POOL_RE.match(name)

class NewPool(BaseHandler):
  def get(self):
    if not self.user:
      self.require_login()
      return;

    params = dict()
    for i in range(1, 7):
      params['pts_' + str(i)] = int(math.pow(2, i))

    self.render('pool-form.html', **params)

  def post(self):
    if not self.user:
      self.redirect('/')
      return;

    have_error = False
    name = self.request.get('name')
    password = self.request.get('password')
    verify = self.request.get('verify')
    points = []
    bonus = self.request.get('bonus')

    params = dict(name = name)

    if not name:
      params['message_name'] = "Please enter a name"
      params['status_name'] = "error"
      have_error = True
    elif not valid_poolname(name):
      params['message_name'] = "Max 50 characters."
      params['status_name'] = "error"
      have_error = True

    if not valid_password(password):
      params['message_password'] = PASSWORD_ERROR
      params['status_password'] = "error"
      have_error = True
    elif password != verify:
      params['message_verify'] = "Your passwords didn't match"
      params['status_password'] = "error"
      params['status_verify'] = "error"
      have_error = True

    for i in range(1, 7):
      point = self.request.get('pts_' + str(i))
      params['pts_' + str(i)] = point
      try:
        pt = float(point)
        if pt > 0:
          points.append(pt)
        else:
          params['error_points'] = "All point values must be valid, positive numbers"
          have_error = True
      except ValueError:
        params['error_points'] = "All point values must be valid, positive numbers"
        have_error = True

    if not have_error:
      pool = Pool.by_name(name)
      if not pool:
        pool = Pool.submit(name, password, points, bonus, self.user)
      else: 
        params['message_name'] = "That Pool name is already in use"
        params['status_name'] = "info"
        have_error = True

    if have_error:
      self.render('pool-form.html', **params)
    else:
      self.redirect('/pools/' + str(pool.id))

class AllPools(BaseHandler):
  def get(self):
    if not self.user:
      self.require_login()
      return

    pools = Pool.all().filter('year =', datetime.now().year).order("name").ancestor(pools_key()).run(batch_size=1000)
    self.render('all-pools.html', pools = pools)

class PoolPage(BaseHandler):
  def get(self, pool_id):
    if not self.user:
      self.require_login()
      return
      
    pool = Pool.by_id(int(pool_id))
    if not pool:
      self.error(404)
    else:
      if self.user.id in pool.users or self.user.admin:
        entries = []
        all_standings = Standings.by_pool(pool.id)
        for e in Entry.by_pool(pool.id):
          if e.id in all_standings:
            e.standings = all_standings[e.id]
          else:
            e.standings = Standings.add_new(e.id, pool.id)    
          entries.append(e)
        entries.sort(key=attrgetter('name'))
        entries.sort(key=attrgetter('standings.max_score_rank'))
        entries.sort(key=attrgetter('standings.rank'))
        for e in entries:
          e.own = self.user.id == e.user.id
        params = dict()
        params['pool'] = pool
        params['entries'] = entries
        self.render('pool.html', **params)
      else:
        self.render('pool-join.html', pool = pool)

  def post(self, pool_id):
    if not self.user:
      self.redirect('/')
      return

    pool = Pool.by_id(int(pool_id))
    if self.user.id in pool.users:
      self.redirect('/pools/' + pool_id)
    else:
      password = self.request.get('password')
      if valid_pw(pool.name, password, pool.pw_hash):
        pool.users.append(self.user.id)
        pool.put()
        self.redirect('/pools/' + pool_id)
      else:
        self.render('pool-join.html', error_login = 'That password is incorrect', pool = pool)

class PoolAdmin(BaseHandler):
  def get(self, pool_id):
    pool = Pool.by_id(int(pool_id))
    if not pool:
      self.error(404)
    else:
      if not self.user:
        self.require_login()
      elif self.user.id != pool.admin_user.id:
        self.render('access-denied.html')
      else:
        entries = dict()
        for e in Entry.by_pool(pool.id):
          if e.user.id in entries:
            entries[e.user.id].append(e)
          else:
            entries[e.user.id] = [e]
        users = []
        for u in User.by_id(pool.users):
          u.admin = u.id == self.user.id
          u.paid = u.id in pool.paid
          if u.id in entries:
            u.brackets = entries[u.id]
          users.append(u)
        users.sort(key=attrgetter('name'))
        users.sort(key=attrgetter('admin'), reverse=True)
        params = dict()
        params['pool'] = pool
        params['users'] = users

        self.render('pool-admin.html', **params)

  def post(self, pool_id):
    pool = Pool.by_id(int(pool_id))
    if not pool:
      self.redirect('/pools/all')
    else:
      if not self.user or self.user.id != pool.admin_user.id:
        self.redirect('/')
      else:
        removed = []
        pool.paid = []
        for user_id in pool.users:
          remove = self.request.get('remove_' + str(user_id))
          if remove:
            pool.remove_entries(user_id)
            removed.append(user_id)
          else:
            paid = self.request.get('paid_' + str(user_id))
            if paid:
              pool.paid.append(user_id)

        msg = mail.EmailMessage(sender="Accounts <accounts@notabasketballpool.appspotmail.com>",
                                subject="Removed from pool",
                                html=render_str('removed-email.html', pool=pool, url=self.base_url + '/mypools'))
        for user_id in removed:
          pool.users.remove(user_id)
          u = User.by_id(user_id)
          if u and u.email:
            msg.to = u.email
            msg.send()
        pool.put()

        self.add_flash('Changes were saved successfully.', 'success')
        self.redirect(self.request.path)

class PoolExportPicks(BaseHandler):
  def get(self, pool_id):
    pool = Pool.by_id(int(pool_id))
    if not pool:
      self.error(404)
    else:
      if not self.user:
        self.require_login()
      elif self.user.id != pool.admin_user.id:
        self.render('access-denied.html')
      else:
        teams = Team.get_teams_dict()
        self.response.headers['Content-Type'] = 'text/csv'
        self.response.headers['Content-Disposition'] = "attachment; filename=Exported Picks for {0}.csv".format(pool.name)
        self.write('Bracket Name,User Name,R32-1,R32-2,R32-3,R32-4,R32-5,R32-6,R32-7,R32-8,R32-9,R32-10,R32-11,R32-12,R32-13,R32-14,R32-15,R32-16,R32-17,R32-18,R32-19,R32-20,R32-21,R32-22,R32-23,R32-24,R32-25,R32-26,R32-27,R32-28,R32-29,R32-30,R32-31,R32-32,SS1,SS2,SS3,SS4,SS5,SS6,SS7,SS8,SS9,SS10,SS11,SS12,SS13,SS14,SS15,SS16,EE1,EE2,EE3,EE4,EE5,EE6,EE7,EE8,FinalFour1,FinalFour2,FinalFour3,FinalFour4,Finalist1,Finalist2,Champ')
        for e in Entry.by_pool(pool.id):
          picks = []
          for p in e.picks:
            team = teams[p]
            picks.append('{0} {1}'.format(team.seed, team.name))
          self.write('\r\n' + ','.join([e.name, e.user.name] + picks))

class PoolMasterBracket(BaseHandler):
  def get(self, pool_id):
    if not self.user:
      self.require_login()
      return

    pool = Pool.by_id(int(pool_id))
    if not pool:
      self.error(404)
      return

    if self.user.id not in pool.users or not self.locked:
      self.render('access-denied.html')
      return

    all_teams = Team.get_teams_dict()
    teams = [] 
    for team in sorted(all_teams.values(), key=attrgetter('bracket_position')):
      teams.append(str(team.seed) + ' ' + team.name)

    master = Entry.get_master()
    if master: 
      for p in master.picks:
        if p != -1:
          team = all_teams[p]
          teams.append(str(team.seed) + ' ' + team.name)
        else:
          teams.append('')

    a = Admin.get_current()
    self.render('pool-master.html', pool = pool, teams = teams, regions = a.regions)

def calculate_standings():
  master = Entry.get_master()
  if not master:
    return

  standings = dict()
  for s in Standings.current():
    if s.pool_id in standings:
      standings[s.pool_id][s.entry_id] = s
    else:
      standings[s.pool_id] = {s.entry_id: s}

  entries = dict()
  for e in Entry.by_year(datetime.now().year):
    for p in e.pools:
      if p in entries:
        entries[p].append(e)
      else:
        entries[p] = [e]

  games = Game.get_current()
  teams = Team.get_teams_dict()

  for pool in Pool.by_year(datetime.now().year):
    if pool.id in entries:
      for entry in entries[pool.id]:
        potential_points = 0
        standing = standings[pool.id][entry.id]
        standing.reset()
        for i, game in enumerate(games):
          ## If the game has been played, calculate actual points. Otherwise, calculate potential points
          if game.winning_team:
            if entry.picks[i] == game.winning_team:
              ## Calculate bonus
              bonus = 0
              if pool.bonus != 'none':
                winner = teams[game.winning_team]
                loser = teams[game.losing_team]
                if pool.bonus == 'upset':
                  bonus = max(0, winner.seed - loser.seed)
                elif pool.bonus == 'seed':
                  bonus = winner.seed
              ## Calculate round
              if i < 32:
                standing.points[0] += pool.points[0] + bonus
              elif i < 48:
                standing.points[1] += pool.points[1] + bonus
              elif i < 56:
                standing.points[2] += pool.points[2] + bonus
              elif i < 60:
                standing.points[3] += pool.points[3] + bonus
              elif i < 62:
                standing.points[4] += pool.points[4] + bonus
              else:
                standing.points[5] += pool.points[5] + bonus
          else:
            picked_winner = teams[entry.picks[i]]
            ## If the chosen winner is still alive, add the appropiate points plus any possible bonus
            if not picked_winner.eliminated:
              ## Calculate bonus
              bonus = 0
              if pool.bonus != 'none':
                if pool.bonus == 'upset':
                  picked_loser = teams[entry.losers[i]]
                  if not picked_loser.eliminated:
                    bonus = max(0, picked_winner.seed - picked_loser.seed)
                  else:
                    if picked_winner.id in game.team_1_potentials or (game.team_1 and picked_winner.id == game.team_1.id):
                      if game.team_2:
                        lowest_potential_seed = game.team_2.seed
                      else:
                        lowest_potential_seed = game.team_2_lowest_potential_seed
                    else:
                      if game.team_1:
                        lowest_potential_seed = game.team_1.seed
                      else:
                        lowest_potential_seed = game.team_1_lowest_potential_seed
                    bonus = max(0, picked_winner.seed - lowest_potential_seed)
                elif pool.bonus == 'seed':
                  bonus = picked_winner.seed
              ## Calculate round
              if i < 32:
                potential_points += pool.points[0] + bonus
              elif i < 48:
                potential_points += pool.points[1] + bonus
              elif i < 56:
                potential_points += pool.points[2] + bonus
              elif i < 60:
                potential_points += pool.points[3] + bonus
              elif i < 62:
                potential_points += pool.points[4] + bonus
              else:
                potential_points += pool.points[5] + bonus
        standing.total = math.fsum(filter(None, standing.points))
        standing.max_score = standing.total + potential_points
    ## Calculate rankings
    if pool.id in standings:
      rank_tie = 1
      last_score = None
      for i, standing in enumerate(sorted(standings[pool.id].values(), key=attrgetter('total'), reverse=True), start=1):
        if standing.total == last_score:
          standing.rank = rank_tie
        else:
          standing.rank = rank_tie = i
        last_score = standing.total

      rank_tie = 1
      last_score = None
      for i, standing in enumerate(sorted(standings[pool.id].values(), key=attrgetter('max_score'), reverse=True), start=1):
        if standing.max_score == last_score:
          standing.max_score_rank = rank_tie
        else:
          standing.max_score_rank = rank_tie = i
        last_score = standing.max_score
        standing.put()

class BracketEntry(BaseHandler):
  def get(self, entry_id):
    if not self.user:
      self.require_login()
      return

    if entry_id == 'master' and not self.user.admin:
      self.render('access-denied.html')
      return

    params = dict()
    winners = []
    css_winners = []
    a = Admin.get_current()
    params['regions'] = a.regions
    if entry_id == 'new':
      pool_id = self.request.get('p')
      if pool_id:
        try:
          pool = Pool.by_id(int(pool_id))
        except ValueError:
          pool = None
        if not pool or not self.user.id in pool.users:
          self.error(404)
          return
      params['pool_id'] = pool_id
      teams = Team.get_teams_dict()
      params['final_score'] = 0
    elif entry_id == 'master':
      teams = Team.get_teams_dict()
      params['name'] = 'Master Bracket'
      params['master'] = True
      params['locked'] = False
      entry = Entry.get_master()
      if entry: 
        for p in entry.picks:
          if p != -1:
            team = teams[p]
            winners.append(str(team.seed) + ' ' + team.name)
          else:
            winners.append('')
        params['final_score'] = entry.final_score
    else:
      entry = Entry.by_id(int(entry_id))
      if entry:
        if not self.locked and self.user.id != entry.user.id and not self.user.admin:
          self.render('access-denied.html')
          return
        if self.locked:
          master = Entry.get_master()
          i = 0
          losers = []
        teams = Team.get_teams_dict(entry.year)
        master_pick = None
        for p in entry.picks:
          team = teams[p]
          winners.append(str(team.seed) + ' ' + team.name)
          if self.locked:
            if p in losers:
              css_winners.append('incorrect')
            else:
              master_pick = master.picks[i]
              if master_pick == -1:
                css_winners.append('')
              else:
                if p == master_pick:
                  css_winners.append('correct')
                else:
                  css_winners.append('incorrect')
                  losers.append(p)
            i += 1

        params['name'] = entry.name
        params['final_score'] = entry.final_score
      else:
        self.error(404)
        return

    params['teams'] = sorted(teams.values(), key=attrgetter('bracket_position'))
    params['winners'] = winners
    params['css_winners'] = css_winners

    self.render('bracketentry.html', **params)

  def post(self, entry_id):
    if not self.user:
      self.redirect('/')
      return

    if entry_id != 'master' and self.locked:
      self.error(404)
      return

    teams = dict()
    for team in Team.all().filter('year = ', datetime.now().year).fetch(limit=64):
      teams[team.name] = team

    try:
      final_score = int(self.request.get('final_score'))
    except ValueError:
      final_score = 0

    name = self.request.get('entry_name')
    games = Game.get_current()
    picks = []
    losers = []
    for i, game in enumerate(games):
      result = self.request.get('winner_' + str(i + 1))
      if result:
        winner = teams[result[result.find(' ') + 1:]]
        picks.append(winner.id)
        ## If both teams were set, figure out who was the loser
        if game.team_1 and game.team_2:
          if winner.id == game.team_1.id:
            losers.append(game.team_2.id)
          else:
            losers.append(game.team_1.id)
        else:
          losers.append(-1)
      else:
        winner = None
        picks.append(-1)
        losers.append(-1)
      ## Move on the winning team to the next round
      if game.next_game:
        next_game = games[game.next_game - 1]
        if i % 2 == 0:
          next_game.team_1 = winner
        else:
          next_game.team_2 = winner

    entry = None
    if entry_id == 'new':
      pool_id = None
      p_id = self.request.get('p')
      if p_id:
        try:  
          pool = Pool.by_id(int(p_id))
        except ValueError:
          pool = None
        if not pool or not self.user.id in pool.users:
          self.error(404)
          return
        else:
          pool_id = pool.id
      entry = Entry.submit(name, picks, losers, final_score, self.user, pool_id)
    elif entry_id == 'master':
      if self.user.admin:
        entry = Entry.get_master()
        if entry:
          entry.update(picks, losers, final_score)
        else:
          entry = Entry.submit('Master Bracket', picks, losers, final_score, None, None)
        regions = []
        for i in xrange(4):
          regions.append(self.request.get('region_' + str(i + 1)))
        Admin.update_regions(regions)
        Game.update_games()
        calculate_standings()
        self.add_flash('Master Bracket was saved successfully and standings were recalculated.', 'success')
        self.redirect('/brackets/master')
        return
    else:
      entry = Entry.by_id(int(entry_id))
      if entry and self.user.id == entry.user.id:
          entry.update(picks, losers, final_score)

    if entry:
      self.add_flash('Bracket was saved successfully.', 'success')
      self.redirect('/brackets/' + str(entry.id))

class BracketChoose(BaseHandler):
  def get(self):
    if not self.user:
      self.require_login()
      return

    pool_id = self.request.get('p')
    try:  
      pool = Pool.by_id(int(pool_id))
    except ValueError:
      pool = None

    if not pool or not self.user.id in pool.users:
      self.error(404)
    else:
      entries = []
      for e in self.user.get_entries():
        if not pool.id in e.pools:
          entries.append(e)
      if len(entries) > 0:
        params = dict()
        params['pool'] = pool
        params['entries'] = entries
        self.render('bracket-choose.html', **params)
      else:
        self.redirect('/brackets/new?p=' + str(pool.id))

  def post(self):
    if not self.user:
      self.redirect('/')
      return    

    pool_id = self.request.get('p')
    try:  
      pool = Pool.by_id(int(pool_id))
    except ValueError:
      pool = None

    if not pool or not self.user.id in pool.users:
      self.error(404)
    else:
      entries = self.request.get_all('entry')
      for e in entries:
        entry = Entry.by_id(int(e))
        if entry and pool.id not in entry.pools:
          entry.pools.append(pool.id)
          entry.put()
          Standings.add_new(entry.id, pool.id)
      self.redirect('/pools/' + str(pool.id))

class ManageTourney(BaseHandler):
  def get(self):
    if not self.user:
      self.require_login()
      return
  
    entries = self.user.get_entries()
    standings = dict()
    # for e in entries:
    #   entry_standings = Standings.by_entry(e.id)
    #   for s in entry_standings:
    #     if s.entry_id in standings:
    #       standings[s.entry_id][s.pool_id] = s
    #     else:
    #       standings[s.entry_id] = {s.pool_id: s}

    pools = dict()
    for p in self.user.get_pools():
      pools[p.id] = p
      
    params = dict()
    params['pools'] = pools 
    params['entries'] = entries
    params['standings'] = standings
    
    self.render('manage-tourney.html',  **params)

class MyBrackets(BaseHandler):
  def get(self):
    if not self.user:
      self.require_login()
      return

    entries = []
    pools = dict()
    for p in self.user.get_pools():
      pools[p.id] = p
    for e in self.user.get_entries():
      e.pool_items = []
      for p in e.pools:
        e.pool_items.append(pools[p])
      e.pool_items.sort(key=attrgetter('name'))
      entries.append(e)

    for e in entries:
      e.points = []
      for p in e.pool_items:
        e.points.append(Points.get(e.id, p.id))

    self.render('mybrackets.html', entries = entries)

class MyPools(BaseHandler):
  def get(self):
    if not self.user:
      self.require_login()
      return

    pools = []
    entries = dict() 
    for e in self.user.get_entries():
      for p in e.pools:
        if p in entries:
          entries[p].append(e)
        else:
          entries[p] = [e]
    for p in self.user.get_pools():
      if p.id in entries:
        p.entries = entries[p.id]
      pools.append(p)

    self.render('mypools.html', pools = pools)

class UploadTeams(BaseHandler):
  def get(self):
    if not self.user:
      self.require_login()
      return

    if not self.user.admin:
      self.render('access-denied.html')
      return

    self.render('upload-teams.html')

  def post(self):
    if not self.user or not self.user.admin:
      self.redirect('/')
      return

    year = int(self.request.get('year'))
    old_teams = Team.by_year(year)
    team_count = len(old_teams)

    teams = self.request.get('team_file')
    for i, row in enumerate(csv.reader(StringIO.StringIO(teams)), start=-1):
      if row[0] != 'Team':
        if i < team_count:
          team = old_teams[i]
          team.update(row[0], year, int(row[1]), int(row[2]))
        else:
          Team.submit(row[0], year, int(row[1]), int(row[2]))

    Game.create_games(year)

    self.redirect('/admin')

class AdminPage(BaseHandler):
  def get(self):
    if not self.user:
      self.require_login()
      return

    if not self.user.admin:
      self.render('access-denied.html')
      return

    params = dict()
    a = Admin.get_current()
    if a:
      params['lock_date'] = datetime.strftime(a.lock_date, '%m/%d/%Y')

    self.render('admin.html', **params)

  def post(self):
    if not self.user or not self.user.admin:
      self.redirect('/')
      return

    lock_date = datetime.strptime(self.request.get('lock_date'), '%m/%d/%Y')
    Admin.submit(lock_date)

    self.add_flash('Changes were saved successfully.', 'success')
    self.redirect('/admin')

class RecalcStandings(BaseHandler):
  def get(self):
    calculate_standings()
    self.add_flash('Standings have been recalculated.', 'success')
    self.redirect('/admin')

class ValidateEntry(BaseHandler):
  def get(self):
    name = self.request.get('entry_name')
    if name:
      e = Entry.by_name(name)
      if e:
        result = False
      else:
        result = True
      self.response.out.write(json.dumps(result))

def get_game_title(game_id):
  a = Admin.get_current()
  title = ''
  region = ''
  if game_id < 32:
    title = 'Round of 64'
    if game_id < 8:
      region = a.regions[0]
    elif game_id < 16:
      region = regions[1]
    elif game_id < 24:
      region = a.regions[2]
    else:
      region = a.regions[3]
  elif game_id < 48:
    title = 'Round of 32'
    if game_id < 36:
      region = a.regions[0]
    elif game_id < 40:
      region = a.regions[1]
    elif game_id < 44:
      region = a.regions[2]
    else:
      region = a.regions[3]
  elif game_id < 56:
    title = 'Sweet Sixteen'
    if game_id < 50:
      region = a.regions[0]
    elif game_id < 52:
      region = a.regions[1]
    elif game_id < 54:
      region = a.regions[2]
    else:
      region = a.regions[3]
  elif game_id < 60:
    title = 'Elite Eight'
    if game_id < 57:
      region = a.regions[0]
    elif game_id < 58:
      region = a.regions[1]
    elif game_id < 59:
      region = a.regions[2]
    else:
      region = a.regions[3]
  elif game_id < 62:
    title = 'Final Four'
  elif game_id == 62:
    title = 'National Championship'
  return title, region

class GameAnalysis(BaseHandler):
  def get(self, pool_id, game_id):
    if not self.user:
      self.require_login()
      return

    pool_id = int(pool_id)
    game_id = int(game_id) - 1

    pool = Pool.by_id(pool_id)
    if not pool or game_id < 0 or game_id > 62:
      self.error(404)
      return

    if self.user.id not in pool.users or not self.locked:
      self.render('access-denied.html')
      return
    
    all_teams = Team.get_teams_dict()
    total = 0
    teams = []
    entries = []
    points = Points.by_pool(pool_id)
    for e in Entry.by_pool(pool_id):
      team = all_teams[e.picks[game_id]]
      e.team = team
      e.points = points[e.id]
      e.own = self.user.id == e.user.id
      entries.append(e)
      if team in teams:
        team.picked += 1
      else:
        team.picked = 1
        teams.append(team)
      total += 1

    for t in teams:
      t.percent_picked = float(t.picked)/total
      t.percent_picked_display = '{:.{}%}'.format(t.percent_picked, int(t.percent_picked * 100 % 1 > 0))

    teams.sort(key=attrgetter('name'))
    teams.sort(key=attrgetter('percent_picked'), reverse=True)
    entries.sort(key=attrgetter('name'))

    params = dict()
    params['teams'] = teams
    params['entries'] = entries
    params['pool'] = pool
    game, region = get_game_title(game_id)
    params['game'] = game
    params['region'] = region

    self.render('game-analysis.html', **params)

class AccountSettings(BaseHandler):
  def get(self):
    if not self.user:
      self.require_login()
      return

    params = dict(username = self.user.name, email = self.user.email)
    self.render('account-settings.html', **params)

  def post(self):
    if not self.user:
      self.redirect('/')
      return

    if self.request.get('delete') == "true":
      self.user.delete_account()
      self.logout()
      self.redirect('/')
      return

    have_error = False

    username = self.request.get('username')
    password_new = self.request.get('password_new')
    verify_new = self.request.get('verify_new')
    email = self.request.get('email')

    params = dict(username = username, email = email)

    if not valid_username(username):
      params['message_username'] = USERNAME_ERROR
      params['status_username'] = "error"
      have_error = True

    if password_new:
      if not valid_password(password_new):
        params['message_password_new'] = PASSWORD_ERROR
        params['status_password_new'] = "error"
        have_error = True
      elif password_new != verify_new:
        params['message_verify_new'] = "Your passwords didn't match"
        params['status_password_new'] = "error"
        params['status_verify_new'] = "error"
        have_error = True

    if not valid_email(email):
      params['message_email'] = "That's not a valid email"
      params['status_email'] = "error"
      have_error = True

    if not have_error:
      password = self.request.get('password')
      if not valid_pw(self.user.name, password, self.user.pw_hash):
        params['message_password'] = "Incorrect password"
        params['status_password'] = "error"
        have_error = True
    
    if not have_error:
      name = username.strip()
      if name.upper() != self.user.name_search:
        user = User.by_name(name)
        if not user:
          self.user.name = name
          self.user.name_search = name.upper()
          self.user.pw_hash = make_pw_hash(password, name)
        else:
          params['message_username'] = "That username is taken"
          params['status_username'] = "info" 
          have_error = True

    if not have_error:
      self.user.email = email
      if password_new:
        self.user.pw_hash = make_pw_hash(password_new, self.user.name)

      self.user.put()
      self.add_flash('Your changes were saved successfully.', 'success')
      self.redirect('/settings')
    else:
      self.add_flash('Your changes were not saved.', 'error')
      self.render('account-settings.html', **params)

  def delete(self):
    self.write("deleted")    

class ResetPassword(BaseHandler):
  def get(self):
    self.render('reset-password.html', reset_token=self.request.get('token'))

  def post(self):
    reset_token = self.request.get('reset_token')
    params = dict()
    params['reset_token'] = reset_token

    have_error = False
    password = self.request.get('password')
    verify = self.request.get('verify')
    if not valid_password(password):
      params['message_password'] = PASSWORD_ERROR
      params['status_password'] = "error"
      have_error = True
    elif password != verify:
      params['message_verify'] = "Your passwords didn't match."
      params['status_password'] = "error"
      params['status_verify'] = "error"
      have_error = True

    if not have_error:
      have_error = True
      params['error_reset'] = 'Reset password token is invalid.'
      if reset_token:
        u = look_for_token(reset_token)
        if u:
          if datetime.now() > u.reset_expiration:
            params['error_reset'] = 'Reset password token has expired.'
          else:
            have_error = False
            u.pw_hash = make_pw_hash(password, u.name)
            self.login(u)
          u.reset_token = None
          u.reset_expiration = None
          u.put()     

    if have_error:
      self.render('reset-password.html', **params)
    else:
      self.redirect('/settings')

class ForgotPassword(BaseHandler):
  def get(self):
    self.render('forgot-password.html')

  def post(self):
    have_error = False
    username = self.request.get('username')
    if not username:
      have_error = True
      error_username = 'Please provide Username'

    u = User.by_name(username)
    if not u:
      have_error = True
      error_username = "That username doesn't exist"
    else:
      if not u.email:
        have_error = True
        error_username = "There is no email associated with this account! Password can't be reset."

    if have_error:
      self.render('forgot-password.html', error_username = error_username)
    else:
      token = u.prepare_reset_token()
      url = "%s/settings/password/reset?token=%s" % (self.base_url, token)
      msg = mail.EmailMessage(sender="Accounts <accounts@notabasketballpool.appspotmail.com>",
              to=u.email,
              subject="Password reset instructions",
              html=render_str('reset-email.html', url=url))
      msg.send()
      self.redirect('/login?password_reset=true')

class UserSimilarity(BaseHandler):
	def get(self, pool_id):
		if not self.user:
			self.require_login()
			return
		
		pool_id = int(pool_id)
		pool = Pool.by_id(pool_id)
		entries = Entry.by_pool(pool_id)
		gameMatches = 0  #initialize variable to track matches with other users
		
		if not pool:
			self.error(404)
		else:
			if self.user.id in pool.users:
				sameGamePicks = {} # this stores the dictionary of game similarities
				bracketnames = {}  # this will store the bracket entry names
				for e1 in entries:
					sameGamePicks[e1.id] = {}
					bracketnames[e1.id] = e1.name
					for e2 in Entry.by_pool(pool_id):
						for game in range(63):
							if (e1.picks[game] == e2.picks[game]):
								gameMatches += 1
						sameGamePicks[e1.id][e2.id] = gameMatches
						gameMatches = 0
#				self.write(str(sameGamePicks)+ '<br>')   this was for testing the output to the browser
		
		params = dict()
		params['pool'] = pool
		params['gamePicks'] = sameGamePicks
		params['bracketnames'] = bracketnames
		self.render('usersimilarity.html', **params)
		
class FAQ(BaseHandler):
  def get(self):
    self.render('FAQ.html')
		
###POOL SETTINGS CHANGES FROM BRIAN
class PoolSettings(BaseHandler):
  def get(self, pool_id):
    pooltoedit = Pool.by_id(int(pool_id))

    if not pooltoedit:
      self.error(404)
    else:
      if not self.user:
        self.require_login()
      elif self.user.id != pooltoedit.admin_user.id:
        self.render('access-denied.html')
      else:
        params = dict(username = self.user.name, poolname = pooltoedit.name, pool_id=pooltoedit.id)
        self.render('pool-settings.html', **params)

  def post(self, pool_id):
    if not self.user:
      self.redirect('/')
      return

    have_error = False

    username = self.user.name
    pooltoedit = Pool.by_id(int(pool_id))
    pooltoeditname = pooltoedit.name
    pooltoeditID = pooltoedit.id
    password_new = self.request.get('password_new')
    verify_new = self.request.get('verify_new')

    params = dict(pooltoedit = pooltoedit, username = username)

    if password_new:
      if not valid_password(password_new):
        params['message_password_new'] = PASSWORD_ERROR
        params['status_password_new'] = "error"
        have_error = True
      elif password_new != verify_new:
        params['message_verify_new'] = "Your passwords didn't match"
        params['status_password_new'] = "error"
        params['status_verify_new'] = "error"
        have_error = True

    if not have_error:
      pooltoedit.pw_hash = make_pw_hash(password_new, pooltoedit.name)
      #self.redirect('/pools/99/PoolSettings')

      pooltoedit.put()
      self.add_flash('Your changes were saved successfully.', 'success')
      self.redirect('/pools/all')
    else:
      self.add_flash('Your changes were not saved.', 'error')
      self.render('pool-settings.html', **params)

config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'mavlkjhasehffcsasldfkj',
}

app = webapp2.WSGIApplication([('/', Front),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/brackets/(new|master|[0-9]+)', BracketEntry),
                               ('/brackets/choose', BracketChoose),
                               ('/pools/new', NewPool),
                               ('/pools/all', AllPools),
                               ('/pools/([0-9]+)', PoolPage),
                               ('/pools/([0-9]+)/usersimilarity', UserSimilarity), #User Similarity Page per Pool
                               ('/pools/([0-9]+)/admin', PoolAdmin),
                               ('/pools/([0-9]+)/admin/PoolSettings', PoolSettings),
                               ('/pools/([0-9]+)/admin/export-picks', PoolExportPicks),
                               ('/pools/([0-9]+)/master', PoolMasterBracket),
                               ('/pools/([0-9]+)/master/([0-9]+)', GameAnalysis),
                               ('/mybrackets', MyBrackets),
                               ('/mypools', MyPools),
                               ('/admin', AdminPage),
                               ('/admin/teams/upload', UploadTeams),
                               ('/admin/recalc-standings', RecalcStandings),
                               ('/settings', AccountSettings),
                               ('/settings/password/forgot', ForgotPassword),
                               ('/settings/password/reset', ResetPassword),
                               ('/validate/entry', ValidateEntry),
                               ('/manage', ManageTourney),
                               ('/FAQ', FAQ)],
                              debug=True, config=config)