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
import StringIO
from datetime import datetime
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
  t = jinja_env.get_template(template)
  return t.render(params)

secret = 'bball'
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
      
  def initialize(self, *a, **kw):
    webapp2.RequestHandler.initialize(self, *a, **kw)
    uid = self.read_secure_cookie('user_id')
    self.user = uid and User.by_id(int(uid))

####User####
def make_salt(length = 5):
  return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
  if not salt:
      salt = make_salt()
  h = hashlib.sha256(name + pw + salt).hexdigest()
  return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
  salt = h.split(',')[0]
  return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
  return db.Key.from_path('users', group)

class User(db.Model):
  name = db.StringProperty(required = True)
  pw_hash = db.StringProperty(required = True)
  email = db.StringProperty()
  admin = db.BooleanProperty(required = True)

  @property
  def id(self):
    return self.key().id()

  @classmethod
  def by_id(cls, uid):
    return User.get_by_id(uid, parent = users_key())

  @classmethod
  def by_name(cls, name):
    u = User.all().filter('name =', name).ancestor(users_key()).get()
    return u

  @classmethod
  def register(cls, name, pw, email = None):
    pw_hash = make_pw_hash(name, pw)
    u = User(parent = users_key(),
                name = name,
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

####Team####
def teams_key(group = 'default'):
  return db.Key.from_path('teams', group)

class Team(db.Model):
  name = db.StringProperty(required = True)
  year = db.IntegerProperty(required = True)
  seed = db.IntegerProperty(required = True)
  bracket_position = db.IntegerProperty(required = True)

  @classmethod
  def submit(cls, name, year, seed, bracket_position):
    t = Team(parent = pools_key(),
              year = datetime.now().year,
              name = name,
              seed = seed,
              bracket_position = bracket_position)
    t.put()
    return t

####Pool####
def pools_key(group = 'default'):
  return db.Key.from_path('pools', group)

class Pool(db.Model):
  name = db.StringProperty(required = True)
  pw_hash = db.StringProperty(required = True)
  year = db.IntegerProperty(required = True)
  admin_user = db.ReferenceProperty(User, required = True)
  users = db.ListProperty(int, required = True)

  @classmethod
  def submit(cls, name, pw, user):
    pw_hash = make_pw_hash(name, pw)
    p = Pool(parent = pools_key(),
              name = name,
              pw_hash = pw_hash,
              admin_user = user,
              users = [user.id],
              year = datetime.now().year)
    p.put()
    return p

  @classmethod
  def by_name(cls, name):
    p = Pool.all().filter('name =', name).ancestor(pools_key()).get()
    return p

  @classmethod
  def by_id(cls, pid):
    return Pool.get_by_id(pid, parent = pools_key())

####Entry####
def entries_key(group = 'default'):
  return db.Key.from_path('entries', group)

class Entry(db.Model):
  name = db.StringProperty(required = True)
  final_score = db.IntegerProperty(required = True)
  user = db.ReferenceProperty(User, required = True)
  pool = db.ReferenceProperty(Pool, required = True)
  year = db.IntegerProperty(required = True)

  @classmethod
  def submit(cls, name, picks, final_score, user, pool):
    e = Entry(parent = entries_key(),
              name = name,
              final_score = final_score,
              user = user,
              pool = pool,
              year = datetime.now().year)
    e.put()

    i = 1
    for p in picks:
      Pick.submit(i, p, e)
      i += 1

    return e

  @classmethod
  def by_id(cls, eid):
    return Entry.get_by_id(eid, parent = entries_key())

  def update(self, name, picks, final_score):
    self.name = name
    self.final_score = final_score
    self.put()

    pick_keys = Pick.all(keys_only=True).filter('entry =', self).run(limit=63)
    for pk in pick_keys:
      db.delete(pk)

    i = 1
    for p in picks:
      Pick.submit(i, p, self)
      i += 1

####Pick####
def picks_key(group = 'default'):
  return db.Key.from_path('picks', group)

class Pick(db.Model):
  game = db.IntegerProperty(required = True)
  team = db.StringProperty(required = True)
  entry = db.ReferenceProperty(Entry, required = True)

  @classmethod
  def submit(cls, game, team, entry):
    p = Pick(parent = picks_key(),
              game = game,
              team = team,
              entry = entry)
    p.put()
    return p

class Front(BaseHandler):
  def get(self):
    self.render('front.html')

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BaseHandler):
  def get(self):
      self.render("signup-form.html")

  def post(self):
      have_error = False
      username = self.request.get('username')
      password = self.request.get('password')
      verify = self.request.get('verify')
      email = self.request.get('email')

      params = dict(username = username, email = email)

      if not valid_username(username):
        params['error_username'] = "Username must be between 3 and 20 characters and contain no special characters."
        have_error = True

      if not valid_password(password):
        params['error_password'] = "Password must be between 3 and 20 characters."
        have_error = True
      elif password != verify:
        params['error_verify'] = "Your passwords didn't match."
        have_error = True

      if not valid_email(email):
        params['error_email'] = "That's not a valid email."
        have_error = True

      if have_error:
        self.render('signup-form.html', **params)
      else:
        user = User.by_name(username)
        if not user:
          u = User.register(username, password, email)
          u.put()
          self.login(u)
          self.redirect('/')
        else:   
          params['error_username'] = "That username already exsists."
          self.render('signup-form.html', **params)

class Login(BaseHandler):
  def get(self):
    self.render('login-form.html')

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
    self.redirect('/')

POOL_RE = re.compile(r"^(?:[a-zA-Z0-9_-]|\s){1,50}$")
def valid_poolname(name):
    return name and POOL_RE.match(name)

class NewPool(BaseHandler):
  def get(self):
    if not self.user:
      self.redirect('/login?return-url=/pools/new')

    self.render('pool-form.html')

  def post(self):
    if not self.user:
      self.redirect('/')

    have_error = False
    name = self.request.get('name')
    password = self.request.get('password')
    verify = self.request.get('verify')

    params = dict(name = name)

    if not valid_poolname(name):
      params['error_name'] = "Name must be between 1 and 50 characters and contain no special characters."
      have_error = True

    if not valid_password(password):
      params['error_password'] = "Password must be between 3 and 20 characters."
      have_error = True
    elif password != verify:
      params['error_verify'] = "Your passwords didn't match."
      have_error = True

    if have_error:
      self.render('pool-form.html', **params)
    else:
      pool = Pool.by_name(name)
      if not pool:
        pool = Pool.submit(name, password, self.user)
        self.redirect('/pools/' + str(pool.key().id()))
      else:   
        params['error_name'] = "That Pool name is already in use."
        self.render('pool-form.html', **params)

class AllPools(BaseHandler):
  def get(self):
    if not self.user:
      self.redirect('/login?return-url=/pools/all')

    pools = Pool.all().run(batch_size=1000)
    self.render('all-pools.html', pools = pools)

class PoolPage(BaseHandler):
  def get(self, pool_id):
    if not self.user:
      self.redirect('/login?return-url=/pools/' + pool_id)
      
    pool = Pool.by_id(int(pool_id))
    if not pool:
      self.redirect('/pools/all')
    else:
      if self.user.id in pool.users:
        self.render('pool.html', pool = pool)
      else:
        self.render('pool-join.html', pool = pool)

  def post(self, pool_id):
    if not self.user:
      self.redirect('/')

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
        self.render('pool-join.html', error_login = 'Invalid password', pool = pool)

class BracketEntry(BaseHandler):
  def get(self, entry_id):
    if not self.user:
      self.redirect('/login?return-url=/brackets/' + entry_id)

    year = datetime.now().year
    params = dict()
    winners = []

    if entry_id != 'new':
      entry = Entry.by_id(int(entry_id))
      if entry:
        for p in Pick.all().filter('entry = ', entry).order('game').run(limit=63):
          winners.append(p.team)
        params['name'] = entry.name
        params['final_score'] = entry.final_score
        params['locked'] = datetime.today() > entry.pool.lock_date
        year = entry.year
      else:
        self.redirect('/brackets/new')

    params['teams'] = Team.all().filter('year = ', year).fetch(limit=64)
    params['winners'] = winners

    self.render('bracketentry.html', **params)

  def post(self, entry_id):
    picks = []
    for i in range(1, 64):
      result = self.request.get('winner_' + str(i))
      picks.append(result)

    entry = None
    if entry_id != 'new':
      entry = Entry.by_id(int(entry_id))

    if entry:
      entry.update(self.request.get('entry_name'), picks, int(self.request.get('final_score')))
    else:
      entry = Entry.submit(self.request.get('entry_name'), picks, int(self.request.get('final_score')), self.user, Pool.all().get())

    self.redirect('/mybrackets')

class MyBrackets(BaseHandler):
  def get(self):
    if not self.user:
      self.redirect('/login')

    entries = Entry.all().filter("user =", self.user).run(batch_size=1000)
    self.render('mybrackets.html', entries = entries)

class UploadTeams(BaseHandler):
  def get(self):
    if not self.user or not self.user.admin:
      self.redirect('/')

    self.render('upload-teams.html')

  def post(self):
    if not self.user or self.user.admin:
      self.redirect('/')

    year = self.request.get('year')
    old_teams = Team.all().filter('year = ', int(year)).fetch(limit=64)
    db.delete(old_teams)

    teams = self.request.get('team_file')
    for row in csv.reader(StringIO.StringIO(teams)):
      if row[0] != 'Team':
        Team.submit(row[0], year, int(row[1]), int(row[2]))

app = webapp2.WSGIApplication([('/', Front),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/brackets/(new|[0-9]+)', BracketEntry),
                               ('/pools/new', NewPool),
                               ('/pools/all', AllPools),
                               ('/pools/([0-9]+)', PoolPage),
                               ('/mybrackets', MyBrackets),
                               ('/teams/upload', UploadTeams)],
                              debug=True)