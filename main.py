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
import math
import json
from datetime import datetime
from string import letters
from operator import attrgetter

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
      
  def initialize(self, *a, **kw):
    webapp2.RequestHandler.initialize(self, *a, **kw)
    uid = self.read_secure_cookie('user_id')
    self.user = uid and User.by_id(int(uid))
    self.locked = False

  def check_locked(self):
    a = Admin.get_current()
    if datetime.today() > a.lock_date:
      self.locked = True

  def require_login(self):
    self.redirect('/login?return-url=' + self.request.path_qs)

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
  name_search = db.StringProperty(required = True)
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
    u = User.all().filter('name_search =', name.strip().upper()).ancestor(users_key()).get()
    return u

  @classmethod
  def register(cls, name, pw, email = None):
    name = name.strip()
    pw_hash = make_pw_hash(name, pw)
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

  def get_entries(self):
    return Entry.all().filter("user =", self).filter("year =", datetime.now().year).order("name").ancestor(entries_key()).run(batch_size=1000)

  def get_pools(self):
    return Pool.all().filter("users =", self.id).filter("year =", datetime.now().year).order("name").ancestor(pools_key()).run(batch_size=1000)    

####Team####
def teams_key(group = 'default'):
  return db.Key.from_path('teams', group)

class Team(db.Model):
  name = db.StringProperty(required = True)
  year = db.IntegerProperty(required = True)
  seed = db.IntegerProperty(required = True)
  bracket_position = db.IntegerProperty(required = True)

  @property
  def id(self):
    return self.key().id()

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
  name_search = db.StringProperty(required = True)
  pw_hash = db.StringProperty(required = True)
  year = db.IntegerProperty(required = True)
  admin_user = db.ReferenceProperty(User, required = True)
  users = db.ListProperty(int, required = True)
  paid = db.ListProperty(int, required = True)
  points = db.ListProperty(float, required = True)

  @property
  def id(self):
    return self.key().id()

  @classmethod
  def submit(cls, name, pw, points, user):
    name = name.strip()
    pw_hash = make_pw_hash(name, pw)
    p = Pool(parent = pools_key(),
              name = name,
              name_search = name.upper(),
              pw_hash = pw_hash,
              points = points,
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

####Entry####
def entries_key(group = 'default'):
  return db.Key.from_path('entries', group)

class Entry(db.Model):
  name = db.StringProperty(required = True)
  name_search = db.StringProperty(required = True)
  picks = db.ListProperty(int, required = True)
  final_score = db.IntegerProperty(required = True)
  user = db.ReferenceProperty(User)
  pools = db.ListProperty(int)
  year = db.IntegerProperty(required = True)

  @property
  def id(self):
    return self.key().id()

  @classmethod
  def submit(cls, name, picks, final_score, user, pool_id):
    e = Entry(parent = entries_key(),
              name = name.strip(),
              name_search = name.strip().upper(),
              picks = picks,
              final_score = final_score,
              year = datetime.now().year)
    if user:
      e.user = user
    if pool_id:
      e.pools = [pool_id]
    e.put()
    if pool_id:
      Points.add_new(e.id, pool_id)
    return e

  def update(self, picks, final_score):
    self.picks = picks
    self.final_score = final_score
    self.put()

  @classmethod
  def by_id(cls, eid):
    return Entry.get_by_id(eid, parent = entries_key())

  @classmethod
  def by_name(cls, name, year = datetime.now().year):
    return Entry.all().filter('name_search =', name.strip().upper()).filter('year =', year).ancestor(entries_key()).get()

  @classmethod
  def by_pool(cls, pool_id):
    return Entry.all().filter("pools =", pool_id).ancestor(entries_key()).run(batch_size=1000)

  @classmethod
  def by_year(cls, year):
    return Entry.all().filter('year =', year).ancestor(entries_key()).run(batch_size=1000)

####Points####
def points_key(group = 'default'):
  return db.Key.from_path('points', group)

class Points(db.Model):
  entry_id = db.IntegerProperty(required = True)
  pool_id = db.IntegerProperty(required = True)
  round_1 = db.FloatProperty(required = True)
  round_2 = db.FloatProperty(required = True)
  round_3 = db.FloatProperty(required = True)
  round_4 = db.FloatProperty(required = True)
  round_5 = db.FloatProperty(required = True)
  round_6 = db.FloatProperty(required = True)
  total = db.FloatProperty(required = True)
  year = db.IntegerProperty(required = True)

  @classmethod
  def add_new(cls, entry_id, pool_id):
    p = Points(parent = points_key(),
                entry_id = entry_id, 
                pool_id = pool_id,
                round_1 = 0.0,
                round_2 = 0.0,
                round_3 = 0.0,
                round_4 = 0.0,
                round_5 = 0.0,
                round_6 = 0.0,
                total = 0.0,
                year = datetime.now().year)
    p.put()
    return p

  def reset(self):
    self.round_1 = 0.0
    self.round_2 = 0.0
    self.round_3 = 0.0
    self.round_4 = 0.0
    self.round_5 = 0.0
    self.round_6 = 0.0

  @classmethod
  def get(cls, entry_id, pool_id):
    p = Points.all().filter('entry_id =', entry_id).filter('pool_id =', pool_id).ancestor(points_key()).get()
    return p

  @classmethod
  def by_year(cls, year):
    return Points.all().filter('year =', year).ancestor(points_key()).run(batch_size = 1000)

  @classmethod
  def by_pool(cls, pool_id):
    points = dict()
    for p in Points.all().filter('pool_id =', pool_id).ancestor(points_key()).run(batch_size=1000):
      points[p.entry_id] = p
    return points

####Admin####
def admins_key(group = 'default'):
  return db.Key.from_path('admins', group)

class Admin(db.Model):
  year = db.IntegerProperty(required = True)
  lock_date = db.DateTimeProperty(required = True)

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
        self.login(u)
        return_url = self.request.get('return-url')
        if return_url:
          self.redirect(return_url)
        else:
          self.redirect('/')
      else:   
        params['error_username'] = "That username already exsists."
        self.render('signup-form.html', **params)

class Login(BaseHandler):
  def get(self):
    return_url = self.request.get('return-url')
    if return_url:
      return_url = '?return-url=' + return_url
    self.render('login-form.html', return_url = return_url)

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
      params['pts_' + str(i)] = i

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

    params = dict(name = name)

    if not valid_poolname(name):
      params['error_name'] = "Name must 50 characters or less and contain no special characters."
      have_error = True

    if not valid_password(password):
      params['error_password'] = "Password must be between 3 and 20 characters."
      have_error = True
    elif password != verify:
      params['error_verify'] = "Your passwords didn't match."
      have_error = True

    for i in range(1, 7):
      point = self.request.get('pts_' + str(i))
      params['pts_' + str(i)] = point
      try:
        pt = float(point)
        if pt > 0:
          points.append(pt)
        else:
          params['error_points'] = "All point values must be valid, positive numbers."
          have_error = True
      except ValueError:
        params['error_points'] = "All point values must be valid, positive numbers."
        have_error = True

    if have_error:
      self.render('pool-form.html', **params)
    else:
      pool = Pool.by_name(name)
      if not pool:
        pool = Pool.submit(name, password, points, self.user)
        self.redirect('/pools/' + str(pool.id))
      else:   
        params['error_name'] = "That Pool name is already in use."
        self.render('pool-form.html', **params)

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
      if self.user.id in pool.users:
        self.check_locked()
        entries = []
        all_points = Points.by_pool(pool.id)
        for e in Entry.by_pool(pool.id):
          e.points = all_points[e.id]
          entries.append(e)
        entries.sort(key=attrgetter('points.total'), reverse=True)
        rank = 1
        ties = 0
        last_score = None
        for e in entries:
          e.own = self.user.id == e.user.id
          if e.points.total != last_score:
            e.rank = rank
            ties = 0
          else:
            ties += 1
            e.rank = rank - ties
          rank += 1
          last_score = e.points.total
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
        self.render('pool-join.html', error_login = 'Invalid password', pool = pool)

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
        for user_id in pool.users:
          if user_id != pool.admin_user.id:
            u = User.by_id(user_id)
            if u:
              u.paid = u.id in pool.paid
              if u.id in entries:
                u.brackets = entries[u.id]
              users.append(u)
        users.sort(key=attrgetter('name'))
        params = dict()
        params['pool'] = pool
        params['users'] = users
        
        if self.request.get('success') == "true":
          params['message'] = 'Changes were saved successfully.'

        self.render('pool-admin.html', **params)

  def post(self, pool_id):
    pool = Pool.by_id(int(pool_id))
    if not pool:
      self.redirect('/pools/all')
    else:
      if not self.user or self.user.id != pool.admin_user.id:
        self.redirect('/')
      else:
        pool.paid = []
        for user_id in pool.users:
          remove = self.request.get('remove_' + str(user_id))
          if remove:
            pool.users.remove(user_id)
            pool.remove_entries(user_id)            
          else:
            paid = self.request.get('paid_' + str(user_id))
            if paid:
              pool.paid.append(user_id)
        pool.put()

        self.redirect(self.request.path + '?success=true')

def get_teams(year):
  teams = dict()
  for team in Team.all().filter('year = ', year).fetch(limit=64):
    teams[team.id] = team
  return teams

def update_points():
  master = Entry.by_name('Master Bracket')
  if master:
    points = dict()
    for pts in Points.by_year(datetime.now().year):
      if pts.pool_id in points:
        points[pts.pool_id][pts.entry_id] = pts
      else:
        points[pts.pool_id] = {pts.entry_id: pts}

    entries = dict()
    for e in Entry.by_year(datetime.now().year):
      for p in e.pools:
        if p in entries:
          entries[p].append(e)
        else:
          entries[p] = [e]

    for pool in Pool.by_year(datetime.now().year):
      if pool.id in entries:
        for entry in entries[pool.id]:
          p = points[pool.id][entry.id]
          p.reset()
          for i in range(len(master.picks)):
            if (entry.picks[i] == master.picks[i]):
              if i < 32:
                p.round_1 += pool.points[0]
              elif i < 48:
                p.round_2 += pool.points[1]
              elif i < 56:
                p.round_3 += pool.points[2]
              elif i < 60:
                p.round_4 += pool.points[3]
              elif i < 62:
                p.round_5 += pool.points[4]
              else:
                p.round_6 += pool.points[5]
          p.total = math.fsum([p.round_1, p.round_2, p.round_3, p.round_4, p.round_5, p.round_6])
          p.put()

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
    if entry_id == 'new':
      pool_id = self.request.get('p')
      try:  
        pool = Pool.by_id(int(pool_id))
      except ValueError:
        pool = None
      if not pool or not self.user.id in pool.users:
        self.error(404)
        return
      teams = get_teams(datetime.now().year)
      params['final_score'] = 0
    elif entry_id == 'master':
      teams = get_teams(datetime.now().year)
      params['name'] = 'Master Bracket'
      params['master'] = True
      entry = Entry.by_name('Master Bracket')
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
        self.check_locked()

        if not self.locked and self.user.id != entry.user.id:
          self.render('access-denied.html')
          return

        if self.locked:
          master = Entry.by_name('Master Bracket')
          i = 0
          losers = []
        teams = get_teams(entry.year)
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

    params['teams'] = teams.values()
    params['winners'] = winners
    params['css_winners'] = css_winners

    self.render('bracketentry.html', **params)

  def post(self, entry_id):
    if not self.user:
      self.redirect('/')
      return

    if entry_id != 'master':
      a = Admin.get_current()
      if datetime.today() > a.lock_date:
        self.error(404)
        return

    teams = dict()
    for team in Team.all().filter('year = ', datetime.now().year).fetch(limit=64):
      teams[team.name] = team.id

    try:
      final_score = int(self.request.get('final_score'))
    except ValueError:
      final_score = 0

    name = self.request.get('entry_name')
    picks = []
    for i in range(1, 64):
      result = self.request.get('winner_' + str(i))
      if result:
        picks.append(teams[result[result.find(' ') + 1:]])
      else:
        picks.append(-1)

    entry = None
    if entry_id == 'new':
      pool_id = self.request.get('p')
      try:  
        pool = Pool.by_id(int(pool_id))
      except ValueError:
        pool = None
      if not pool or not self.user.id in pool.users:
        self.error(404)
        return
      else:
        entry = Entry.submit(name, picks, final_score, self.user, pool.id)
    elif entry_id == 'master':
      if self.user.admin:
        entry = Entry.by_name('Master Bracket')
        if entry:
          entry.update(picks, final_score)
        else:
          entry = Entry.submit('Master Bracket', picks, final_score, None, None)
        update_points()
        self.redirect('/brackets/master')
        return
    else:
      entry = Entry.by_id(int(entry_id))
      if entry and self.user.id == entry.user.id:
          entry.update(picks, final_score)

    if entry:
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
      entries = self.request.get('entry', allow_multiple=True)
      for e in entries:
        entry = Entry.by_id(int(e))
        if entry and pool.id not in entry.pools:
          entry.pools.append(pool.id)
          entry.put()
      self.redirect('/pools/' + str(pool.id))

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
    if not self.user or self.user.admin:
      self.redirect('/')
      return

    year = self.request.get('year')
    old_teams = Team.all().filter('year = ', int(year)).fetch(limit=64)
    db.delete(old_teams)

    teams = self.request.get('team_file')
    for row in csv.reader(StringIO.StringIO(teams)):
      if row[0] != 'Team':
        Team.submit(row[0], year, int(row[1]), int(row[2]))

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

    if self.request.get('success') == "true":
      params['message'] = 'Changes were saved successfully.'

    self.render('admin.html', **params)

  def post(self):
    if not self.user or not self.user.admin:
      self.redirect('/')
      return

    lock_date = datetime.strptime(self.request.get('lock_date'), '%m/%d/%Y')
    Admin.submit(lock_date)

    self.redirect('/admin?success=true')

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

app = webapp2.WSGIApplication([('/', Front),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/brackets/(new|master|[0-9]+)', BracketEntry),
                               ('/brackets/choose', BracketChoose),
                               ('/pools/new', NewPool),
                               ('/pools/all', AllPools),
                               ('/pools/([0-9]+)', PoolPage),
                               ('/pools/([0-9]+)/admin', PoolAdmin),
                               ('/mybrackets', MyBrackets),
                               ('/mypools', MyPools),
                               ('/admin', AdminPage),
                               ('/admin/teams/upload', UploadTeams),
                               ('/validate/entry', ValidateEntry)],
                              debug=True)