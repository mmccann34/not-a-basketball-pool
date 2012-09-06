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
    self.set_secure_cookie('user_id', str(user.key().id()))

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
                email = email)
    u.put()
    return u

  @classmethod
  def login(cls, name, pw):
    u = cls.by_name(name)
    if u and valid_pw(name, pw, u.pw_hash):
        return u

####Entry####
def entries_key(group = 'default'):
  return db.Key.from_path('entries', group)

class Entry(db.Model):
  name = db.StringProperty(required = True)
  final_score = db.IntegerProperty(required = True)
  user = db.ReferenceProperty(User, required = True)

  @classmethod
  def submit(cls, name, picks, final_score, user):
    e = Entry(parent = entries_key(),
              name = name,
              final_score = final_score,
              user = user)
    e.put()

    i = 1
    for p in picks:
      Pick.submit(i, p, e)
      i += 1

    return e

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
        params['error_username'] = "That's not a valid username."
        have_error = True

      if not valid_password(password):
        params['error_password'] = "That's not a valid password."
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
      self.redirect('/')
    else:
      params = dict(username = username, error_login = 'Invalid login')
      self.render('login-form.html', **params)

class Logout(BaseHandler):
  def get(self):
    self.logout()
    self.redirect('/')

class BracketEntry(BaseHandler):
  def get(self, entry_id):
    if not self.user:
      self.redirect('/login')

    params = dict()
    teams = ['Ohio State', 'Alabama St', 'George Mason', 'Villanova', 
              'West Virgina', 'UAB', 'Kentucky', 'Princeton', 'Xavier',
              'Marquette', 'Syracuse', 'Indiana St.', 'Washington', 
              'Georgia', 'UNC', 'LIU', 'Duke', 'Hampton', 'Michigan',
              'Tennessee', 'Arizona', 'Memphis', 'Texas', 'Oakland',
              'Cincinnati', 'Missouri', 'UCONN', 'Bucknell', 'Temple',
              'Penn St.', 'San Diego St.', 'No. Colorado',
              'Kansas', 'Boston U.', 'UNLV', 'Illinois',
              'Vanderbilt', 'Richmond', 'Louisville', 'Morehead St.',
              'Georgetown', 'VCU', 'Purdue', "St. Peter's", 'Texas A&M',
              'Florida St.', 'Notre Dame', 'Akron', 'Pittsburgh',
              'UNCA', 'Butler', 'Old Dominion', 'Kansas St.', 'Utah St.',
              'Wisconsin', 'Belmont', "St. John's", 'Gonzaga', 'BYU',
              'Wofford', 'UCLA', 'Michigan St.', 'Florida', 'UCSB']
    winners = []

    if entry_id != 'new':
      entry = Entry.get_by_id(int(entry_id), parent = entries_key())
      if entry:
        for p in Pick.all().filter('entry = ', entry).order('game').run(limit=63):
          winners.append(p.team)
        params['name'] = entry.name
        params['final_score'] = entry.final_score

    params['teams'] = teams
    params['winners'] = winners

    # params['locked'] = True

    self.render('bracketentry.html', **params)

  def post(self, entry_id):
    picks = []
    for i in range(1, 64):
      result = self.request.get('winner_' + str(i))
      picks.append(result)

    entry = None
    if entry_id != 'new':
      entry = Entry.get_by_id(int(entry_id), parent = entries_key())

    if entry:
      entry.update(self.request.get('entry_name'), picks, int(self.request.get('final_score')))
    else:
      entry = Entry.submit(self.request.get('entry_name'), picks, int(self.request.get('final_score')), self.user)

    self.redirect('/mybrackets')

class MyBrackets(BaseHandler):
  def get(self):
    if not self.user:
      self.redirect('/login')
      
    entries = Entry.all().filter("user =", self.user).run(batch_size=1000)
    self.render('mybrackets.html', entries = entries)

app = webapp2.WSGIApplication([('/', Front),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/brackets/(new|[0-9]+)', BracketEntry),
                               ('/mybrackets', MyBrackets)],
                              debug=True)