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
import webapp2
import jinja2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
  t = jinja_env.get_template(template)
  return t.render(params)

class BaseHandler(webapp2.RequestHandler):
  def write(self, *a, **kw):
      self.response.out.write(*a, **kw)
      
  def render_str(self, template, **params):
      return render_str(template, **params)
      
  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

class Front(BaseHandler):
  def get(self):
    self.render('front.html')

class BracketEntry(BaseHandler):
  def get(self):
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
    self.render('bracketentry.html', teams = teams)

  def post(self):
    for i in range(1, 64):
      name = 'winner_' + str(i)
      result = self.request.get(name)
      self.write(name + ': ' + result + '<br>')

app = webapp2.WSGIApplication([('/', Front),
                               ('/bracketentry', BracketEntry)],
                              debug=True)
