class PoolChoose(BaseHandler):
  def get(self):
    if not self.user:
      self.require_login()
      return

    pool_id = self.request.get('p')  # what does this line do?
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
        self.render('pool-choose.html', **params)
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
          Points.add_new(entry.id, pool.id)
      self.redirect('/pools/' + str(pool.id)+'/master'+str(game.id))