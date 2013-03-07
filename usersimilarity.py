class UserSimilarity(BaseHandler):
	def get(self, pool_id):
		if not self.user:
			self.require_login()
			return
		
		pool_id = int(pool_id)
		pool = Pool.by_id(pool_id)
		gameMatches = 0  #initialize variable to track matches with other users

		if not pool:
			self.error(404)
		else:
			if self.user.id in pool.users:
				sameGamePicks = {}
				for e1 in Entry.by_pool(pool_id):
					sameGamePicks[e1.id] = {}
					for e2 in Entry.by_pool(pool_id):
						for game in range(63):
							if (e1.picks[game] == e2.picks[game]):
								gameMatches += 1
						sameGamePicks[e1.id][e2.id] = gameMatches
						gameMatches = 0
				self.write(str(sameGamePicks)+ '<br>')
		
		params = dict()
		params['pool'] = pool
		params['gamePicks'] = sameGamePicks
		self.render('usersimilarity.html', **params)