from collections import defaultdict

class TagsDriver(object):

	def __init__(self, db):
		self.db = db

	def change_tag(self, tag):
		"""Changes tags into redis key."""
		return "TAG:{0}".format(tag)

	def change_post_id(self, post_id):
		"""Changes post_id into redis key."""
		return "POST_ID:{0}".format(post_id)

	def set_tags(self, tags, post_id):
		"""Adds tags to post_id and adds post_id to tags."""
		self.db.sadd(self.change_post_id(post_id), *tags)
		for tag in tags:
			self.db.sadd(self.change_tag(tag), post_id)

	def get_tags(self, post_id):
		"""Returns tags by post_id."""
		return self.db.smembers(self.change_post_id(post_id))

	def get_posts(self, tag):
		"""Returns post_id by tags."""
		return self.db.smembers(self.change_tag(tag))
