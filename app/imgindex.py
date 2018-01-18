class ImgIndexDriver(object):

	def __init__(self, db):
		self.db = db

	def change_post_id(self, post_id):
		"""Changes post id into redis key"""

		return "IMG_POST_ID:{0}".format(post_id)

	def get_image_ids(self, post_id):
		"""Returns image ids by given post id."""

		return self.db.smembers(self.change_post_id(post_id))

	def set_image_ids(self, image_ids, post_id):
		"""Save image ids of the post id."""

		for image_id in image_ids:
			self.db.sadd(self.change_post_id(post_id), image_id)
