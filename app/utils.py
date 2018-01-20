"""Various utils for the app."""

TIMESTAMP_WEB_FORMAT = "%-d %b %Y %H:%M"
"""Timestamp format for web. 

	Format: "1 Jan 1970 00:00"
"""


def format_datetime(timestamp):
	"""Formats datetime object for web."""

	return timestamp.strftime(TIMESTAMP_WEB_FORMAT)
