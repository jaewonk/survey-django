from django.db import models

# Create your models here.
class Subject(models.Model):
	twitter_id = models.CharField(max_length = 100)
	counter = models.IntegerField()
	def __unicode__(self):
		return str(self.twitter_id) + "\t" + str(self.counter)
		
