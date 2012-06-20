from django.db import models

# Create your models here.
	
	
class Poll(models.Model):
	question = models.CharField(max_length=200)
	pub_date = models.DateTimeField('date published')
	def __unicode__(self):
		return self.question

class Choice(models.Model):
	poll = models.ForeignKey('Poll')
	choice = models.CharField(max_length=200)
	votes = models.IntegerField()
	def __unicode__(self):
		return self.choice
# 
# class Client(models.Model):
# 	def __unicode__(self):
# 		return 'blah'
# 		
# class Client_Twitter(models.Model):
# 	user = models.OneToOneField('Client')
# 	twitter_id = models.DecimalField(max_digits=20, decimal_places=0,null=True)
# 	access_token = models.CharField(max_length=200,null=True)
# 	access_token_secret = models.CharField(max_length=200,null=True)
# 	twitter_username = models.CharField(max_length=200,null=True)
# 	def __unicode__(self):	
# 		return self.user.user.username
