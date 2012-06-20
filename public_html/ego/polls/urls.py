from django.conf.urls.defaults import patterns, include, url

urlpatterns = patterns('',
	url(r'^$', 'polls.views.index'),
	url(r'^(?P<poll_id>\d+)/$', 'polls.views.detail'),
	url(r'^(?P<poll_id>\d+)/results/$', 'polls.views.results'),
	url(r'^(?P<poll_id>\d+)/vote/$', 'polls.views.vote'),
	# url(r'^twitter$', 'twitter.views.connect'),	
	# url(r'^twitter_connect$', 'polls.views.twitter_connect'),
)