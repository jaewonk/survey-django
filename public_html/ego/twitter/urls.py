from django.conf.urls.defaults import *

from views import *

urlpatterns = patterns('',
	url(r'^$', 'twitter.views.main'),
	url(r'^auth/$', 'twitter.views.auth'),
	url(r'^return/$', 'twitter.views.return_'),
	url(r'^list/$', 'twitter.views.friend_list'),
	url(r'^clear/$', 'twitter.views.clear'),
	url(r'^unauth/$', 'twitter.views.unauth'),
	
    # url(r'^$',
    #     view=main,
    #     name='twitter_oauth_main'),
    # 
    # url(r'^auth/$',
    #     view=auth,
    #     name='twitter_oauth_auth'),
    # 
    # url(r'^return/$',
    #     view=return_,
    #     name='twitter_oauth_return'),
    #   
    # url(r'^list/$',
    #     view=friend_list,
    #     name='twitter_oauth_friend_list'),
    # 
    # url(r'^clear/$',
    #     view=unauth,
    #     name='twitter_oauth_unauth'),
)