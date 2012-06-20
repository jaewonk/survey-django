from django.conf.urls.defaults import *
from django.contrib import admin
from django.conf import settings

from views import *

admin.autodiscover()

urlpatterns = patterns('',
	url(r'^$', 'page.views.page', {'page' : 'index'}),
	# url(r'^take/(?P<questionnaire_id>[0-9]+)/$', 'questionnaire.views.generate_run'),
	url(r'^take/(?P<questionnaire_id>\d+)/$', 'questionnaire.views.generate_run'),
	# url(r'^bigfive/$', 'questionnaire.views.generate_run_bigfive'),
 	url(r'^/(?P<page>.*)\.html$', 'page.views.page'),
    url(r'^(?P<runcode>[^/]+)/(?P<qs>\d+)/$', questionnaire, name='questionset'),
    url(r'^(?P<runcode>[^/]+)/', questionnaire, name='questionnaire'),

	#  	url(r'^/(?P<lang>..)/(?P<page>.*)\.html$', 'page.views.langpage'),
	# url(r'^/setlang/$', 'questionnaire.views.set_language'),

	# url(r'^media/(.*)', 'django.views.static.serve',
	# { 'document_root' : settings.MEDIA_ROOT }),
	# url(r'^unauth/$', 'twitter.views.unauth'),
	
	## (r'', include('questionnaire.urls')),
	## (r'^take/(?P<questionnaire_id>[0-9]+)/$', 'questionnaire.views.generate_run'),
	## (r'^$', 'page.views.page', {'page' : 'index'}),
	## (r'^(?P<page>.*)\.html$', 'page.views.page'),
	## (r'^(?P<lang>..)/(?P<page>.*)\.html$', 'page.views.langpage'),
	# 
	## (r'^setlang/$', 'questionnaire.views.set_language'),
	# 
	## (r'^media/(.*)', 'django.views.static.serve',
	# 	{ 'document_root' : settings.MEDIA_ROOT }),
	# 
	# # (r'^admin/(.*)', admin.site.root),
	# (r'^admin/', include(admin.site.urls)),
)
