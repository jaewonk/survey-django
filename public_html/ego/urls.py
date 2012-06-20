from django.conf.urls.defaults import *
from django.conf import settings

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
	url(r'^polls/', include('polls.urls')),
	url(r'^twitter/', include('twitter.urls')),
	url(r'^questionnaire/', include('questionnaire.urls')),
	url(r'^admin/', include(admin.site.urls)),
	url(r'^media/(.*)', 'django.views.static.serve',
        { 'document_root' : settings.MEDIA_ROOT }),
    
)