# import oauth, httplib, simplejson, time, datetime
# 
# from django.http import *
# from django.conf import settings
# from django.shortcuts import render_to_response

import oauth2 as oauth
from django.template import RequestContext
from polls.models import *
from django.http import HttpResponse, HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response, get_object_or_404
import settings, urlparse

def index(request):
	latest_poll_list = Poll.objects.all().order_by('-pub_date')[:5]
	return render_to_response('polls/index.html', {'latest_poll_list':latest_poll_list})
	
def detail(request, poll_id):
	p = get_object_or_404(Poll, pk = poll_id)
	return render_to_response('polls/detail.html', {'poll':p}, context_instance=RequestContext(request))

def results(request, poll_id):
	p = get_object_or_404(Poll, pk = poll_id)
	return render_to_response('polls/results.html', {'poll':p})

def vote(request, poll_id):
	p = get_object_or_404(Poll, pk=poll_id)
	try:
		selected_choice = p.choice_set.get(pk=request.POST['choice'])
	except (KeyError, Choice.DoesNotExist):
		return render_to_response('polls/detail.html', {
		'poll':p,
		'error_message':"You didn't select a choice.",
		}, context_instance = RequestContext(request))
	else:
		selected_choice.votes += 1
		selected_choice.save()
		return HttpResponseRedirect(reverse('polls.views.results', args = (p.id,)))
# 		
# def twitter_connect(request):
# 	print "hello twitter"
# 	twitter_consumer_key = settings.TWITTER_CONSUMER_KEY
# 	twitter_consumer_secret = settings.TWITTER_CONSUMER_SECRET
# 
# 	request_token_url = 'http://twitter.com/oauth/request_token'
# 	access_token_url = 'http://twitter.com/oauth/access_token'
# 	authorize_url = 'http://twitter.com/oauth/authorize'
# 	consumer = oauth.Consumer(twitter_consumer_key,twitter_consumer_secret)
# 	print "consumer:", consumer
# 	
# 	try:
# 		print "1"
# 		next = '/dashboard/'
# 		if('redirect' in request.session):
# 			print "redirect"
# 			next = request.session['redirect']
# 			del request.session['redirect']
# 		print "1.5"
# 		print "REQUEST:",request
# 		print "REQUEST.USER:",request.user
# 		print "THEN:",request.user.get_profile()
# 		twitter = Client_Twitter.objects.get(user=request.user.get_profile())
# 		print "1.7"
# 		#return HttpResponseRedirect('/account/login?next='+next)
# 		print "twitter:",twitter
# 		return HttpResponseRedirect(next)
# 		
# 	except Exception:
# 		print "2"
# 		if ('oauth_verifier' not in request.GET):
# 			print "3"
# 			client = oauth.Client(consumer)
# 			resp, content = client.request(request_token_url, "GET")
# 			request_token = dict(urlparse.parse_qsl(content))
# 			roauth_token = request_token['oauth_token']
# 			roauth_token_secret = request_token['oauth_token_secret']
# 			request.session['roauth_token'] = roauth_token
# 			request.session['roauth_token_secret'] = roauth_token_secret
# 			new_authorize_url = authorize_url+'?oauth_token='+request_token['oauth_token']
# 			return HttpResponseRedirect(new_authorize_url)
# 	
# 		elif(request.GET['oauth_verifier'] != "" ):
# 			print "4"
# 			oauth_verifier = request.GET['oauth_verifier']
# 			token = oauth.Token(request.session.get('roauth_token', None),request.session.get('roauth_token_secret', None))
# 			token.set_verifier(oauth_verifier)
# 			client = oauth.Client(consumer, token)
# 
# 			resp, content = client.request(access_token_url, "POST")
# 			access_token = dict(urlparse.parse_qsl(content))
# 
# 			del request.session['roauth_token']
# 			del request.session['roauth_token_secret']
# 
# 			oauth_token = access_token['oauth_token']
# 			oauth_token_secret = access_token['oauth_token_secret']
# 			userid = access_token['user_id']
# 			screenname = access_token['screen_name']
# 	
# 			twitter_user = Client_Twitter.objects.get(user = client)
# 			access_token = twitter_user.access_token
# 			access_token_secret = twitter_user.access_token_secret
# 			token = oauth.Token(access_token,access_token_secret)
# 			consumer_key = settings.TWITTER_CONSUMER_KEY
# 			consumer_secret = settings.TWITTER_CONSUMER_SECRET
# 			consumer = oauth.Consumer(consumer_key,consumer_secret)
# 			client = oauth.Client(consumer,token)
# 
# 			data = {'status':'I just checked at 24 hr Fitness'}
# 			request_uri = 'https://api.twitter.com/1/statuses/update.json'
# 			resp, content = client.request(request_uri, 'POST', urllib.urlencode(data))
# 		print "5"
# 	print "6"
# 
# 
# 
# SERVER = getattr(settings, 'OAUTH_SERVER', 'twitter.com')
# print SERVER
# REQUEST_TOKEN_URL = getattr(settings, 'OAUTH_REQUEST_TOKEN_URL', 'https://%s/twitter_app/request_token' % SERVER)
# ACCESS_TOKEN_URL = getattr(settings, 'OAUTH_ACCESS_TOKEN_URL', 'https://%s/twitter_app/access_token' % SERVER)
# AUTHORIZATION_URL = getattr(settings, 'OAUTH_AUTHORIZATION_URL', 'http://%s/twitter_app/authorize' % SERVER)
# 
# CONSUMER_KEY = getattr(settings, 'CONSUMER_KEY', 'YOUR_CONSUMER_KEY')
# CONSUMER_SECRET = getattr(settings, 'CONSUMER_SECRET', 'YOUR_CONSUMER_SECRET')
# 
# # We use this URL to check if Twitters oAuth worked
# TWITTER_CHECK_AUTH = 'https://twitter.com/account/verify_credentials.json'
# TWITTER_FRIENDS = 'https://twitter.com/statuses/friends.json'
# 
# connection = httplib.HTTPSConnection(SERVER)
# consumer = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
# signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()
# 
# # Shortcut around oauth.OauthRequest
# def request(url, access_token, parameters=None):
#     """
#     usage: request( '/url/', your_access_token, parameters=dict() )
#     Returns a OAuthRequest object
#     """
#     oauth_request = oauth.OAuthRequest.from_consumer_and_token(
#         consumer, token=access_token, http_url=url, parameters=parameters,
#     )
#     oauth_request.sign_request(signature_method, consumer, access_token)
#     return oauth_request
# 
# 
# def fetch_response(oauth_request, connection):
#     url = oauth_request.to_url()
#     connection.request(oauth_request.http_method,url)
#     response = connection.getresponse()
#     s = response.read()
#     return s
# 
# def get_unauthorised_request_token():
#     oauth_request = oauth.OAuthRequest.from_consumer_and_token(
#         consumer, http_url=REQUEST_TOKEN_URL
#     )
#     oauth_request.sign_request(signature_method, consumer, None)
#     resp = fetch_response(oauth_request, connection)
#     token = oauth.OAuthToken.from_string(resp)
#     return token
# 
# 
# def get_authorisation_url(token):
#     oauth_request = oauth.OAuthRequest.from_consumer_and_token(
#         consumer, token=token, http_url=AUTHORIZATION_URL
#     )
#     oauth_request.sign_request(signature_method, consumer, token)
#     return oauth_request.to_url()
# 
# def exchange_request_token_for_access_token(request_token):
#     oauth_request = oauth.OAuthRequest.from_consumer_and_token(
#         consumer, token=request_token, http_url=ACCESS_TOKEN_URL
#     )
#     oauth_request.sign_request(signature_method, consumer, request_token)
#     resp = fetch_response(oauth_request, connection)
#     return oauth.OAuthToken.from_string(resp) 
# 
# def is_authenticated(access_token):
#     oauth_request = request(TWITTER_CHECK_AUTH, access_token)
#     json = fetch_response(oauth_request, connection)
#     if 'screen_name' in json:
#         return json
#     return False
# 
# def get_friends(access_token):
#     """Get friends on Twitter"""
#     oauth_request = request(TWITTER_FRIENDS, access_token, {'page': page})
#     json = fetch_response(oauth_request, connection)
#     return json
# 
# 
# 
# ### DJANGO VIEWS BELOW THIS LINE
# 
# 
# def main(request):
#     if request.get_host().startswith('www.') or '/labs/followers/' in request.path: # Should really be middleware
#         return HttpResponseRedirect("http://fourmargins.com/labs/following/")
#     if request.session.has_key('access_token'):
#         return HttpResponseRedirect('/list/')
#     else:
#         return render_to_response('oauth/base.html')
# 
# def unauth(request):
#     response = HttpResponseRedirect('/')
#     request.session.clear()
#     return response
# 
# def auth(request):
#     "/auth/"
#     token = get_unauthorised_request_token()
#     auth_url = get_authorisation_url(token)
#     response = HttpResponseRedirect(auth_url)
#     request.session['unauthed_token'] = token.to_string()   
#     return response
# 
# def return_(request):
#     "/return/"
#     unauthed_token = request.session.get('unauthed_token', None)
#     if not unauthed_token:
#         return HttpResponse("No un-authed token cookie")
#     token = oauth.OAuthToken.from_string(unauthed_token)   
#     if token.key != request.GET.get('oauth_token', 'no-token'):
#         return HttpResponse("Something went wrong! Tokens do not match")
#     access_token = exchange_request_token_for_access_token(token)
#     response = HttpResponseRedirect('/list/')
#     request.session['access_token'] = access_token.to_string()
#     return response
# 
# def get_friends(request):
#     users = []
# 
#     access_token = request.session.get('access_token', None)
#     if not access_token:
#         return HttpResponse("You need an access token!")
#     token = oauth.OAuthToken.from_string(access_token)   
# 
#     # Check if the token works on Twitter
#     auth = is_authenticated(token)
#     if auth:
#         # Load the credidentials from Twitter into JSON
#         creds = simplejson.loads(auth)
#         name = creds.get('name', creds['screen_name']) # Get the name
# 
#         # Get number of friends. The API only returns 100 results per page,
#         # so we might need to divide the queries up.
#         friends_count = str(creds.get('friends_count', '100'))
#         pages = int( (int(friends_count)/100) ) + 1
#         pages = min(pages, 10) # We only want to make ten queries
# 
# 
# 
#         for page in range(pages):
#             friends = get_friends(token, page+1)
# 
#             # if the result is '[]', we've reached the end of the users friends
#             if friends == '[]': break
# 
#             # Load into JSON
#             json = simplejson.loads(friends)
# 
#             users.append(json)
# 
#     return render_to_response('oauth/list.html', {'users': users})