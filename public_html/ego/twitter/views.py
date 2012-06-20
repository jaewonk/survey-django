import oauth, httplib, time, datetime
from twitter.models import *
from django.http import *
from django.shortcuts import render_to_response, get_object_or_404
from django.core.urlresolvers import reverse
from django.db import transaction
from utils import *
import settings
 
try:
	import simplejson
except ImportError:
	try:
		import json as simplejson
	except ImportError:
		try:
			from django.utils import simplejson
		except:
			raise "Requires either simplejson, Python 2.6 or django.utils!"


# NEEDS_NEW_CONNECTION = True
# if NEEDS_NEW_CONNECTION:
info = {}

info["CONSUMER"] = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
info["CONNECTION"] = httplib.HTTPSConnection(SERVER)
	# NEEDS_NEW_CONNECTION = False

def main(request):
	# print "in twitter.views.main"
	# return render_to_response('twitter/base.html')	
	if request.session.has_key('access_token'):
		###
		# print "yes key"
		token = request.session.get('access_token', None)
		# print token
		return HttpResponseRedirect(reverse('twitter.views.friend_list'))
	else:
		# print "no key"
		# return render_to_response('twitter/base.html')	
		response = HttpResponseRedirect(reverse('twitter.views.auth'))
		return response

def unauth(request):
	# NEEDS_NEW_CONNECTION = True
	
	# response = HttpResponseRedirect(reverse('twitter.views.unauth'))
	# request.session.clear()
	response = HttpResponseRedirect(reverse('twitter.views.main'))
	# request.session.clear()
	
	return response

def clear(request):
	# NEEDS_NEW_CONNECTION = True
	
	info['CONSUMER'] = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
	info['CONNECTION'] = httplib.HTTPSConnection(SERVER)
	print 2, info
	print "clear function called\n"*1
	# info[CONSUMER:oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET), CONNECTION:httplib.HTTPSConnection(SERVER)}
	
	response = HttpResponseRedirect(reverse('twitter.views.main'))
	# request.session.clear()
	# print "session items",request.session.items()

	return response
	
def auth(request):
	"/auth/"
	# print "auth"
	
	# print "CONSUMER:",CONSUMER
	# print "CONNECTION:",CONNECTION
	# CONNECTION = httplib.HTTPSConnection(SERVER)
	# print "CONNECTION:",CONNECTION
	# CONNECTION = httplib.HTTPSConnection(SERVER)
	# print "session info",request.session.items()
	response = None
	try:
		print "in try..."
		token = get_unauthorised_request_token(info['CONSUMER'], info['CONNECTION'])
		# print "token:",token
		auth_url = get_authorisation_url(info['CONSUMER'], token)
		# print "auth_url:",auth_url
		response = HttpResponseRedirect(auth_url)
		request.session['unauthed_token'] = token.to_string()	
		# print "setting time: 10"
		request.session.set_expiry(600)
		
	except Exception:
		# print "clearing..."
		# return clear(request)
		response = HttpResponseRedirect(reverse('twitter.views.clear'))
 		# response = HttpResponseRedirect(reverse('twitter.views.main'))
		
	print 1,info
		
	print "response=",response
	print 3, response
	return response

def return_(request):
	# print "return function called"
	"/return/"
	unauthed_token = request.session.get('unauthed_token', None)
	# print unauthed_token
	if not unauthed_token:
		return HttpResponse("No un-authed token cookie")
	token = oauth.OAuthToken.from_string(unauthed_token)  
	# print token
	if token.key != request.GET.get('oauth_token', 'no-token'):
		return HttpResponse("Something went wrong! Tokens do not match")
	# print "here"
	verifier = request.GET.get('oauth_verifier')
	access_token = exchange_request_token_for_access_token(info['CONSUMER'], token, params={'oauth_verifier':verifier})
	# response = HttpResponseRedirect(reverse('twitter_oauth_friend_list'))
	response = HttpResponseRedirect(reverse('twitter.views.friend_list'))
	# print response
	request.session['access_token'] = access_token.to_string()
	return response

def friend_list(request):
	# print "friend list function called"
	
	
	users = []
	statuses = []
	
	access_token = request.session.get('access_token', None)
	# print "access_token",access_token
	if not access_token:
		return HttpResponse("You need an access token!")
	token = oauth.OAuthToken.from_string(access_token)	 
	# print "token",token
	# Check if the token works on Twitter
	auth = None
	try:
		# auth = is_authenticated(CONSUMER, CONNECTION, token)
 		auth = is_authenticated(info['CONSUMER'], info['CONNECTION'], token)
	except Exception:
		
		# print "not working"
		response = HttpResponseRedirect(reverse('twitter.views.auth'))
		return response
		### 
		# return not working condition
		
	if auth:
		# print "authed"
		

		# this_string = 'hello world'
		# update_status(CONSUMER, CONNECTION, token, this_string)
		# print "hello world"
		
		# Load the cre`didentials from Twitter into JSON
		creds = simplejson.loads(auth)
		
		name = creds.get('name', creds['screen_name']) # Get the name
		screen_name = creds.get('screen_name')
		request.session['real_name'] = name
		request.session['screen_name'] = screen_name
		# print creds
		with transaction.commit_on_success():
			try:
				subject = get_object_or_404(Subject, twitter_id = name)
				# print "existing subject:",name
			except Exception:
				subject = Subject.objects.create(twitter_id = name, counter = 0)
				# print "creating new subject:",name
			# print "subject information:", subject
			subject.counter = subject.counter + 1
			# print "subject information:", subject
			subject.save()
			
		# print Subject.objects.all()

		# print creds
		
		# Get number of friends. The API only returns 100 results per page,
		# so we might need to divide the queries up.
		friends_count = str(creds.get('friends_count', '100'))
		# print friends_count
		pages = int( (int(friends_count)/100) ) + 1
		pages = min(pages, 10) # We only want to make ten queries
		for page in range(pages):
			friends = get_friends(info['CONSUMER'], info['CONNECTION'], token, name, page+1)
			# print "friends:",friends
			# if the result is '[]', we've reached the end of the users friends
			if friends == '[]': break
			
			# Load into JSON
			json = simplejson.loads(friends)
			# print "JSON1:",json
			users.append(json)
		
		statuses_count = str(creds.get('statuses_count', '100'))
		# print "num statuses:",statuses_count
		# pages = int((int(statuses_count) / 200)) + 1
		# pages = min(pages, 10)
		pages = 1
		for page in range(pages):
			status = get_statuses(info['CONSUMER'], info['CONNECTION'], token, name, page+1)
			# print "1:",status
			if status == '[]':break
			json = simplejson.loads(status)
			statuses.append(json)
			# print "JSON2:",json
			
	# print "users:",users	
	# print "statuses:",statuses
	
	
	
	return render_to_response('twitter/list.html', {'users': users, 'statuses':statuses[0]})

	# return render_to_response('twitter/list.html', {'num_users': len(users)})