import oauth
import urllib

from django.conf import settings


signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()

SERVER = getattr(settings, 'OAUTH_SERVER', 'twitter.com')
REQUEST_TOKEN_URL = getattr(settings, 'OAUTH_REQUEST_TOKEN_URL', 'https://%s/oauth/request_token' % SERVER)
ACCESS_TOKEN_URL = getattr(settings, 'OAUTH_ACCESS_TOKEN_URL', 'https://%s/oauth/access_token' % SERVER)
AUTHORIZATION_URL = getattr(settings, 'OAUTH_AUTHORIZATION_URL', 'http://%s/oauth/authorize' % SERVER)

CONSUMER_KEY = getattr(settings, 'CONSUMER_KEY', '0xG2Zper8Oxe3T6okndpJw')
CONSUMER_SECRET = getattr(settings, 'CONSUMER_SECRET', 'E9kOBpLsJzjpofChoIfanMAKm506FpO1vcQ8KKo0')
# print "consumer_key:",CONSUMER_KEY
# print "consumer_secret:",CONSUMER_SECRET
# We use this URL to check if Twitters oAuth worked
# TWITTER_CHECK_AUTH = 'https://twitter.com/account/verify_credentials.json'
TWITTER_CHECK_AUTH = 'https://api.twitter.com/1/account/verify_credentials.json'
# TWITTER_FRIENDS = 'https://twitter.com/statuses/friends.json'
TWITTER_UPDATE_STATUS = 'https://api.twitter.com/1/statuses/update.json'
TWITTER_FRIENDS = 'https://api.twitter.com/1/friends/ids.json?cursor=-1&screen_name='
TWITTER_STATUSES = 'https://api.twitter.com/1/statuses/user_timeline.json?include_entities=true&include_rts=true&screen_name='
def request_oauth_resource(consumer, url, access_token, parameters=None, signature_method=signature_method, http_method="GET"):
	"""
	usage: request_oauth_resource( consumer, '/url/', your_access_token, parameters=dict() )
	Returns a OAuthRequest object
	"""
	oauth_request = oauth.OAuthRequest.from_consumer_and_token(
		consumer, token=access_token, http_method=http_method, http_url=url, parameters=parameters,
	)
	oauth_request.sign_request(signature_method, consumer, access_token)
	return oauth_request


def fetch_response(oauth_request, connection):
	url = oauth_request.to_url()
	# print "url=",url
	connection.request(oauth_request.http_method, url)
	response = connection.getresponse()
	# print "reseponse:",response
	s = response.read()
	return s

def get_unauthorised_request_token(consumer, connection, signature_method=signature_method):
	# print 1, consumer
	# print 1, connection
	oauth_request = oauth.OAuthRequest.from_consumer_and_token(
		consumer, http_url=REQUEST_TOKEN_URL
	)
	# print 2, oauth_request
	oauth_request.sign_request(signature_method, consumer, None)
	# print 3
	resp = fetch_response(oauth_request, connection)
	# print 4, resp
	token = oauth.OAuthToken.from_string(resp)
	# print 5, token
	return token


def get_authorisation_url(consumer, token, xture_method=signature_method):
	oauth_request = oauth.OAuthRequest.from_consumer_and_token(
		consumer, token=token, http_url=AUTHORIZATION_URL
	)
	oauth_request.sign_request(signature_method, consumer, token)
	return oauth_request.to_url()

def get_oauth_url(oauth_request):
	url = oauth_request.to_url()
	package = urllib.urlopen(url)
	return package.read()

def exchange_request_token_for_access_token(consumer, request_token, signature_method=signature_method, params={}):
	oauth_request = oauth.OAuthRequest.from_consumer_and_token(
		consumer, token=request_token, http_url=ACCESS_TOKEN_URL, parameters=params
	)
	oauth_request.sign_request(signature_method, consumer, request_token)
	resp = get_oauth_url(oauth_request)
	return oauth.OAuthToken.from_string(resp) 

def is_authenticated(consumer, connection, access_token):
	oauth_request = request_oauth_resource(consumer, TWITTER_CHECK_AUTH, access_token)
	json = fetch_response(oauth_request, connection)
	if 'screen_name' in json:
		return json
	return False

def get_friends(consumer, connection, access_token, screen_name, page=0):
	"""Get friends on Twitter"""
	oauth_request = request_oauth_resource(consumer, TWITTER_FRIENDS+screen_name, access_token, {'page': page})
	json = fetch_response(oauth_request, connection)
	# print "json:", json
	return json
	
def get_statuses(consumer, connection, access_token, screen_name, page=0):
	"""Get statuses on Twitter"""
	oauth_request = request_oauth_resource(consumer, TWITTER_STATUSES+screen_name+'&count=2', access_token, {'page': page})
	json = fetch_response(oauth_request, connection)
	# print "json:", json
	return json

def update_status(consumer, connection, access_token, status):
	"""Update twitter status, i.e., post a tweet"""
	oauth_request = request_oauth_resource(consumer,
										   TWITTER_UPDATE_STATUS,
										   access_token,
										   {'status': status},
										   http_method='POST')
	json = fetch_response(oauth_request, connection)
	return json