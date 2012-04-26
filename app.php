<?php
use Symfony\Component\HttpFoundation\Tests\RequestContentProxy;

use Symfony\Component\HttpFoundation\Request;

define('CONS_KEY', 'deadbeef');
define('CONS_SECRET', 'deadbeef');

require_once __DIR__.'/vendor/autoload.php';

$app = new Silex\Application();

// register the session extension
$app->register(new Silex\Provider\SessionServiceProvider());

$app->get('/', function() use($app) {
	$username = $app['session']->get('username');

	if ($username == null) {
		return 'Welcome Guest. <a href="/login">Login</a>';
	} else {
		return 'Welcome ' . $app->escape($username);
	}
});

$app->get('/login', function () use ($app) {
	// check if the user is already logged-in
	if (null !== ($username = $app['session']->get('username'))) {
		return $app->redirect('/');
	}

	$consumer = new \Eher\OAuth\Consumer(CONS_KEY, CONS_SECRET, OAUTH_SIG_METHOD_HMACSHA1, OAUTH_AUTH_TYPE_URI);
	$request_token = \Eher\OAuth\Request::from_consumer_and_token($consumer, NULL, 'GET', 'https://www.allplayers.com/oauth/request_token', '');
	$request_token->sign_request(new \Eher\OAuth\HmacSha1(), $consumer, NULL);
	$response = \Httpful\Request::get($request_token->to_url())->sendIt();
	$response = explode('&', $response);
	$oauth_token = array_pop(explode('=', $response[0]));
	$oauth_token_secret = array_pop(explode('=', $response[1]));

	$app['session']->set('secret', $oauth_token_secret);
	return $app->redirect('https://www.allplayers.com/oauth/authorize?oauth_token=' . $oauth_token);
});

$app->get('/auth', function() use ($app) {
	// check if the user is already logged-in
	if (null !== ($username = $app['session']->get('username'))) {
		return $app->redirect('/');
	}

	$oauth_token = $app['request']->get('oauth_token');

	if ($oauth_token == null) {
		$app->abort(400, 'Invalid token');
	}

	$secret = $app['session']->get('secret');

	$oauth = new OAuth(CONS_KEY, CONS_SECRET, OAUTH_SIG_METHOD_HMACSHA1, OAUTH_AUTH_TYPE_URI);
	$oauth->setToken($oauth_token, $secret);

	try {
		$oauth_token_info = $oauth->getAccessToken('https://twitter.com/oauth/access_token');
	} catch (OAuthException $e) {
		$app->abort(401, $e->getMessage());
	}

	// retrieve Twitter user details
	$oauth->setToken($oauth_token_info['oauth_token'], $oauth_token_info['oauth_token_secret']);
	$oauth->fetch('https://twitter.com/account/verify_credentials.json');
	$json = json_decode($oauth->getLastResponse());

	$app['session']->set('username', $json->screen_name);

	return $app->redirect('/');
});

$app->run();
