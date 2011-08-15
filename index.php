<?php
define('CONS_KEY', 'Application consumer key');
define('CONS_SECRET', 'Application consumer secret');

require_once __DIR__.'/silex.phar'; 

$app = new Silex\Application(); 

// register the session extension
$app->register(new Silex\Extension\SessionExtension());

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

	$oauth = new OAuth(CONS_KEY, CONS_SECRET, OAUTH_SIG_METHOD_HMACSHA1, OAUTH_AUTH_TYPE_URI);
	$request_token = $oauth->getRequestToken('https://twitter.com/oauth/request_token');

	$app['session']->set('secret', $request_token['oauth_token_secret']);

	return $app->redirect('https://twitter.com/oauth/authenticate?oauth_token=' . $request_token['oauth_token']);
});

$app->get('/auth', function() use ($app, $pdo) {
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