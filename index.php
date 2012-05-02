<?php
use Symfony\Component\HttpFoundation\Tests\RequestContentProxy;
use Symfony\Component\HttpFoundation\Request;

define('CONS_KEY', 'deadbeef');
define('CONS_SECRET', 'deadbeef');

require_once __DIR__.'/vendor/autoload.php';

$app = new Silex\Application();

// Debug helper provided by Silex
$app['debug'] = TRUE;

// register the session extension
$app->register(new Silex\Provider\SessionServiceProvider());

$app->get('/', function() use($app) {
  $app['session']->start();
  $username = $app['session']->get('username');

  if ($username == null) {
    return 'Welcome Guest. <a href="/login">Login</a>';
  } else {
    return 'Welcome ' . $app->escape($username);
  }
});

$app->get('/login', function () use ($app) {
  $app['session']->start();
  // check if the user is already logged-in
  if (null !== ($username = $app['session']->get('username'))) {
    return $app->redirect('/');
  }

  $oauth = new HTTP_OAuth_Consumer(CONS_KEY, CONS_SECRET);
  $oauth->accept(new HTTP_Request2(NULL, NULL, array(
    'ssl_cafile' => 'assets/mozilla.pem',
  )));
  $oauth->getRequestToken('https://www.allplayers.com/oauth/request_token');
  $oauth_token = $oauth->getToken();
  $oauth_token_secret = $oauth->getTokenSecret();

  $app['session']->set('access_token', $oauth_token);
  $app['session']->set('access_secret', $oauth_token_secret);

  return $app->redirect('https://www.allplayers.com/oauth/authorize?oauth_token=' . $oauth_token);
});

$app->get('/auth', function() use ($app) {
  $app['session']->start();
  // check if the user is already logged-in or we're already auth
  if ((null !== $app['session']->get('username')) || (null !== $app['session']->get('auth_secret'))) {
    return $app->redirect('/');
  }

  $oauth_token = $app['session']->get('access_token');
  $secret = $app['session']->get('access_secret');
  if ($oauth_token == null) {
    $app->abort(400, 'Invalid token');
  }

  $oauth = new HTTP_OAuth_Consumer(CONS_KEY, CONS_SECRET);
  $oauth->accept(new HTTP_Request2(NULL, NULL, array(
    'ssl_cafile' => 'assets/mozilla.pem',
  )));
  $oauth->setToken($oauth_token);
  $oauth->setTokenSecret($secret);
  try {
    $oauth->getAccessToken('https://www.allplayers.com/oauth/access_token');
  } catch (OAuthException $e) {
    $app->abort(401, $e->getMessage());
  }

  // Set authorized token details for subsequent requests
  $app['session']->set('auth_token', $oauth->getToken());
  $app['session']->set('auth_secret', $oauth->getTokenSecret());

  return $app->redirect('/req');
});

$app->get('/req', function () use ($app) {
  $app['session']->start();
  $token = $app['session']->get('auth_token');
  // check if we have our auth keys
  if (null === ($secret = $app['session']->get('auth_secret'))) {
    return $app->redirect('/');
  }
  $oauth = new HTTP_OAuth_Consumer(CONS_KEY, CONS_SECRET);
  $oauth->accept(new HTTP_Request2(NULL, NULL, array(
    'ssl_cafile' => 'assets/mozilla.pem',
  )));
  $oauth->setToken($token);
  $oauth->setTokenSecret($secret);
  // TODO: Push this upstream to SDK lib
  $oauth->sendRequest('https://www.allplayers.com/?q=api/v1/rest/groups/54395c18-f611-11e0-a44b-12313d04fc0f.json', array(), 'GET');
  $response = $oauth->getLastResponse();
  $json = json_decode($response->getResponse()->getBody());

  // HACK: set username to group UUID (eventually move this to users/current.json)
  $app['session']->set('username', $json->uuid);
  return $app->redirect('/');
});


$app->run();

