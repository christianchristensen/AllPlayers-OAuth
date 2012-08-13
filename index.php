<?php
use Symfony\Component\HttpFoundation\Tests\RequestContentProxy;
use Symfony\Component\HttpFoundation\Request;
use Guzzle\Http\Client;
use Guzzle\Http\Plugin\OauthPlugin;

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

  $sourcelink = '<br /><br />Source: <a href="https://gist.github.com/2495726#file_index.php">gist.github.com/2495726</a>';
  if ($username == null) {
    return 'Welcome Guest. <a href="/login">Login</a>' . $sourcelink;
  } else {
    return 'Welcome ' . $app->escape($username) . $sourcelink;
  }
});

$app->get('/login', function() use ($app) {
  $app['session']->start();
  // check if the user is already logged-in
  if (null !== ($username = $app['session']->get('username'))) {
    return $app->redirect('/');
  }

  $client = new Client('https://www.allplayers.com/oauth', array(
    'curl.CURLOPT_SSL_VERIFYPEER' => TRUE,
    'curl.CURLOPT_CAINFO' => 'assets/mozilla.pem',
    'curl.CURLOPT_FOLLOWLOCATION' => FALSE,
  ));

  $oauth = new OauthPlugin(array(
    'consumer_key' => CONS_KEY,
    'consumer_secret' => CONS_SECRET,
    'token' => FALSE,
    'token_secret' => FALSE,
  ));

  // if $request path !set then set to request_token
  $request = $client->get('request_token');
  $timestamp = date('U');
  $params = $oauth->getParamsToSign($request, $timestamp);
  $string = $oauth->getSignature($request, $timestamp);
  $params['oauth_signature'] = $string;
  $response = $client->get('request_token?' . http_build_query($params))->send();

  // Parse oauth tokens from response object
  $oauth_tokens = array();
  parse_str($response->getBody(TRUE), $oauth_tokens);
  $app['session']->set('access_token', $oauth_tokens['oauth_token']);
  $app['session']->set('access_secret', $oauth_token['oauth_token_secret']);

  return $app->redirect('https://www.allplayers.com/oauth/authorize?oauth_token=' . $oauth_tokens['oauth_token']);
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

