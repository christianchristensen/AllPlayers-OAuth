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
  $timestamp = time();
  $params = $oauth->getParamsToSign($request, $timestamp);
  $params['oauth_signature'] = $oauth->getSignature($request, $timestamp);
  $response = $client->get('request_token?' . http_build_query($params))->send();

  // Parse oauth tokens from response object
  $oauth_tokens = array();
  parse_str($response->getBody(TRUE), $oauth_tokens);
  $app['session']->set('access_token', $oauth_tokens['oauth_token']);
  $app['session']->set('access_secret', $oauth_tokens['oauth_token_secret']);

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
  $client = new Client('https://www.allplayers.com/oauth', array(
    'curl.CURLOPT_SSL_VERIFYPEER' => TRUE,
    'curl.CURLOPT_CAINFO' => 'assets/mozilla.pem',
    'curl.CURLOPT_FOLLOWLOCATION' => FALSE,
  ));

  $oauth = new OauthPlugin(array(
    'consumer_key' => CONS_KEY,
    'consumer_secret' => CONS_SECRET,
    'token' => $oauth_token,
    'token_secret' => $secret,
  ));
  $client->addSubscriber($oauth);

  $response = $client->get('access_token')->send();

  // Parse oauth tokens from response object
  $oauth_tokens = array();
  parse_str($response->getBody(TRUE), $oauth_tokens);
  $app['session']->set('auth_token', $oauth_tokens['oauth_token']);
  $app['session']->set('auth_secret', $oauth_tokens['oauth_token_secret']);
  return $app->redirect('/req');
});

$app->get('/req', function () use ($app) {
  $app['session']->start();
  $token = $app['session']->get('auth_token');
  // check if we have our auth keys
  if (null === ($secret = $app['session']->get('auth_secret'))) {
    return $app->redirect('/');
  }

  $client = new Client('https://www.allplayers.com/api/v1/rest', array(
    'curl.CURLOPT_SSL_VERIFYPEER' => TRUE,
    'curl.CURLOPT_CAINFO' => 'assets/mozilla.pem',
    'curl.CURLOPT_FOLLOWLOCATION' => FALSE,
  ));

  $oauth = new OauthPlugin(array(
    'consumer_key' => CONS_KEY,
    'consumer_secret' => CONS_SECRET,
    'token' => $token,
    'token_secret' => $secret,
  ));
  $client->addSubscriber($oauth);

  $response = $client->get('users/current.json')->send();
  // Note: getLocation returns full URL info, but seems to work as a request in Guzzle
  $response = $client->get($response->getLocation())->send();
  $json = json_decode($response->getBody(TRUE));

  // HACK: set username to group UUID (eventually move this to users/current.json)
  $app['session']->set('username', $json->uuid);
  return $app->redirect('/');
});


$app->run();

