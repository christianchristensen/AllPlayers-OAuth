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

// Setup app default settings
$app->before(function (Request $request) use($app) {
  $app['session']->start();
  $domain = $app['session']->get('domain');
  if ($domain == null) {
    // if (detect query param...) set env
    if ($env = $request->query->get('envuri')) {
      $app['session']->set('domain', $env);
    }
    else {
      $app['session']->set('domain', 'https://www.allplayers.com');
    }
  }
  $consumer_key = $app['session']->get('consumer_key');
  if ($consumer_key == null) {
    if ($key = $request->query->get('key')) {
      $secret = $request->query->get('secret');
      $app['session']->set('consumer_key', $key);
      $app['session']->set('consumer_secret', $secret);
    }
    else {
      $app['session']->set('consumer_key', CONS_KEY);
      $app['session']->set('consumer_secret', CONS_SECRET);
    }
  }
});

$app->get('/', function() use($app) {
  $app['session']->start();
  $username = $app['session']->get('username');

  $info = '<br /> Context: ' . $app['session']->get('domain');
  $sourcelink = '<br /><br /><a href="https://gist.github.com/2495726#file_index.php">Source code</a>';
  $info .= $sourcelink;
  if ($username == null) {
    return 'Welcome Guest. <a href="/login">Login</a>' . $info;
  } else {
    $temp_token = $app['session']->get('access_token');
    $temp_secret = $app['session']->get('access_secret');
    $token = $app['session']->get('auth_token');
    $secret = $app['session']->get('auth_secret');
    // twig/template this
    $keyinfo  = '<br /><br /> <a href="/keyinfo">Key info</a>';
    return 'Welcome ' . $app->escape($username) . $keyinfo . $info;
  }
});

$app->get('/keyinfo', function() use($app) {
  $app['session']->start();
  $username = $app['session']->get('username');

  if ($username == null) {
    return $app->redirect('/');
  } else {
    $consumer_key = $app['session']->get('consumer_key');
    $consumer_secret = $app['session']->get('consumer_secret');
    $temp_token = $app['session']->get('access_token');
    $temp_secret = $app['session']->get('access_secret');
    $token = $app['session']->get('auth_token');
    $secret = $app['session']->get('auth_secret');
    // twig/template this
    $keyinfo  = '<br /><br /> Key info: <ul>';
    $keyinfo .= '<li>Consumer Key: ' . $consumer_key . '</li>';
    $keyinfo .= '<li>Consumer Secret: ' . $consumer_secret . '</li>';
    $keyinfo .= '<li><strike>Temp Key: ' . $temp_token . '</strike></li>';
    $keyinfo .= '<li><strike>Temp Secret: ' . $temp_secret . '</strike></li>';
    $keyinfo .= '<li>Token: ' . $token . '</li>';
    $keyinfo .= '<li>Secret: ' . $secret . '</li>';
    $keyinfo .= '</ul>';
    return 'Welcome ' . $app->escape($username) . $keyinfo;
  }
});

$app->get('/login', function(Request $request) use ($app) {
  $app['session']->start();
  // check if the user is already logged-in
  if (null !== ($username = $app['session']->get('username'))) {
    return $app->redirect('/');
  }

  $client = new Client($app['session']->get('domain') . '/oauth', array(
    'curl.CURLOPT_SSL_VERIFYPEER' => TRUE,
    'curl.CURLOPT_CAINFO' => 'assets/mozilla.pem',
    'curl.CURLOPT_FOLLOWLOCATION' => FALSE,
  ));

  $oauth = new OauthPlugin(array(
    'consumer_key' => $app['session']->get('consumer_key'),
    'consumer_secret' => $app['session']->get('consumer_secret'),
    'token' => FALSE,
    'token_secret' => FALSE,
  ));

  // if $request path !set then set to request_token
  $timestamp = time();
  $params = $oauth->getParamsToSign($client->get('request_token'), $timestamp);
  $params['oauth_signature'] = $oauth->getSignature($client->get('request_token'), $timestamp);
  $response = $client->get('request_token?' . http_build_query($params))->send();

  // Parse oauth tokens from response object
  $oauth_tokens = array();
  parse_str($response->getBody(TRUE), $oauth_tokens);
  $app['session']->set('access_token', $oauth_tokens['oauth_token']);
  $app['session']->set('access_secret', $oauth_tokens['oauth_token_secret']);

  $authorize = '/oauth/authorize?oauth_token=' . $oauth_tokens['oauth_token'];
  $authorize .= '&oauth_callback=' . urlencode($request->getSchemeAndHttpHost() . '/auth');
  return $app->redirect($app['session']->get('domain') . $authorize);
});

$app->get('/logout', function() use($app) {
 $app['session']->start();
 session_destroy();
 return $app->redirect('/');
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
  $client = new Client($app['session']->get('domain') . '/oauth', array(
    'curl.CURLOPT_SSL_VERIFYPEER' => TRUE,
    'curl.CURLOPT_CAINFO' => 'assets/mozilla.pem',
    'curl.CURLOPT_FOLLOWLOCATION' => FALSE,
  ));

  $oauth = new OauthPlugin(array(
    'consumer_key' => $app['session']->get('consumer_key'),
    'consumer_secret' => $app['session']->get('consumer_secret'),
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

  $client = new Client($app['session']->get('domain') . '/api/v1/rest', array(
    'curl.CURLOPT_SSL_VERIFYPEER' => TRUE,
    'curl.CURLOPT_CAINFO' => 'assets/mozilla.pem',
    'curl.CURLOPT_FOLLOWLOCATION' => FALSE,
  ));

  $oauth = new OauthPlugin(array(
    'consumer_key' => $app['session']->get('consumer_key'),
    'consumer_secret' => $app['session']->get('consumer_secret'),
    'token' => $token,
    'token_secret' => $secret,
  ));
  $client->addSubscriber($oauth);

  $response = $client->get('users/current.json')->send();
  // Note: getLocation returns full URL info, but seems to work as a request in Guzzle
  $response = $client->get($response->getLocation())->send();
  $json = json_decode($response->getBody(TRUE));

  // HACK: set username to group UUID (eventually move this to users/current.json)
  $app['session']->set('username', $json->username . " ($json->uuid)");
  return $app->redirect('/');
});

$app->get('/copygroup', function () use ($app) {
  $app['session']->start();
  $token = $app['session']->get('auth_token');
  // check if we have our auth keys
  if (null === ($secret = $app['session']->get('auth_secret'))) {
   return $app->redirect('/');
  }

  $output = '';

  // Flash messages support
  $flash = $app[ 'session' ]->get( 'flash' );
  $app[ 'session' ]->set( 'flash', null );

  if ( !empty( $flash ) )
  {
    $output .= $flash['short'] . '<hr /><br />';
  }


  $client = new Client($app['session']->get('domain') . '/api/v1/rest', array(
    'curl.CURLOPT_SSL_VERIFYPEER' => TRUE,
    'curl.CURLOPT_CAINFO' => 'assets/mozilla.pem',
    'curl.CURLOPT_FOLLOWLOCATION' => FALSE,
  ));

  $oauth = new OauthPlugin(array(
    'consumer_key' => $app['session']->get('consumer_key'),
    'consumer_secret' => $app['session']->get('consumer_secret'),
    'token' => $token,
    'token_secret' => $secret,
  ));
  $client->addSubscriber($oauth);

  $response = $client->get('users/current/groups.json?limit=1000')->send();
  // Note: getLocation returns full URL info, but seems to work as a request in Guzzle
  $response = $client->get($response->getLocation())->send();
  $groups = json_decode($response->getBody(TRUE));

  $options = '';
  foreach ($groups as $group) {
    $uuid = $group->uuid;
    $title = $group->title;
    $options .= "<option value=\"$uuid\">$title</option>";
  }
  $output .= <<<HEREDOC
<form name="copyform" method="POST" action="/copygroup">
  <select name="copy_from">
    $options
  </select>
  <select name="copy_to">
    $options
  </select>
  <input type="submit" value="Submit">
</form>
HEREDOC;

  return $output;
});

$app->post('/copygroup', function (Request $request) use ($app) {
  $app['session']->start();
  $token = $app['session']->get('auth_token');
  // check if we have our auth keys
  if (null === ($secret = $app['session']->get('auth_secret'))) {
   return $app->redirect('/');
  }

  $copy_from = $request->get('copy_from');
  $copy_to = $request->get('copy_to');
  if (!empty($copy_from) && !empty($copy_to)) {
    $client = new Client($app['session']->get('domain') . '/api/v1/rest', array(
      'curl.CURLOPT_SSL_VERIFYPEER' => TRUE,
      'curl.CURLOPT_CAINFO' => 'assets/mozilla.pem',
      'curl.CURLOPT_FOLLOWLOCATION' => FALSE,
    ));

    $oauth = new OauthPlugin(array(
      'consumer_key' => $app['session']->get('consumer_key'),
      'consumer_secret' => $app['session']->get('consumer_secret'),
      'token' => $token,
      'token_secret' => $secret,
    ));
    $client->addSubscriber($oauth);

    $response = $client->post("groups/$copy_to/copy/$copy_from")->send();

    $app[ 'session' ]->set( 'flash', array(
      'type'  =>'info',
      'short' =>'Group Copied!',
    ) );
  }
  return $app->redirect('/copygroup');
});

$app->run();

