<?php

use Illuminate\Support\Str;
use Illuminate\Support\HtmlString;
use Illuminate\Container\Container;
use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Cookie\CookieJar as Cookie;
//use Illuminate\Contracts\Auth\Access\Gate;
//use Illuminate\Contracts\Routing\UrlGenerator;
//use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Database\Eloquent\Factory as EloquentFactory;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;
//use Illuminate\Contracts\Broadcasting\Factory as BroadcastFactory;

if (! function_exists('app_path')) {
    /**
     * Get the path to the application folder.
     *
     * @param  string  $path
     * @return string
     */
    function app_path($path = '')
    {
        return app('path').($path ? DIRECTORY_SEPARATOR.$path : $path);
    }
}

if (! function_exists('config_path')) {
    /**
     * Get the configuration path.
     *
     * @param  string  $path
     * @return string
     */
    function config_path($path = '')
    {
    	$app_path = app_path();
    	$app_path = explode(DIRECTORY_SEPARATOR, $app_path);
    	array_pop($app_path);
    	$config_path = implode(DIRECTORY_SEPARATOR, $app_path).DIRECTORY_SEPARATOR.'config';
        return $config_path.($path ? DIRECTORY_SEPARATOR.$path : $path);
    }
}

if (! function_exists('public_path')) {
    /**
     * Get the path to the public folder.
     *
     * @param  string  $path
     * @return string
     */
    function public_path($path = '')
    {
    	$app_path = app_path();
    	$app_path = explode(DIRECTORY_SEPARATOR, $app_path);
    	array_pop($app_path);
    	$config_path = implode(DIRECTORY_SEPARATOR, $app_path).DIRECTORY_SEPARATOR.'public';
        return $config_path.($path ? DIRECTORY_SEPARATOR.$path : $path);
    }
}

if (! function_exists('__')) {
    /**
     * Translate the given message.
     *
     * @param  string  $key
     * @param  array  $replace
     * @param  string  $locale
     * @return \Illuminate\Contracts\Translation\Translator|string
     */
    function __($key = null, $replace = [], $locale = null)
    {
        return app('translator')->getFromJson($key, $replace, $locale);
    }
}

if (! function_exists('action')) {
    /**
     * Generate the URL to a controller action.
     *
     * @param  string  $name
     * @param  array   $parameters
     * @param  bool    $absolute
     * @return string
     */
    function action($name, $parameters = [], $absolute = true)
    {
    	$routes = app('router')->getRoutes();
    	$found = false;

    	foreach($routes as $r){
    		if (!isset($r['action']['uses'])){
    			continue;
    		}
    		if ($r['action']['uses'] == 'App\\Http\\Controllers\\'.$name and isset($r['action']['as'])){
    			$found = true;
    			$route = $r['action']['as'];
    			break;
    		}
    	}

    	if (!$found){
            throw new InvalidArgumentException("Action {$name} not defined.");
    	}

    	//list($class, $method) = explode('@', $name);
    	//if (!method_exists('App\\Http\\Controllers\\'.$class, $method)){
        //    throw new InvalidArgumentException("Action {$name} not defined.");
    	//}

        return str_replace(['[', ']'], '', app('url')->route($route, $parameters, $absolute));
    }
}

/** /
if (! function_exists('mix')) {
    /**
     * Get the path to a versioned Mix file.
     *
     * @param  string  $path
     * @param  string  $manifestDirectory
     * @return \Illuminate\Support\HtmlString
     *
     * @throws \Exception
     * /
    function mix($path, $manifestDirectory = '')
    {
        static $manifest;

        if (! starts_with($path, '/')) {
            $path = "/{$path}";
        }

        if ($manifestDirectory && ! starts_with($manifestDirectory, '/')) {
            $manifestDirectory = "/{$manifestDirectory}";
        }
        dd($manifestDirectory.'/hot');

        if (file_exists(public_path($manifestDirectory.'/hot'))) {
            return new HtmlString("http://localhost:8080{$path}");
        }

        if (! $manifest) {
            if (! file_exists($manifestPath = public_path($manifestDirectory.'/mix-manifest.json'))) {
                throw new Exception('The Mix manifest does not exist.');
            }

            $manifest = json_decode(file_get_contents($manifestPath), true);
        }

        if (! array_key_exists($path, $manifest)) {
            throw new Exception(
                "Unable to locate Mix file: {$path}. Please check your ".
                'webpack.mix.js output paths and try again.'
            );
        }

        return new HtmlString($manifestDirectory.$manifest[$path]);
    }
}
/**/

if (! function_exists('secure_url')) {
    /**
     * Generate a url for the application.
     *
     * @param  string  $path
     * @param  mixed   $parameters
     * @param  bool    $secure
     * @return string
     */
    function secure_url($path = null, $parameters = [])
    {
        return url($path, $parameters, true);
    }
}

if (! function_exists('asset')) {
    /**
     * Generate a URL to an application asset.
     *
     * @param  string  $path
     * @param  mixed   $parameters
     * @param  bool    $secure
     * @return string
     */
    function asset($path, $secure = null)
    {
        return app('url')->asset($path, $secure);
    }
}

if (! function_exists('secure_asset')) {
    /**
     * Generate a url for the application.
     *
     * @param  string  $path
     * @param  mixed   $parameters
     * @param  bool    $secure
     * @return string
     */
    function secure_asset($path = null)
    {
        return asset($path, true);
    }
}

if (! function_exists('bcrypt'))
{
    /**
     * Generate hash from string.
     *
     * @param  string  $str
     * @param  integer $cost
     * @return string
     */
    function bcrypt($str, $cost = 10){
        $salt = substr(str_shuffle('./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), 0, 22);
        if (function_exists('password_hash'))
        {
            if (phpversion() >= '7.0.0')
                $opt = array(
                        'cost' => $cost,
                    );
            else
                $opt = array(
                        'cost' => $cost,
                        'salt' => $salt,
                    );
            return password_hash($str, PASSWORD_BCRYPT, $opt);
        }
        else
            return crypt($str, sprintf('$2y$%02d$', $cost).$salt);
    }
}

if (! function_exists('bverify'))
{
    /**
     * Check if hash is generated from string.
     *
     * @param  string  $password
     * @param  string  $hash
     * @return boolean
     */
    function bverify($password, $hash)
    {
        if (function_exists('password_verify'))
            return password_verify($password, $hash);
        else
            return (crypt($password, $hash) == $hash);
    }
}

if (! function_exists('abort_if')) {
    /**
     * Throw an HttpException with the given data if the given condition is true.
     *
     * @param  bool    $boolean
     * @param  int     $code
     * @param  string  $message
     * @param  array   $headers
     * @return void
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException
     * @throws \Symfony\Component\HttpKernel\Exception\NotFoundHttpException
     */
    function abort_if($boolean, $code, $message = '', array $headers = [])
    {
        if ($boolean) {
            abort($code, $message, $headers);
        }
    }
}

if (! function_exists('abort_unless')) {
    /**
     * Throw an HttpException with the given data unless the given condition is true.
     *
     * @param  bool    $boolean
     * @param  int     $code
     * @param  string  $message
     * @param  array   $headers
     * @return void
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException
     * @throws \Symfony\Component\HttpKernel\Exception\NotFoundHttpException
     */
    function abort_unless($boolean, $code, $message = '', array $headers = [])
    {
        if (! $boolean) {
            abort($code, $message, $headers);
        }
    }
}

if (! function_exists('csrf_field')) {
    /**
     * Generate a CSRF token form field.
     *
     * @return \Illuminate\Support\HtmlString
     */
    function csrf_field()
    {
   		return new HtmlString('<input type="hidden" name="_token" value="'.csrf_token().'">');
    }
}

if (! function_exists('csrf_token')) {
    /**
     * Get the CSRF token value.
     *
     * @return string
     *
     * @throws \RuntimeException
     */
    function csrf_token()
    {
    	if (session_status() == PHP_SESSION_NONE){
	        throw new RuntimeException('Application session not yet started.');
    	}
    	if (! isset($_SESSION['csrf_token'])){
	    	$_SESSION['csrf_token'] = substr(str_shuffle('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), 32);
	    }
	    return $_SESSION['csrf_token'];
    }
}

if (! function_exists('auth')) {
    /**
     * Get the available auth instance.
     *
     * @param  string|null  $guard
     * @return \Illuminate\Contracts\Auth\Factory|\Illuminate\Contracts\Auth\Guard|\Illuminate\Contracts\Auth\StatefulGuard
     */
    function auth($guard = null)
    {
        if (is_null($guard)) {
            return app(AuthFactory::class);
        } else {
            return app(AuthFactory::class)->guard($guard);
        }
    }
}

/** /
if (! function_exists('back')) {
    /**
     * Create a new redirect response to the previous location.
     *
     * @param  int    $status
     * @param  array  $headers
     * @param  mixed  $fallback
     * @return \Illuminate\Http\RedirectResponse
     * /
    function back($status = 302, $headers = [], $fallback = false)
    {
        return app('redirect')->back($status, $headers, $fallback);
    }
}

if (! function_exists('broadcast')) {
    /**
     * Begin broadcasting an event.
     *
     * @param  mixed|null  $event
     * @return \Illuminate\Broadcasting\PendingBroadcast|void
     * /
    function broadcast($event = null)
    {
        return app(BroadcastFactory::class)->event($event);
    }
}
/**/

if (! function_exists('cache')) {
    /**
     * Get / set the specified cache value.
     *
     * If an array is passed, we'll assume you want to put to the cache.
     *
     * @param  dynamic  key|key,default|data,expiration|null
     * @return mixed
     *
     * @throws \Exception
     */
    function cache()
    {
        $arguments = func_get_args();

        if (empty($arguments)) {
            return app('cache');
        }

        if (is_string($arguments[0])) {
            return app('cache')->get($arguments[0], isset($arguments[1]) ? $arguments[1] : null);
        }

        if (is_array($arguments[0])) {
            if (! isset($arguments[1])) {
                throw new Exception(
                    'You must set an expiration time when putting to the cache.'
                );
            }

            return app('cache')->put(key($arguments[0]), reset($arguments[0]), $arguments[1]);
        }
    }
}

if (! function_exists('cookie')) {
    /**
     * Create a new cookie instance.
     *
     * @param  string  $name
     * @param  string  $value
     * @param  int     $minutes
     * @param  string  $path
     * @param  string  $domain
     * @param  bool    $secure
     * @param  bool    $httpOnly
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    function cookie($name = null, $value = null, $minutes = 0, $path = null, $domain = null, $secure = false, $httpOnly = true)
    {
        $cookie = app(Cookie::class);

        if (is_null($name)) {
            return $cookie;
        }

        return $cookie->make($name, $value, $minutes, $path, $domain, $secure, $httpOnly);
    }
}
