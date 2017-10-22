<?php

if (! function_exists('url')) {
    /**
     * Generate a url for the application.
     *
     * @param  string  $path
     * @param  mixed   $parameters
     * @param  bool    $secure
     * @return string
     */
    function url($path = null, $parameters = [], $secure = null)
    {
        return app('url')->to($path, $parameters, $secure);
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