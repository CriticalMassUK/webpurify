<?php

namespace WebPurify;

class WebPurify
{

    const END_POINT_DOMAIN_UNITED_STATES = 'api1.webpurify.com';
    const END_POINT_DOMAIN_EUROPE        = 'api1-eu.webpurify.com';
    const END_POINT_DOMAIN_ASIA_PACIFIC  = 'api1-ap.webpurify.com';

    /* API Key */
    protected $apiKey;
    /* End point domain */
    protected $endPointDomain;
    /* use SSL */
    protected $useSSL = false;
    /* SSL verify peer */
    protected $sslVerifyPeer = false;

    /* last http request url */
    protected $url;
    /* last http  response code */
    protected $httpCode;
    /* last http  response information */
    protected $httpInfo;

    protected $userAgent;
    protected $connectTimeout;
    protected $timeout;

    protected $sandbox = false;

    public function __construct($api_key)
    {
        // Set the API key
        $this->setApiKey($api_key);

        // Use the US endpoint
        $this->setEndPointDomain(static::END_POINT_DOMAIN_UNITED_STATES);
    }

    /* accessors and mutators */

    public function getApiKey()
    {
        return $this->apiKey;
    }

    public function setApiKey($apiKey)
    {
        $this->apiKey = $apiKey;
    }

    /* endpoints */

    public function getEndPointDomain()
    {
        return $this->endPointDomain;
    }

    public function setEndPointDomain($endPointDomain)
    {
        $this->endPointDomain = $endPointDomain;
    }

    public function setSandbox($sandbox)
    {
        $this->sandbox = $sandbox;
    }

    public function getSandbox($sandbox)
    {
        return $this->sandbox;
    }

    /* helpers */

    public function http($method, array $params = array())
    {
        $params['api_key'] = $this->getApiKey();
        $params['method'] = sprintf(
            'webpurify.%s.%s',
            $this->sandbox ? 'sandbox' : 'live',
            $method
        );

        $url = sprintf(
            "%s://%s/services/rest/?%s",
            $this->useSSL ? 'https' : 'http',
            $this->getEndPointDomain(),
            http_build_query($params)
        );

        $this->httpInfo = array();

        /* CURL setup */
        $ci = curl_init();
        curl_setopt($ci, CURLOPT_USERAGENT, $this->userAgent);
        curl_setopt($ci, CURLOPT_CONNECTTIMEOUT, $this->connectTimeout);
        curl_setopt($ci, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ci, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ci, CURLOPT_SSL_VERIFYPEER, $this->sslVerifyPeer);
        curl_setopt($ci, CURLOPT_HEADERFUNCTION, array($this, 'getHeader'));
        curl_setopt($ci, CURLOPT_HEADER, FALSE);
        curl_setopt($ci, CURLOPT_URL, $url);

        /* CURL send */
        $responseRaw = curl_exec($ci);
        $this->httpCode = curl_getinfo($ci, CURLINFO_HTTP_CODE);
        $this->httpInfo = array_merge($this->httpInfo, curl_getinfo($ci));
        $this->url = $url;

        $curlError = curl_error($ci);
        $curlErrno = curl_errno($ci);

        curl_close ($ci);

        if ($responseRaw === false) {
            throw new WebPurifyException($curlError, $curlErrno);
        }

        /* CURL parse */
        $response = simplexml_load_string($responseRaw, 'SimpleXMLElement', LIBXML_NOCDATA);
        
        if ($response === false) {
            throw new WebPurifyException('Could not interpret response', 0);
        }

        if ($response['stat'] != "ok") {
            throw new WebPurifyException(
                (string) $response->err['msg'],
                (int) $response->err['code']
            );
        }

        // Convert to object
        return json_decode(json_encode($response));
    }

    /**
     * Store header
     */
    public function getHeader($ch, $header) {
        $i = strpos($header, ':');

        if (!empty($i)) {
            $key = str_replace('-', '_', strtolower(substr($header, 0, $i)));
            $value = trim(substr($header, $i + 2));
            $this->http_header[$key] = $value;
        }

        return strlen($header);
    }

    /**
     * Check parameters exist
     */
    public static function requireParams($userInput, $required)
    {
        foreach ($required as $requiredParam) {
            if (!isset($userInput[$requiredParam])) {
                throw new WebPurifyException(sprintf(
                    'Parameter %s required for API request',
                    $requiredParam
                ));
            }
        }
    }

    /* image methods */

    /**
     * Submit an image to the moderation service.
     * @param string|array
     * @return string Image ID
     * @see http://www.webpurify.com/image-moderation/documentation/methods/webpurify.live.imgcheck.php
     */
    public function imgCheck($params = array())
    {
        if (is_string($params)) {
            $params = array('imgurl' => $params);
        }

        WebPurify::requireParams($params, array('imgurl'));

        $response = $this->http('imgcheck', $params);
        return (string) $response->imgid;
    }

    /**
     * Returns the moderation status of an image
     * @param string|array
     * @return boolean|null null => pending, true => approved, false => declined
     * @see http://www.webpurify.com/image-moderation/documentation/methods/webpurify.live.imgstatus.php
     */
    public function imgStatus($params = array())
    {
        if (is_string($params)) {
            $params = array('imgid' => $params);
        }

        WebPurify::requireParams($params, array('imgid'));

        $response = $this->http('imgstatus', $params);

        switch ($response->status)
        {
            case 'pending':
                return null;

            case 'approved':
                return true;

            case 'declined':
                return false;

            default:
                throw new WebPurifyException('Unknown image status response: ' . $response->status);
        }
    }

    /**
     * Check the number of image submissions remaining on your license.
     * @param array
     * @return int Number of image submissions remaining on your license.
     * @see http://www.webpurify.com/image-moderation/documentation/methods/webpurify.live.imgaccount.php
     */
    public function imgAccount($params = array())
    {
        $response = $this->http('imgaccount', $params);
        return (int) $response->remaining;
    }

    /* text methods */

    /**
     * Checks to see if there are profanities in the string
     * @param string|array
     * @return boolean: true => profane, false => clean
     * @see http://www.webpurify.com/documentation/methods/webpurify.live.check.php
     */
    public function check($params = array())
    {
        if (is_string($params)) {
            $params = array('text' => $params);
        }

        static::requireParams($params, array('text'));

        $response = $this->http('check', $params);
        return (boolean) $response->found;
    }

    /**
     * Counts the number of profanities
     * @param string|array
     * @return int => number of profantities (0 = clean)
     * @see http://www.webpurify.com/documentation/methods/webpurify.live.checkcount.php
     */
    public function checkCount($params = array())
    {
        if (is_string($params)) {
            $params = array('text' => $params);
        }

        static::requireParams($params, array('text'));

        $response = $this->http('checkcount', $params);
        return (boolean) $response->found;
    }

    /**
     * Replace profanities with a symbol
     * @param string|array
     * @return string
     * @see http://www.webpurify.com/documentation/methods/webpurify.live.replace.php
     */
    public function replace($params = array())
    {
        if (is_string($params)) {
            $params = array('text' => $params, 'replacesymbol' => '*');
        }

        static::requireParams($params, array('text', 'replacesymbol'));

        $response = $this->http('replace', $params);
        return (string) $response->text;
    }

    /**
     * Returns a list of the profanities in a string
     * @param string|array
     * @return array => list of profanities
     * @see http://www.webpurify.com/documentation/methods/webpurify.live.return.php
     */
    public function returnExpletives($params = array())
    {
        if (is_string($params)) {
            $params = array('text' => $params);
        }

        static::requireParams($params, array('text'));

        $response = $this->http('return', $params);

        if (!$response->found) {
            return array();
        }

        if (is_string($response->expletive)) {
            return array($response->expletive);
        }

        return (array) $response->expletive;
    }

    /**
     * Add a profanity to the Black List
     * @param string|array
     * @return boolean => success
     * @see http://www.webpurify.com/documentation/methods/webpurify.live.addtoblacklist.php
     */
    public function addToBlackList($params = array())
    {
        if (is_string($params)) {
            $params = array('word' => $params);
        }

        static::requireParams($params, array('word'));

        $response = $this->http('addtoblacklist', $params);
        return (boolean) $response->success;
    }

    /**
     * Add a profanity to the White List
     * @param string|array
     * @return boolean => success
     * @see http://www.webpurify.com/documentation/methods/webpurify.live.addtowhitelist.php
     */
    public function addToWhiteList($params = array())
    {
        if (is_string($params)) {
            $params = array('word' => $params);
        }

        static::requireParams($params, array('word'));

        $response = $this->http('addtowhitelist', $params);
        return (boolean) $response->success;
    }

    /**
     * Remove a profanity from the Black List
     * @param string|array
     * @return boolean => success
     * @see http://www.webpurify.com/documentation/methods/webpurify.live.removefromblacklist.php
     */
    public function removeFromBlackList($params = array())
    {
        if (is_string($params)) {
            $params = array('word' => $params);
        }

        static::requireParams($params, array('word'));

        $response = $this->http('removefromblacklist', $params);
        return (boolean) $response->success;
    }

    /**
     * Remove a profanity from the White List
     * @param string|array
     * @return boolean => success
     * @see http://www.webpurify.com/documentation/methods/webpurify.live.removefromwhitelist.php
     */
    public function removeFromWhiteList($params = array())
    {
        if (is_string($params)) {
            $params = array('word' => $params);
        }

        static::requireParams($params, array('word'));

        $response = $this->http('removefromwhitelist', $params);
        return (boolean) $response->success;
    }

    /**
     * Get the Black List
     * @param array
     * @return array
     * @see http://www.webpurify.com/documentation/methods/webpurify.live.getblacklist.php
     */
    public function getBlackList($params = array())
    {
        $response = $this->http('getblacklist', $params);

        if (!isset($response->word)) {
            return array();
        }

        if (is_string($response->word)) {
            return array($response->word);
        }

        return (array) $response->word;
    }

    /**
     * Get the White List
     * @param array
     * @return array
     * @see http://www.webpurify.com/documentation/methods/webpurify.live.getwhitelist.php
     */
    public function getWhiteList($params = array())
    {
        $response = $this->http('getwhitelist', $params);

        if (!isset($response->word)) {
            return array();
        }

        if (is_string($response->word)) {
            return array($response->word);
        }
        
        return (array) $response->word;
    }
}