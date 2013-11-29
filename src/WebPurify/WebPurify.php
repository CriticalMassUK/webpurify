<?php

namespace WebPurify;

abstract class WebPurify
{

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

    /* User agent */
    protected $userAgent = 'WebPurify';
    /* Set timeout default. */
    protected $timeout = 30;
    /* Set connect timeout. */
    protected $connectTimeout = 30;

    protected $sandbox = false;

    public function __construct($api_key)
    {
        // Set the API key
        $this->setApiKey($api_key);
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

    /* sandbox */

    public function setSandbox($sandbox)
    {
        $this->sandbox = $sandbox;
    }

    public function getSandbox($sandbox)
    {
        return $this->sandbox;
    }

    /* helpers */

    public function http($method, array $params = array(), $endPointDomain = null)
    {
        if (is_null($endPointDomain)) {
            $endPointDomain = $this->getEndPointDomain();
        }

        $params['api_key'] = $this->getApiKey();
        $params['method'] = sprintf(
            'webpurify.%s.%s',
            $this->sandbox ? 'sandbox' : 'live',
            $method
        );

        $url = sprintf(
            "%s://%s/services/rest/?%s",
            $this->useSSL ? 'https' : 'http',
            $endPointDomain,
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

        return $responseRaw;
    }

    public function request($method, array $params = array(), $endPointDomain = null)
    {
        $responseRaw = $this->http($method, $params, $endPointDomain);

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
}