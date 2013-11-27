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

    /* Live service*/
    public $live;

    public function __construct($api_key)
    {
        // Set the API key
        $this->setApiKey($api_key);

        // Use the US endpoint
        $this->setEndPointDomainUnitedStates();

        // Setup the live service
        $this->live = new WebPurifyLive($this);
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

    public function setEndPointDomain()
    {
        return $this->endPointDomain;
    }

    public function setEndPointDomainUnitedStates()
    {
        $this->endPointDomain = static::END_POINT_DOMAIN_UNITED_STATES;
    }

    public function setEndPointDomainEurope()
    {
        $this->endPointDomain = static::END_POINT_DOMAIN_EUROPE;
    }

    public function setEndPointDomainAsiaPacific()
    {
        $this->endPointDomain = static::END_POINT_DOMAIN_ASIA_PACIFIC;
    }

    /* helpers */

    public function http($method, array $params = array())
    {
        $params['method']   = $method;
        $params['api_key']  = $this->getApiKey();
        $params['format']   = 'json';

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
        $response = json_decode($responseRaw);
        
        if ($response === false) {
            throw new WebPurifyException('Could not interpret response', 0);
        }

        if ($response->rsp->{"@attributes"}->stat != "ok" || isset($response->rsp->err)) {
            throw new WebPurifyException(
                $response->rsp->err->{"@attributes"}->msg,
                $response->rsp->err->{"@attributes"}->code
            );
        }

        return $response;
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
                throw new Exception(sprintf(
                    'Parameter %s required for API request',
                    $requiredParam
                ));
            }
        }
    }
}