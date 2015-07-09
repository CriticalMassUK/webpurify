<?php

namespace WebPurify;

use Psr\Log\LogLevel;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;

/**
 * @package CriticalMassUK/webpurify
 */
abstract class WebPurify implements LoggerAwareInterface
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
    /* last http response code */
    protected $httpCode;
    /* last http response information */
    protected $httpInfo;

    /* User agent */
    protected $userAgent = 'CriticalMassUK/WebPurify';
    /* Set timeout default. */
    protected $timeout = 30;
    /* Set connect timeout. */
    protected $connectTimeout = 30;

    protected $sandbox = false;

    /* Logger */
    protected $logger;

    /**
     * @param string $apiKey The API key from WebPurify to verify content
     */

    public function __construct($apiKey)
    {
        // Set the API key
        $this->setApiKey($apiKey);

        // Set up an NULL logger
        $this->logger = new \Psr\Log\NullLogger;
    }

    /* accessors and mutators */

    /**
     * Get the API key in use
     */
    public function getApiKey()
    {
        return $this->apiKey;
    }

    /**
     * Change the API key in use
     *
     * @param string $apiKey The new API key to use
     */
    public function setApiKey($apiKey)
    {
        $this->apiKey = (string) $apiKey;
    }

    /**
     * Get the SSL configuration property
     */
    public function getUseSSL()
    {
        return $this->useSSL;
    }

    /**
     * Set the SSL configuration property
     *
     * @param boolean $useSSL Whether to use SSL for requests
     */
    public function setUseSSL($useSSL)
    {
        $this->useSSL = (boolean) $useSSL;
    }

    /**
     * Get the sslVerifyPeer property
     */
    public function getSSLVerifyPeer()
    {
        return $this->sslVerifyPeer;
    }

    /**
     * Set the SSL configuration property
     *
     * @param boolean $sslVerifyPeer Whether to verify SSL peer for requests
     */
    public function setSSLVerifyPeer($sslVerifyPeer)
    {
        $this->sslVerifyPeer = (boolean) $sslVerifyPeer;
    }

    /**
     * Get the user agent
     */
    public function getUserAgent()
    {
        return $this->userAgent;
    }

    /**
     * Set the user agent
     *
     * @param string $userAgent The new user agent to use
     */
    public function setUserAgent($userAgent)
    {
        $this->userAgent = (string) $userAgent;
    }

    /* endpoints */

    public function getEndPointDomain()
    {
        return $this->endPointDomain;
    }

    public function setEndPointDomain($endPointDomain)
    {
        $this->endPointDomain = (string) $endPointDomain;
    }

    /**
     * Get the last HTTP response code
     * @return int
     * @see http://php.net/manual/en/function.curl-getinfo.php#100556
     */
    public function getHTTPCode() {
        return $this->httpCode;
    }

    /**
     * Get all the HTTP information for the last request
     * @return array
     */
    public function getHTTPInfo() {
        return $this->httpInfo;
    }

    /**
     * Turn sandbox on/off
     *
     * @param boolean $sandbox Whether or not to turn on the sandbox
     */
    public function setSandbox($sandbox)
    {
        $this->sandbox = (boolean) $sandbox;
    }

    /**
     * Get the sandbox status
     */
    public function getSandbox()
    {
        return $this->sandbox;
    }

    /* psr-3 */

    public function setLogger(LoggerInterface $logger) 
    {
        $this->logger = $logger;
    }

    /* helpers */

    /**
     *
     */

    protected function http($method, array $params = array(), $endPointDomain = null)
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
        curl_setopt($ci, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ci, CURLOPT_SSL_VERIFYPEER, $this->sslVerifyPeer);
        curl_setopt($ci, CURLOPT_HEADERFUNCTION, array($this, 'getHeader'));
        curl_setopt($ci, CURLOPT_HEADER, false);
        curl_setopt($ci, CURLOPT_URL, $url);

        /* CURL send */
        $responseRaw = curl_exec($ci);
        $this->httpCode = curl_getinfo($ci, CURLINFO_HTTP_CODE);
        $this->httpInfo = array_merge($this->httpInfo, curl_getinfo($ci));
        $this->url = $url;

        $curlError = curl_error($ci);
        $curlErrno = curl_errno($ci);

        curl_close($ci);

        $this->logger->log(LogLevel::DEBUG, $url);

        if ($responseRaw === false) {
            throw new WebPurifyException($curlError, $curlErrno);
        }

        $this->logger->log(LogLevel::DEBUG, $responseRaw);

        return $responseRaw;
    }

    /**
     * Perform a request
     *
     * Interprets the response from a HTTP request into an object
     */

    protected function request($method, array $params = array(), $endPointDomain = null)
    {
        $responseRaw = $this->http($method, $params, $endPointDomain);

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
     * Stores HTTP Response Headers
     *
     * Helper method for CURL to store HTTP response header information
     * for later use
     */
    public function getHeader($ch, $header)
    {
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
     *
     * Static method for checking that a parameter exists in the $params
     * array passed to WebPurity methods
     *
     * @param array $userInput A hash of HTTP GET/POST parameters
     * @param array $required  An array of required parameters
     */
    protected static function requireParams($userInput, $required)
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

    /**
     * Check exactly one of the given parameters exists
     *
     * Static method for checking that exactly one of the given parameters
     * exists in the $params array passed to WebPurity methods
     *
     * @param array $userInput A hash of HTTP GET/POST parameters
     * @param array $required  An array of parameters
     */
    protected static function requireExactlyOneParamFrom($userInput, $parameters)
    {
        $count = 0;
        foreach ($parameters as $requiredParam) {
            if (isset($userInput[$requiredParam])) {
                if (++$count > 1) {
                    break;
                }
            }
        }

        if ($count !== 1) {
            throw new WebPurifyException(
                'Exactly one of the parameters '
                . implode(', ', $parameters)
                . ' required for API request'
            );
        }
    }
}
