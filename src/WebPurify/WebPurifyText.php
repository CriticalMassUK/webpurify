<?php

namespace WebPurify;

class WebPurifyText extends WebPurify
{

    const END_POINT_DOMAIN_UNITED_STATES = 'api1.webpurify.com';
    const END_POINT_DOMAIN_EUROPE        = 'api1-eu.webpurify.com';
    const END_POINT_DOMAIN_ASIA_PACIFIC  = 'api1-ap.webpurify.com';

    public function __construct($api_key)
    {
        parent::__construct($api_key);

        // Use the US endpoint
        $this->setEndPointDomain(static::END_POINT_DOMAIN_UNITED_STATES);
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

        $response = $this->request('check', $params);
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

        $response = $this->request('checkcount', $params);
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

        $response = $this->request('replace', $params);
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

        $response = $this->request('return', $params);

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

        $response = $this->request('addtoblacklist', $params);
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

        $response = $this->request('addtowhitelist', $params);
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

        $response = $this->request('removefromblacklist', $params);
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

        $response = $this->request('removefromwhitelist', $params);
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
        $response = $this->request('getblacklist', $params);

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
        $response = $this->request('getwhitelist', $params);

        if (!isset($response->word)) {
            return array();
        }

        if (is_string($response->word)) {
            return array($response->word);
        }
        
        return (array) $response->word;
    }
}