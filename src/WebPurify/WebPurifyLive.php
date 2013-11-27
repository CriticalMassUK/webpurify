<?php

namespace WebPurify;

class WebPurifyLive
{

    protected $webPurify;

    public function __construct(WebPurify $webPurify)
    {
        $this->setWebPurify($webPurify);
    }

    /* accessors and mutators */

    public function setWebPurify($webPurify)
    {
        $this->webPurify = $webPurify;
    }

    public function getWebPurify()
    {
        return $this->webPurify;
    }

    /* methods */

    /**
     * Checks to see if there are profanities in the string
     * @param string|array
     * @return boolean: true => profane, false => clean
     */
    public function check($params = array())
    {
        if (is_string($params)) {
            $params = array('text' => $params);
        }

        WebPurify::requireParams($params, array('text'));

        $response = $this->webPurify->http('webpurify.live.check', $params);
        return (boolean) $response->rsp->found;
    }

    /**
     * Counts the number of profanities
     * @param string|array
     * @return int => number of profantities (0 = clean)
     */
    public function checkCount($params = array())
    {
        if (is_string($params)) {
            $params = array('text' => $params);
        }

        WebPurify::requireParams($params, array('text'));

        $response = $this->webPurify->http('webpurify.live.checkcount', $params);
        return (boolean) $response->rsp->found;
    }

    /**
     * Replace profanities with a symbol
     * @param string|array
     * @return string
     */
    public function replace($params = array())
    {
        if (is_string($params)) {
            $params = array('text' => $params, 'replacesymbol' => '*');
        }

        WebPurify::requireParams($params, array('text', 'replacesymbol'));

        $response = $this->webPurify->http('webpurify.live.replace', $params);
        return (string) $response->rsp->text;
    }

    /**
     * Returns a list of the profanities in a string
     * @param string|array
     * @return array => list of profanities
     */
    public function returnText($params = array())
    {
        if (is_string($params)) {
            $params = array('text' => $params);
        }

        WebPurify::requireParams($params, array('text'));

        $response = $this->webPurify->http('webpurify.live.return', $params);
        return (array) $response->rsp->expletive;
    }

    /**
     * Add a profanity to the Black List
     * @param string|array
     * @return boolean => success
     */
    public function addToBlackList($params = array())
    {
        if (is_string($params)) {
            $params = array('word' => $params);
        }

        WebPurify::requireParams($params, array('word'));

        $response = $this->webPurify->http('webpurify.live.addtoblacklist', $params);
        return (boolean) $response->rsp->success;
    }

    /**
     * Add a profanity to the White List
     * @param string|array
     * @return boolean => success
     */
    public function addToWhiteList($params = array())
    {
        if (is_string($params)) {
            $params = array('word' => $params);
        }

        WebPurify::requireParams($params, array('word'));

        $response = $this->webPurify->http('webpurify.live.addtowhitelist', $params);
        return (boolean) $response->rsp->success;
    }

    /**
     * Remove a profanity from the Black List
     * @param string|array
     * @return boolean => success
     */
    public function removeFromBlackList($params = array())
    {
        if (is_string($params)) {
            $params = array('word' => $params);
        }

        WebPurify::requireParams($params, array('word'));

        $response = $this->webPurify->http('webpurify.live.removefromblacklist', $params);
        return (boolean) $response->rsp->success;
    }

    /**
     * Remove a profanity from the White List
     * @param string|array
     * @return boolean => success
     */
    public function removeFromWhiteList($params = array())
    {
        if (is_string($params)) {
            $params = array('word' => $params);
        }

        WebPurify::requireParams($params, array('word'));

        $response = $this->webPurify->http('webpurify.live.removefromwhitelist', $params);
        return (boolean) $response->rsp->success;
    }

    /**
     * Get the Black List
     * @param array
     * @return array
     */
    public function getBlackList($params = array())
    {
        $response = $this->webPurify->http('webpurify.live.getblacklist', $params);
        return (array) $response->rsp->word;
    }

    /**
     * Get the White List
     * @param array
     * @return array
     */
    public function getWhiteList($params = array())
    {
        $response = $this->webPurify->http('webpurify.live.getwhitelist', $params);
        return (array) $response->rsp->word;
    }
}