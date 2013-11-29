<?php

namespace WebPurify;

class WebPurifyImage extends WebPurify
{
    const END_POINT_DOMAIN_IMAGES = 'im-api1.webpurify.com';

    public function __construct($api_key)
    {
        parent::__construct($api_key);

        // Use the image API endpoint
        $this->setEndPointDomain(static::END_POINT_DOMAIN_IMAGES);
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

        $response = $this->request('imgcheck', $params, static::END_POINT_DOMAIN_IMAGES);
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

        $response = $this->request('imgstatus', $params, static::END_POINT_DOMAIN_IMAGES);

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
        $response = $this->request('imgaccount', $params, static::END_POINT_DOMAIN_IMAGES);
        return (int) $response->remaining;
    }
}