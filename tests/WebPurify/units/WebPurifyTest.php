<?php

/**
 * I'm so sorry for the language,
 * My mother didn't teach me to speak like this ...
 */

use WebPurify\WebPurify;

class WebPurifyTextTest extends PHPUnit_Framework_TestCase
{
    
    protected $webPurify;

    public function __construct()
    {
        $this->webPurify = new WebPurify(WEB_PURIFY_API_KEY);
    }

    public function testGetBlackList()
    {
        $blackList = $this->webPurify->getBlackList();
        $this->assertInternalType('array', $blackList);
    }

    public function testGetWhiteList()
    {
        $whiteList = $this->webPurify->getWhiteList();
        $this->assertInternalType('array', $whiteList);
    }

    /**
     * @expectedException WebPurify\WebPurifyException
     */
    public function testMissingParameter()
    {
        $profane = $this->webPurify->check();
    }

    public function testCheckPass()
    {
        $profane = $this->webPurify->check("the quick brown fox jumps over the lazy dog");
        $this->assertFalse($profane);
    }

    public function testCheckFail()
    {
        $profane = $this->webPurify->check("the quick brown fuck jumps over the lazy dog");
        $this->assertTrue($profane);
    }

    public function testCheckCountNone()
    {
        $profanities = $this->webPurify->check("the quick brown fox jumps over the lazy dog");
        $this->assertEquals(0, $profanities);
    }

    public function testCheckCountOne()
    {
        $profanities = $this->webPurify->check("the quick brown fuck jumps over the lazy dog");
        $this->assertEquals(1, $profanities);
    }

    public function testReplace()
    {
        $replaced = $this->webPurify->replace("the quick brown fuck jumps over the lazy dog");
        $this->assertEquals("the quick brown **** jumps over the lazy dog", $replaced);
    }

    public function testReturnExpletivesNone()
    {
        $returned = $this->webPurify->returnExpletives("the quick brown fox jumps over the lazy dog");
        $this->assertCount(0, $returned);
    }

    public function testReturnExpletivesOne()
    {
        $returned = $this->webPurify->returnExpletives("the quick brown fuck jumps over the lazy dog");
        $this->assertCount(1, $returned);
    }

    public function testReturnExpletivesTwo()
    {
        $returned = $this->webPurify->returnExpletives("the quick brown fuck jumps over the lazy pussy");
        $this->assertCount(2, $returned);
    }

    /**
     * @expectedException WebPurify\WebPurifyException
     */
    public function testNoAPIKey()
    {
        $apiKey = $this->webPurify->getApiKey();
        
        try
        {
            $this->webPurify->setApiKey(null);
            $this->webPurify->check("test");
        }
        catch (Exception $e)
        {
            $this->webPurify->setApiKey($apiKey);
            throw $e;
        }
    }

    /**
     * @expectedException WebPurify\WebPurifyException
     */
    public function testInvalidAPIKey()
    {
        $apiKey = $this->webPurify->getApiKey();

        try
        {
            $this->webPurify->setApiKey("abc");
            $this->webPurify->check("test");
        }
        catch (Exception $e)
        {
            $this->webPurify->setApiKey($apiKey);
            throw $e;
        }
    }

    /** 
     * EndPoint domain
     */
    public function testEndPointDomain()
    {
        $this->webPurify->setEndPointDomain(WebPurify::END_POINT_DOMAIN_EUROPE);
        $this->assertEquals(WebPurify::END_POINT_DOMAIN_EUROPE, $this->webPurify->getEndPointDomain());

        $this->webPurify->setEndPointDomain(WebPurify::END_POINT_DOMAIN_UNITED_STATES);
        $this->assertEquals(WebPurify::END_POINT_DOMAIN_UNITED_STATES, $this->webPurify->getEndPointDomain());
    }
}