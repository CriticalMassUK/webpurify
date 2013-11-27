<?php

/**
 * I'm so sorry for the language,
 * My mother didn't teach me to speak like this ...
 */

class WebPurifyLiveTest extends PHPUnit_Framework_TestCase
{
    
    protected $webPurify;

    public function __construct()
    {
        $this->webPurify = new \WebPurify\WebPurify(WEB_PURIFY_API_KEY);
    }

    public function testCheckPass()
    {
        $profane = $this->webPurify->live->check("the quick brown fox jumps over the lazy dog");
        $this->assertFalse($profane);
    }

    public function testCheckFail()
    {
        $profane = $this->webPurify->live->check("the fucking quick brown fox jumps over the lazy dog");
        $this->assertTrue($profane);
    }

    public function testCheckCount()
    {
        $profanities = $this->webPurify->live->check("the quick brown fox jumps over the lazy dog");
        $this->assertEquals(0, $profanities);
    }

    public function testReplace()
    {
        $replaced = $this->webPurify->live->replace("fuck, the quick brown fox jumps over the lazy dog");
        $this->assertEquals("****, the quick brown fox jumps over the lazy dog", $replaced);
    }

    public function testReturnExpletivesNone()
    {
        $returned = $this->webPurify->live->returnExpletives("the quick brown fox jumps over the lazy dog");
        $this->assertCount(0, $returned);
    }

    public function testReturnExpletivesOne()
    {
        $returned = $this->webPurify->live->returnExpletives("fuck, the quick brown fox jumps over the lazy dog");
        $this->assertCount(1, $returned);
    }

    public function testReturnExpletivesTwo()
    {
        $returned = $this->webPurify->live->returnExpletives("fuck, the quick brown fox jumps over the lazy pussy");
        $this->assertCount(2, $returned);
    }

    /**
     * @expectedException WebPurify\WebPurifyException
     */
    public function testNoAPIKey()
    {
        $this->webPurify->setApiKey(null);
        $this->webPurify->live->check("test");
    }

    /**
     * @expectedException WebPurify\WebPurifyException
     */
    public function testInvalidAPIKey()
    {
        $this->webPurify->setApiKey("abc");
        $this->webPurify->live->check("test");
    }
}