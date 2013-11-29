<?php

namespace WebPurify;

use PHPUnit_Framework_TestCase;

class WebPurifyTextTest extends WebPurifyTest
{

    public function setUp()
    {
        $this->webPurify = $this
             ->getMockBuilder('WebPurify\WebPurifyText')
             ->setConstructorArgs(array(WEB_PURIFY_API_KEY))
             ->setMethods(array('http'))
             ->getMock();
    }

    /* */
    
    public function testGetBlackListNone()
    {
        $this->mockHTTP('text/getblacklist_0.xml');

        $expected = array();

        $whiteList = $this->webPurify->getBlackList();
        $this->assertEquals(sort($expected), sort($whiteList));
    }

    public function testGetBlackListOne()
    {
        $this->mockHTTP('text/getblacklist_1.xml');

        $expected = array('cockburn');

        $blackList = $this->webPurify->getBlackList();
        $this->assertEquals(sort($expected), sort($blackList));
    }

    public function testGetBlackListTwo()
    {
        $this->mockHTTP('text/getblacklist_2.xml');

        $expected = array('cockburn', 'scunthorpe', 'swang');

        $blackList = $this->webPurify->getBlackList();
        $this->assertEquals(sort($expected), sort($blackList));
    }

    public function testGetWhiteListNone()
    {
        $this->mockHTTP('text/getwhitelist_0.xml');

        $expected = array();

        $whiteList = $this->webPurify->getWhiteList();
        $this->assertEquals(sort($expected), sort($whiteList));
    }

    public function testGetWhiteListOne()
    {
        $this->mockHTTP('text/getwhitelist_1.xml');

        $expected = array('cockburn');

        $whiteList = $this->webPurify->getWhiteList();
        $this->assertEquals(sort($expected), sort($whiteList));
    }

    public function testGetWhiteListTwo()
    {
        $this->mockHTTP('text/getwhitelist_2.xml');

        $expected = array('cockburn', 'scunthorpe');

        $whiteList = $this->webPurify->getWhiteList();
        $this->assertEquals(sort($expected), sort($whiteList));
    }

    /**
     * @expectedException WebPurify\WebPurifyException
     */
    public function testMissingParameter()
    {
        $profane = $this->webPurify->check();
    }

    public function testCheckApproved()
    {
        $this->mockHTTP('text/check_approved.xml');

        $profane = $this->webPurify->check('the quick brown fox jumps over the lazy dog');
        $this->assertFalse($profane);
    }

    public function testCheckDeclined()
    {
        $this->mockHTTP('text/check_declined.xml');

        $profane = $this->webPurify->check('the quick brown fuck jumps over the lazy dog');
        $this->assertTrue($profane);
    }

    public function testCheckCountNone()
    {
        $this->mockHTTP('text/checkcount_0.xml');

        $profanities = $this->webPurify->checkCount('the quick brown fox jumps over the lazy dog');
        $this->assertEquals(0, $profanities);
    }

    public function testCheckCountOne()
    {
        $this->mockHTTP('text/checkcount_1.xml');

        $profanities = $this->webPurify->checkCount('the quick brown fuck jumps over the lazy dog');
        $this->assertEquals(1, $profanities);
    }

    public function testCheckCountTwo()
    {
        $this->mockHTTP('text/checkcount_2.xml');

        $profanities = $this->webPurify->checkCount('the quick brown fuck jumps over the lazy pussy');
        $this->assertEquals(2, $profanities);
    }

    public function testReplace()
    {
        $this->mockHTTP('text/replace_1.xml');

        $replaced = $this->webPurify->replace('the quick brown fuck jumps over the lazy dog');
        $this->assertEquals('the quick brown **** jumps over the lazy dog', $replaced);
    }

    public function testReturnExpletivesNone()
    {
        $this->mockHTTP('text/return_0.xml');

        $returned = $this->webPurify->returnExpletives('the quick brown fox jumps over the lazy dog');
        $this->assertCount(0, $returned);
    }

    public function testReturnExpletivesOne()
    {
        $this->mockHTTP('text/return_1.xml');

        $returned = $this->webPurify->returnExpletives('the quick brown fuck jumps over the lazy dog');
        $this->assertCount(1, $returned);
    }

    public function testReturnExpletivesTwo()
    {
        $this->mockHTTP('text/return_2.xml');

        $returned = $this->webPurify->returnExpletives('the quick brown fuck jumps over the lazy pussy');
        $this->assertCount(2, $returned);
    }

    public function testAddToBlackList()
    {
        $this->mockHTTP('text/addtoblacklist_success.xml');

        $success = $this->webPurify->addToBlackList('pussy');
        $this->assertTrue($success);
    }

    public function testRemoveFromBlackList()
    {
        $this->mockHTTP('text/removefromblacklist_success.xml');

        $success = $this->webPurify->removeFromBlackList('pussy');
        $this->assertTrue($success);
    }

    public function testAddToWhiteList()
    {
        $this->mockHTTP('text/addtowhitelist_success.xml');

        $success = $this->webPurify->addToWhiteList('pussy');
        $this->assertTrue($success);
    }

    public function testRemoveFromWhiteList()
    {
        $this->mockHTTP('text/removefromwhitelist_success.xml');

        $success = $this->webPurify->removeFromWhiteList('pussy');
        $this->assertTrue($success);
    }
}