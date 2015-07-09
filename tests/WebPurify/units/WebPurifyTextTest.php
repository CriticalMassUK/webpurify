<?php

namespace WebPurify;

use PHPUnit_Framework_TestCase;

class WebPurifyTextTest extends WebPurifyTest
{

    public function testGetBlackListNone()
    {
        $expected = array();

        $whiteList = $this->webPurify->getBlackList();
        $this->assertEquals(sort($expected), sort($whiteList));
    }

    public function testGetBlackListOne()
    {
        $expected = array('cockburn');

        $blackList = $this->webPurify->getBlackList();
        $this->assertEquals(sort($expected), sort($blackList));
    }

    public function testGetBlackListTwo()
    {
        $expected = array('cockburn', 'scunthorpe', 'swang');

        $blackList = $this->webPurify->getBlackList();
        $this->assertEquals(sort($expected), sort($blackList));
    }

    public function testGetWhiteListNone()
    {
        $expected = array();

        $whiteList = $this->webPurify->getWhiteList();
        $this->assertEquals(sort($expected), sort($whiteList));
    }

    public function testGetWhiteListOne()
    {
        $expected = array('cockburn');

        $whiteList = $this->webPurify->getWhiteList();
        $this->assertEquals(sort($expected), sort($whiteList));
    }

    public function testGetWhiteListTwo()
    {
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
        $profane = $this->webPurify->check('the quick brown fox jumps over the lazy dog');
        $this->assertFalse($profane);
    }

    public function testCheckDeclined()
    {
        $profane = $this->webPurify->check('the quick brown fuck jumps over the lazy dog');
        $this->assertTrue($profane);
    }

    public function testCheckCountNone()
    {
        $profanities = $this->webPurify->checkCount('the quick brown fox jumps over the lazy dog');
        $this->assertEquals(0, $profanities);
    }

    public function testCheckCountOne()
    {
        $profanities = $this->webPurify->checkCount('the quick brown fuck jumps over the lazy dog');
        $this->assertEquals(1, $profanities);
    }

    public function testCheckCountTwo()
    {
        $profanities = $this->webPurify->checkCount('the quick brown fuck jumps over the lazy pussy');
        $this->assertSame(2, $profanities);
    }

    public function testReplace()
    {
        $replaced = $this->webPurify->replace('the quick brown fuck jumps over the lazy dog');
        $this->assertEquals('the quick brown **** jumps over the lazy dog', $replaced);
    }

    public function testReturnExpletivesNone()
    {
        $returned = $this->webPurify->returnExpletives('the quick brown fox jumps over the lazy dog');
        $this->assertCount(0, $returned);
    }

    public function testReturnExpletivesOne()
    {
        $returned = $this->webPurify->returnExpletives('the quick brown fuck jumps over the lazy dog');
        $this->assertCount(1, $returned);
    }

    public function testReturnExpletivesTwo()
    {
        $returned = $this->webPurify->returnExpletives('the quick brown fuck jumps over the lazy pussy');
        $this->assertCount(2, $returned);
    }

    public function testAddToBlackList()
    {
        $success = $this->webPurify->addToBlackList('pussy');
        $this->assertTrue($success);
    }

    public function testRemoveFromBlackList()
    {
        $success = $this->webPurify->removeFromBlackList('pussy');
        $this->assertTrue($success);
    }

    public function testAddToWhiteList()
    {
        $success = $this->webPurify->addToWhiteList('pussy');
        $this->assertTrue($success);
    }

    public function testRemoveFromWhiteList()
    {
        $success = $this->webPurify->removeFromWhiteList('pussy');
        $this->assertTrue($success);
    }
}
