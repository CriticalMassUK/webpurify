# Web Purify API

[![Build Status](https://travis-ci.org/bashaus/webpurify.png?branch=master)](https://travis-ci.org/bashaus/webpurify)

A library for interfacing with [WebPurify](http://webpurify.com/).

The library is covered by PHPUnit tests using stub mocks and is PSR-0, PSR-1, PSR-2 and PSR-3 compliant.

## Installation

Add the following to your `composer.json`.

```
{
	"require": {
		"bashaus/webpurify": "dev-master"
	}
}
```

## Usage

There are two classes which you can use to make requests to Web Purify:

- `WebPurify\WebPurifyImage`
- `WebPurify\WebPurifyText`

Most methods listed on the WebPurify documentation can be used as method names
for making API calls. There is exception as `return` is a reserved keyword in 
PHP the method name is `returnExpletives`.

* [Web Purify Image documentation](http://webpurify.com/image-moderation/documentation/)
* [Web Purify Text documentation](http://webpurify.com/documentation/)

## WebPurify

These methods are available in both classes.

### setLogger

WebPurify class is a PSR-3 compliant LoggerAwareInterface. It outputs all HTTP 
requests and responses to a logger. You will need a logger 
(like [Monolog](https://github.com/Seldaek/monolog)).

```
$logger = new Logger('name');
$logger->pushHandler(new StreamHandler('path/to/your.log'));

$webPurifyImage = new WebPurify\WebPurifyImage($apiKey);
$webPurifyImage->setLogger($logger);
```

## WebPurifyImage

Instantiate `WebPurifyImage` by passing through your API key:

```
$webPurifyImage = new WebPurify\WebPurifyImage($apiKey);
```

### imgCheck

Returns: &lt;imgid&gt;

Documentation:
[webpurify.live.imgcheck](http://webpurify.com/image-moderation/documentation/methods/webpurify.live.imgcheck.php)

```
# string => imgurl
$webPurifyImage->imgCheck("http://.../");

# array => post data
$webPurifyImage->imgCheck(array(
	"imgurl" => "http://.../"
	// ...
));
```

### imgStatus

Returns:

- true => approved
- false => declined
- null => pending

Documentation:
[webpurify.live.imgstatus](http://webpurify.com/image-moderation/documentation/methods/webpurify.live.imgstatus.php)

```
# string => imgid
$webPurifyImage->imgStatus("0123456789abcdef0123456789abcdef");

# array => post data
$webPurifyImage->imgCheck(array(
	"imgid" => "0123456789abcdef0123456789abcdef"
	// ...
));
```

### imgAccount

Returns: &lt;remaining&gt;

Documentation:
[webpurify.live.imgaccount](http://webpurify.com/image-moderation/documentation/methods/webpurify.live.imgaccount.php)

```
# No parameters
$webPurifyImage->imgAccount();

# array => post data
$webPurifyImage->imgAccount(array(
	// ...
));
```

## WebPurifyText

Instantiate `WebPurifyTexxt` by passing through your API key:

```
$webPurifyText = new WebPurify\WebPurifyText($apiKey);
```

### check

Returns: boolean &lt;found&gt;

Documentation:
[webpurify.live.check](http://webpurify.com/documentation/methods/webpurify.live.check.php)

```
# string => text
$webPurifyText->check("the quick brown fox jumps over the lazy dog");

# array => post data
$webPurifyText->check(array(
	"text" => "the quick brown fox jumps over the lazy dog"
	// ...
));
```

### checkCount

Returns: boolean &lt;found&gt;

Documentation:
[webpurify.live.checkcount](http://webpurify.com/documentation/methods/webpurify.live.checkcount.php)

```
# string => text
$webPurifyText->checkCount("the quick brown fox jumps over the lazy dog");

# array => post data
$webPurifyText->check(array(
	"text" => "the quick brown fox jumps over the lazy dog"
	// ...
));
```

### replace

Returns: string &lt;text&gt;

Documentation:
[webpurify.live.replace](http://webpurify.com/documentation/methods/webpurify.live.replace.php)

```
# string => text
$webPurifyText->checkCount("the quick brown fox jumps over the lazy dog");

# array => post data
$webPurifyText->check(array(
	"text" => "the quick brown fox jumps over the lazy dog"
	// ...
));
```

### returnExpletives

Returns: array &lt;word&gt;

Documentation:
[webpurify.live.return](http://webpurify.com/documentation/methods/webpurify.live.return.php)

```
# string => text
$webPurifyText->returnExpletives("the quick brown fox jumps over the lazy dog");

# array => post data
$webPurifyText->returnExpletives(array(
	"text" => "the quick brown fox jumps over the lazy dog"
	// ...
));
```

### addToBlackList

Returns: boolean &lt;success&gt;

Documentation:
[webpurify.live.addtoblacklist](http://webpurify.com/documentation/methods/webpurify.live.addtoblacklist.php)

```
# string => text
$webPurifyText->addToBlackList("scunthorpe");

# array => post data
$webPurifyText->addToBlackList(array(
	"word" => "scunthorpe"
	// ...
));
```

### addToWhiteList

Returns: boolean &lt;success&gt;

Documentation:
[webpurify.live.addtowhitelist](http://webpurify.com/documentation/methods/webpurify.live.addtowhitelist.php)

```
# string => word
$webPurifyText->addToWhiteList("scunthorpe");

# array => post data
$webPurifyText->addToWhiteList(array(
	"word" => "scunthorpe"
	// ...
));
```

### removeFromBlackList

Returns: boolean &lt;success&gt;

Documentation:
[webpurify.live.removefromblacklist](http://webpurify.com/documentation/methods/webpurify.live.removefromblacklist.php)

```
# string => word
$webPurifyText->removeFromBlackList("scunthorpe");

# array => post data
$webPurifyText->removeFromBlackList(array(
	"word" => "scunthorpe"
	// ...
));
```

### removeFromWhiteList

Returns: boolean &lt;success&gt;

Documentation:
[webpurify.live.removefromwhitelist](http://webpurify.com/documentation/methods/webpurify.live.removefromwhitelist.php)

```
# string => word
$webPurifyText->removeFromWhiteList("scunthorpe");

# array => post data
$webPurifyText->removeFromWhiteList(array(
	"word" => "scunthorpe"
	// ...
));
```

### getBlackList

Returns: array &lt;word&gt;

Documentation:
[webpurify.live.getblacklist](http://webpurify.com/documentation/methods/webpurify.live.getblacklist.php)

```
# No parameters
$webPurifyText->getBlackList();

# array => post data
$webPurifyText->getBlackList(array(
	// ...
));
```

### getWhiteList

Returns: array &lt;word&gt;

Documentation:
[webpurify.live.getwhitelist](http://webpurify.com/documentation/methods/webpurify.live.getwhitelist.php)

```
# No parameters
$webPurifyText->getWhiteList();

# array => post data
$webPurifyText->getWhiteList(array(
	// ...
));
```