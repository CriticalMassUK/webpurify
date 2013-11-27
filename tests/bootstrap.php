<?php

ini_set('date.timezone', 'UTC');

if (!@include __DIR__ . '/../vendor/autoload.php') {
    die(<<<'EOT'
You must set up the project dependencies, run the following commands:
wget http://getcomposer.org/composer.phar
php composer.phar install

EOT
    );
}

foreach (array('WEB_PURIFY_API_KEY') as $constant) {
    if (array_key_exists($constant, $_ENV)) {
        define($constant, $_ENV[$constant]);
    }
}