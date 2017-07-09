<?php

if(!defined("PHP_VERSION_ID") || PHP_VERSION_ID < 50300 || !extension_loaded('openssl') || !extension_loaded('curl')) {
    die("You need at least PHP 5.3.0 with OpenSSL and curl extension\n");
}
require 'code/letsencript.php';

// you can use any logger according to Psr\Log\LoggerInterface
class Logger { function __call($name, $arguments) { echo date('Y-m-d H:i:s')." [$name] ${arguments[0]}\n"; }}
$logger = new Logger();

try {
	
	$domain_folder = str_replace(".","_", $domain);
	
    $le = new Analogic\ACME\Lescript('/certificate/storage', '/var/sentora/hostdata/$username/public_html/$domain_folder', $logger);
    # or without logger:
    # $le = new Analogic\ACME\Lescript('/certificate/storage', '/var/www/test.com');
	
	$mailto = "mailto:postmaster@".$domain;
    $le->contact = array($mailto); // optional

    $le->initAccount();
    $le->signDomains(array($domain, 'www.'.$domain));

} catch (\Exception $e) {

    $logger->error($e->getMessage());
    $logger->error($e->getTraceAsString());
}
?>