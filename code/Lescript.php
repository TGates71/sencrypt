<?php
// lets encrypt class - start
namespace Analogic\ACME;

class Lescript
{
    public $ca = 'https://acme-v01.api.letsencrypt.org'; // production
    //public $ca = 'https://acme-staging.api.letsencrypt.org'; // testing
    public $license = 'https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf';
    public $countryCode = 'US';
    public $state = "Massachusetts";
    public $challenge = 'http-01'; // http-01 challenge only
    public $contact = array(); // optional
    //public $contact = array("mailto:postmaster@".$domain);

    private $certificatesDir;
    private $webRootDir;
	private $domain;

    /** @var \Psr\Log\LoggerInterface */
    private $logger;
    private $client;
    private $accountKeyPath;

    public function __construct($certificatesDir, $webRootDir, $logger = null, ClientInterface $client = null)
    {
        $this->certificatesDir = $certificatesDir;
        $this->webRootDir = $webRootDir;
        $this->logger = $logger;
        $this->client = $client ? $client : new Client($this->ca);
        $this->accountKeyPath = $certificatesDir . '/_account/private.pem';
    }

    public function initAccount()
    {
        if (!is_file($this->accountKeyPath)) {

            // generate and save new private key for account
            // ---------------------------------------------

            printf('Starting new account registration\n');
            $this->generateKey(dirname($this->accountKeyPath));
            $this->postNewReg();
            printf('New account certificate registered\n');

        } else {

            printf('Account already registered. Continuing.\n');

        }
    }

    //public function signDomains($domain, array $domains, $reuseCsr = false)
	public function signDomains($domain, $reuseCsr = false)
    {
        printf('Starting certificate generation process...\n');

		//$domains = $domain;
		$domains = $domain;
        $privateAccountKey = $this->readPrivateKey($this->accountKeyPath);
        $accountKeyDetails = openssl_pkey_get_details($privateAccountKey);

        // start domains authentication
        // ----------------------------

        foreach ($domains as $domain) {

            // 1. getting available authentication options
            // -------------------------------------------

            printf("Requesting challenge for ".$domain."\n");

            $response = $this->signedRequest("/acme/new-authz", array("resource" => "new-authz", "identifier" => array("type" => "dns", "value" => $domain))
            );
            
            if (empty($response['challenges'])) {
                printf("HTTP Challenge for $domain is not available. Whole response: ".json_encode($response) . "\n");
				exit();
            }

            $self = $this;
            $challenge = array_reduce($response['challenges'], function ($v, $w) use (&$self) {
                return $v ? $v : ($w['type'] == $self->challenge ? $w : false);
            });
            if (!$challenge) {
				printf("HTTP Challenge for $domain is not available. Whole response: " . json_encode($response) . "\n");
				exit();
				}

            printf("Got challenge token for $domain\n");
            $location = $this->client->getLastLocation();


            // 2. saving authentication token for web verification
            // ---------------------------------------------------

            $directory = $this->webRootDir . '/.well-known/acme-challenge';
            $tokenPath = $directory . '/' . $challenge['token'];

            if (!file_exists($directory) && !@mkdir($directory, 0755, true)) {
                printf("Couldn't create directory to expose challenge: ${tokenPath}\n");
				exit();
            }

            $header = array(
                // need to be in precise order!
                "e" => Base64UrlSafeEncoder::encode($accountKeyDetails["rsa"]["e"]),
                "kty" => "RSA",
                "n" => Base64UrlSafeEncoder::encode($accountKeyDetails["rsa"]["n"])

            );
            $payload = $challenge['token'] . '.' . Base64UrlSafeEncoder::encode(hash('sha256', json_encode($header), true));

            file_put_contents($tokenPath, $payload);
            chmod($tokenPath, 0644);

            // 3. verification process itself
            // -------------------------------

            $uri = "http://${domain}/.well-known/acme-challenge/${challenge['token']}";

            printf("Token for $domain saved at: $tokenPath\nToken should be available at: $uri\n");

            printf("Sending request to challenge\n");

            // send request to challenge
            $result = $this->signedRequest(
                $challenge['uri'],
                array(
                    "resource" => "challenge",
                    "type" => $this->challenge,
                    "keyAuthorization" => $payload,
                    "token" => $challenge['token']
                )
            );

            // waiting loop
            do {
                if (empty($result['status']) || $result['status'] == "invalid") {
                    printf("Verification ended with error: " . json_encode($result) . "\n");
					exit();
                }
                $ended = !($result['status'] === "pending");
                if (!$ended) {
                    printf("Verification pending, sleeping 1s\n");
                    sleep(1);
                }

                $result = $this->client->get($location);

            } while (!$ended);

            printf("Verification ended with status: ${result['status']}\n");
            unlink($tokenPath);
        }

        // requesting certificate
        // ----------------------
        //$domainPath = $this->getDomainPath(reset($domain));
		$domainPath = $this->getDomainPath($domain);
		$domainPath = rtrim($domainPath, '/') . '/';

        // generate private key for domain if not exist
		printf("Generating key if not exist\n");
        if (!is_dir($domainPath) || !is_file($domainPath . '/private.pem')) {
            $this->generateKey($domainPath);
			printf("Key Generated\n");
        }
		
        // load domain key
		printf("Loading Key\n");
        $privateDomainKey = $this->readPrivateKey($domainPath . '/private.pem');

        $this->client->getLastLinks();

        $csr =	$reuseCsr && is_file($domainPath . "/last.csr") ?
            	$this->getCsrContent($domainPath . "/last.csr") :
            	$this->generateCSR($privateDomainKey, $domain);

        // request certificates creation
		printf("Requesting certificate creation\n");
        $result = $this->signedRequest(
            "/acme/new-cert",
            array('resource' => 'new-cert', 'csr' => $csr)
        );

        if ($this->client->getLastCode() !== 201) {
            printf("Invalid response code: " . $this->client->getLastCode() . ", " . json_encode($result) . "\n");
			exit();
        }
        $location = $this->client->getLastLocation();

        // waiting loop
        $certificates = array();
        while (1) {
            $this->client->getLastLinks();

            $result = $this->client->get($location);

            if ($this->client->getLastCode() == 202) {

                printf("Certificate generation pending, sleeping 1s\n");
                sleep(1);

            } else if ($this->client->getLastCode() == 200) {

                printf("Got certificate!\n");
                $certificates[] = $this->parsePemFromBody($result);


                foreach ($this->client->getLastLinks() as $link) {
                    printf("Requesting chained cert at $link\n");
                    $result = $this->client->get($link);
                    $certificates[] = $this->parsePemFromBody($result);
                }

                break;
            } else {

                printf("Can't get certificate: HTTP code " . $this->client->getLastCode() . "\n");
				exit();

            }
        }

        if (empty($certificates)) { printf('No certificates generated\n'); exit(); }

        printf("Saving fullchain.pem\n");
        file_put_contents($domainPath . '/fullchain.pem', implode("\n", $certificates));

        printf("Saving cert.pem\n");
        file_put_contents($domainPath . '/cert.pem', array_shift($certificates));

        printf("Saving chain.pem\n");
        file_put_contents($domainPath . "/chain.pem", implode("\n", $certificates));

        printf("Done!\n");
    }

    private function readPrivateKey($path)
    {
		printf("Reading Private Key...\n");
        if (($key = openssl_pkey_get_private('file://' . $path)) === FALSE) {
            printf(openssl_error_string() . "\n");
			exit();
        }

        return $key;
    }

    private function parsePemFromBody($body)
    {
        $pem = chunk_split(base64_encode($body), 64, "\n");
        return "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";
    }

    private function getDomainPath($domain)
    {
        //return $this->certificatesDir . '/' . $domain . '/';
		return $this->certificatesDir;
    }

    private function postNewReg()
    {
        printf('Sending registration to letsencrypt server\n');

        $data = array('resource' => 'new-reg', 'agreement' => $this->license);
        if(!$this->contact) {
            $data['contact'] = $this->contact;
        }

        return $this->signedRequest(
            '/acme/new-reg',
            $data
        );
    }

    //private function generateCSR($privateKey, array $domains) // using array here does not work or passed variable is wrong
	private function generateCSR($privateKey, $domains)
    {
		printf("Generating CSR\n");

        //$domain = reset($domains);
		$domain = $domains;

//        $san = implode(",", array_map(function($dns) {
//            return "DNS:" . $dns;
//        }, $domains));
		
        $tmpConf = tmpfile();
        $tmpConfMeta = stream_get_meta_data($tmpConf);
        $tmpConfPath = $tmpConfMeta["uri"];

        // workaround to get SAN working
        fwrite($tmpConf,
            'HOME = .
RANDFILE = $ENV::HOME/.rnd
[ req ]
default_bits = 2048
default_keyfile = private.pem
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
countryName = Country Name (2 letter code)
[ v3_req ]
basicConstraints = CA:FALSE
subjectAltName = DNS:' . $domain . '
keyUsage = nonRepudiation, digitalSignature, keyEncipherment');

        $csr = openssl_csr_new(
            array(
                "CN" => $domain,
                "ST" => $this->state,
                "C" => $this->countryCode,
                "O" => "Unknown",
            ),
            $privateKey,
            array(
                "config" => $tmpConfPath,
                "digest_alg" => "sha256"
            )
        );

        if (!$csr) { printf("CSR couldn't be generated! " . openssl_error_string() . "\n"); exit(); }

        openssl_csr_export($csr, $csr);
        fclose($tmpConf);

		$csrPath = $this->certificatesDir . "/last.csr";

        file_put_contents($csrPath, $csr);

        return $this->getCsrContent($csrPath);
    }

    private function getCsrContent($csrPath) {
        $csr = file_get_contents($csrPath);

        preg_match('~REQUEST-----(.*)-----END~s', $csr, $matches);

        return trim(Base64UrlSafeEncoder::encode(base64_decode($matches[1])));
    }

    private function generateKey($outputDirectory)
    {
        $res = openssl_pkey_new(array(
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "private_key_bits" => 4096,
        ));

        if(!openssl_pkey_export($res, $privateKey)) {
            printf("Key export failed!\n");
        }

        $details = openssl_pkey_get_details($res);

        if(!is_dir($outputDirectory)) @mkdir($outputDirectory, 0700, true);
        if(!is_dir($outputDirectory)) { printf("Cant't create directory $outputDirectory \n"); exit(); }

        file_put_contents($outputDirectory.'/private.pem', $privateKey);
        file_put_contents($outputDirectory.'/public.pem', $details['key']);
    }

    //private function signedRequest($uri, array $payload)
	private function signedRequest($uri, $payload)
    {
        $privateKey = $this->readPrivateKey($this->accountKeyPath);
        $details = openssl_pkey_get_details($privateKey);

        $header = array(
            "alg" => "RS256",
            "jwk" => array(
                "kty" => "RSA",
                "n" => Base64UrlSafeEncoder::encode($details["rsa"]["n"]),
                "e" => Base64UrlSafeEncoder::encode($details["rsa"]["e"]),
            )
        );

        $protected = $header;
        $protected["nonce"] = $this->client->getLastNonce();


        $payload64 = Base64UrlSafeEncoder::encode(str_replace('\\/', '/', json_encode($payload)));
        $protected64 = Base64UrlSafeEncoder::encode(json_encode($protected));

        openssl_sign($protected64.'.'.$payload64, $signed, $privateKey, "SHA256");

        $signed64 = Base64UrlSafeEncoder::encode($signed);

        $data = array(
            'header' => $header,
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $signed64
        );

        printf("Sending signed request to $uri\n");

        return $this->client->post($uri, json_encode($data));
    }

    protected function log($message)
    {
        if($this->logger) {
            $this->logger->info($message);
        } else {
            echo $message."\n";
        }
    }
}

interface ClientInterface
{
    /**
     * Constructor
     *
     * @param string $base the ACME API base all relative requests are sent to
     */
    public function __construct($base);
    /**
     * Send a POST request
     *
     * @param string $url URL to post to
     * @param array $data fields to sent via post
     * @return array|string the parsed JSON response, raw response on error
     */
    public function post($url, $data);
    /**
     * @param string $url URL to request via get
     * @return array|string the parsed JSON response, raw response on error
     */
    public function get($url);
    /**
     * Returns the Replay-Nonce header of the last request
     *
     * if no request has been made, yet. A GET on $base/directory is done and the
     * resulting nonce returned
     *
     * @return mixed
     */
    public function getLastNonce();
    /**
     * Return the Location header of the last request
     *
     * returns null if last request had no location header
     *
     * @return string|null
     */
    public function getLastLocation();
    /**
     * Return the HTTP status code of the last request
     *
     * @return int
     */
    public function getLastCode();
    /**
     * Get all Link headers of the last request
     *
     * @return string[]
     */
    public function getLastLinks();
}

class Client implements ClientInterface
{
    private $lastCode;
    private $lastHeader;

    private $base;

    public function __construct($base)
    {
        $this->base = $base;
    }

    private function curl($method, $url, $data = null)
    {
        $headers = array('Accept: application/json', 'Content-Type: application/json');
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, preg_match('~^http~', $url) ? $url : $this->base.$url);
        curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_HEADER, true);

        // DO NOT DO THAT!
        // curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, false);
        // curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);

        switch ($method) {
            case 'GET':
                break;
            case 'POST':
                curl_setopt($handle, CURLOPT_POST, true);
                curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
                break;
        }
        $response = curl_exec($handle);

        if(curl_errno($handle)) {
            printf('Curl: '.curl_error($handle) . "\n");
        }

        $header_size = curl_getinfo($handle, CURLINFO_HEADER_SIZE);

        $header = substr($response, 0, $header_size);
        $body = substr($response, $header_size);

        $this->lastHeader = $header;
        $this->lastCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);

        $data = json_decode($body, true);
        return $data === null ? $body : $data;
    }

    public function post($url, $data)
    {
        return $this->curl('POST', $url, $data);
    }

    public function get($url)
    {
        return $this->curl('GET', $url);
    }

    public function getLastNonce()
    {
        if(preg_match('~Replay\-Nonce: (.+)~i', $this->lastHeader, $matches)) {
            return trim($matches[1]);
        }

        $this->curl('GET', '/directory');
        return $this->getLastNonce();
    }

    public function getLastLocation()
    {
        if(preg_match('~Location: (.+)~i', $this->lastHeader, $matches)) {
            return trim($matches[1]);
        }
        return null;
    }

    public function getLastCode()
    {
        return $this->lastCode;
    }

    public function getLastLinks()
    {
        preg_match_all('~Link: <(.+)>;rel="up"~', $this->lastHeader, $matches);
        return $matches[1];
    }
}

class Base64UrlSafeEncoder
{
    public static function encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    public static function decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
}
// lets encrypt class - end
?>