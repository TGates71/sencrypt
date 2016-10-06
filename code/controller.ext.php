<?php

class module_controller extends ctrl_module
{
		
		static $ok;
		static $error;
		static $delok;
		static $keyadd;
		static $download;
		static $empty;
		
		static function ExecuteDownload($domain, $username)
	 {
		set_time_limit(0);
		global $zdbh;
		global $controller;
		$domain = str_replace('.', '_', $domain);
		$temp_dir = ctrl_options::GetSystemOption('sentora_root') . "etc/tmp/";
		$homedir = ctrl_options::GetSystemOption('hosted_dir') . $username;
    	$backupname = $domain;
		$resault = exec("cd " . $homedir . "/ssl/" .$domain ."/ && " . ctrl_options::GetSystemOption('zip_exe') . " -r9 " . $temp_dir . $backupname . " *");
        @chmod($temp_dir . $backupname . ".zip", 0777);
		$filename = $backupname . ".zip";
		$filepath = $temp_dir;
		header("Pragma: public");
		header("Expires: 0");
		header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
		header("Cache-Control: public");
		header("Content-Description: File Transfer");
		header("Content-type: application/octet-stream");
		header("Content-Disposition: attachment; filename=\"".$filename."\"");
		header("Content-Transfer-Encoding: binary");
		header("Content-Length: ".filesize($filepath.$filename));
		ob_end_flush();
		readfile($filepath.$filename);
		unlink($temp_dir . $backupname . ".zip");
		return true;
		}
		
		static function doDownload()
        {
        global $controller;
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
        if (self::ExecuteDownload($formvars['inName'], $currentuser["username"]))
            return true;
        }
		
		static function doMakeCSR()
    {
        global $controller;
        runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
		if (empty($formvars['inDomain']) || empty($formvars['inName']) || empty($formvars['inAddress']) || empty($formvars['inCity']) || empty($formvars['inCountry']) || empty($formvars['inCompany'])) { 
		self::$empty = true;
		return false; }
        if (self::ExecuteCSR($formvars['inDomain'], $formvars['inName'], $formvars['inAddress'], $formvars['inCity'], $formvars['inCountry'], $formvars['inCompany'], $formvars['inPassword']))
        return true;
    }
	
	static function ExecuteCSR($domain, $name, $address, $city, $country, $company, $password)
	{
		global $zdbh;
		global $controller;
		$currentuser = ctrl_users::GetUserDetail();
		$formvars = $controller->GetAllControllerRequests('FORM');
		$config = array('digest_alg' => 'sha256', 'private_key_bits' => 4096, 'private_key_type' => OPENSSL_KEYTYPE_RSA,  'encrypt_key' => true);
		$csrconfig = array('digest_alg' => 'sha256');
		if (!is_dir("/var/sentora/hostdata/". $currentuser["username"] ."/key/") ) {
				mkdir("/var/sentora/hostdata/". $currentuser["username"] ."/key/", 0777);
			}
		$dn = array(
								"countryName" => "$country",
								"stateOrProvinceName" => "$name",
								"localityName" => "$city",
								"organizationName" => "$company",
								"commonName" => "$domain",
								"emailAddress" => "$address"
							);
		
		$privkey = openssl_pkey_new($config);
		$csr = openssl_csr_new($dn, $privkey, $csrconfig);
		
		openssl_csr_export($csr, $csrout);
		openssl_pkey_export($privkey, $pkeyout, $password);
		
		openssl_pkey_export_to_file($privkey, ctrl_options::GetSystemOption('hosted_dir'). $currentuser["username"] ."/key/".$domain.".key");
		
			$email = $address;
			$emailsubject = "Certificate Signing Request";
            $emailbody = "Hi $currentuser[username]\n\n
			---------------------------------CSR START-------------------------------
			\n\n\n
			$csrout
			\n\n\n
			---------------------------------CSR END-------------------------------";
		

            $phpmailer = new sys_email();
            $phpmailer->Subject = $emailsubject;
            $phpmailer->Body = $emailbody;
			$phpmailer->AddAttachment(ctrl_options::GetSystemOption('hosted_dir'). $currentuser["username"] ."/key/".$domain.".key");
            $phpmailer->AddAddress($email);
            $phpmailer->SendEmail();
			unlink(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/key/".$domain.".key");
			rmdir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/key/");
			self::$keyadd = true;
			return true;
	}
		
		static function doDelete()
        {
        global $controller;
        runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
        if (self::ExecuteDelete($formvars['inName'], $currentuser["username"]))
            return true;
        }
		
		static function ExecuteDelete($domain, $username)
	 {
		 global $zdbh;
		 global $controller;
		 $currentuser = ctrl_users::GetUserDetail();
		 $rootdir = str_replace('.', '_', $domain);
		 $dir = ctrl_options::GetSystemOption('hosted_dir') . $username ."/ssl/". $rootdir;
		 $objects = scandir($dir);
     foreach ($objects as $object) {
       if ($object != "." && $object != "..") {
         unlink($dir."/".$object);
       }
     }
     //reset($objects);
	 rmdir($dir);
	 
	  if($domain == ctrl_options::GetSystemOption('sentora_domain')) {
			
				$name = 'global_zpcustom';
            	$new = '';
				
				$line = "# Made from Cert manager start" . fs_filehandler::NewLine();
				$line  .= fs_filehandler::NewLine();
				$line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/". $domain.".crt". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir."/" . $domain.".key". fs_filehandler::NewLine();
				$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir."/intermediate.crt". fs_filehandler::NewLine();
				$line .= "SSLProtocol All -SSLv2 -SSLv3" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+AESGCM EECDH EDH+AESGCM EDH+aRSA HIGH !MEDIUM !LOW !aNULL !eNULL !LOW !RC4 !MD5 !EXP !PSK !SRP !DSS\"" . fs_filehandler::NewLine();
				$line .= "# Made from Cert manager end" . fs_filehandler::NewLine();
				
				$sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = replace(so_value_tx, :data, :new) WHERE so_name_vc = :name");
        		$sql->bindParam(':data', $line);
				$sql->bindParam(':new', $new);
				$sql->bindParam(':name', $name);
        		$sql->execute();
				
				$line = "# Made from Cert manager start" . fs_filehandler::NewLine();
				$line  .= fs_filehandler::NewLine();
				$line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/". $domain.".crt". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir."/" . $domain.".key". fs_filehandler::NewLine();
				$line .= "SSLProtocol All -SSLv2 -SSLv3" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+AESGCM EECDH EDH+AESGCM EDH+aRSA HIGH !MEDIUM !LOW !aNULL !eNULL !LOW !RC4 !MD5 !EXP !PSK !SRP !DSS\"" . fs_filehandler::NewLine();
				$line .= "# Made from Cert manager end" . fs_filehandler::NewLine();
				
				$sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = replace(so_value_tx, :data, :new) WHERE so_name_vc = :name");
        		$sql->bindParam(':data', $line);
				$sql->bindParam(':new', $new);
				$sql->bindParam(':name', $name);
        		$sql->execute();
				
					$portname = "sentora_port";
					$port = "80";
					$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
                    $updatesql->bindParam(':value', $port);
                    $updatesql->bindParam(':name', $portname);
                    $updatesql->execute();
			
				} else {
					$port 			= NULL;
					$portforward	= NULL;
					$new = '';
					
				$line = "# Made from Cert manager start" . fs_filehandler::NewLine();
				$line .= fs_filehandler::NewLine();
                $line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/" . $domain.".crt". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/" . $domain.".key". fs_filehandler::NewLine();
				$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir."/intermediate.crt". fs_filehandler::NewLine();
				$line .= "SSLProtocol All -SSLv2 -SSLv3" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+AESGCM EECDH EDH+AESGCM EDH+aRSA HIGH !MEDIUM !LOW !aNULL !eNULL !LOW !RC4 !MD5 !EXP !PSK !SRP !DSS\"" . fs_filehandler::NewLine();
				$line .= "# Made from Cert manager end" . fs_filehandler::NewLine();
			
			
			$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx = replace(vh_custom_tx, :data, :new), vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");
             
        	$sql->bindParam(':data', $line);
			$sql->bindParam(':new', $new);
			$sql->bindParam(':domain', $domain);
			$sql->bindParam(':port', $port);
			$sql->bindParam(':portforward', $portforward);
        	$sql->execute();
			
				$line = "# Made from Cert manager start" . fs_filehandler::NewLine();
				$line .= fs_filehandler::NewLine();
                $line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/" . $domain.".crt". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/" . $domain.".key". fs_filehandler::NewLine();
				$line .= "SSLProtocol All -SSLv2 -SSLv3" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+AESGCM EECDH EDH+AESGCM EDH+aRSA HIGH !MEDIUM !LOW !aNULL !eNULL !LOW !RC4 !MD5 !EXP !PSK !SRP !DSS\"" . fs_filehandler::NewLine();
				$line .= "# Made from Cert manager end" . fs_filehandler::NewLine();


			$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx = replace(vh_custom_tx, :data, :new), vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");
             
        	$sql->bindParam(':data', $line);
			$sql->bindParam(':new', $new);
			$sql->bindParam(':domain', $domain);
			$sql->bindParam(':port', $port);
			$sql->bindParam(':portforward', $portforward);
        	$sql->execute();
                    }

	  		self::SetWriteApacheConfigTrue();
		 	self::$delok = true;
			return true;
	 }
		static function doUploadSSL()
	{
		global $zdbh;
		global $controller;
		$currentuser = ctrl_users::GetUserDetail();
		$formvars = $controller->GetAllControllerRequests('FORM');
		$domain = $formvars["inDomain"];
		$rootdir = str_replace('.', '_', $domain);
		if (empty($_FILES["inkey"]["name"]) || empty($_FILES["inWCA"]["name"])) { 
		self::$empty = true;
		return false; }
		if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/") ) {
				mkdir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/", 0777);
			}
		if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/". $rootdir ."/") ) {
				mkdir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/". $rootdir ."/", 0777);
			} else {
			self::$error = true;
			return false;
			}
			
			$target_dir = ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/". $rootdir ."/";
			
			$uploadkey = $target_dir . $domain . ".key";
			$uploadwcrt = $target_dir . $domain . ".crt";
			$uploadicrt = $target_dir . "intermediate.crt";
			move_uploaded_file($_FILES["inkey"]["tmp_name"], $uploadkey);
			move_uploaded_file($_FILES["inWCA"]["tmp_name"], $uploadwcrt);
			move_uploaded_file($_FILES["inICA"]["tmp_name"], $uploadicrt);
			
			if($domain == ctrl_options::GetSystemOption('sentora_domain')) {
			
				
				$line = "# Made from Cert manager start" . fs_filehandler::NewLine();
				$line  .= fs_filehandler::NewLine();
				$line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/". $domain.".crt". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir."/" . $domain.".key". fs_filehandler::NewLine();
				$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir."/intermediate.crt". fs_filehandler::NewLine();
				$line .= "SSLProtocol All -SSLv2 -SSLv3" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+AESGCM EECDH EDH+AESGCM EDH+aRSA HIGH !MEDIUM !LOW !aNULL !eNULL !LOW !RC4 !MD5 !EXP !PSK !SRP !DSS\"" . fs_filehandler::NewLine();
				$line .= "# Made from Cert manager end" . fs_filehandler::NewLine();
			$name = 'global_zpcustom';
            $sql = $zdbh->prepare("SELECT * FROM x_settings WHERE so_name_vc  = :name");
            $sql->bindParam(':name', $name);
            $sql->execute();
            while ($row = $sql->fetch()) { $olddata = $row['so_value_tx']; }
			$data = $olddata.$line;
			
			        $updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
                    $updatesql->bindParam(':value', $data);
                    $updatesql->bindParam(':name', $name);
                    $updatesql->execute();
					
					$portname = "sentora_port";
					$port = "443";
					$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
                    $updatesql->bindParam(':value', $port);
                    $updatesql->bindParam(':name', $portname);
                    $updatesql->execute();
			
			} else {
				
				$line = "# Made from Cert manager start" . fs_filehandler::NewLine();
				$line .= fs_filehandler::NewLine();
                $line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/" . $domain.".crt". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/" . $domain.".key". fs_filehandler::NewLine();
				$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir."/intermediate.crt". fs_filehandler::NewLine();
				$line .= "SSLProtocol All -SSLv2 -SSLv3" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+AESGCM EECDH EDH+AESGCM EDH+aRSA HIGH !MEDIUM !LOW !aNULL !eNULL !LOW !RC4 !MD5 !EXP !PSK !SRP !DSS\"" . fs_filehandler::NewLine();
				$line .= "# Made from Cert manager end" . fs_filehandler::NewLine();
			$port 			= "443";
			$portforward 	= "1";
            $sql = $zdbh->prepare("SELECT * FROM x_vhosts WHERE vh_name_vc = :domain AND vh_deleted_ts IS NULL");
            $sql->bindParam(':domain', $domain);
            $sql->execute();
            while ($row = $sql->fetch()) { $olddata = $row['vh_custom_tx']; }
			$data = $olddata.$line;
			
        	$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx=:data, vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");
        	$sql->bindParam(':data', $data);
			$sql->bindParam(':domain', $domain);
			$sql->bindParam(':port', $port);
			$sql->bindParam(':portforward', $portforward);
        	$sql->execute();
			}
			
			self::SetWriteApacheConfigTrue();
			self::$ok = true;
		return true;
	}
		
		static function doMakenew()
		{
        global $controller;
        runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
		if (empty($formvars['inDomain']) || empty($formvars['inName']) || empty($formvars['inAddress']) || empty($formvars['inCity']) || empty($formvars['inCountry']) || empty($formvars['inCompany'])) { 
		self::$empty = true;
		return false; }
        if (self::ExecuteMakessl($formvars['inDomain'], $formvars['inName'], $formvars['inAddress'], $formvars['inCity'], $formvars['inCountry'], $formvars['inCompany']))
        return true;
		}
		
		static function ExecuteMakessl($domain, $name, $address, $city, $country, $company)
    {
		global $zdbh;
		global $controller;
		$currentuser = ctrl_users::GetUserDetail();
		$formvars = $controller->GetAllControllerRequests('FORM');
		$rootdir = str_replace('.', '_', $domain);
		
		if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/") ) {
				mkdir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/", 0777);
			}
		if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/". $rootdir ."/") ) {
				mkdir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/". $rootdir ."/", 0777);
			} else {
			self::$error = true;
			return false;
			}
	
	// GET user info
		
		 $dn = array(
								"countryName" => "$country",
								"stateOrProvinceName" => "$name",
								"localityName" => "$city",
								"organizationName" => "$company",
								"commonName" => "$domain",
								"emailAddress" => "$address",
								"subjectAltName" => "DNS: $domain, DNS: www.$domain"
							); 		
		// Make Key
		
		//$config = array('private_key_bits' => 4096);
		
		$privkey = openssl_pkey_new();
		
		// Generate a certificate signing request
		$csr = openssl_csr_new($dn, $privkey);
		
		$config = array("digest_alg" => "sha256", "x509_extensions" => "v3_req");
		
		$sscert = openssl_csr_sign($csr, null, $privkey, 365, $config);
		
		//openssl_csr_export($csr, $csrout);
		//openssl_x509_export($sscert, $certout);
		//openssl_pkey_export($privkey, $pkeyout, $password);
		
		openssl_x509_export_to_file($sscert, ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/" .$rootdir ."/". $domain .".crt");
		openssl_pkey_export_to_file($privkey, ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/" .$rootdir ."/". $domain .".key");
			
           if($domain == ctrl_options::GetSystemOption('sentora_domain')) {
				
				$line = "# Made from Cert manager start" . fs_filehandler::NewLine();
				$line .= fs_filehandler::NewLine();
				$line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/". $domain.".crt". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir."/" . $domain.".key". fs_filehandler::NewLine();
				$line .= "SSLProtocol All -SSLv2 -SSLv3" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+AESGCM EECDH EDH+AESGCM EDH+aRSA HIGH !MEDIUM !LOW !aNULL !eNULL !LOW !RC4 !MD5 !EXP !PSK !SRP !DSS\"" . fs_filehandler::NewLine();
				$line .= "# Made from Cert manager end" . fs_filehandler::NewLine();
			$name = 'global_zpcustom';
            $sql = $zdbh->prepare("SELECT * FROM x_settings WHERE so_name_vc  = :name");
            $sql->bindParam(':name', $name);
            $sql->execute();
            while ($row = $sql->fetch()) { $olddata = $row['so_value_tx']; }
			$data = $olddata.$line;
			
			        $updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
                    $updatesql->bindParam(':value', $data);
                    $updatesql->bindParam(':name', $name);
                    $updatesql->execute();
					$portname = "sentora_port";
					$port = "443";
					$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
                    $updatesql->bindParam(':value', $port);
                    $updatesql->bindParam(':name', $portname);
                    $updatesql->execute();
			
			} else {
				
				$line = "# Made from Cert manager start" . fs_filehandler::NewLine();
				$line .= fs_filehandler::NewLine();
                $line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/" . $domain.".crt". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/" . $rootdir. "/" . $domain.".key". fs_filehandler::NewLine();
				$line .= "SSLProtocol All -SSLv2 -SSLv3" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+AESGCM EECDH EDH+AESGCM EDH+aRSA HIGH !MEDIUM !LOW !aNULL !eNULL !LOW !RC4 !MD5 !EXP !PSK !SRP !DSS\"" . fs_filehandler::NewLine();
				$line .= "# Made from Cert manager end" . fs_filehandler::NewLine();
			$port 			= "443";
			$portforward 	= "1";
            $sql = $zdbh->prepare("SELECT * FROM x_vhosts WHERE vh_name_vc = :domain AND vh_deleted_ts IS NULL");
            $sql->bindParam(':domain', $domain);
            $sql->execute();
            while ($row = $sql->fetch()) { $olddata = $row['vh_custom_tx']; }
			$data = $olddata.$line;
			
        	$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx=:data, vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");
        	$sql->bindParam(':data', $data);
			$sql->bindParam(':domain', $domain);
			$sql->bindParam(':port', $port);
			$sql->bindParam(':portforward', $portforward);
        	$sql->execute();
			}

			self::SetWriteApacheConfigTrue();
			self::$ok = true;	
			return true;	
	}
		
		
		
		
		static function ListDomains($uid)
		{
        global $zdbh;
		global $controller;
        $currentuser = ctrl_users::GetUserDetail($uid);
        $sql = "SELECT * FROM x_vhosts WHERE vh_acc_fk=:userid AND vh_enabled_in=1 AND vh_deleted_ts IS NULL ORDER BY vh_name_vc ASC";
        $numrows = $zdbh->prepare($sql);
        $numrows->bindParam(':userid', $currentuser['userid']);
        $numrows->execute();
        if ($numrows->fetchColumn() <> 0) {
            $sql = $zdbh->prepare($sql);
            $sql->bindParam(':userid', $currentuser['userid']);
            $res = array();
            $sql->execute();
			if($currentuser["username"] == "zadmin") {
					$name = ctrl_options::GetSystemOption('sentora_domain');
				$res[] = array('domain' => "$name");
				}
            while ($rowdomains = $sql->fetch()) {
                $res[] = array('domain' => $rowdomains['vh_name_vc']);
            }
            return $res;
        } else {
            return false;
        }
		}
		
		static function getDomainList()
		{
			$currentuser = ctrl_users::GetUserDetail();
			return self::ListDomains($currentuser['userid']);
		}
	
			static function ListSSL($uname)
		{
			global $controller;
			if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $uname ."/ssl/") ) {
				mkdir( ctrl_options::GetSystemOption('hosted_dir'). $uname ."/ssl/", 0777);
		}
				$dir = ctrl_options::GetSystemOption('hosted_dir') . $uname. "/ssl/";
				if(substr($dir, -1) != "/") $dir .= "/";
				$d = @dir($dir);
				while(false !== ($entry = $d->read())) {
				$entry1 = str_replace('_', '.', $entry);
				if($entry[0] == ".") continue;
			$retval[] = array("name" => "$entry1");
		}
			$d->close();
			return $retval;
		}
	
			static function getSSLList()
		{
			$currentuser = ctrl_users::GetUserDetail();
			return self::ListSSL($currentuser['username']);
		}
		
		static function getisShowCSR()
		{
        global $controller;
        $urlvars = $controller->GetAllControllerRequests('URL');
        return (isset($urlvars['show'])) && ($urlvars['show'] == "ShowCSR");
		}
	
		static function getisShowSelf()
		{
        global $controller;
        $urlvars = $controller->GetAllControllerRequests('URL');
        return (isset($urlvars['show'])) && ($urlvars['show'] == "ShowSelf");
		}
	
		static function getisBought()
		{
        global $controller;
        $urlvars = $controller->GetAllControllerRequests('URL');
        return (isset($urlvars['show'])) && ($urlvars['show'] == "Bought");
		}
		static function doselect()
		{
        global $controller;
        runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
		
            if (isset($formvars['inSSLself'])) {
                header("location: ./?module=" . $controller->GetCurrentModule() . '&show=ShowSelf');
                exit;
            }
			if (isset($formvars['inSSLbought'])) {
                header("location: ./?module=" . $controller->GetCurrentModule() . '&show=Bought');
                exit;
            }
			if (isset($formvars['inSSLCSR'])) {
                header("location: ./?module=" . $controller->GetCurrentModule() . '&show=ShowCSR');
                exit;
            }
        return true;
		}
		
		static function getListCountry()
		{
			$res = '<option value="AF">Afghanistan</option> <option value="AX">Åland Islands</option> <option value="AL">Albania</option> <option value="DZ">Algeria</option> <option value="AS">American Samoa</option> <option value="AD">Andorra</option> <option value="AO">Angola</option> <option value="AI">Anguilla</option> <option value="AQ">Antarctica</option> <option value="AG">Antigua and Barbuda</option> <option value="AR">Argentina</option> <option value="AM">Armenia</option> <option value="AW">Aruba</option> <option value="AU">Australia</option> <option value="AT">Austria</option> <option value="AZ">Azerbaijan</option> <option value="BS">Bahamas</option> <option value="BH">Bahrain</option> <option value="BD">Bangladesh</option> <option value="BB">Barbados</option> <option value="BY">Belarus</option> <option value="BE">Belgium</option> <option value="BZ">Belize</option> <option value="BJ">Benin</option> <option value="BM">Bermuda</option> <option value="BT">Bhutan</option> <option value="BO">Bolivia</option> <option value="BA">Bosnia and Herzegovina</option> <option value="BW">Botswana</option> <option value="BV">Bouvet Island</option> <option value="BR">Brazil</option> <option value="IO">British Indian Ocean Territory</option> <option value="BN">Brunei Darussalam</option> <option value="BG">Bulgaria</option> <option value="BF">Burkina Faso</option> <option value="BI">Burundi</option> <option value="KH">Cambodia</option> <option value="CM">Cameroon</option> <option value="CA">Canada</option> <option value="CV">Cape Verde</option> <option value="KY">Cayman Islands</option> <option value="CF">Central African Republic</option> <option value="TD">Chad</option> <option value="CL">Chile</option> <option value="CN">China</option> <option value="CX">Christmas Island</option> <option value="CC">Cocos (Keeling) Islands</option> <option value="CO">Colombia</option> <option value="KM">Comoros</option> <option value="CG">Congo</option> <option value="CD">Congo, The Democratic Republic of The</option> <option value="CK">Cook Islands</option> <option value="CR">Costa Rica</option> <option value="CI">Cote D´ivoire</option> <option value="HR">Croatia</option> <option value="CU">Cuba</option> <option value="CY">Cyprus</option> <option value="CZ">Czech Republic</option> <option value="DK">Denmark</option> <option value="DJ">Djibouti</option> <option value="DM">Dominica</option> <option value="DO">Dominican Republic</option> <option value="EC">Ecuador</option> <option value="EG">Egypt</option> <option value="SV">El Salvador</option> <option value="GQ">Equatorial Guinea</option> <option value="ER">Eritrea</option> <option value="EE">Estonia</option> <option value="ET">Ethiopia</option> <option value="FK">Falkland Islands (Malvinas)</option> <option value="FO">Faroe Islands</option> <option value="FJ">Fiji</option> <option value="FI">Finland</option> <option value="FR">France</option> <option value="GF">French Guiana</option> <option value="PF">French Polynesia</option> <option value="TF">French Southern Territories</option> <option value="GA">Gabon</option> <option value="GM">Gambia</option> <option value="GE">Georgia</option> <option value="DE">Germany</option> <option value="GH">Ghana</option> <option value="GI">Gibraltar</option> <option value="GR">Greece</option> <option value="GL">Greenland</option> <option value="GD">Grenada</option> <option value="GP">Guadeloupe</option> <option value="GU">Guam</option> <option value="GT">Guatemala</option> <option value="GG">Guernsey</option> <option value="GN">Guinea</option> <option value="GW">Guinea-bissau</option> <option value="GY">Guyana</option> <option value="HT">Haiti</option> <option value="HM">Heard Island and Mcdonald Islands</option> <option value="VA">Holy See (Vatican City State)</option> <option value="HN">Honduras</option> <option value="HK">Hong Kong</option> <option value="HU">Hungary</option> <option value="IS">Iceland</option> <option value="IN">India</option> <option value="ID">Indonesia</option> <option value="IR">Iran, Islamic Republic of</option> <option value="IQ">Iraq</option> <option value="IE">Ireland</option> <option value="IM">Isle of Man</option> <option value="IL">Israel</option> <option value="IT">Italy</option> <option value="JM">Jamaica</option> <option value="JP">Japan</option> <option value="JE">Jersey</option> <option value="JO">Jordan</option> <option value="KZ">Kazakhstan</option> <option value="KE">Kenya</option> <option value="KI">Kiribati</option> <option value="KP">Korea, Democratic People´s Republic of</option> <option value="KR">Korea, Republic of</option> <option value="KW">Kuwait</option> <option value="KG">Kyrgyzstan</option> <option value="LA">Lao People´s Democratic Republic</option> <option value="LV">Latvia</option> <option value="LB">Lebanon</option> <option value="LS">Lesotho</option> <option value="LR">Liberia</option> <option value="LY">Libyan Arab Jamahiriya</option> <option value="LI">Liechtenstein</option> <option value="LT">Lithuania</option> <option value="LU">Luxembourg</option> <option value="MO">Macao</option> <option value="MK">Macedonia, The Former Yugoslav Republic of</option> <option value="MG">Madagascar</option> <option value="MW">Malawi</option> <option value="MY">Malaysia</option> <option value="MV">Maldives</option> <option value="ML">Mali</option> <option value="MT">Malta</option> <option value="MH">Marshall Islands</option> <option value="MQ">Martinique</option> <option value="MR">Mauritania</option> <option value="MU">Mauritius</option> <option value="YT">Mayotte</option> <option value="MX">Mexico</option> <option value="FM">Micronesia, Federated States of</option> <option value="MD">Moldova, Republic of</option> <option value="MC">Monaco</option> <option value="MN">Mongolia</option> <option value="ME">Montenegro</option> <option value="MS">Montserrat</option> <option value="MA">Morocco</option> <option value="MZ">Mozambique</option> <option value="MM">Myanmar</option> <option value="NA">Namibia</option> <option value="NR">Nauru</option> <option value="NP">Nepal</option> <option value="NL">Netherlands</option> <option value="AN">Netherlands Antilles</option> <option value="NC">New Caledonia</option> <option value="NZ">New Zealand</option> <option value="NI">Nicaragua</option> <option value="NE">Niger</option> <option value="NG">Nigeria</option> <option value="NU">Niue</option> <option value="NF">Norfolk Island</option> <option value="MP">Northern Mariana Islands</option> <option value="NO">Norway</option> <option value="OM">Oman</option> <option value="PK">Pakistan</option> <option value="PW">Palau</option> <option value="PS">Palestinian Territory, Occupied</option> <option value="PA">Panama</option> <option value="PG">Papua New Guinea</option> <option value="PY">Paraguay</option> <option value="PE">Peru</option> <option value="PH">Philippines</option> <option value="PN">Pitcairn</option> <option value="PL">Poland</option> <option value="PT">Portugal</option> <option value="PR">Puerto Rico</option> <option value="QA">Qatar</option> <option value="RE">Reunion</option> <option value="RO">Romania</option> <option value="RU">Russian Federation</option> <option value="RW">Rwanda</option> <option value="SH">Saint Helena</option> <option value="KN">Saint Kitts and Nevis</option> <option value="LC">Saint Lucia</option> <option value="PM">Saint Pierre and Miquelon</option> <option value="VC">Saint Vincent and The Grenadines</option> <option value="WS">Samoa</option> <option value="SM">San Marino</option> <option value="ST">Sao Tome and Principe</option> <option value="SA">Saudi Arabia</option> <option value="SN">Senegal</option> <option value="RS">Serbia</option> <option value="SC">Seychelles</option> <option value="SL">Sierra Leone</option> <option value="SG">Singapore</option> <option value="SK">Slovakia</option> <option value="SI">Slovenia</option> <option value="SB">Solomon Islands</option> <option value="SO">Somalia</option> <option value="ZA">South Africa</option> <option value="GS">South Georgia and The South Sandwich Islands</option> <option value="ES">Spain</option> <option value="LK">Sri Lanka</option> <option value="SD">Sudan</option> <option value="SR">Suriname</option> <option value="SJ">Svalbard and Jan Mayen</option> <option value="SZ">Swaziland</option> <option value="SE">Sweden</option> <option value="CH">Switzerland</option> <option value="SY">Syrian Arab Republic</option> <option value="TW">Taiwan, Province of China</option> <option value="TJ">Tajikistan</option> <option value="TZ">Tanzania, United Republic of</option> <option value="TH">Thailand</option> <option value="TL">Timor-leste</option> <option value="TG">Togo</option> <option value="TK">Tokelau</option> <option value="TO">Tonga</option> <option value="TT">Trinidad and Tobago</option> <option value="TN">Tunisia</option> <option value="TR">Turkey</option> <option value="TM">Turkmenistan</option> <option value="TC">Turks and Caicos Islands</option> <option value="TV">Tuvalu</option> <option value="UG">Uganda</option> <option value="UA">Ukraine</option> <option value="AE">United Arab Emirates</option> <option value="GB">United Kingdom</option> <option value="US">United States</option> <option value="UM">United States Minor Outlying Islands</option> <option value="UY">Uruguay</option> <option value="UZ">Uzbekistan</option> <option value="VU">Vanuatu</option> <option value="VE">Venezuela</option> <option value="VN">Viet Nam</option> <option value="VG">Virgin Islands, British</option> <option value="VI">Virgin Islands, U.S.</option> <option value="WF">Wallis and Futuna</option> <option value="EH">Western Sahara</option> <option value="YE">Yemen</option> <option value="ZM">Zambia</option> <option value="ZW">Zimbabwe</option>';
			return $res;
		}

		static function SetWriteApacheConfigTrue()
    {
        global $zdbh;
        $sql = $zdbh->prepare("UPDATE x_settings
								SET so_value_tx='true'
								WHERE so_name_vc='apache_changed'");
        $sql->execute();
    }

		static function getResult()
    {
		 if (self::$ok) {
            return ui_sysmessage::shout(ui_language::translate("You SSL has been made. It will be ready in about 5 min."), "zannounceok");
        }
		if (self::$delok) {
            return ui_sysmessage::shout(ui_language::translate("The selected certificate has been deleted."), "zannounceerror");
        }
		if (self::$error) {
            return ui_sysmessage::shout(ui_language::translate("A certificate with that name already exists."), "zannounceerror");
        }
		if (self::$empty) {
            return ui_sysmessage::shout(ui_language::translate("An empty field is not allowed."), "zannounceerror");
        }
		if (self::$keyadd) {
            return ui_sysmessage::shout(ui_language::translate("Certificate Signing Request was made and sent to the mail you have entered"), "zannounceok");
        }
        return;
    }
}
?>