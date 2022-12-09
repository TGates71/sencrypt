<?php
/**
	* Controller for sencrypt module for sentora version 1.0.3
	* Version : 200
	* Author  : Sentora Team, Jettaman, TGages, Diablo925. 
	* Script credits  : Diablo925, TGages
*/


// for LEscript you can use any logger according to Psr\Log\LoggerInterface
class Logger {
	function __call($name, $arguments) {
		echo date('Y-m-d H:i:s')." [$name] ${arguments[0]}\n";
	}
}
//$logger = new Logger();


class module_controller extends ctrl_module {
	
	static $ok;
	static $delok;
	static $error;
	static $dnsInvalid;
	static $modReqsError;
	static $revokecert;
	static $keyadd;
	//static $loggererror;
	
	// For LEscript you can use any logger according to Psr\Log\LoggerInterface
	//function __call($name, $arguments) {
		//echo date('Y-m-d H:i:s')." [$name] ${arguments[0]}\n";
	//}
	
	static function getCheckModReq() {
		# Need to rewrit to be friendly and throw sentora error instead of DIE error --- #### Need to fix ASAP
		if (!defined("PHP_VERSION_ID") || PHP_VERSION_ID < 50300 || !extension_loaded('openssl') || !extension_loaded('curl')) {
			//die("You need at least PHP 5.3.0 with OpenSSL and curl extension installed.\n");
			self::$modReqsError = true;
			//exit;
		}
	}

######### Module & Dispaly stuff - START

	static function getShowLetsEncryptTab() {
		
		# start code
		//if (isset($_GET['ShowPanel']) == 'letsencrypt') {
		//$_GET['ShowPanel'] = null;	
			
		//if ($_GET['ShowPanel'] == 'letsencrypt') {
		if (isset($_GET['ShowPanel']) == true ) {
			if ($_GET['ShowPanel'] == 'letsencrypt') {
				$showPanel = "block";
				return $showPanel;
			}
		} else {
			$showPanel = "none";
			return $showPanel;
		}
	}

	static function getShowThirdPartyTab() {
	
		# start code
		//if (isset($_GET['ShowPanel']) == 'third-party' )  {
		//$_GET['ShowPanel'] = null;
		
		//if ($_GET['ShowPanel'] == 'third-party' )  {
		if (isset($_GET['ShowPanel']) == true ) {
			if ($_GET['ShowPanel'] == 'third-party' )  {
				$showPanel = "block";
				return $showPanel;
			}		
		} else {
			$showPanel = "none";
			return $showPanel;
		}
	}

	static function getShowLetsencryptActive() {
		if (isset($_GET['ShowPanel']) == true ) {
			if ($_GET['ShowPanel'] == 'letsencrypt') {
				$showActiveTab = "active";
				return $showActiveTab;
			} else {
				$showActiveTab = "none";
				return $showActiveTab;
			}
		}
	}


	static function getShowThird_partyActive() {

		if (isset($_GET['ShowPanel']) == true ) {
			if ($_GET['ShowPanel'] == 'third-party') {
				$showActiveTab = "active";
				return $showActiveTab;
			} else {
				$showActiveTab = "none";
				return $showActiveTab;
			}
		}
	}

	static function getAdmin() {
		$user = ctrl_users::GetUserDetail();
		return ($user['usergroup'] == 'Administrators');
	}
	
	static function getList_of_Panel_Domains() {
		$currentuser = ctrl_users::GetUserDetail();
		return self::Show_Panel_domains($currentuser['userid']);
	}	
	
	///////////// Delete active panel ssl domains 
	static function getList_of_Active_Panel_SSL() {
		$currentuser = ctrl_users::GetUserDetail();
		return self::Show_Active_Panel_SSL_Domains($currentuser['userid']);
	}
	
	static function Show_Active_Panel_SSL_Domains() {
		global $zdbh, $controller;
		$currentuser = ctrl_users::GetUserDetail();
		$panelCertPath = ctrl_options::GetSystemOption('hosted_dir');
		$panelDomain = ctrl_options::GetSystemOption('sentora_domain');
		
		// Check if Panel ssl folder exists - This file should have been created during install.
		//if (!is_dir( "/etc/sentora/ssl/sencrypt/letencrypt") ) {
			//fs_director::CreateDirectory( "/etc/sentora/ssl/sencrypt/letsencrypt" );
		//} 
		
		// Check if cert exist or not
		//if (!is_dir( $panelPath . "ssl/sencrypt/letsencrypt/" . $panelDomain . "/") ) {
		if ( is_dir( $panelCertPath . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/". $panelDomain ."/" ) ) {			
			
			$panelDeleteButton = '<form action="./?module=sencrypt&ShowPanel=letsencrypt&action=DeletePanelSSL" method="post">
			<input type="hidden" name="inName" value="'.$panelDomain.'">
			<button class="button-loader btn btn-warning" type="submit" id="button" name="inDeleteSSL" id="inDeletePanelSSL" value="inDeletePanelSSL">Delete</button>
			</form>';
			$certinfo = openssl_x509_parse(file_get_contents(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] . "/ssl/sencrypt/letsencrypt/". $panelDomain ."/cert.pem"));
			$validTo = date('Y-m-d', $certinfo["validTo_time_t"]);
			$now = time();
			$your_date = strtotime("$validTo");
			$datediff = $your_date - $now;
			$panelday = floor($datediff / (60 * 60 * 24));
			$reNewDay = $panelday - 30;
			
			if($panelday <= "-1700") {
				$paneldays = "Not initialized yet"; } else {
				$paneldays = "Expiry in ". $panelday . " days - Auto-renewal in " . $reNewDay . " Days.";
			}
			
			# Revoke button just incase its needed
			$panelRevokeButton = '<form action="./?module=sencrypt&action=RevokePanelSSL" method="post">
				<input type="hidden" name="inDomain" value="'.$panelDomain.'">
				<button class="button-loader btn btn-danger" type="submit" id="button" name="inRevokeSSL" id="inRevokePanelSSL" value="inRevokePanelSSL">Revoke</button>
			</form>';
		
			$panelres[] = array('Active_Panel_Domain' => $panelDomain, 'Vendor_AC' => $sslvendor, 'Active_Panel_Days' =>  $paneldays, 'Active_Panel_Button' => $panelDeleteButton,  'Active_Panel_Revoke' => $panelRevokeButton);
		
		/////////////// If third party ssl show
		} elseif ( is_dir( $panelCertPath . $currentuser["username"] ."/ssl/sencrypt/third_party/". $panelDomain ."/" ) ) {
						
			$panelDeleteButton = '<form action="./?module=sencrypt&ShowPanel=third_party&action=TPDelete" method="post">
			<input type="hidden" name="inName" value="'.$panelDomain.'">
			<button class="button-loader btn btn-warning" type="submit" id="button" name="inDeleteSSL" id="inDeletePanelSSL" value="inDeletePanelSSL">Delete</button>
			</form>';
			$certinfo = openssl_x509_parse(file_get_contents(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] . "/ssl/sencrypt/third_party/". $panelDomain ."/cert.pem"));
			$validTo = date('Y-m-d', $certinfo["validTo_time_t"]);
			$now = time();
			$your_date = strtotime("$validTo");
			$datediff = $your_date - $now;
			$panelday = floor($datediff / (60 * 60 * 24));
			$reNewDay = $panelday - 30;
			$sslvendor = "Third Party";
			
			if($panelday <= "-1700") {
				$paneldays = "Not initialized yet"; } else {
				$paneldays = "Expiry in ". $panelday . " days.";
			}
		
			$panelres[] = array('Active_Panel_Domain' => $panelDomain, 'Active_Panel_Providor' => $sslvendor, 'Active_Panel_Days' =>  $paneldays, 'Active_Panel_Button' => $panelDeleteButton, 'Active_Panel_Revoke' => NULL);
		
		} else {
			// Do nothing because there is no ssl
			//$panelres[] = NULL;
			$panelres[] = array('Active_Panel_Domain' => "No active Panel Domain SSL's", 'Active_Panel_Providor' => NULL, 'Active_Panel_Days' =>  NULL, 'Active_Panel_Button' => NULL, 'Active_Panel_Revoke' => NULL);
			
		}
		return $panelres;
		
	}

	//////////////////
	
	
	
	
	
	static function Show_Panel_Domains() {
		global $zdbh, $controller;
		$currentuser = ctrl_users::GetUserDetail();
		//$panelPath = "/etc/sentora/";
		$panelDomain = ctrl_options::GetSystemOption('sentora_domain');
		
		// Check if certs already exisst on system	
		if ( !is_dir( ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/" . $panelDomain . "/") ) {
					
			if ( !is_dir( ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrpyt/" . $panelDomain . "/") ) {
				// do nothing cert exists
				$panelbutton = '<form action="./?module=sencrypt&ShowPanel=letsencrypt&action=MakePanelSSL" method="post">
				<input type="hidden" name="inDomain" value="'.$panelDomain.'">
				<button class="button-loader btn btn-primary" type="submit" id="button" name="in" id="inMakePanelSSL" value="inMakePanelSSL">Encrypt</button>
				</form>';
				$paneldays = "";
				
				$panelres[] = array('Panel_Domain' => $panelDomain, 'Panel_Button' => $panelbutton, 'Panel_Days' =>  $paneldays);
				
			}
		
		} else {
			// Do nothing	
			$panelres[] = array('Panel_Domain' => "<h4 style='color:red;'>All panel domains have Active SSL Cert's. Please see active cert's above.<h4>", 'Vendor_AC' => NULL, 'Panel_Days' =>  NULL, 'Panel_Button' => NULL,  'Panel_Revoke' => NULL);			
		
		}
		
		return $panelres;
		
	}
	
	static function getList_of_domains() {
		$currentuser = ctrl_users::GetUserDetail();
		return self::Show_list_of_domains($currentuser['userid']);
	}	
	

	static function Show_list_of_domains() {
		global $zdbh, $controller;
        $currentuser = ctrl_users::GetUserDetail();
		
		$sql = "SELECT * FROM x_vhosts WHERE vh_acc_fk=:userid AND vh_enabled_in=1 AND vh_deleted_ts IS NULL ORDER BY vh_name_vc ASC";
        $numrows = $zdbh->prepare($sql);
        $numrows->bindParam(':userid', $currentuser['userid']);
        $numrows->execute();
        if ($numrows->fetchColumn() <> 0) {
            $sql = $zdbh->prepare($sql);
            $sql->bindParam(':userid', $currentuser['userid']);
            $res = array();
            $sql->execute();
            while ($rowdomains = $sql->fetch()) {
			// Check if folder ssl exists
				if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/") ) {
					//mkdir (ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/");	
					fs_director::CreateDirectory( ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/" );
				}
				
			// Check if cert exist or not
				if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/". $rowdomains['vh_name_vc'] ."/") ) {

					// Check if ssl exists else where
					if ( is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $rowdomains['vh_name_vc'] ."/") ) {

						# Do nothing

					} else {

						//$button = '<form action="./?module=sencrypt&action=MakeSSL" method="post">
						$button = '<form action="./?module=sencrypt&ShowPanel=letsencrypt&action=MakeSSL" method="post">
							<input type="hidden" name="inDomain" value="'.$rowdomains['vh_name_vc'].'">
							<button class="button-loader btn btn-primary" type="submit" id="button" name="in" id="inMakeSSL" value="inMakeSSL">Encrypt</button>
						</form>';
						$days = "";
						
						$res[] = array('Domain' => $rowdomains['vh_name_vc'], 'Button' => $button, 'Days' =>  $days);
						
					}
					
				} else {
				
				//if ( is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/". $rowdomains['vh_name_vc'] ."/") ) {
					
					/*
					$button = '<form action="./?module=sencrypt&ShowPanel=letsencrypt&action=Delete" method="post">
						<input type="hidden" name="inDomain" value="'.$rowdomains['vh_name_vc'].'">
						<button class="button-loader btn btn-warning" type="submit" id="button" name="inDeleteSSL" id="inDeleteSSL" value="inDeleteSSL">Delete</button>
					</form>';
					$certinfo = openssl_x509_parse(file_get_contents(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/". $rowdomains['vh_name_vc'] ."/cert.pem"));
					$validTo = date('Y-m-d', $certinfo["validTo_time_t"]);
					$now = time();
					$your_date = strtotime("$validTo");
					$datediff = $your_date - $now;
					$day = floor($datediff / (60 * 60 * 24));
					
					$reNewDay = $day - 30;
					
					if($day <= "-1700") {
						$days = "Not initialized yet"; } else {
						$days = "Expiry in ". $day . " days - Auto-renewal in " . $reNewDay . " Days.";
					}
					
					# Revoke button just incase its needed
					$RevokeButton = '<form action="./?module=sencrypt&action=RevokeSSL" method="post">
						<input type="hidden" name="inDomain" value="'.$rowdomains['vh_name_vc'].'">
						<button class="button-loader btn btn-warning" type="submit" id="button" name="inRevokeSSL" id="inRevokePanelSSL" value="inRevokePanelSSL" > Revoke </button>
					</form>';
					
					$res[] = array('Domain' => $rowdomains['vh_name_vc'], 'Button' => $button, 'Days' =>  $days, 'Revoke' => $RevokeButton);
					*/
				}
				
				# OLD CODE
				//$res[] = array('Domain' => $rowdomains['vh_name_vc'], 'Button' => $button, 'Days' =>  $days, 'Revoke' => $RevokeButton);
		
				
			}



			return $res;
			
		} else {		
			return false;
		}
	}



















#################### NEW CODE
	static function getList_of_active_domains_ssl() {
		$currentuser = ctrl_users::GetUserDetail();
		return self::Show_list_of_active_domain_ssl($currentuser['userid']);
	}
	
	static function Show_list_of_active_domain_ssl() {
		global $zdbh, $controller;
	    $currentuser = ctrl_users::GetUserDetail();
		$panelDomain = ctrl_options::GetSystemOption('sentora_domain');
		
		/////////////////////////////// NEW CODE
	
		# Show Sentora panel SSLs certs
		if ( is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/". $panelDomain ."/" ) ) {
							
			// start here
				# Show active Sentora Panel SSLs
				//if ( is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $rowdomains['vh_name_vc'] ."/" ) ) {
				//if ( is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/". ctrl_options::GetSystemOption('sentora_domain') ."/" ) ) {
					
			
					
			$button = '<form action="./?module=sencrypt&ShowPanel=third-party&action=# method="post">
				<input type="hidden" name="inName" value="'. $rowdomains['vh_name_vc'] .'">
				<button class="btn btn-warning" type="submit" id="button" name="inDelete_'.$currentuser["username"].'" id="inDelete_'.$currentuser["username"].'" value="inDelete_' . $currentuser["username"] . '">Delete</button></td>
						 '.runtime_csfr::Token().'
				</form>';
					
			$Downloadbutton = '<form action="./?module=sencrypt&ShowPanel=third-party&action=#" method="post">
				<input type="hidden" name="inName" value="'. $rowdomains['vh_name_vc'] .'">
				<button class="btn btn-primary1" type="submit" id="button" name="inDownload_'.$currentuser["username"].'" id="inDownload_'.$currentuser["username"].'" value="inDownload_'.$currentuser["username"].'">Download</button></td>
				</form>';
					
			$certinfo = openssl_x509_parse(file_get_contents(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $rowdomains['vh_name_vc'] ."/cert.pem"));
			$validTo = date('Y-m-d', $certinfo["validTo_time_t"]);
			$now = time();
			$your_date = strtotime("$validTo");
			$datediff = $your_date - $now;
			$day = floor($datediff / (60 * 60 * 24));
			$sslvendor = "Third-party";
					
			$reNewDay = $day - 30;
					
			if($day <= "-1700") {
				$days = "Not initialized yet"; } else {
				$days = "Expiry in ". $day . " days ";
			}
							
			$res[] = array('Domain_AC' => $panelDomain, 'Button_AC' => $button, 'Vendor_AC' => $sslvendor, 'Days_AC' =>  $days, 'Download_AC' => $Downloadbutton, 'Revoke_AC' => NULL );					
					
		}
				
				
				
				
		////////////////////////////// NEW CODE

		# Vhosts BELOW 

		$sql = "SELECT * FROM x_vhosts WHERE vh_acc_fk=:userid AND vh_enabled_in=1 AND vh_deleted_ts IS NULL ORDER BY vh_name_vc ASC";
        $numrows = $zdbh->prepare($sql);
        $numrows->bindParam(':userid', $currentuser['userid']);
        $numrows->execute();
        if ($numrows->fetchColumn() > 0) {
            $sql = $zdbh->prepare($sql);
            $sql->bindParam(':userid', $currentuser['userid']);
            $res = array();
            $sql->execute();
            while ($rowdomains = $sql->fetch()) {
			// Check if folder ssl exists
				if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/") ) {
					//mkdir (ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/");	
					fs_director::CreateDirectory( ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/" );
				}
				
				# Check if cert exist or not
				//if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/". $rowdomains['vh_name_vc'] ."/") ) {
				/*
					//$button = '<form action="./?module=sencrypt&action=MakeSSL" method="post">
					$button = '<form action="./?module=sencrypt&ShowPanel=letsencrypt&action=MakeSSL" method="post">
						<input type="hidden" name="inDomain" value="'.$rowdomains['vh_name_vc'].'">
						<button class="button-loader btn btn-primary" type="submit" id="button" name="in" id="inMakeSSL" value="inMakeSSL">Encrypt</button>
					</form>';
					$days = "";
					
					$res[] = array('Domain_AC' => $rowdomains['vh_name_vc'], 'Button_AC' => $button, 'Days_AC' =>  $days);
					*/
				//} else {
				
		

				
				
				///////////////////////////////////////////////////////////////////
				
				
				# If Third Party Vhost cert	
				if ( is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $rowdomains['vh_name_vc'] ."/" ) ) {	
					//$button = '<form action="./?module=sencrypt&ShowPanel=letsencrypt&action=Delete" method="post">
						//<input type="hidden" name="inDomain" value="'.$rowdomains['vh_name_vc'].'">
						//<button class="button-loader btn btn-warning" type="submit" id="button" name="inDeleteSSL" id="inDeleteSSL" value="inDeleteSSL">Delete</button>
					//</form>';
					
					$button = '<form action="./?module=sencrypt&ShowPanel=third-party&action=TPDelete" method="post">
						<input type="hidden" name="inName" value="'. $rowdomains['vh_name_vc'] .'">
						<button class="btn btn-warning" type="submit" id="button" name="inDelete_'.$currentuser["username"].'" id="inDelete_'.$currentuser["username"].'" value="inDelete_' . $currentuser["username"] . '">Delete</button></td>
						 '.runtime_csfr::Token().'
					</form>';
					
					$Downloadbutton = '<form action="./?module=sencrypt&ShowPanel=third-party&action=Download" method="post">
							<input type="hidden" name="inName" value="'. $rowdomains['vh_name_vc'] .'">
							<button class="btn btn-primary1" type="submit" id="button" name="inDownload_'.$currentuser["username"].'" id="inDownload_'.$currentuser["username"].'" value="inDownload_'.$currentuser["username"].'">Download</button></td>
					</form>';
					
					$certinfo = openssl_x509_parse(file_get_contents(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $rowdomains['vh_name_vc'] ."/cert.pem"));
					$validTo = date('Y-m-d', $certinfo["validTo_time_t"]);
					$now = time();
					$your_date = strtotime("$validTo");
					$datediff = $your_date - $now;
					$day = floor($datediff / (60 * 60 * 24));
					$sslvendor = "Third-party";
					
					$reNewDay = $day - 30;
					
					if($day <= "-1700") {
						$days = "Not initialized yet"; } else {
						$days = "Expiry in ". $day . " days ";
					}
							
					$res[] = array('Domain_AC' => $rowdomains['vh_name_vc'], 'Button_AC' => $button, 'Vendor_AC' => $sslvendor, 'Days_AC' =>  $days, 'Download_AC' => $Downloadbutton, 'Revoke_AC' => NULL );
					
				
				
				// If Letsencrypt cert	
				} elseif ( is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/". $rowdomains['vh_name_vc'] ."/" ) ) {	
					
					$button = '<form action="./?module=sencrypt&ShowPanel=letsencrypt&action=Delete" method="post">
						<input type="hidden" name="inDomain" value="'.$rowdomains['vh_name_vc'].'">
						<button class="button-loader btn btn-warning" type="submit" id="button" name="inDeleteSSL" id="inDeleteSSL" value="inDeleteSSL">Delete</button>
					</form>';
					
					# Revoke button just incase its needed
					$RevokeButton = '<form action="./?module=sencrypt&action=RevokeSSL" method="post">
						<input type="hidden" name="inDomain" value="'.$rowdomains['vh_name_vc'].'">
						<button class="button-loader btn btn btn-danger" type="submit" id="button" name="inRevokeSSL" id="inRevokeSSL" value="inRevokeSSL" > Revoke </button>
					</form>';
					
					$certinfo = openssl_x509_parse(file_get_contents(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/". $rowdomains['vh_name_vc'] ."/cert.pem"));
					$validTo = date('Y-m-d', $certinfo["validTo_time_t"]);
					$now = time();
					$your_date = strtotime("$validTo");
					$datediff = $your_date - $now;
					$day = floor($datediff / (60 * 60 * 24));
					$sslvendor = "Lets Encrypt";
					
					
					$reNewDay = $day - 30;
					
					if($day <= "-1700") {
						$days = "Not initialized yet"; } else {
						$days = "Expiry in ". $day . " days - Auto-renewal in " . $reNewDay . " Days.";
					}
					
					$res[] = array('Domain_AC' => $rowdomains['vh_name_vc'], 'Button_AC' => $button, 'Vendor_AC' => $sslvendor, 'Days_AC' =>  $days, 'Download_AC' => NULL, 'Revoke_AC' => $RevokeButton);
					
				}
			}
			return $res;
			
		} else {		
			//return false;
			
			
			//// TESTING
			$res[] = array('Domain_AC' => "No active Domain SSL's", 'Button_AC' => NULL, 'Vendor_AC' => NULL, 'Days_AC' =>  NULL, 'Download_AC' => NULL, 'Revoke_AC' => NULL);
			
			return $res;
			
		}
	}

######################### END NEW CODE

######### Module & Dispaly stuff - END













############## Third_Party code below - START

	static function ExecuteDownload($domain, $username) {
		set_time_limit(0);
		global $zdbh;
		global $controller;
		$rootdir = str_replace('.', '_', $domain);
		
		$temp_dir = ctrl_options::GetSystemOption('sentora_root') . "etc/tmp/";
		$homedir = ctrl_options::GetSystemOption('hosted_dir') . $username;
    	$backupname = $rootdir;
		$resault = exec("cd " . $homedir . "/ssl/sencrypt/third_party/" .$domain . "/ && " . ctrl_options::GetSystemOption('zip_exe') . " -r9 " . $temp_dir . $backupname . " *");
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
		
		// Return to page. Reload issue. Fix below
		header('Location: ' . $_SERVER['HTTP_REFERER']);
	}
	
	static function doDownload() {
		
        global $controller;
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
        if (self::ExecuteDownload($formvars['inName'], $currentuser["username"])) {
            return true;
		}
    }

	static function doMakeCSR() {
		global $controller;
		runtime_csfr::Protect();
		$currentuser = ctrl_users::GetUserDetail();
		$formvars = $controller->GetAllControllerRequests('FORM');
		if (empty($formvars['inDomain']) || empty($formvars['inName']) || empty($formvars['inAddress']) || empty($formvars['inCity']) || empty($formvars['inCountry']) || empty($formvars['inCompany'])) { 
			self::$empty = true;
			return false;
		}
		if (self::ExecuteCSR($formvars['inDomain'], $formvars['inName'], $formvars['inAddress'], $formvars['inCity'], $formvars['inCountry'], $formvars['inCompany'], $formvars['inPassword'])) {
			return true;
		}
	}
		
	static function ExecuteCSR($domain, $name, $address, $city, $country, $company, $password) {
		global $zdbh;
		global $controller;
		$currentuser = ctrl_users::GetUserDetail();
		$formvars = $controller->GetAllControllerRequests('FORM');
		$config = array('digest_alg' => 'sha256', 'private_key_bits' => 4096, 'private_key_type' => OPENSSL_KEYTYPE_RSA,  'encrypt_key' => true);
		$csrconfig = array('digest_alg' => 'sha256');
		if (!is_dir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/sencrypt/third_party/key/") ) {
			//mkdir("/var/sentora/hostdata/". $currentuser["username"] ."/ssl/sencrypt/third_party/key/", 0777);
			fs_director::CreateDirectory( "/var/sentora/hostdata/". $currentuser["username"] ."/ssl/sencrypt/third_party/key/" );
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
			
		openssl_pkey_export_to_file($privkey, ctrl_options::GetSystemOption('hosted_dir'). $currentuser["username"] ."/ssl/sencrypt/third_party/key/".$domain.".key");
			
			$email = $address;
			$emailsubject = "Certificate Signing Request";
			$emailbody = "Hi $currentuser[username]\n\n
			---------------------------------CSR START-------------------------------
			\n\n\n
			$csrout
			\n\n\n
			---------------------------------CSR END-------------------------------";
			
			// PHP Mailer option
			$phpmailer = new sys_email();
			$phpmailer->Subject = $emailsubject;
			$phpmailer->Body = $emailbody;
			$phpmailer->AddAttachment(ctrl_options::GetSystemOption('hosted_dir'). $currentuser["username"] ."/ssl/sencrypt/third_party/key/".$domain.".key");
			$phpmailer->AddAddress($email);
			$phpmailer->SendEmail();

			unlink(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/key/".$domain.".key");
			rmdir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/key/");
			self::$keyadd = true;
			return true;
			
	}

















	static function doTPDelete() {
        global $controller;
        //runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
		
		$sub_module = "third_party";
		
        if (self::ExecuteTPDelete($formvars['inName'], $currentuser["username"], $sub_module)) {
            return true;
		}
    }

	static function ExecuteTPDelete($domain, $username, $sub_module) {
		global $zdbh;
		global $controller;
		$currentuser = ctrl_users::GetUserDetail();
		//$rootdir = str_replace('.', '_', $domain);
		$dir = ctrl_options::GetSystemOption('hosted_dir') . $username ."/ssl/sencrypt/".$sub_module."/". $domain;
		$objects = scandir($dir);
		 
		foreach ($objects as $object) {
			if ($object != "." && $object != "..") {
				unlink($dir."/".$object);
			}
		}
			
     	//reset($objects); 		NOT SURE IF WE NEED THIS
		rmdir($dir);

		# Sentora domain CERTS
		if($domain == ctrl_options::GetSystemOption('sentora_domain')) {
			
			### For Letsencrypt or third-party NON Self signed
				
			$line = "# Made from Sencrypt - ".$sub_module." - start" . fs_filehandler::NewLine();
			$line .= fs_filehandler::NewLine();
			$line .= 'SSLEngine On' . fs_filehandler::NewLine();
			$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain. "/cert.pem". fs_filehandler::NewLine();
			$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain."/private.pem". fs_filehandler::NewLine();
			#####################
			# If Letsencrypt or purchased SSL
			if ( $sub_module == "letsencrypt" ) {
				$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain."/chain.pem". fs_filehandler::NewLine();
				
			} elseif ( $sub_module == "third_party" ) {
				$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain."/intermediate.crt". fs_filehandler::NewLine();
				
			} elseif ( $sub_module == "self_signed" ) {
				# self signed - DO NOthing
			}
			######################
			$line .= "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();
			$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
			$line .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
			$line .= "# Made from Sencrypt - ".$sub_module." - end" . fs_filehandler::NewLine();
				
			
			//////// NEW CODE
			if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {
				// For older Sentora support
				$new = '';
				$name = 'global_zpcustom';
				
				$sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = replace(so_value_tx, :data, :new) WHERE so_name_vc = :name");
				$sql->bindParam(':data', $line);
				$sql->bindParam(':new', $new);
				$sql->bindParam(':name', $name);
				$sql->execute();
	
			} else {
				// For Sentora 2.0
				$new = NULL;
				$name = 'panel_ssl_tx';
					
				$sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = replace(so_value_tx, :data, :new) WHERE so_name_vc = :name");
				$sql->bindParam(':data', $line);
				$sql->bindParam(':new', $new);
				$sql->bindParam(':name', $name);
				$sql->execute();		
			
			}
			
			
			### For Self signed
			
			#####################################################
			//////// NEW CODE - this should be for self signed...

			$line = "# Made from Sencrypt - ".$sub_module." - start" . fs_filehandler::NewLine();
			$line .= fs_filehandler::NewLine();
			$line .= 'SSLEngine On' . fs_filehandler::NewLine();
			$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain. "/cert.pem". fs_filehandler::NewLine();
			$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain."/private.pem". fs_filehandler::NewLine();
			$line .= "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();
			$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
			$line .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
			$line .= "# Made from Sencrypt - ".$sub_module." - end" . fs_filehandler::NewLine();
				
			// Update Data
			$sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = replace(so_value_tx, :data, :new) WHERE so_name_vc = :name");
			$sql->bindParam(':data', $line);
			$sql->bindParam(':new', $new);
			$sql->bindParam(':name', $name);
			$sql->execute();
			
			// Update Port
			//$portname = "sentora_port";
			//$port = "80";
			
			//$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
			//$updatesql->bindParam(':value', $port);
			//$updatesql->bindParam(':name', $portname);
			//$updatesql->execute();
			
		} else {
			
			### USER Domain Letsencrypt and Third-party CERT
			
			$port 			= NULL;
			$portforward	= NULL;
						
			$line = "# Made from Sencrypt - ".$sub_module." - start" . fs_filehandler::NewLine();
			$line .= fs_filehandler::NewLine();
			$line .= 'SSLEngine On' . fs_filehandler::NewLine();
			$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain."/cert.pem". fs_filehandler::NewLine();
			$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain."/private.pem". fs_filehandler::NewLine();
			
			#####################
			# If Letsencrypt or purchased SSL
			if ( $sub_module == "letsencrypt" ) {
				$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain."/chain.pem". fs_filehandler::NewLine();
				
			} elseif ( $sub_module == "third_party" ) {
				$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain."/intermediate.crt". fs_filehandler::NewLine();
				
			} elseif ( $sub_module == "self_signed" ) {
				# self signed - DO NOthing
			}
			######################
			
			$line .= "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();
			$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
			$line .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
			$line .= "# Made from Sencrypt - ".$sub_module." - end" . fs_filehandler::NewLine();
				
			//////// NEW CODE
			if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {	
				// For older Sentora support
				$new = '';
				
				$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx = replace(vh_custom_tx, :data, :new), vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");
				$sql->bindParam(':data', $line);
				$sql->bindParam(':new', $new);
				$sql->bindParam(':domain', $domain);
				$sql->bindParam(':port', $port);
				$sql->bindParam(':portforward', $portforward);
				$sql->execute();
				
			} else {
				// For Sentora 2.0
				$new = NULL;
				
				$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_ssl_tx = replace(vh_ssl_tx, :data, :new), vh_ssl_port_in=:port WHERE vh_name_vc = :domain");
				$sql->bindParam(':data', $line);
				$sql->bindParam(':new', $new);
				$sql->bindParam(':domain', $domain);
				$sql->bindParam(':port', $port);
				$sql->execute();
													
			}
			
			
			

			//////// NEW CODE

			###########################################################
			// Self Signed 

				$ssline = "# Made from Sencrypt - ".$sub_module." - start" . fs_filehandler::NewLine();
				$ssline .= fs_filehandler::NewLine();
				$ssline .= 'SSLEngine On' . fs_filehandler::NewLine();
				$ssline .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain."/cert.pem". fs_filehandler::NewLine();
				$ssline .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/".$sub_module."/".$domain."/private.pem". fs_filehandler::NewLine();			
				$ssline .= "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();	
				$ssline .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$ssline .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
				$ssline .= "# Made from Sencrypt - ".$sub_module." - end" . fs_filehandler::NewLine();


				
				if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {	
					// For older Sentora support
					$new = '';
					
					$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx = replace(vh_custom_tx, :data, :new), vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");
					$sql->bindParam(':data', $ssline);
					$sql->bindParam(':new', $new);
					$sql->bindParam(':domain', $domain);
					$sql->bindParam(':port', $port);
					$sql->bindParam(':portforward', $portforward);
					$sql->execute();
					
				} else {
					// For Sentora 2.0
					$new = NULL;
					
					$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_ssl_tx = replace(vh_ssl_tx, :data, :new), vh_ssl_port_in=:port WHERE vh_name_vc = :domain");
					$sql->bindParam(':data', $ssline);
					$sql->bindParam(':new', $new);
					$sql->bindParam(':domain', $domain);
					$sql->bindParam(':port', $port);
					$sql->execute();
				}
				
	
			/////// Self sign END
				
				
				
				
		}

	  	self::SetWriteApacheConfigTrue();
		self::$delok = true;
		return true;

	}
	


































	static function doUploadSSL() {
		global $zdbh;
		global $controller;
		$currentuser = ctrl_users::GetUserDetail();
		$formvars = $controller->GetAllControllerRequests('FORM');
		$domain = $formvars["inDomain"];
		//$rootdir = str_replace('.', '_', $domain);
		if (empty($_FILES["inkey"]["name"]) || empty($_FILES["inWCA"]["name"])) { 
			self::$empty = true;
			return false; 
		}
		
		if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/") ) {
			mkdir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/", 0777);
		}
			
		if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $domain ."/") ) {
				mkdir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $domain ."/", 0777);
			} else {
				self::$error = true;
				return false;
			}
			
			$target_dir = ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $domain ."/";
			
			# OLD
			//$uploadkey = $target_dir . $domain . ".key";
			//$uploadwcrt = $target_dir . $domain . ".crt";
			//$uploadicrt = $target_dir . "intermediate.crt";
			$uploadkey = $target_dir . "private.pem";
			$uploadwcrt = $target_dir . "cert.pem";
			$uploadicrt = $target_dir . "intermediate.crt";
			
			move_uploaded_file($_FILES["inkey"]["tmp_name"], $uploadkey);
			move_uploaded_file($_FILES["inWCA"]["tmp_name"], $uploadwcrt);
			move_uploaded_file($_FILES["inICA"]["tmp_name"], $uploadicrt);
			
			if($domain == ctrl_options::GetSystemOption('sentora_domain')) {
			
				$line = "# Made from Sencrypt - third_party - start" . fs_filehandler::NewLine();
				$line  .= fs_filehandler::NewLine();
				$line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/third_party/" . $domain. "/cert.pem". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/third_party/" . $domain."/private.pem". fs_filehandler::NewLine();
				$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/third_party/" . $domain."/intermediate.crt". fs_filehandler::NewLine();
				$line .= "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();		
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
				$line .= "# Made from Sencrypt - third_party - end" . fs_filehandler::NewLine();

				//////// NEW CODE
				if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {
					// For older Sentora support

					$sql = $zdbh->prepare("SELECT * FROM x_settings WHERE so_name_vc  = :name");
					$sql->bindParam(':name', $name);
					$sql->execute();
				
					while ($row = $sql->fetch()) { $olddata = $row['so_value_tx']; }
						$data = $olddata.$line;
						$name = 'global_zpcustom';
						
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
					// For Sentora 2.0
						$name = 'panel_ssl_tx';
						
						// update panel data
						$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
						$updatesql->bindParam(':value', $line);
						$updatesql->bindParam(':name', $name);
						$updatesql->execute();
					
						// Update panel port					
						//$portname = "sentora_port";
						//$port = "443";
						//$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
						//$updatesql->bindParam(':value', $port);
						//$updatesql->bindParam(':name', $portname);
						//$updatesql->execute();
						
				}
				//////// NEW CODE

			} else {
				
				//$line = "# Made from Cert manager start" . fs_filehandler::NewLine();
				$line = "# Made from Sencrypt - third_party - start" . fs_filehandler::NewLine();
				$line .= fs_filehandler::NewLine();
                $line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/third_party/" . $domain. "/cert.pem". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/third_party/" . $domain. "/private.pem". fs_filehandler::NewLine();
				$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/third_party/" . $domain."/intermediate.crt". fs_filehandler::NewLine();
				$line .= "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();	
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
				$line .= "# Made from Sencrypt - third_party - end" . fs_filehandler::NewLine();
				
				$port 			= "443";
				
				//////// NEW CODE
				if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {
					// For older Sentora support
					$portforward 	= "1";
					
					$sql = $zdbh->prepare("SELECT * FROM x_vhosts WHERE vh_name_vc = :domain AND vh_deleted_ts IS NULL");
					$sql->bindParam(':domain', $domain);
					$sql->execute();
					
					while ($row = $sql->fetch()) { 
						$olddata = $row['vh_custom_tx']; 
					}	
						
						$data = $olddata.$line;
						
						$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx=:data, vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");
						$sql->bindParam(':data', $data);
						$sql->bindParam(':domain', $domain);
						$sql->bindParam(':port', $port);
						$sql->bindParam(':portforward', $portforward);
						$sql->execute();
					
				} else {
					// For Sentora 2.0
					$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_ssl_tx=:data, vh_ssl_port_in=:port WHERE vh_name_vc = :domain");
					$sql->bindParam(':data', $line);
					$sql->bindParam(':domain', $domain);
					$sql->bindParam(':port', $port);
					$sql->execute();
						
				}
			}
			//////// NEW CODE
			
			self::SetWriteApacheConfigTrue();
			self::$ok = true;
			return true;
	}

	static function doMakenew() {
        global $controller;
        runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
		if (empty($formvars['inDomain']) || empty($formvars['inName']) || empty($formvars['inAddress']) || empty($formvars['inCity']) || empty($formvars['inCountry']) || empty($formvars['inCompany'])) { 
			self::$empty = true;
			return false;
		}
        if (self::ExecuteMakeTPssl($formvars['inDomain'], $formvars['inName'], $formvars['inAddress'], $formvars['inCity'], $formvars['inCountry'], $formvars['inCompany']))
	        return true;
	}
		
	static function ExecuteMakeTPssl($domain, $name, $address, $city, $country, $company) {
		global $zdbh;
		global $controller;
		$currentuser = ctrl_users::GetUserDetail();
		$formvars = $controller->GetAllControllerRequests('FORM');
		$rootdir = str_replace('.', '_', $domain);
		
		if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party") ) {
			mkdir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party", 0777);
		}
		
		//if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $rootdir ."/") ) {
			//mkdir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $rootdir ."/", 0777);
		if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $domain ."/") ) {
			mkdir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $domain ."/", 0777);	
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
			
			
			
			
			
			
		#################################################	
		
		#OLD
		//openssl_x509_export_to_file($sscert, ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $domain ."/". $domain .".crt");
		//openssl_pkey_export_to_file($privkey, ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $domain ."/". $domain .".key");
				
		openssl_x509_export_to_file($sscert, ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $domain ."/cert.pem");
		openssl_pkey_export_to_file($privkey, ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $domain ."/private.pem");	
				
		#############################################		
				
		
		if ( $domain == ctrl_options::GetSystemOption('sentora_domain') ) {
					
			$line = "# Made from Sencrypt - third_party - start" . fs_filehandler::NewLine();
			$line .= fs_filehandler::NewLine();
			$line .= 'SSLEngine On' . fs_filehandler::NewLine();
			$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/third_party/". $domain ."/cert.pem". fs_filehandler::NewLine();
			$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/third_party/". $domain ."/private.pem". fs_filehandler::NewLine();
			$line .= "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();
			$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
			$line .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
			$line .= "# Made from Sencrypt - third_party - end" . fs_filehandler::NewLine();					

			$portname = "sentora_port";
			$port = "443";
				
			//////// NEW CODE
			if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {
				// For older Sentora support
				
				$name = 'global_zpcustom';
				$sql = $zdbh->prepare("SELECT * FROM x_settings WHERE so_name_vc  = :name");
				$sql->bindParam(':name', $name);
				$sql->execute();
						
				while ($row = $sql->fetch()) { 
					$olddata = $row['so_value_tx']; 
					
				}
					$data = $olddata.$line;
								
					// Update data
					$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
					$updatesql->bindParam(':value', $data);
					$updatesql->bindParam(':name', $name);
					$updatesql->execute();
								
					// Update port
					//$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
					//$updatesql->bindParam(':value', $port);
					//$updatesql->bindParam(':name', $portname);
					//$updatesql->execute();
								
			} else {
				// For Sentora 2.0
					$name = 'panel_ssl_tx';
					
					// Update data
					$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
					$updatesql->bindParam(':value', $line);
					$updatesql->bindParam(':name', $name);
					$updatesql->execute();
								
					// Update port
					//$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
					//$updatesql->bindParam(':value', $port);
					//$updatesql->bindParam(':name', $portname);
					//$updatesql->execute();
						
			}
			//////// NEW CODE

		} else {
					
			$line = "# Made from Sencrypt - third_party - start" . fs_filehandler::NewLine();
			$line .= fs_filehandler::NewLine();
			$line .= 'SSLEngine On' . fs_filehandler::NewLine();
			$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/third_party/". $domain ."/cert.pem". fs_filehandler::NewLine();
			$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/third_party/". $domain ."/private.pem". fs_filehandler::NewLine();
			$line .= "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();	
			$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
			$line .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
			$line .= "# Made from Sencrypt - third_party - end" . fs_filehandler::NewLine();
			
			$port 			= "443";
	
			//////// NEW CODE
			if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {
				// For older Sentora support
				$portforward 	= "1";								

				$sql = $zdbh->prepare("SELECT * FROM x_vhosts WHERE vh_name_vc = :domain AND vh_deleted_ts IS NULL");
				$sql->bindParam(':domain', $domain);
				$sql->execute();
							
				while ($row = $sql->fetch()) { 
					$olddata = $row['vh_custom_tx']; 
				
				}
					$data = $olddata.$line;
							
					$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx=:data, vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");
					$sql->bindParam(':data', $data);
					$sql->bindParam(':domain', $domain);
					$sql->bindParam(':port', $port);
					$sql->bindParam(':portforward', $portforward);
					# Exacute
					$sql->execute();
				
				
			} else {
					// For Sentora 2.0
					$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_ssl_tx=:data, vh_ssl_port_in=:port WHERE vh_name_vc = :domain");
					$sql->bindParam(':data', $line);
					$sql->bindParam(':domain', $domain);
					$sql->bindParam(':port', $port);
					# Exacute
					$sql->execute();
		
			}
					
		}
			//////// NEW CODE
			
		self::SetWriteApacheConfigTrue();
		self::$ok = true;	
		return true;	
				
	}


	static function ListDomains($uid) {
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
			
			
			
			
			
			// Panel values
			$panel_Domain = ctrl_options::GetSystemOption('sentora_domain');
			
			// Check if ssl exists else where
			if ( !is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/". $panel_Domain ."/") ) {
			
				//check if cert exist or not
				if ( is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $panel_Domain ."/") ) {
					# Do nothing

				} else {
					
					$name = $panel_Domain;
					$res[] = array('domain' => "$name");
				}
				
			} else {
				
				// Do nothing
				
			}
				
				
				
				
				
				
				
            while ($rowdomains = $sql->fetch()) {
				
				//check if cert exist or not
				if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/third_party/". $rowdomains['vh_name_vc'] ."/") ) {

					// Check if ssl exists else where
					if ( is_dir(ctrl_options::GetSystemOption('hosted_dir') . $currentuser["username"] ."/ssl/sencrypt/letsencrypt/". $rowdomains['vh_name_vc'] ."/") ) {
						# Do nothing

					} else {
						$res[] = array('domain' => $rowdomains['vh_name_vc']);
				
					}				
				} else {
					# Do nothing

				}				
            }
            return $res;
			
        } else {
            return false;
        }
	}
		
	static function getDomainList() {
			$currentuser = ctrl_users::GetUserDetail();
			return self::ListDomains($currentuser['userid']);
	}
	
	static function ListSSL($uname) {
		global $controller;
		$retval = null;
		if (!is_dir(ctrl_options::GetSystemOption('hosted_dir') . $uname ."/ssl/sencrypt/third_party/") ) {
			mkdir( ctrl_options::GetSystemOption('hosted_dir'). $uname ."/ssl/sencrypt/third_party/", 0777);
		}
		
		$dir = ctrl_options::GetSystemOption('hosted_dir') . $uname. "/ssl/sencrypt/third_party/";
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

	static function getSSLList() {
		$currentuser = ctrl_users::GetUserDetail();
		return self::ListSSL($currentuser['username']);
	}
		
	static function getisShowCSR() {
        global $controller;
        $urlvars = $controller->GetAllControllerRequests('URL');
        return (isset($urlvars['show'])) && ($urlvars['show'] == "ShowCSR");
	}
	
	static function getisShowSelf() {
        global $controller;
        $urlvars = $controller->GetAllControllerRequests('URL');
        return (isset($urlvars['show'])) && ($urlvars['show'] == "ShowSelf");
	}
	
	static function getisBought() {
        global $controller;
        $urlvars = $controller->GetAllControllerRequests('URL');
        return (isset($urlvars['show'])) && ($urlvars['show'] == "Bought");
	}

	static function doselect() {
        global $controller;
        runtime_csfr::Protect();
        $currentuser = ctrl_users::GetUserDetail();
        $formvars = $controller->GetAllControllerRequests('FORM');
		
            if (isset($formvars['inSSLself'])) {
                header("location: ./?module=" . $controller->GetCurrentModule() . '&ShowPanel=third-party' . '&show=ShowSelf');
                exit;
            }
			if (isset($formvars['inSSLbought'])) {
                header("location: ./?module=" . $controller->GetCurrentModule() . '&ShowPanel=third-party' . '&show=Bought');
                exit;
            }
			if (isset($formvars['inSSLCSR'])) {
                header("location: ./?module=" . $controller->GetCurrentModule() . '&ShowPanel=third-party' . '&show=ShowCSR');
                exit;
            }
        return true;
	}

	static function getListCountry() {
			$res = '<option value="AF">Afghanistan</option> <option value="AX">Åland Islands</option> <option value="AL">Albania</option> <option value="DZ">Algeria</option> <option value="AS">American Samoa</option> <option value="AD">Andorra</option> <option value="AO">Angola</option> <option value="AI">Anguilla</option> <option value="AQ">Antarctica</option> <option value="AG">Antigua and Barbuda</option> <option value="AR">Argentina</option> <option value="AM">Armenia</option> <option value="AW">Aruba</option> <option value="AU">Australia</option> <option value="AT">Austria</option> <option value="AZ">Azerbaijan</option> <option value="BS">Bahamas</option> <option value="BH">Bahrain</option> <option value="BD">Bangladesh</option> <option value="BB">Barbados</option> <option value="BY">Belarus</option> <option value="BE">Belgium</option> <option value="BZ">Belize</option> <option value="BJ">Benin</option> <option value="BM">Bermuda</option> <option value="BT">Bhutan</option> <option value="BO">Bolivia</option> <option value="BA">Bosnia and Herzegovina</option> <option value="BW">Botswana</option> <option value="BV">Bouvet Island</option> <option value="BR">Brazil</option> <option value="IO">British Indian Ocean Territory</option> <option value="BN">Brunei Darussalam</option> <option value="BG">Bulgaria</option> <option value="BF">Burkina Faso</option> <option value="BI">Burundi</option> <option value="KH">Cambodia</option> <option value="CM">Cameroon</option> <option value="CA">Canada</option> <option value="CV">Cape Verde</option> <option value="KY">Cayman Islands</option> <option value="CF">Central African Republic</option> <option value="TD">Chad</option> <option value="CL">Chile</option> <option value="CN">China</option> <option value="CX">Christmas Island</option> <option value="CC">Cocos (Keeling) Islands</option> <option value="CO">Colombia</option> <option value="KM">Comoros</option> <option value="CG">Congo</option> <option value="CD">Congo, The Democratic Republic of The</option> <option value="CK">Cook Islands</option> <option value="CR">Costa Rica</option> <option value="CI">Cote D´ivoire</option> <option value="HR">Croatia</option> <option value="CU">Cuba</option> <option value="CY">Cyprus</option> <option value="CZ">Czech Republic</option> <option value="DK">Denmark</option> <option value="DJ">Djibouti</option> <option value="DM">Dominica</option> <option value="DO">Dominican Republic</option> <option value="EC">Ecuador</option> <option value="EG">Egypt</option> <option value="SV">El Salvador</option> <option value="GQ">Equatorial Guinea</option> <option value="ER">Eritrea</option> <option value="EE">Estonia</option> <option value="ET">Ethiopia</option> <option value="FK">Falkland Islands (Malvinas)</option> <option value="FO">Faroe Islands</option> <option value="FJ">Fiji</option> <option value="FI">Finland</option> <option value="FR">France</option> <option value="GF">French Guiana</option> <option value="PF">French Polynesia</option> <option value="TF">French Southern Territories</option> <option value="GA">Gabon</option> <option value="GM">Gambia</option> <option value="GE">Georgia</option> <option value="DE">Germany</option> <option value="GH">Ghana</option> <option value="GI">Gibraltar</option> <option value="GR">Greece</option> <option value="GL">Greenland</option> <option value="GD">Grenada</option> <option value="GP">Guadeloupe</option> <option value="GU">Guam</option> <option value="GT">Guatemala</option> <option value="GG">Guernsey</option> <option value="GN">Guinea</option> <option value="GW">Guinea-bissau</option> <option value="GY">Guyana</option> <option value="HT">Haiti</option> <option value="HM">Heard Island and Mcdonald Islands</option> <option value="VA">Holy See (Vatican City State)</option> <option value="HN">Honduras</option> <option value="HK">Hong Kong</option> <option value="HU">Hungary</option> <option value="IS">Iceland</option> <option value="IN">India</option> <option value="ID">Indonesia</option> <option value="IR">Iran, Islamic Republic of</option> <option value="IQ">Iraq</option> <option value="IE">Ireland</option> <option value="IM">Isle of Man</option> <option value="IL">Israel</option> <option value="IT">Italy</option> <option value="JM">Jamaica</option> <option value="JP">Japan</option> <option value="JE">Jersey</option> <option value="JO">Jordan</option> <option value="KZ">Kazakhstan</option> <option value="KE">Kenya</option> <option value="KI">Kiribati</option> <option value="KP">Korea, Democratic People´s Republic of</option> <option value="KR">Korea, Republic of</option> <option value="KW">Kuwait</option> <option value="KG">Kyrgyzstan</option> <option value="LA">Lao People´s Democratic Republic</option> <option value="LV">Latvia</option> <option value="LB">Lebanon</option> <option value="LS">Lesotho</option> <option value="LR">Liberia</option> <option value="LY">Libyan Arab Jamahiriya</option> <option value="LI">Liechtenstein</option> <option value="LT">Lithuania</option> <option value="LU">Luxembourg</option> <option value="MO">Macao</option> <option value="MK">Macedonia, The Former Yugoslav Republic of</option> <option value="MG">Madagascar</option> <option value="MW">Malawi</option> <option value="MY">Malaysia</option> <option value="MV">Maldives</option> <option value="ML">Mali</option> <option value="MT">Malta</option> <option value="MH">Marshall Islands</option> <option value="MQ">Martinique</option> <option value="MR">Mauritania</option> <option value="MU">Mauritius</option> <option value="YT">Mayotte</option> <option value="MX">Mexico</option> <option value="FM">Micronesia, Federated States of</option> <option value="MD">Moldova, Republic of</option> <option value="MC">Monaco</option> <option value="MN">Mongolia</option> <option value="ME">Montenegro</option> <option value="MS">Montserrat</option> <option value="MA">Morocco</option> <option value="MZ">Mozambique</option> <option value="MM">Myanmar</option> <option value="NA">Namibia</option> <option value="NR">Nauru</option> <option value="NP">Nepal</option> <option value="NL">Netherlands</option> <option value="AN">Netherlands Antilles</option> <option value="NC">New Caledonia</option> <option value="NZ">New Zealand</option> <option value="NI">Nicaragua</option> <option value="NE">Niger</option> <option value="NG">Nigeria</option> <option value="NU">Niue</option> <option value="NF">Norfolk Island</option> <option value="MP">Northern Mariana Islands</option> <option value="NO">Norway</option> <option value="OM">Oman</option> <option value="PK">Pakistan</option> <option value="PW">Palau</option> <option value="PS">Palestinian Territory, Occupied</option> <option value="PA">Panama</option> <option value="PG">Papua New Guinea</option> <option value="PY">Paraguay</option> <option value="PE">Peru</option> <option value="PH">Philippines</option> <option value="PN">Pitcairn</option> <option value="PL">Poland</option> <option value="PT">Portugal</option> <option value="PR">Puerto Rico</option> <option value="QA">Qatar</option> <option value="RE">Reunion</option> <option value="RO">Romania</option> <option value="RU">Russian Federation</option> <option value="RW">Rwanda</option> <option value="SH">Saint Helena</option> <option value="KN">Saint Kitts and Nevis</option> <option value="LC">Saint Lucia</option> <option value="PM">Saint Pierre and Miquelon</option> <option value="VC">Saint Vincent and The Grenadines</option> <option value="WS">Samoa</option> <option value="SM">San Marino</option> <option value="ST">Sao Tome and Principe</option> <option value="SA">Saudi Arabia</option> <option value="SN">Senegal</option> <option value="RS">Serbia</option> <option value="SC">Seychelles</option> <option value="SL">Sierra Leone</option> <option value="SG">Singapore</option> <option value="SK">Slovakia</option> <option value="SI">Slovenia</option> <option value="SB">Solomon Islands</option> <option value="SO">Somalia</option> <option value="ZA">South Africa</option> <option value="GS">South Georgia and The South Sandwich Islands</option> <option value="ES">Spain</option> <option value="LK">Sri Lanka</option> <option value="SD">Sudan</option> <option value="SR">Suriname</option> <option value="SJ">Svalbard and Jan Mayen</option> <option value="SZ">Swaziland</option> <option value="SE">Sweden</option> <option value="CH">Switzerland</option> <option value="SY">Syrian Arab Republic</option> <option value="TW">Taiwan, Province of China</option> <option value="TJ">Tajikistan</option> <option value="TZ">Tanzania, United Republic of</option> <option value="TH">Thailand</option> <option value="TL">Timor-leste</option> <option value="TG">Togo</option> <option value="TK">Tokelau</option> <option value="TO">Tonga</option> <option value="TT">Trinidad and Tobago</option> <option value="TN">Tunisia</option> <option value="TR">Turkey</option> <option value="TM">Turkmenistan</option> <option value="TC">Turks and Caicos Islands</option> <option value="TV">Tuvalu</option> <option value="UG">Uganda</option> <option value="UA">Ukraine</option> <option value="AE">United Arab Emirates</option> <option value="GB">United Kingdom</option> <option value="US">United States</option> <option value="UM">United States Minor Outlying Islands</option> <option value="UY">Uruguay</option> <option value="UZ">Uzbekistan</option> <option value="VU">Vanuatu</option> <option value="VE">Venezuela</option> <option value="VN">Viet Nam</option> <option value="VG">Virgin Islands, British</option> <option value="VI">Virgin Islands, U.S.</option> <option value="WF">Wallis and Futuna</option> <option value="EH">Western Sahara</option> <option value="YE">Yemen</option> <option value="ZM">Zambia</option> <option value="ZW">Zimbabwe</option>';
			return $res;
	}

############## Third_Party code below - END

############## LETS Encrypt code below - START

		static function doMakeSSL() {
			global $controller;
			
			$sub_module = "letsencrypt";
			
			$currentuser = ctrl_users::GetUserDetail();
        	$formvars = $controller->GetAllControllerRequests('FORM');
        	if (self::ExecuteMakeSSL($formvars['inDomain'], $currentuser["username"], $sub_module))
            return true;
		}
		
		static function doMakePanelSSL() {
			global $controller;
			
			$sub_module = "letsencrypt";
			
			$currentuser = ctrl_users::GetUserDetail();
        	$formvars = $controller->GetAllControllerRequests('FORM');
        	if (self::ExecuteMakePanelSSL($formvars['inDomain'], $currentuser["username"], $sub_module))
            return true;
		}
		
		static function ExecuteMakeSSL($domain, $username, $sub_module) {
			global $zdbh, $controller;
			$zsudo = ctrl_options::GetOption('zsudo');
			$currentuser = ctrl_users::GetUserDetail();
			$username = $currentuser["username"];
			$userid = $currentuser["userid"];
			$certlocation = ctrl_options::GetSystemOption('hosted_dir') . $username ."/ssl/sencrypt/letsencrypt/";
			$domain_folder = str_replace(".","_", $domain);
			$Domainroot = "/var/sentora/hostdata/".$username."/public_html/".$domain_folder;

			require("modules/sencrypt/code/Lescript.php");
			date_default_timezone_set("UTC");
			
			# Make Let´s encrypt SSL
			$logger = new Logger();
			
			try {

				$le = new Analogic\ACME\Lescript($certlocation, $Domainroot, $logger);
				
				# uses client's email used during registration
				$le->contact = array('mailto:'.$currentuser['email']); // optional
				
		 		# Init. Account and update account email to keep current.
				$le->initAccount();
				$le->postUpdateRegEmail();
				
				# Start signing here
				# Need to check if we need to add www for parent domain and not subdomain
				//$le->signDomains(array($domain)); OLD 
				
				# Check if domain is a subdomain
				$sql = "SELECT vh_type_in FROM x_vhosts WHERE vh_acc_fk=:userid AND vh_name_vc=:domain AND vh_enabled_in=1 AND vh_deleted_ts IS NULL ORDER BY vh_name_vc ASC";
				$query = $zdbh->prepare($sql);
				$query->bindParam(':userid', $currentuser['userid']);
				$query->bindParam(':domain', $domain);
				$query->execute();
			
			    while ($row = $query->fetch()) {
                    
					if ($row['vh_type_in'] == 2 ) {
						// Create domain without www. becuase its a subdomain
						$le->signDomains(array($domain));
						
					} else {
						// Create a SSL with www. because its a root domain
						$le->signDomains(array($domain, 'www.'.$domain));
						
					}
                }
			}
			catch (\Exception $e) {
				$logger->error($e->getMessage());
				$logger->error($e->getTraceAsString());
				exit(1);
			}
			
			##### TESTING
			//exit();
			
//*
				$line = "# Made from Sencrypt - ".$sub_module." - start" . fs_filehandler::NewLine();
				$line .= fs_filehandler::NewLine();
                $line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . $certlocation . $domain. "/cert.pem". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . $certlocation . $domain. "/private.pem". fs_filehandler::NewLine();
				$line .= "SSLCACertificateFile " . $certlocation . $domain."/chain.pem". fs_filehandler::NewLine();
				$line .= "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
				$line .= "# Made from Sencrypt - ".$sub_module." - end" . fs_filehandler::NewLine();

				$port 			= 443;
				$portforward 	= 1;

				$sql = $zdbh->prepare("SELECT * FROM x_vhosts WHERE vh_name_vc = :domain AND vh_deleted_ts IS NULL");
            	$sql->bindParam(':domain', $domain);
            	$sql->execute();
				
            	while ($row = $sql->fetch()) {
					$olddata = $row['vh_custom_tx'];
				}
					$data = $olddata.$line;
					
					//////// NEW CODE
					
					if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {
						// For older Sentora support
						//$portforward 	= 1;
						
						$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx=:data, vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");
						$sql->bindParam(':portforward', $portforward);
						$sql->bindParam(':data', $data);
						$sql->bindParam(':domain', $domain);
						$sql->bindParam(':port', $port);
						$sql->execute();	
						
					} else {
						// For Sentora 2.0
						$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_ssl_tx=:data, vh_ssl_port_in=:port WHERE vh_name_vc = :domain");
						$sql->bindParam(':data', $data);
						$sql->bindParam(':domain', $domain);
						$sql->bindParam(':port', $port);
						$sql->execute();			
						
					}
					//////// NEW CODE
				

        			//$sql->bindParam(':data', $data);
					//$sql->bindParam(':domain', $domain);
					//$sql->bindParam(':port', $port);
					//$sql->bindParam(':portforward', $portforward);
					//$sql->execute();			
//*/
					//self::SetWriteApacheConfigTrue();
					//self::$ok = true;
					//return true;
					
					
		}

		#### Make SSL for Panel domain
		static function ExecuteMakePanelSSL($domain, $username, $sub_module) {
			global $zdbh, $controller;
			$zsudo = ctrl_options::GetOption('zsudo');
			$currentuser = ctrl_users::GetUserDetail();
			$username = $currentuser["username"];
			$userid = $currentuser["userid"];
						
			// OLD CODE TO DELETE
			$sentoraPath = "/etc/sentora/"; 
			//$panelDomain = ctrl_options::GetSystemOption('sentora_domain');

			//$certlocation = ($sentoraPath . "/ssl/sencrypt/");
			$certlocation = ctrl_options::GetSystemOption('hosted_dir') . $username ."/ssl/sencrypt/letsencrypt/";
			
			//$domain_folder = str_replace(".","_", "panel");
			$Domainroot = ($sentoraPath. "panel/");
			$domain_folder = str_replace(".","_", $domain);
			//$Domainroot = "/var/sentora/hostdata/".$username."/public_html/".$domain_folder;
			
			

			
			//require("modules/sencrypt/code/Lescript.php");
			//date_default_timezone_set("UTC");
			
			//Make Let´s encrypt SSL
			//$logger = new Logger();
			/*
			try {
				$le = new Analogic\ACME\Lescript($certlocation, $Domainroot, $logger);
				
				// uses client's email used during registration
				$le->contact = array('mailto:' . $currentuser['email']); // optional
			
				# Init. Account and update account email to keep current.
				//$le->initAccount();
	//			$le->postUpdateRegEmail();
				
				# Sign domains
				//$le->signDomains(array($domain));
				
			}
			catch (\Exception $e) {
				$logger->error($e->getMessage());
				$logger->error($e->getTraceAsString());
				exit(1);
			}
			*/
				$line = "# Made from Sencrypt - ".$sub_module." - start" . fs_filehandler::NewLine();
				$line .= fs_filehandler::NewLine();
                $line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . $certlocation . $domain. "/cert.pem". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . $certlocation . $domain. "/private.pem". fs_filehandler::NewLine();
				$line .= "SSLCACertificateFile " . $certlocation . $domain. "/chain.pem". fs_filehandler::NewLine();
				$line .= "all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
				$line .= "# Made from Sencrypt - ".$sub_module." - end" . fs_filehandler::NewLine();

				# Removed because users dont check port 443 access before setup.
				// Update panel Port
				//$port = 443;
				//$portname = "sentora_port";
				//$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
				//$updatesql->bindParam(':value', $port);
				//$updatesql->bindParam(':name', $portname);
				//$updatesql->execute();
				
				
				
				####################################################################
				// MAY HAVE ISSUE HERE.
				///////////// NEW CODE
				if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {
					
					// Update panel Port
					//$port = 443;
					//$portname = "sentora_port";
					//$updatesql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :value WHERE so_name_vc = :name");
					//$updatesql->bindParam(':value', $port);
					//$updatesql->bindParam(':name', $portname);
					//$updatesql->execute();
					
					// For older Sentora support
					// Update panel SSL data
					$panel_so_name = "global_zpcustom";
					
					$sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :data WHERE so_name_vc = :panel_so_name");
					$sql->bindParam(':data', $line);
					$sql->bindParam(':panel_so_name', $panel_so_name);
					
				} else {
					// For Sentora 2.0
					$panel_so_name = "panel_ssl_tx";
					
					$sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = :data WHERE so_name_vc = :panel_so_name");
					$sql->bindParam(':data', $line);
					$sql->bindParam(':panel_so_name', $panel_so_name);
					
				}
				///////////// NEW CODE

			$sql->bindParam(':data', $line);
			$sql->execute();
				
			self::SetWriteApacheConfigTrue();
			self::$ok = true;
			return true;
			
		}

		static function doDelete() {
	        global $controller;
	        $currentuser = ctrl_users::GetUserDetail();
	        $formvars = $controller->GetAllControllerRequests('FORM');
			
			$sub_module = "letsencrypt";
			
	        if (self::ExecuteTPDelete($formvars['inDomain'], $currentuser["username"], $sub_module))
	        return true;
		}

/*
		static function ExecuteDelete($domain, $username) {
			global $zdbh;
			global $controller;
			$currentuser = ctrl_users::GetUserDetail();
			$rootdir = str_replace('.', '_', $domain);
			$dir = ctrl_options::GetSystemOption('hosted_dir') . $username ."/ssl/sencrypt/letsencrypt/". $domain;
			$objects = scandir($dir);
			foreach ($objects as $object) {
				if ($object != "." && $object != "..") {
			         unlink($dir."/".$object);
				}
			}
		
			rmdir($dir);
	
			$port = NULL;
			$new = NULL;
	
			$line = "# Lets Encrypt start" . fs_filehandler::NewLine();
			$line .= fs_filehandler::NewLine();
			$line .= 'SSLEngine On' . fs_filehandler::NewLine();
			$line .= "SSLCertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/letsencrypt/" . $domain. "/cert.pem". fs_filehandler::NewLine();
			$line .= "SSLCertificateKeyFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/letsencrypt/" . $domain. "/private.pem". fs_filehandler::NewLine();
			$line .= "SSLCACertificateFile " . ctrl_options::GetSystemOption('hosted_dir') . $currentuser['username'] . "/ssl/sencrypt/letsencrypt/" . $domain."/chain.pem". fs_filehandler::NewLine();
			$line .= "SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();
			$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
			$line .= "SSLCipherSuite \"EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+AESGCM EECDH EDH+AESGCM EDH+aRSA HIGH !MEDIUM !LOW !aNULL !eNULL !LOW !RC4 !MD5 !EXP !PSK !SRP !DSS\"" . fs_filehandler::NewLine();
			$line .= "# Lets Encrypt end" . fs_filehandler::NewLine();
	
			//$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_ssl_tx = replace(vh_ssl_tx, :data, :new), vh_ssl_port_in=:port WHERE vh_name_vc = :domain");
			
			
			
			
			
			
			/////// NEW CODE
			if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {
				// For older Sentora support
				//$portforward 	= 1;
				
				$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx = replace(vh_custom_tx, :data, :new), vh_custom_port_in=:port WHERE vh_name_vc = :domain");
				//$sql->bindParam(':portforward', $portforward);
				
			} else {
				// For Sentora 2.0
				$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_ssl_tx = replace(vh_ssl_tx, :data, :new), vh_ssl_port_in=:port WHERE vh_name_vc = :domain");
				
			}
			/////// NEW CODE
			
			
	
			
	
			$sql->bindParam(':data', $line);
			$sql->bindParam(':new', $new);
			$sql->bindParam(':domain', $domain);
			$sql->bindParam(':port', $port);
			$sql->execute();
			self::SetWriteApacheConfigTrue();
			self::$delok = true;
			return true;
		}
	
	*/
	
	
	
	
		### Delete Panel SSL		
		static function doDeletePanelSSL() {
	        global $controller;
	        $currentuser = ctrl_users::GetUserDetail();
	        $formvars = $controller->GetAllControllerRequests('FORM');			
	        if (self::ExecuteDeletePanelSSL($formvars['inDomain'], $currentuser["username"]))
	        return true;
		}

		static function ExecuteDeletePanelSSL($domain, $username) {
			global $zdbh;
			global $controller;
			$currentuser = ctrl_users::GetUserDetail();
			$rootdir = str_replace('.', '_', $domain);
			
			$sub_module = "letsencrypt";
			
			//$sentoraCertPath = "/etc/sentora";
			$sentoraCertPath = ctrl_options::GetSystemOption('hosted_dir') . $username; 
			//$certlocation = ($sentoraPath . "/ssl/sencrypt/letsencrypt/");
			$certlocation = $sentoraCertPath . "/ssl/sencrypt/letsencrypt/";
			
			$dir = $sentoraCertPath ."/ssl/sencrypt/letsencrypt/". $domain;
	
			$objects = scandir($dir);
			foreach ($objects as $object) {
				if ($object != "." && $object != "..") {
			         unlink($dir."/".$object);
				}
			}
		
			rmdir($dir);

			$new = NULL;

			$line = "# Made from Sencrypt - ".$sub_module." - start" . fs_filehandler::NewLine();
			$line .= fs_filehandler::NewLine();
			$line .= 'SSLEngine On' . fs_filehandler::NewLine();
			$line .= "SSLCertificateFile " . $certlocation . $domain . "/cert.pem". fs_filehandler::NewLine();
			$line .= "SSLCertificateKeyFile " . $certlocation . $domain . "/private.pem". fs_filehandler::NewLine();
			$line .= "SSLCACertificateFile " . $certlocation . $domain . "/chain.pem". fs_filehandler::NewLine();
			$line .= "all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();
			$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
			$line .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
			$line .= "# Made from Sencrypt - ".$sub_module." - end" . fs_filehandler::NewLine();
	
			////////////// NEW CODE
			if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {
				// For older Sentora support
				$port = 443;
				
				$sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = replace(so_value_tx, :data, :new) WHERE so_name_vc = :panel_ssl");
				$panelssltxt = "global_zpcustom";
				$sql->bindParam(':panel_ssl', $panelssltxt);
				
			} else {
				// For Sentora 2.0
				$sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx = replace(so_value_tx, :data, :new) WHERE so_name_vc = :panel_ssl");
				$panelssltxt = "panel_ssl_tx";
				$sql->bindParam(':panel_ssl', $panelssltxt);
			}

		////////////// NEW CODE

			$sql->bindParam(':data', $line);
			$sql->bindParam(':new', $new);
			$sql->execute();
		
			self::SetWriteApacheConfigTrue();
			self::$delok = true;
			return true;
		
		}	
	
		static function doRevokeSSL() {
			global $controller;
			
			$sub_module = "letsencrypt";
			
			$currentuser = ctrl_users::GetUserDetail();
        	$formvars = $controller->GetAllControllerRequests('FORM');
        	if (self::ExecuteRevokeSSL($formvars['inDomain'], $currentuser["username"], $sub_module))
            return true;
		}
	
		static function ExecuteRevokeSSL($domain, $username, $sub_module) {
			global $zdbh, $controller;
			$zsudo = ctrl_options::GetOption('zsudo');
			$currentuser = ctrl_users::GetUserDetail();
			$username = $currentuser["username"];
			$userid = $currentuser["userid"];
			$certlocation = ctrl_options::GetSystemOption('hosted_dir') . $username ."/ssl/sencrypt/letsencrypt/";
			//$domain_folder = str_replace(".","_", $domain);
			//$Domainroot = "/var/sentora/hostdata/".$username."/public_html/".$domain_folder;
			$Domainroot = "/var/sentora/hostdata/".$username."/public_html/".$domain;

			// Convert PEM cert to DER format base64url for revoke
			$pem_data = file_get_contents($certlocation."sentoratestssl.dukecitysolutions.com/cert.pem");
			$pem2der = self::base64url(self::pem2der($pem_data));
			

			require("modules/sencrypt/code/Lescript.php");
			date_default_timezone_set("UTC");
			
			$logger = new Logger();
			
			# Revoke Let´s encrypt SSL
			try {
				$le = new Analogic\ACME\Lescript($certlocation, $Domainroot, $logger);
				
				// uses client's email used during registration
				//$le->contact = array('mailto:' . $currentuser['email']); // optional
			
				$le->initAccount();
								
				# start revoke
				$le->postRevoke($pem2der);
				
			}
			
			catch (\Exception $e) {
				$logger->error($e->getMessage());
				$logger->error($e->getTraceAsString());
				exit(1);
			}
			
			// FOR TESTING
			//exit();
			
			// Delete Letsencrypt Cert from DB & System
			
				$line = "# Made from Sencrypt - ".$sub_module." - start" . fs_filehandler::NewLine();
				$line .= fs_filehandler::NewLine();
                $line .= 'SSLEngine On' . fs_filehandler::NewLine();
				$line .= "SSLCertificateFile " . $certlocation . $domain. "/cert.pem". fs_filehandler::NewLine();
				$line .= "SSLCertificateKeyFile " . $certlocation . $domain. "/private.pem". fs_filehandler::NewLine();
				$line .= "SSLCACertificateFile " . $certlocation . $domain."/chain.pem". fs_filehandler::NewLine();
				$line .= "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1" . fs_filehandler::NewLine();
				$line .= "SSLHonorCipherOrder on" . fs_filehandler::NewLine();
				$line .= "SSLCipherSuite \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\"" . fs_filehandler::NewLine();
				$line .= "# Made from Sencrypt - ".$sub_module." - end" . fs_filehandler::NewLine();

				$port 			= NULL;
				$portforward 	= NULL;
				$new = '';

				$sql = $zdbh->prepare("SELECT * FROM x_vhosts WHERE vh_name_vc = :domain AND vh_deleted_ts IS NULL");
            	$sql->bindParam(':domain', $domain);
            	$sql->execute();
				
            	while ($row = $sql->fetch()) {
					$olddata = $row['vh_custom_tx'];
				}
				
					$data = $olddata.$line;
					
					//$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_ssl_tx=:data, vh_ssl_port_in=:port WHERE vh_name_vc = :domain");
				
					//////// NEW CODE
					if ( ctrl_options::GetSystemOption('dbversion') <= "1.0.3") {
						// For older Sentora support						
						//$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_ssl_tx=:data, vh_ssl_port_in=:port WHERE vh_name_vc = :domain");
						
						$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_custom_tx= replace(vh_custom_tx, :data, :new), vh_custom_port_in=:port, vh_portforward_in=:portforward WHERE vh_name_vc = :domain");
						$sql->bindParam(':data', $line);
						$sql->bindParam(':new', $new);
						$sql->bindParam(':port', $port);
						$sql->bindParam(':domain', $domain);
						$sql->bindParam(':portforward', $portforward);
						$sql->execute();	
						
					} else {
						// For Sentora 2.0
						$sql = $zdbh->prepare("UPDATE x_vhosts SET vh_ssl_tx= (vh_ssl_tx, :data, :new), vh_ssl_port_in=:port WHERE vh_name_vc = :domain");
						$sql->bindParam(':data', $data);
						$sql->bindParam(':new', $new);
						$sql->bindParam(':port', $port);
						$sql->bindParam(':domain', $domain);
						$sql->execute();
						
					}
					//////// NEW CODE END
					

        			//$sql->bindParam(':data', $data);
					//$sql->bindParam(':domain', $domain);
					//$sql->bindParam(':port', $port);
					//$sql->bindParam(':portforward', $portforward);
					//$sql->execute();			

				self::SetWriteApacheConfigTrue();
				self::$revokecert = true;
				return true;
	
		}
	
		static function pem2der($pem) {
			return base64_decode(implode('',array_slice(
				array_map('trim',explode("\n",trim($pem))),1,-1
			)));
		}
	
		static function base64url($data){ // RFC7515 - Appendix C
			return rtrim(strtr(base64_encode($data),'+/','-_'),'=');
		}
	
	
############## LETS Encrypt code below - END
	
	
	
	static function SetWriteApacheConfigTrue() {
		global $zdbh;
		$sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx='true'	WHERE so_name_vc='apache_changed'");
		$sql->execute();
	}

    static function getCopyright() {
		
        $copyright = '<font face="ariel" size="2">'.ui_module::GetModuleName().' v2.0.0 &copy; 2016-'.date("Y").' by <a target="_blank" href="#">Jettaman, TGates & Diablo</a> for <a target="_blank" href="http://sentora.org">Sentora Control Panel</a>&nbsp;&#8212;&nbsp;Help support future development of this module and donate today!</font>';
		
        return $copyright;
    }
	
		# Added to check DNS before Creating SSL Certs
		static function GetNameservers($domain) {
			$nameservers	= array();
			$dns			= @dns_get_record($domain, DNS_NS);
			
			# NOT tested or maybe needed - CHeck first
			/*if(!$dns) {
				if(sys_versions::ShowOSPlatformVersion() !== 'Windows') {
					$result = shell_exec('dig NS +trace ' . $domain);
					$lines	= explode("\n", $result);
					$dns	= [];
					
					foreach($lines AS $line) {
						preg_match('/^(?P<host>.*)\.\s(?P<ttl>[0-9]+)\s(?P<class>IN)\s(?P<type>NS)\s(?P<target>.*)\.$/Uis', $line, $matches);
				
						if(!empty($matches)) {
							$dns[] = [
								'type'		=> $matches['type'],
								'ttl'		=> $matches['ttl'],
								'class'		=> $matches['class'],
								'type'		=> $matches['type'],
								'target'	=> $matches['target']
							];
						}
					}
				}
			}*/
			
			if(!empty($dns)) {
				foreach($dns AS $entry) {
					if($entry['type'] === 'NS') {
						$nameservers[] = $entry['target'];
					}
				}
			}
			
			return $nameservers;
		}
		
		static function HasSentoraDNS($domain) {
			$nameservers	= self::GetNameservers($domain);
			
			// @ToDo check DNS
			return (in_array('ns1.' . $domain, $nameservers) && in_array('ns2.' . $domain, $nameservers));
		}
	

	static function getResult() {
		if (self::$modReqsError)
		{
			return ui_sysmessage::shout(ui_language::translate("You need at least PHP 5.3.0 with OpenSSL and curl extension installed. Contact your admin for help. This Module may not work correctly until the issues are fixed."), "zannounceerror");
		}
		if (self::$ok)
		{
			return ui_sysmessage::shout(ui_language::translate("Your FREE Letsencrypt SSL Certificate has been Created. It will be active in about 5 minutes."), "zannounceok");
		}
		if (self::$delok)
		{
			return ui_sysmessage::shout(ui_language::translate("The selected certificate has been deleted."), "zannounceok");
		}
		if (self::$error)
		{
			return ui_sysmessage::shout(ui_language::translate("A certificate with that name already exists."), "zannounceerror");
		}
		if (self::$dnsInvalid)
		{
			return ui_sysmessage::shout(ui_language::translate("Your DNS for this domain is not public yet. Please retry again later."), "zannounceerror");
		}
		if (self::$revokecert) {
            return ui_sysmessage::shout(ui_language::translate("The Requested Certificate has been revoked"), "zannounceok");
        }
		if (self::$keyadd) {
            return ui_sysmessage::shout(ui_language::translate("Certificate Signing Request was made and sent to the mail you have entered"), "zannounceok");
        }
		return;
	}


}
?>
