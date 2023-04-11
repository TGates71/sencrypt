<?php
/**
	* Controller for sencrypt module for sentora version 2.0.0
	* Version : 3.0.0
	* Author : TGates
	* Additional work by Diablo925, Jettaman
 */
 
# Start functions here
function renewCertificates() {
	global $zdbh, $controller;

	# renew in-active domains until deleted?
	$rowvhost = $zdbh->prepare("SELECT * FROM x_vhosts WHERE vh_active_in = '1' AND vh_ssl_tx IS NOT NULL AND vh_ssl_port_in IS NOT NULL AND vh_enabled_in = '1' AND vh_deleted_ts IS NULL");
	$rowvhost->execute();
	$sslVhosts = $rowvhost->fetchAll();
	$result = "";
	
	foreach($sslVhosts as $sslVhost) {
		//if (strpos($sslVhost['vh_ssl_tx'], 'Sencrypt') !== false) {
		if ($sslVhost['vh_ssl_tx'] !== false) {
			
			$vhostOwner = ctrl_users::GetUserDetail($sslVhost['vh_acc_fk']);
			$hostdatadir = ctrl_options::GetOption('hosted_dir');
			$domainPath = $hostdatadir . $vhostOwner['username'] . "/public_html" . $sslVhost['vh_directory_vc'];
			$result .= "Checking certificate for Client: " . $vhostOwner['username'] . " / Domain: " . $sslVhost['vh_name_vc'] . "<br>";
			$result .= "At location: " . $domainPath . "<br>";
			# Lescript automatic updating script.
			#
			# This is an example of how Lescript can be used to automatically update
			# expiring certificates.
			#
			# This code is based on FreePBX's LetsEncrypt integration
			#
			# Copyright (c) 2016 Rob Thomas <rthomas@sangoma.com>
			# Licence:  AGPLv3.
			#
			# In addition, Stanislav Humplik <sh@analogic.cz> is explicitly granted permission
			# to relicence this code under the open source licence of their choice.
			
			# Configuration:
			$domains = $sslVhost['vh_name_vc'];
			$domains = array($domains);
			$domain = $sslVhost['vh_name_vc'];
			$webroot = $domainPath;
			//$certlocation = "/etc/letsencrypt/live/" . $sslVhost['vh_name_vc'];
			
			$accountDir = $hostdatadir . $vhostOwner['username'] . "/ssl/sencrypt/letsencrypt/";
			# Changed to help with backup and compability
			$certlocation = $hostdatadir . $vhostOwner['username'] . "/ssl/sencrypt/letsencrypt/" . $sslVhost['vh_name_vc'];
			
			# Require Lescript for renewal of SSL certs
			require_once 'modules/sencrypt/code/Lescript.php';
			
			# Always use UTC
			date_default_timezone_set("UTC");
			
			# Do we need to create or upgrade our cert? Assume no to start with.
			$needsgen = false;
			
			# Do we HAVE a certificate for all our domains?
			foreach ($domains as $d) {
				//$certfile = "$certlocation/$d/cert.pem";
				$certfile = "$certlocation/cert.pem";
				if (!file_exists($certfile)) {
					# We don't have a cert, so we need to request one.
					$needsgen = true;
				} else {
					# We DO have a certificate.
					$certdata = openssl_x509_parse(file_get_contents($certfile));
					print_r("   Checking certificate for: " . $d . "...") . fs_filehandler::NewLine();
					# If it expires in less than a month, we want to renew it.
					$renewafter = $certdata['validTo_time_t']-(86400*30);
					
					if (time() > $renewafter) {
						# Less than a month left, we need to renew.
						print_r("   --- Renewing certificate : " . $d . " for 90 Days" ) . fs_filehandler::NewLine();
						$needsgen = true;
					}
				}
			}
			
			# Do we need to generate a certificate?
			if ($needsgen) {
				try {
					//$le = new Analogic\ACME\Lescript($accountDir, $certlocation, $webroot, $logger);
					# or without logger:
					$le = new Analogic\ACME\Lescript($accountDir, $certlocation, $webroot);
					$le->initAccount();
					//$le->signDomains(array($domain));

					# Check if domain is a subdomain
					$sql = "SELECT vh_type_in FROM x_vhosts WHERE vh_acc_fk=:userid AND vh_name_vc=:domain AND vh_enabled_in=1 AND vh_deleted_ts IS NULL ORDER BY vh_name_vc ASC";
					$query = $zdbh->prepare($sql);
					$query->bindParam(':userid', $currentuser['userid']);
					$query->bindParam(':domain', $domain);
					$query->execute();
				
					while ($row = $query->fetch()) {
						
						if ($row['vh_type_in'] == 2 ) {
							# Create domain without www. becuase its a subdomain
							$le->signDomains(array($domain));
							
						} else {
							# Create a SSL with www. because its a root domain
							$le->signDomains(array($domain, 'www.' . $domain));
							
						}
					}
			
				}
				catch (\Exception $e) {
					print_r("ERROR!");
					$logger->error($e->getMessage());
					$logger->error($e->getTraceAsString());
					# Exit with an error code, something went wrong.
					exit(1);
				}
			}

			# Create a complete .pem file for use with haproxy or apache 2.4,
			# and save it as domain.name.pem for easy reference. It doesn't
			# matter that this is updated each time, as it'll be exactly
			# the same.
			/* 
			foreach ($domains as $d) {
				//$pem = file_get_contents("$certlocation/$d/fullchain.pem")."\n".file_get_contents("$certlocation/$d/private.pem");
				$pem = file_get_contents("$certlocation/fullchain.pem")."\n".file_get_contents("$certlocation/private.pem");
				file_put_contents("$certlocation/$d.pem", $pem);
			}
			*/
#end
			$result .= "Domain: " . $sslVhost['vh_name_vc'] . " analyzed." . fs_filehandler::NewLine();
		}
	}
	return $result;
}

function renewPanelCertificates() {
	global $zdbh, $controller;
/*
	# renew in-active domains until deleted?
	$rowvhost = $zdbh->prepare("SELECT * FROM x_vhosts WHERE vh_active_in = '1' AND vh_ssl_tx IS NOT NULL AND vh_ssl_port_in IS NOT NULL AND vh_enabled_in = '1' AND vh_deleted_ts IS NULL");
	$rowvhost->execute();
	$sslVhosts = $rowvhost->fetchAll();
	$result = "";
	
	foreach($sslVhosts as $sslVhost) {
		//if (strpos($sslVhost['vh_ssl_tx'], 'Sencrypt') !== false) {
		if ($sslVhost['vh_ssl_tx'] !== false) {
			
			$vhostOwner = ctrl_users::GetUserDetail($sslVhost['vh_acc_fk']);
			$hostdatadir = ctrl_options::GetOption('hosted_dir');
			$domainPath = $hostdatadir . $vhostOwner['username'] . "/public_html" . $sslVhost['vh_directory_vc'];
			$result .= "Checking certificate for Client: " . $vhostOwner['username'] . " / Domain: " . $sslVhost['vh_name_vc'] . "<br>";
			$result .= "At location: " . $domainPath . "<br>";
			# Lescript automatic updating script.
			#
			# This is an example of how Lescript can be used to automatically update
			# expiring certificates.
			#
			# This code is based on FreePBX's LetsEncrypt integration
			#
			# Copyright (c) 2016 Rob Thomas <rthomas@sangoma.com>
			# Licence:  AGPLv3.
			#
			# In addition, Stanislav Humplik <sh@analogic.cz> is explicitly granted permission
			# to relicence this code under the open source licence of their choice.
			
			# Configuration:
			$domains = $sslVhost['vh_name_vc'];
			$domains = array($domains);
			$domain = $sslVhost['vh_name_vc'];
			$webroot = $domainPath;
			//$certlocation = "/etc/letsencrypt/live/" . $sslVhost['vh_name_vc'];
			
			$accountDir = $hostdatadir . $vhostOwner['username'] . "/ssl/sencrypt/letsencrypt/";
			# Changed to help with backup and compability
			$certlocation = $hostdatadir . $vhostOwner['username'] . "/ssl/sencrypt/letsencrypt/" . $sslVhost['vh_name_vc'];
			
			# Require Lescript for renewal of SSL certs
			require_once 'modules/sencrypt/code/Lescript.php';
			
			# Always use UTC
			date_default_timezone_set("UTC");
			
			# Do we need to create or upgrade our cert? Assume no to start with.
			$needsgen = false;
			
			# Do we HAVE a certificate for all our domains?
			foreach ($domains as $d) {
				//$certfile = "$certlocation/$d/cert.pem";
				$certfile = "$certlocation/cert.pem";
				if (!file_exists($certfile)) {
					# We don't have a cert, so we need to request one.
					$needsgen = true;
				} else {
					# We DO have a certificate.
					$certdata = openssl_x509_parse(file_get_contents($certfile));
					print_r("   Checking certificate for: " . $d . "...") . fs_filehandler::NewLine();
					# If it expires in less than a month, we want to renew it.
					$renewafter = $certdata['validTo_time_t']-(86400*30);
					
					if (time() > $renewafter) {
						# Less than a month left, we need to renew.
						print_r("   --- Renewing certificate : " . $d . " for 90 Days" ) . fs_filehandler::NewLine();
						$needsgen = true;
					}
				}
			}
			
			# Do we need to generate a certificate?
			if ($needsgen) {
				try {
					//$le = new Analogic\ACME\Lescript($accountDir, $certlocation, $webroot, $logger);
					# or without logger:
					$le = new Analogic\ACME\Lescript($accountDir, $certlocation, $webroot);
					$le->initAccount();
					//$le->signDomains(array($domain));

					# Check if domain is a subdomain
					$sql = "SELECT vh_type_in FROM x_vhosts WHERE vh_acc_fk=:userid AND vh_name_vc=:domain AND vh_enabled_in=1 AND vh_deleted_ts IS NULL ORDER BY vh_name_vc ASC";
					$query = $zdbh->prepare($sql);
					$query->bindParam(':userid', $currentuser['userid']);
					$query->bindParam(':domain', $domain);
					$query->execute();
				
					while ($row = $query->fetch()) {
						
						if ($row['vh_type_in'] == 2 ) {
							# Create domain without www. becuase its a subdomain
							$le->signDomains(array($domain));
							
						} else {
							# Create a SSL with www. because its a root domain
							$le->signDomains(array($domain, 'www.' . $domain));
							
						}
					}
			
				}
				catch (\Exception $e) {
					print_r("ERROR!");
					$logger->error($e->getMessage());
					$logger->error($e->getTraceAsString());
					# Exit with an error code, something went wrong.
					exit(1);
				}
			}

			# Create a complete .pem file for use with haproxy or apache 2.4,
			# and save it as domain.name.pem for easy reference. It doesn't
			# matter that this is updated each time, as it'll be exactly
			# the same.
			/* 
			foreach ($domains as $d) {
				//$pem = file_get_contents("$certlocation/$d/fullchain.pem")."\n".file_get_contents("$certlocation/$d/private.pem");
				$pem = file_get_contents("$certlocation/fullchain.pem")."\n".file_get_contents("$certlocation/private.pem");
				file_put_contents("$certlocation/$d.pem", $pem);
			}
			$result .= "Domain: " . $sslVhost['vh_name_vc'] . " analyzed." . fs_filehandler::NewLine();
		}
	}
	return $result; 
*/
}
echo fs_filehandler::NewLine() . "START Sencrypt Manager SSL Renewal Hook." . fs_filehandler::NewLine();
if (ui_module::CheckModuleEnabled('Sencrypt Manager')) {
	
    echo "Sencrypt Manager module ENABLED..." . fs_filehandler::NewLine();
	
	//if ( ctrl_options::GetSystemOption('panel_ssl_tx') != null) {
	//	echo "Renewing Sentora Control panel certificates..." . fs_filehandler::NewLine();
			# Run renew panel cert function
			//renewPanelCertificates();
	//}
	
	echo "Renewing client certificates..." . fs_filehandler::NewLine();
		# Run renew cert function
		renewCertificates();
		
	echo fs_filehandler::NewLine()."Renewing client certificates completed." . fs_filehandler::NewLine();
	
} else {
	
    echo "Sencrypt Manager module DISABLED...nothing to do." . fs_filehandler::NewLine();
}

echo "END Sencrypt Manager SSL Renewal Hook." . fs_filehandler::NewLine();



?>