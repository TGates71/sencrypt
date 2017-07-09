<?php

		//* Generate Let's Encrypt SSL certificate
		if($data['new']['ssl'] == 'y' && $data['new']['ssl_letsencrypt'] == 'y' && ( // ssl and let's encrypt is active
			($data['old']['ssl'] == 'n' OR $data['old']['ssl_letsencrypt'] == 'n') // we have new let's encrypt configuration
			OR ($data['old']['domain'] != $data['new']['domain']) // we have domain update
			OR ($data['old']['subdomain'] != $data['new']['subdomain']) // we have new or update on "auto" subdomain
			OR ($data['new']['type'] == 'subdomain') // we have new or update on subdomain
			OR ($data['old']['type'] == 'alias' OR $data['new']['type'] == 'alias') // we have new or update on alias domain
		)) {
				$data['new']['ssl_domain'] = $domain;
				$vhost_data['ssl_domain'] = $domain;
				// default values
				$temp_domains = array();
				$lddomain     = $domain;
				$subdomains   = null;
				$aliasdomains = null;
				$sub_prefixes = array();
				//* be sure to have good domain
				if($data['new']['subdomain'] == "www" OR $data['new']['subdomain'] == "*") {
					$temp_domains[] = "www." . $domain;
				}
				//* then, add subdomain if we have
				$subdomains = $app->db->queryAllRecords('SELECT domain FROM web_domain WHERE parent_domain_id = '.intval($data['new']['domain_id'])." AND active = 'y' AND type = 'subdomain'");
				if(is_array($subdomains)) {
					foreach($subdomains as $subdomain) {
						$temp_domains[] = $subdomain['domain'];
						$sub_prefixes[] = str_replace($domain, "", $subdomain['domain']);
					}
				}
				//* then, add alias domain if we have
				$aliasdomains = $app->db->queryAllRecords('SELECT domain,subdomain FROM web_domain WHERE parent_domain_id = '.intval($data['new']['domain_id'])." AND active = 'y' AND type = 'alias'");
				if(is_array($aliasdomains)) {
					foreach($aliasdomains as $aliasdomain) {
						$temp_domains[] = $aliasdomain['domain'];
						if(isset($aliasdomain['subdomain']) && ! empty($aliasdomain['subdomain'])) {
							if($aliasdomain['subdomain'] != "none"){
								$temp_domains[] = $aliasdomain['subdomain'] . "." . $aliasdomain['domain'];
							}
						}
						foreach($sub_prefixes as $s) {
							$temp_domains[] = $s . $aliasdomain['domain'];
						}
					}
				}
				// prevent duplicate
				$temp_domains = array_unique($temp_domains);
				// generate cli format
				foreach($temp_domains as $temp_domain) {
					$lddomain .= (string) " --domains " . $temp_domain;
				}
				// useless data
				unset($subdomains);
				unset($temp_domains);
				$crt_tmp_file = "/etc/letsencrypt/live/".$domain."/cert.pem";
				$key_tmp_file = "/etc/letsencrypt/live/".$domain."/privkey.pem";
				$bundle_tmp_file = "/etc/letsencrypt/live/".$domain."/chain.pem";
				$webroot = $data['new']['document_root']."/web";
				//* check if we have already a Let's Encrypt cert
				if(!file_exists($crt_tmp_file) && !file_exists($key_tmp_file)) {
					$app->log("Create Let's Encrypt SSL Cert for: $domain", LOGLEVEL_DEBUG);
					if(is_dir($webroot . "/.well-known/")) {
						$app->log("Remove old challenge directory", LOGLEVEL_DEBUG);
						$this->_exec("rm -rf " . $webroot . "/.well-known/");
					}
					$app->log("Create challenge directory", LOGLEVEL_DEBUG);
					$app->system->mkdirpath($webroot . "/.well-known/");
					$app->system->chown($webroot . "/.well-known/", $data['new']['system_user']);
					$app->system->chgrp($webroot . "/.well-known/", $data['new']['system_group']);
					$app->system->mkdirpath($webroot . "/.well-known/acme-challenge");
					$app->system->chown($webroot . "/.well-known/acme-challenge/", $data['new']['system_user']);
					$app->system->chgrp($webroot . "/.well-known/acme-challenge/", $data['new']['system_group']);
					$app->system->chmod($webroot . "/.well-known/acme-challenge", "g+s");
					$this->_exec("/root/.local/share/letsencrypt/bin/letsencrypt auth -a webroot --email postmaster@$domain --domains $lddomain --webroot-path $webroot");
				};
				//* check is been correctly created
				if(file_exists($crt_tmp_file) OR file_exists($key_tmp_file)) {
					$date = date("YmdHis");
					if(is_file($key_file)) {
						$app->system->copy($key_file, $key_file.'.old'.$date);
						$app->system->chmod($key_file.'.old.'.$date, 0400);
						$app->system->unlink($key_file);
					}
					if ($web_config["website_symlinks_rel"] == 'y') {
						$this->create_relative_link(escapeshellcmd($key_tmp_file), escapeshellcmd($key_file));
					} else {
						exec("ln -s ".escapeshellcmd($key_tmp_file)." ".escapeshellcmd($key_file));
					}
					if(is_file($crt_file)) {
						$app->system->copy($crt_file, $crt_file.'.old.'.$date);
						$app->system->chmod($crt_file.'.old.'.$date, 0400);
						$app->system->unlink($crt_file);
					}
					if($web_config["website_symlinks_rel"] == 'y') {
						$this->create_relative_link(escapeshellcmd($crt_tmp_file), escapeshellcmd($crt_file));
					} else {
						exec("ln -s ".escapeshellcmd($crt_tmp_file)." ".escapeshellcmd($crt_file));
					}
					if(is_file($bundle_file)) {
						$app->system->copy($bundle_file, $bundle_file.'.old.'.$date);
						$app->system->chmod($bundle_file.'.old.'.$date, 0400);
						$app->system->unlink($bundle_file);
					}
					if($web_config["website_symlinks_rel"] == 'y') {
						$this->create_relative_link(escapeshellcmd($bundle_tmp_file), escapeshellcmd($bundle_file));
					} else {
						exec("ln -s ".escapeshellcmd($bundle_tmp_file)." ".escapeshellcmd($bundle_file));
					}
					/* we don't need to store it.
					/* Update the DB of the (local) Server */
					$app->db->query("UPDATE web_domain SET ssl_request = '', ssl_cert = '$ssl_cert', ssl_key = '$ssl_key' WHERE domain = '".$data['new']['domain']."'");
					$app->db->query("UPDATE web_domain SET ssl_action = '' WHERE domain = '".$data['new']['domain']."'");
					/* Update also the master-DB of the Server-Farm */
					$app->dbmaster->query("UPDATE web_domain SET ssl_request = '', ssl_cert = '$ssl_cert', ssl_key = '$ssl_key' WHERE domain = '".$data['new']['domain']."'");
					$app->dbmaster->query("UPDATE web_domain SET ssl_action = '' WHERE domain = '".$data['new']['domain']."'");
				}
			};
?>