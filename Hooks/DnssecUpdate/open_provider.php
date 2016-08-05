<?php
/*
**********************************************

         *** SoluteDNS for WHMCS ***

File:					custom_hooks.php
Version:				0.0.2
Date:					05-08-2016
Provider:				Openprovider
Sponsor:				uHost.nl

Copyright (C) NetDistrict 2016
All Rights Reserved
**********************************************

## DESCRIPTION ##

This hook will automatically send DNSsec keys to the domain provider API.

Please see: http://www.solutedns.com/documentation/hook-points/ for more
information about SoluteDNS hooks and when they are triggered.

## MANUAL ##

1. Review the configuration settings in this file.

2. Check if you have the provider API and if the include path is accurate.

3. Upload this file to the solutedns addon directory in WHMCS.

4. Rename this file to: custom_hooks.php

Compatibility:
-------------------------------
WHMCS:			v6.3.x or later
SoluteDNS:		v0.2.5 or later
-------------------------------
*/

if (!defined("WHMCS"))
	die("This file cannot be accessed directly");

use Illuminate\Database\Capsule\Manager as Capsule;

function SDNS_hook_DnssecUpdate($vars) {
	
	##############################################
	## CONFIG                                   ##
	##############################################
	
	// API Credentials
	$username			= 	'';
	$password			= 	'';
	$debug 				= 	false;
	$registrar_limit	= 	true; // Checks if domain has API provider as registrar
	$registrar_module	=	'openprovider';
	$api_url			=	'https://api.openprovider.eu';

	// Provider API Class location
	require_once('custom/API.php');
	
	// Get the API from: https://doc.openprovider.eu/index.php/Example_Class_API_PHP
	
	##############################################
	
	// Check registrar
	$start = false;
	
	if ($registrar_limit == true) {
	
		// Get index info
		$index = Capsule::table('mod_solutedns_zones')->where('domain',$vars['domain'])->first();
	
		if($index->type == 'd') {
		
			// Get domain info	
			$domaindetails = Capsule::table('tbldomains')->where('id',$index->local_id)->first();
			
			if ($domaindetails->registrar == $registrar_module) $start = true;
			
		}

	} else $start = true;

	if ($start == true) {
	
		// Intiate API
		$api = new OP_API ($api_url);

		// Reform keys for API request
		if (!is_null($vars['keys'])) {
		
			foreach($vars['keys'] as $result) {
				
				$public_key = $result['public_key'];
				
				if ($public_key == NULL) continue;	
				
				if ($result['flag'] == 'CSK') $flag = '257';
				if ($result['flag'] == 'KSK') $flag = '257';
				if ($result['flag'] == 'ZSK') $flag = '256';
								
				$send_dnssec[] = array(
					'flags' => $flag,
					'alg' => $result['algorithm'],
					'protocol' => 3,
					'pubKey' => $public_key,
				);
			
			}
			
		} else $send_dnssec = NULL;
		
		// Split tld from domain
		$domain = explode('.', $vars['domain'], 2);

		// Prepare API Request
		$request = new OP_Request;
		$request->setCommand('modifyDomainRequest')
		  ->setAuth(array('username' => $username, 'password' => $password))
		  ->setArgs(array(
			'domain' => array(
			  'name' => $domain[0],
			  'extension' => $domain[1]
			),
			'dnssecKeys' => $send_dnssec,
		  ));
		
		// Send request
		if ($debug == true) {
			$reply = $api->setDebug(1)->process($request);
			var_dump($reply);
		} else {
			$reply = $api->process($request);
		}
		
		// Log errors to activity log
		if ($reply->getFaultCode() != 0) {
			logActivity('Open Provider API Error ['.$reply->getFaultCode().'] occurred: '.$reply->getFaultString().' in: SDNS_hook_DnssecUpdate');
		}
		
		unset($api,$vars,$reply,$request,$result);
	}

}
?>