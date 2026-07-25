;***********************
;* FiSH_11 mIRC Script *
;***********************
; "FiSH_11" - Secure IRC encryption script for mIRC
; Written by GuY, 2025-26. Licensed under GPL-v3.
;
; SECURITY NOTICE: The security of this script depends entirely on the
; binary DLL files (fish_11.dll, fish_11_inject.dll). This mIRC script
; only provides the user interface. Ensure the DLLs are from a trusted
; source, as vulnerabilities in them can compromise your system.

; === INITIALIZATION AND STARTUP ===
on *:START: {
  .fish11_startup
}

alias fish11_startup {
  echo 4 -a *** FiSH_11 SECURITY NOTiCE *** This script relies on 2 external DLL files. Only use trusted, signed versions from official sources.  ***
  echo 4 -a *** FiSH_11 SECURITY NOTiCE *** Never run this script if you suspect your system has been compromised.                                ***

  var %exe_dir = $nofile($mircexe)

  ; Set paths to DLLs
  %Fish11InjectDllFile = $qt(%exe_dir $+ fish_11_inject.dll)
  %Fish11DllFile = $qt(%exe_dir $+ fish_11.dll)

  echo 4 -a DEBUG : loading DLLs...
  echo 4 -a DEBUG : Fish11_InjectDllFile = %Fish11InjectDllFile
  echo 4 -a DEBUG : Fish11_DllFile = %Fish11DllFile

  ; Check if DLLs exist
  if (!$exists(%Fish11InjectDllFile)) {
    echo 4 -a *** FiSH_11 ERROR: inject DLL not found: %Fish11InjectDllFile
    halt
  }

  if (!$exists(%Fish11DllFile)) {
    echo 4 -a *** FiSH_11 ERROR: DLL not found: %Fish11DllFile
    halt
  }

  ; Check mIRC's DLL lock
  if ($lock(dll)) {
    echo 4 -a *** FiSH_11 ERROR: mIRC DLLs are locked. Enable DLLs in mIRC settings.
    halt
  }

  ; Initialize hash table for tracking key exchanges (X25519)
  if (!$hget(fish11.dh).size) {
    hmake fish11.dh 10
  }

  ; Initialize hash table for tracking legacy DH1080 key exchanges
  if (!$hget(fish10.dh).size) {
    hmake fish10.dh 10
  }

  ; Set configuration path in DLL
  echo 4 -a DEBUG : calling fish_11.dll FiSH11_SetMircDir to set configuration path...
  noop $dll(%Fish11DllFile, FiSH11_SetMircDir, $mircdir)
  echo 4 -a DEBUG : MIRCDIR set to: $mircdir

  ; Initialize config file path
  %fish_config_file = $+(%exe_dir, fish_11.ini)

  ; Get and display inject DLL version
  var %inject_version = $dll(%Fish11InjectDllFile, FiSH11_InjectVersion, $null)
  if (%inject_version) {
    echo -ts *** %inject_version ***
  }
  else {
    echo -ts *** FiSH_11: WARNING - could not load inject DLL version ***
  }

  ; Get and display core DLL version
  var %raw_version_info = $dll(%Fish11DllFile, FiSH11_GetVersion, $null)
  
  if (%raw_version_info) {
    ; Parse the raw string: VERSION|BUILD_TYPE
    ; 124 is ASCII for |
    var %version_string = $gettok(%raw_version_info, 1, 124)
    var %build_type = $gettok(%raw_version_info, 2, 124)

    ; Display the base version info
    echo -ts *** %version_string ***

    ; Display context-specific warning or info message
    if (%build_type == DEBUG) {
      echo 4 -ts $chr(3)4 *** WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING ***
      echo 4 -ts $chr(3)4 *** 
      echo 4 -ts $chr(3)4 *** SECURITY WARNiNG : you're running a DEBUG version which logs EVERYTHING (keys, private messages, etc.) ON YOUR DISK.
      echo 4 -ts $chr(3)4 *** DO NOT USE THiS VERSION IN REAL LiFE.
      echo 4 -ts $chr(3)4 *** 
      echo 4 -ts $chr(3)4 *** WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING ***
    }
    else {
      echo 4 -ts $chr(3)3 *** w00t, you are running a RELEASE version. Sensitive data is NOT logged.
    }
  }
  else {
    echo -ts *** FiSH_11: WARNING - could not load core DLL version ***
  }

  ; Initialize default settings if not already set
  if (%autokeyx == $null) { set %autokeyx [Off] }
  if (%mark_outgoing == $null) { set %mark_outgoing [Off] }
  if (%mark_style == $null) { set %mark_style 1 }
  if (%NickTrack == $null) { set %NickTrack [Off] }
  ; Key exchange timeout (seconds) - keep in sync with DLL constant; can be overridden by user
  if (%KEY_EXCHANGE_TIMEOUT_SECONDS == $null) { set %KEY_EXCHANGE_TIMEOUT_SECONDS 10 }

  ; Check if master key is unlocked, if not prompt user
  .fish11_check_masterkey
}


;*******************************
;* FiSH_11 Key Management      *
;*******************************
; Key set/get/del/list and fingerprint operations

; === TRACK NICK CHANGES FOR KEY MANAGEMENT ===
on *:NICK:{
  if (($nick == $me) || ($upper($newnick) == $upper($nick))) { return }
  if (($query($newnick) == $null) || (%NickTrack != [On])) { return }
  
  var %old_nick_key = $dll(%Fish11DllFile, FiSH11_FileGetKey, $nick)
  
  ; If we have a key for the old nick
  if ($len(%old_nick_key) > 4) {
    var %new_nick_key = $dll(%Fish11DllFile, FiSH11_FileGetKey, $newnick)
    
    ; If a key already exists for the new nick, warn user about conflict
    if ($len(%new_nick_key) > 4) {
      echo $color(Error) -at *** FiSH_11: nick change conflict ! You have a key for $nick, who is now $newnick. However, you ALREADY have a different key for $newnick. No keys were changed. Please resolve this manually.
      unset %old_nick_key
      unset %new_nick_key
      return
    }
    
    ; Store the key under the new nickname
    if ($dll(%Fish11DllFile, FiSH11_SetKey, $+($network," ",$newnick," ",%old_nick_key))) {
      echo $color(Mode text) -at *** FiSH_11: key for $nick has been moved to new nick $newnick.
      ; Remove the key from the old nickname to prevent reuse by another user
      noop $dll(%Fish11DllFile, FiSH11_FileDelKey, $+($network," ",$nick))
    }
    unset %new_nick_key
  }
  unset %old_nick_key
}


; === KEY MANAGEMENT FUNCTIONS ===
; Set key with different encoding options
alias fish11_setkey {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish11_setkey <nickname> <key>
    return
  }
  ; $1 = nickname (data), $2- = key (parms)
  var %msg = $dll(%Fish11DllFile, FiSH11_SetKey, $+($network, $chr(32), $1, $chr(32), $2-))
  if (%msg && $left(%msg, 6) != Error:) {
    echo -a *** FiSH_11: key set for $1 on network $network
  }
  else {
    var %error_msg = $iif(%msg, %msg, "Unknown error - could not set key for $1")
    echo -a *** FiSH_11: error setting key for $1 - %error_msg
  }
  unset %msg
}

alias fish11_setkey_manual {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish11_setkey_manual <#channel> <base64_encoded_32byte_key>
    echo 4 -a Example: /fish11_setkey_manual #secret AGN2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0
    return
  }

  ; Validate channel name format
  var %channel = $1
  if (!$regex(%channel, /^[#&]/)) {
    echo 4 -a Error: Channel name must start with # or &
    return
  }

  ; Validate key format (base64, 44 chars)
  var %key = $2-
  
  if ($len(%key) == 44 && $regex(%key, /^[A-Za-z0-9+\/=]+$/)) {
    ; Valid base64 key - use standard function
    var %input = $+(%channel, $chr(32), %key)
    var %msg = $dll(%Fish11DllFile, FiSH11_SetManualChannelKey, %input)
  }
  else {
    ; Non-base64 or different length - use password derivation function
    var %input = $+(%channel, $chr(32), %key)
    var %msg = $dll(%Fish11DllFile, FiSH11_SetManualChannelKeyFromPassword, %input)
  }

  if (%msg && $left(%msg, 6) != Error:) {
    echo -a *** FiSH_11: manual channel key set for %channel
  }
  else {
    var %error_msg = $iif(%msg, %msg, "Unknown error - could not set manual key for %channel")
    echo -a *** FiSH_11: error setting manual key for %channel - %error_msg
  }
}

alias fish11_setkey_utf8 {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish11_setkey_utf8 <nickname> <raw_key>
    return
  }
  var %network = $regsubex($network, /[^\w\d]/g, _)
  var %result = $dll(%Fish11DllFile, FiSH11_SetKey, $+(%network, $chr(32), $1, $chr(32), $2-))
  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_11: key for $1 set to *censored*
  }
  else {
    echo $color(Error) -at *** FiSH_11: error setting key for $1 - $iif(%result, %result, Unknown error)
  }
}


; === KEY EXCHANGE INIT ===
; Initialize key exchange
alias fish11_X25519_INIT {
  if (($1 == /query) || ($1 == $null)) var %cur_contact = $active
  else var %cur_contact = $1

  ; If there's an existing exchange in progress, cancel it first
  if ($hget(fish11.dh, %cur_contact) == 1) {
    echo $color(Mode text) -at *** FiSH_11: restarting key exchange with %cur_contact
  }

  ; Use a hash table to track in-progress exchanges.
  hadd -m fish11.dh %cur_contact 1

  var %pub = $dll(%Fish11DllFile, FiSH11_ExchangeKey, %cur_contact)

  ; Use regex to validate the entire key format.
  if ($regex(%pub, /^X25519_INIT:[A-Za-z0-9+\/=]+$/)) {
    .notice %cur_contact X25519_INIT %pub
    echo $color(Mode text) -tm %cur_contact *** FiSH_11: sent X25519_INIT to %cur_contact $+ , waiting for reply...
  }
  else {
    ; Fallback: show what we got (safely)
    echo $color(Mode text) -at *** FiSH_11: ERROR - key exchange initiation failed. DLL returned: $qt(%pub)
  }

  ; Start a timer to cancel the exchange if no response is received
  .timer.fish11_x25519_ $+ %cur_contact 1 %KEY_EXCHANGE_TIMEOUT_SECONDS fish11_timeout_keyexchange %cur_contact
}

; Process received public key
alias fish11_ProcessPublicKey {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish11_ProcessPublicKey <nickname> <public_key>
    return
  }
  
  ; Process the public key
  var %result = $dll(%Fish11DllFile, FiSH11_ProcessPublicKey, $1 $2-)
  
  ; Check if processing was successful (no error message)
  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_11: key exchange completed with $1
    echo $color(Error) -at *** FiSH_11 WARNING: key exchange complete, but the identity of $1 is NOT VERIFIED.
    echo $color(Error) -at *** FiSH_11: use /fish_fp11 $1 to see their key fingerprint and verify it with them through a secure channel (e.g., voice call).
  }
  else {
    ; Display error message from DLL
    echo $color(Mode text) -at *** FiSH_11: %result
  }
}

; Shorthand for key exchange
alias keyx { fish11_X25519_INIT $1 }


; === USE KEY FROM ANOTHER CHANNEL/USER ===
alias fish11_usechankey {
  if ($server == $null) {
    echo $color(Mode text) -at *** FiSH_11: ERROR - not connected to a server.
    return
  }
  var %theKey = $dll(%Fish11DllFile, FiSH11_FileGetKey, $2)
  if (%theKey == $null) {
    echo $color(Mode text) -at *** FiSH_11: no valid key for $2 found
  }
  else {
    if ($dll(%Fish11DllFile, FiSH11_SetKey, $+($network," ",$1," ",%theKey))) {
      echo $color(Mode text) -at *** FiSH_11: using same key as $2 for $1
    }
    unset %theKey
  }
}


; === SHOW KEY ===
alias fish11_showkey {
  if ($1 == /query) var %cur_contact = $active
  else var %cur_contact = $1

  var %theKey = $dll(%Fish11DllFile, FiSH11_FileGetKey, %cur_contact)
  if (%theKey != $null) {
    window -dCo +l @FiSH-Key -1 -1 500 120
    aline @FiSH-Key Key for %cur_contact :
    aline -p @FiSH-Key %theKey
    
    ; Show key TTL (expiration) if available
    var %ttl = $dll(%Fish11DllFile, FiSH11_GetKeyTTL, %cur_contact)
    if (%ttl == EXPIRED) {
      aline @FiSH-Key Status: EXPIRED - use /fish11_X25519_INIT %cur_contact to renew
    }
    else if (%ttl == NO_TTL) {
      aline @FiSH-Key Status: No expiration (manually set key)
    }
    else if (%ttl isnum) {
      var %hours = $int($calc(%ttl / 3600))
      var %mins = $int($calc((%ttl % 3600) / 60))
      aline @FiSH-Key Status: Expires in %hours hours %mins minutes
    }
    
    unset %theKey
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: no valid key for %cur_contact found
  }
}


; === REMOVE KEY ===
alias fish11_removekey {
  if ($1 == /query) var %cur_contact = $active
  else var %cur_contact = $1
  
  ; Get result message from DLL
  var %msg = $dll(%Fish11DllFile, FiSH11_FileDelKey, $+($network," ",%cur_contact))
  
  ; Display message from DLL (works for both success and error)
  if (%msg) {
    echo $color(Mode text) -at *** FiSH_11: %msg
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: error - could not remove key for %cur_contact
  }
}


; === SAFETY FUNCTION ===
; Safety function to prevent accidental key overwrites
alias fish11_setkey_safe {
  var %target = $1
  var %existing_key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %target)
  
  if ($len(%existing_key) > 1) {
    if ($?!="Key already exists for %target $+ . Overwrite? (Yes/No)") {
      fish11_setkey %target $2-
    }
  }
  else {
    fish11_setkey %target $2-
  }
}


; === KEY TTL (EXPIRATION) ===
; Show the remaining lifetime of an exchange key
; Exchange keys have a 24-hour TTL from creation time
; Usage: /fish11_keyttl <nickname>
alias fish11_keyttl {
  if ($1 == $null) {
    echo 4 -a Syntax: /fish11_keyttl <nickname>
    return
  }
  
  var %nickname = $1
  var %ttl = $dll(%Fish11DllFile, FiSH11_GetKeyTTL, %nickname)
  
  if (%ttl == EXPIRED) {
    echo $color(Error) -at *** FiSH_11: key for %nickname has EXPIRED
    echo $color(Mode text) -at *** FiSH_11: use /fish11_X25519_INIT %nickname to establish a new key
  }
  else if (%ttl == NO_TTL) {
    echo $color(Mode text) -at *** FiSH_11: key for %nickname has no expiration (manually set key)
  }
  else if (%ttl isnum) {
    var %hours = $int($calc(%ttl / 3600))
    var %mins = $int($calc((%ttl % 3600) / 60))
    echo $color(Mode text) -at *** FiSH_11: key for %nickname expires in %hours hours %mins minutes
  }
  else {
    echo $color(Error) -at *** FiSH_11: could not get key TTL for %nickname
  }
}

; Short alias for key TTL
alias fkeyttl { fish11_keyttl $1 }


; === LIST ALL KEYS ===
alias fish11_file_list_keys {
  ; Check the DLL exists before trying to call it
  if (!$isfile(%Fish11DllFile)) {
    echo $color(Mode text) -at *** FiSH ERROR- DLL not found: %Fish11DllFile
    return
  }
  ; Log that we're about to call the function
  echo $color(Mode text) -at *** FiSH: listing keys...
  ; Ensure MIRCDIR is set (should already be set at startup, but be safe)
  noop $dll(%Fish11DllFile, FiSH11_SetMircDir, $mircdir)
  
  ; Call DLL function using proper syntax for data return
  echo $color(Mode text) -at *** FiSH: about to call FiSH11_FileListKeys...
  var %keys = $dll(%Fish11DllFile, FiSH11_FileListKeys, $null)
  echo $color(Mode text) -at *** FiSH: DLL call completed, result length: $len(%keys)
  
  ; Check for errors (DLL returns "Error: ..." for errors)
  if ($left(%keys, 6) == Error:) {
    echo $color(Error) -at *** FiSH ERROR: %keys
    return
  }
  
  ; If the function returns data, display it line by line
  if (%keys != $null && $len(%keys) > 0) {
    fish11_display_multiline_result %keys
  }
  else {
    echo $color(Mode text) -at *** FiSH: no keys found
  }
}


; Helper function to safely display multi-line text from DLL
alias -l fish11_display_multiline_result {
  var %text = $1-
  var %line_count = 0
  var %max_lines = 100

  ; Handle different line ending formats
  %text = $replace(%text, $chr(13) $+ $chr(10), $chr(1))
  %text = $replace(%text, $chr(13), $chr(1))
  %text = $replace(%text, $chr(10), $chr(1))

  ; Display each line
  var %i = 1
  var %num_tokens = $numtok(%text, 1)
  while (%i <= %num_tokens) {
    var %line = $gettok(%text, %i, 1)

    ; Safety check: limit number of lines to prevent crashes
    inc %line_count
    if (%line_count > %max_lines) {
      echo $color(Mode text) -at *** FiSH_11: output truncated (exceeded %max_lines lines)
      break
    }

    ; Display the line with proper formatting
    if ($len(%line) > 0) {
      echo $color(Mode text) -at %line
    }

    inc %i
  }
}


; === FINGERPRINT ===
; Helper function to get and format colored fingerprint for a target
; Returns the colored fingerprint or $null if not available
; Also caches the result in %fish11.lastfingerprint.<target>
alias -l fish11_GetColoredFingerprint {
  var %target = $1
  
  ; Check if there's a cached fingerprint first
  if (%fish11.lastfingerprint. $+ [ %target ] != $null) {
    return $($+(%,fish11.lastfingerprint.,%target),2)
  }
  
  ; Get the fingerprint from DLL
  var %fingerprint = $dll(%Fish11DllFile, FiSH11_GetKeyFingerprint, %target)
  
  ; Check if the response is an error message
  if ($left(%fingerprint, 6) == Error:) {
    return $null
  }
  
  ; Extract just the fingerprint part from the response
  var %fp_only = $gettok(%fingerprint, 2-, 58)
  var %fp_only = $strip(%fp_only)
  
  ; Validate that we have a proper fingerprint
  if (%fp_only == $null || $len(%fp_only) < 10 || $pos(%fp_only, $chr(32)) == 0) {
    return $null
  }
  
  ; Format each group with a different color
  var %group1 = $gettok(%fp_only, 1, 32)
  var %group2 = $gettok(%fp_only, 2, 32) 
  var %group3 = $gettok(%fp_only, 3, 32)
  var %group4 = $gettok(%fp_only, 4, 32)
  
  ; Validate that we have at least 4 groups
  if (%group1 == $null || %group2 == $null || %group3 == $null || %group4 == $null) {
    return $null
  }
  
  ; Create colored version using mIRC color codes
  ; 04=red, 12=blue, 03=green, 07=orange
  var %colored_fp = 04 $+ %group1 $+  12 $+ %group2 $+  03 $+ %group3 $+  07 $+ %group4
  
  ; Cache the result
  set %fish11.lastfingerprint. $+ [ %target ] %colored_fp
  
  return %colored_fp
}

; Display key fingerprint with color for a target
alias fish11_showfingerprint {
  if ($1 == /query) {
    var %target = $active
  }
  else {
    var %target = $1
  }
  
  ; Check if we have a key for this target
  var %key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %target)
  
  if ($len(%key) > 1) {
    var %colored_fp = $fish11_GetColoredFingerprint(%target)
    
    if (%colored_fp != $null) {
      ; Display the colored fingerprint
      echo $color(Mode text) -at *** FiSH_11: key fingerprint for %target is: %colored_fp
    }
    else {
      echo $color(Mode text) -at *** FiSH_11: Error: could not retrieve valid fingerprint for %target
    }
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: no key found for %target
  }
}


; === ALIAS SHORTCUTS FOR USER COMMANDS ===
alias fish_genkey11 { fish11_setkey_safe $1 $2- }
alias fish_setkey11 { fish11_setkey $1 $2- }
alias fish_getkey11 { fish11_showkey $1 }
alias fish_fp11 { fish11_showfingerprint $1- }
alias fish_delkey11 { fish11_removekey $1 }
alias fish_listkeys11 { fish11_file_list_keys }
alias fish_encrypt11 { return $fish11_encrypt($1, $2-) }
alias fish_decrypt11 { return $fish11_decrypt($1, $2-) }
alias fish_keyx11 { fish11_X25519_INIT $1 }
alias fish_keyp11 { fish11_ProcessPublicKey $1 $2- }
alias fish_keyttl11 { fish11_keyttl $1 }
alias fish_test11 { fish11_test_crypt $1- }
alias fish_help11 { fish11_help }
alias fish_version11 { fish11_version }
alias fish_initchannel11 { fish11_initchannel $1- }
alias fish_stats11 { fish11_stats }


;*******************************
;* FiSH_11 Key Exchange         *
;*******************************
; X25519 key exchange protocol handlers

; === AUTO KEY EXCHANGE ===
on *:OPEN:?:{
  ; Don't auto-exchange if autokeyx is not enabled
  if (%autokeyx != [On]) return
  
  ; Don't auto-exchange if a legacy DH1080 exchange is in progress
  if ($hget(fish10.dh, $nick)) return
  
  ; Don't auto-exchange if a FiSH 11 exchange is in progress
  if ($hget(fish11.dh, $nick)) return
  
  var %tmp1 = $dll(%Fish11DllFile, FiSH11_FileGetKey, $nick)
  
  ; Check for error messages or empty result
  ; Only initiate exchange if truly no key exists
  if (%tmp1 == $null || $left(%tmp1, 2) == no || $left(%tmp1, 5) == Error) {
    ; No FiSH 11 key found - check for legacy key
    var %has_legacy = $dll(%Fish11DllFile, FiSH10_HasKey, $nick)
    if (%has_legacy != 1) {
      ; No key at all (neither FiSH 11 nor legacy), initiate FiSH 11 exchange
      fish11_X25519_INIT $nick
    }
    unset %has_legacy
  }
  unset %tmp1
}


; === KEY EXCHANGE PROTOCOL HANDLERS ===
on ^*:NOTICE:X25519_INIT*:?:{
  ; This event triggers when someone initiates a key exchange with us.
  ; $1 = X25519_INIT, $2- = public key token from peer
  var %their_pub = $2-

  ; Validate incoming key format using regex for robustness.
  if (!$regex(%their_pub, /^X25519_INIT:[A-Za-z0-9+\/]{43}=$/)) {
    echo $color(Mode text) -tm $nick *** FiSH_11: received invalid INIT key format from $nick
    halt
  }

  query $nick
  echo $color(Mode text) -tm $nick *** FiSH_11: received X25519 public key from $nick, responding...

  ; 1. Generate our own keypair (or get existing one). The DLL returns our public key token.
  var %our_pub = $dll(%Fish11DllFile, FiSH11_ExchangeKey, $nick)

  ; 2. Process their public key. This computes and saves the shared secret.
  var %process_result = $dll(%Fish11DllFile, FiSH11_ProcessPublicKey, $nick %their_pub)

  ; Check if processing was successful (no error message)
  if (%process_result && $left(%process_result, 6) != Error:) {
    ; 3. If successful, send our public key back to them so they can complete the exchange.
    ; Use more flexible regex to validate public key format
    if ($regex(%our_pub, /^X25519_INIT:[A-Za-z0-9+\/=]+$/)) {
      .notice $nick X25519_FINISH %our_pub
      echo $color(Mode text) -tm $nick *** FiSH_11: sent X25519_FINISH to $nick
    }
    else {
      echo $color(Mode text) -tm $nick *** FiSH_11: ERROR - could not generate our own public key to send in reply. DLL returned: $qt(%our_pub)
    }
  }
  else {
    ; Display error message from DLL
    echo $color(Mode text) -tm $nick *** FiSH_11: %process_result
  }

  halt
}

on ^*:NOTICE:X25519_FINISH*:?:{
  ; This event triggers when a peer responds to our key exchange initiation.
  ; $1 = X25519_FINISH, $2- = public key token from peer
  ; Ensure an exchange is in progress with this user by checking the hash table.
  if ($hget(fish11.dh, $nick).item != 1) {
    echo -at *** FiSH_11: received a FINISH notice, but no key exchange was in progress with $nick $+ .
    halt
  }

  var %their_pub = $2-

  ; Use regex to validate the key format from the peer.
  if ($regex(%their_pub, /^X25519_INIT:[A-Za-z0-9+\/]{43}(=|==)?$/)) {
    ; Process the received public key. The DLL computes and stores the shared secret.
    var %process_result = $dll(%Fish11DllFile, FiSH11_ProcessPublicKey, $nick %their_pub)

    ; Check if processing was successful (no error message)
    if (%process_result && $left(%process_result, 6) != Error:) {
      ; Success! Clean up state variables.
      hdel fish11.dh $nick

      echo $color(Mode text) -tm $nick *** FiSH_11: key exchange complete with $nick
      echo $color(Error) -tm $nick *** FiSH_11 WARNING: key exchange complete, but the identity of $nick is NOT VERIFIED.
      echo $color(Error) -tm $nick *** FiSH_11: use /fish_fp11 $nick to see their key fingerprint and verify it with them through a secure channel.
    }
    else {
      ; Display error message from DLL
      echo $color(Mode text) -tm $nick *** FiSH_11: %process_result
    }
  }
  else {
    echo $color(Mode text) -tm $nick *** FiSH_11: received invalid FINISH key format from $nick $+ : $qt(%their_pub)
  }

  halt
}


; === KEY EXCHANGE TIMEOUT ===
; Handle key exchange timeout
alias fish11_timeout_keyexchange {
  if ($1 == $null) {
    echo $color(Mode text) -at *** FiSH_11: timeout handler called with no parameters
    return
  }
  
  var %contact = $1
  
  ; Check if key exchange is still in progress.
  if ($hget(fish11.dh, %contact) == 1) {
    ; Clean up variables.
    hdel fish11.dh %contact
    
    ; Notify user of timeout with instructions.
    echo $color(Mode text) -at *** FiSH_11: key exchange with %contact timed out after $KEY_EXCHANGE_TIMEOUT_SECONDS seconds
    echo $color(Mode text) -at *** FiSH_11: to try again, use: /fish11_X25519_INIT %contact
  }
}


;*******************************
;* FiSH_11 Outgoing Encryption  *
;*******************************
; Message encryption for outgoing messages

; === OUTGOING MESSAGE HANDLING ===
on *:INPUT:*: {
  ; Check if message should be processed
  var %process_outgoing = $dll(%Fish11DllFile, INI_GetBool, process_outgoing 1)
  if (%process_outgoing == 0) return
  
  ; Get plain prefix
  var %plain_prefix = $dll(%Fish11DllFile, INI_GetString, plain_prefix +p)
  
  ; Don't process if message starts with plain prefix
  if ($left($1-, $len(%plain_prefix)) == %plain_prefix) {
    return
  }
  
  ; Don't process commands
  if (($left($1, 1) == /) && ($1 != /me) && ($1 != /msg) && ($1 != /notice)) return
  
  ; Handle message too long
  if ($len($1-) > 850) {
    echo 4 -a Mirc cannot handle lines longer than 850 characters. Text not sent.
    haltdef
    halt
    return
  }
  
  ; Handle message types
  var %target = $active
  var %message = $1-
  var %encrypted = $null
  
  ; Extract target for /msg and /notice
  if ($1 == /msg || $1 == /notice) {
    %target = $2
    %message = $3-
  }
  ; Handle /me actions
  else if ($1 == /me) {
    ; Check if actions should be encrypted
    var %encrypt_action = $dll(%Fish11DllFile, INI_GetBool, encrypt_action 0)
    if (%encrypt_action == 0) return
    
    %message = $2-
  }
  
  ; Determine which encryption system to use
  ; Check for: FCEP-1 channel key, manual channel key, legacy key, or private key
  
  var %encrypted = $null
  
  ; Determine if target is a channel or private message
  ; Use window type check as primary method (more robust than character check)
  var %is_channel = $false
  if ($window(%target).type == channel) {
    %is_channel = $true
  }
  elseif ($left(%target, 1) == # || $left(%target, 1) == &) {
    %is_channel = $true
  }

  if (%is_channel) {
    ; Channel target - always try FiSH 11 encryption (handles manual and FCEP-1 keys)
    %encrypted = $dll(%Fish11DllFile, FiSH11_EncryptMsg, %target %message)

    ; If FiSH11 failed (no channel key found), try legacy as fallback
    if ($left(%encrypted, 5) == Error || $left(%encrypted, 6) == Legacy || %encrypted == $null) {
      var %has_legacy_key = $dll(%Fish11DllFile, FiSH10_HasKey, %target)
      if (%has_legacy_key == 1) {
        %encrypted = $dll(%Fish11DllFile, FiSH10_EncryptMsg, %target %message)
      }
    }
  }
  else {
    ; Private message - check for legacy key first
    var %has_legacy_key = $dll(%Fish11DllFile, FiSH10_HasKey, %target)

    if (%has_legacy_key == 1) {
      ; Use FiSH 10 legacy encryption (Blowfish)
      %encrypted = $dll(%Fish11DllFile, FiSH10_EncryptMsg, %target %message)
    }
    else {
      ; Use FiSH 11 encryption (ChaCha20-Poly1305)
      %encrypted = $dll(%Fish11DllFile, FiSH11_EncryptMsg, %target %message)
    }
  }
  
  ; Only process if encryption was successful
  ; Check for various error indicators: "Error", "no encryption", empty result, or legacy errors
  if (%encrypted != $null && $left(%encrypted, 5) != Error && $left(%encrypted, 13) != no encryption && $left(%encrypted, 6) != Legacy) {
    ; Add encryption mark if configured
    ; Save active window for display (echo needs the actual window, not the target)
    var %display_win = $active

    if (%mark_outgoing == [On]) {
      if (%mark_style == 1) {
        ; Suffix style
        echo $color(own text) -t %display_win < $+ $me $+ > %message $+ $chr(183)
      }
      else if (%mark_style == 2) {
        ; Prefix style
        echo $color(own text) -t %display_win $chr(183) $+ < $+ $me $+ > %message
      }
      else if (%mark_style == 3) {
        ; Colored brackets style
        echo $color(own text) -t %display_win $chr(91) $+ $chr(43) $+ $chr(93) < $+ $me $+ > %message
      }
    }
    else {
      ; Display message without encryption mark
      echo $color(own text) -t %display_win < $+ $me $+ > %message
    }
    
    ; Send encrypted message based on command type
    if ($1 == /notice) {
      .notice %target %encrypted
      haltdef
    }
    else if ($1 == /msg) {
      .msg %target %encrypted
      haltdef
    }
    else if ($1 == /me) {
      .action %encrypted
      haltdef
    }
    else {
      .msg %target %encrypted
      haltdef
    }
  }
  else {
    ; Encryption failed - display error and prevent sending to server
    if (%encrypted != $null) {
      echo $color(Error) -at *** FiSH ERROR: %encrypted
    }
    else {
      echo $color(Error) -at *** FiSH ERROR: Encryption failed (no key available)
    }
    haltdef
    halt
  }
}


; === ENCRYPT MESSAGE ===
alias fish11_encrypt {
  if (!$1 || !$2) return
  ; FiSH11_EncryptMsg expects one data string: "<target> <message>"
  var %encrypted = $dll(%Fish11DllFile, FiSH11_EncryptMsg, $1 $2-)
  return %encrypted
}


; === DECRYPT MESSAGE ===
alias fish11_decrypt {
  if ($1 == /query) var %cur_contact = $active
  else var %cur_contact = $1
  if ($2- == $null) return
  
  ; FiSH11_DecryptMsg expects one data string: "<target> <message>"
  var %decrypted = $dll(%Fish11DllFile, FiSH11_DecryptMsg, $+(%cur_contact,$chr(32),$2-))
  if (%decrypted != $null && $left(%decrypted, 6) != Error:) {
    return %decrypted
  }
  echo $color(Mode text) -at *** FiSH: decryption failed for %cur_contact
  return $null
}


; === TEST ENCRYPTION ===
alias fish11_test_crypt {
  if ($1 == $null) var %msg = Test message for encryption
  else var %msg = $1-

  echo -s *** FiSH_11 :: TestCrypt -> call DLL with $qt(%msg)
  .dll %Fish11DllFile FiSH11_TestCrypt %msg
  echo -s *** FiSH_11 :: TestCrypt -> DLL returned
}


;*******************************
;* FiSH_11 Incoming Decryption  *
;*******************************
; Fallback handlers for incoming encrypted messages.
; NOTE: The fish_11_inject.dll handles most incoming decryption
; transparently by hooking SSL_Read. These handlers provide a
; fallback for cases where the injection DLL is not loaded.

; === HELPER: Decrypt incoming message ===
alias -l fish11_try_decrypt_incoming {
  var %sender = $1
  var %message = $2-
  
  ; Check if process_incoming is enabled
  var %process_incoming = $dll(%Fish11DllFile, INI_GetBool, process_incoming 1)
  if (%process_incoming == 0) return %message
  
  ; Get the encryption prefix (default: +FiSH)
  var %prefix = $dll(%Fish11DllFile, INI_GetString, encryption_prefix +FiSH)
  
  ; Check if message starts with the encryption prefix
  if ($left(%message, $len(%prefix)) != %prefix) return %message
  
  ; Extract the encrypted data (after prefix + space)
  var %encrypted_data = $mid(%message, $calc($len(%prefix) + 2))
  
  ; Try FiSH 11 decryption first
  var %decrypted = $dll(%Fish11DllFile, FiSH11_DecryptMsg, $+(%sender, $chr(32), %prefix, $chr(32), %encrypted_data))
  
  ; Check if decryption was successful (no error message)
  if (%decrypted != $null && $left(%decrypted, 6) != Error:) {
    return %decrypted
  }
  
  ; Try FiSH 10 legacy decryption
  var %decrypted = $dll(%Fish11DllFile, FiSH10_DecryptMsg, $+(%sender, $chr(32), %prefix, $chr(32), %encrypted_data))
  
  ; Check if decryption was successful
  if (%decrypted != $null && $left(%decrypted, 6) != Error:) {
    return %decrypted
  }
  
  ; Decryption failed, return original message
  return %message
}

; === HELPER: Decrypt channel message ===
alias -l fish11_try_decrypt_channel {
  var %channel = $1
  var %message = $2-
  
  ; Check if process_incoming is enabled
  var %process_incoming = $dll(%Fish11DllFile, INI_GetBool, process_incoming 1)
  if (%process_incoming == 0) return %message
  
  ; Get the encryption prefix (default: +FiSH)
  var %prefix = $dll(%Fish11DllFile, INI_GetString, encryption_prefix +FiSH)
  
  ; Check if message starts with the encryption prefix
  if ($left(%message, $len(%prefix)) != %prefix) return %message
  
  ; Extract the encrypted data (after prefix + space)
  var %encrypted_data = $mid(%message, $calc($len(%prefix) + 2))
  
  ; Try FiSH 11 channel decryption
  var %decrypted = $dll(%Fish11DllFile, FiSH11_DecryptMsg, $+(%channel, $chr(32), %prefix, $chr(32), %encrypted_data))
  
  ; Check if decryption was successful (no error message)
  if (%decrypted != $null && $left(%decrypted, 6) != Error:) {
    return %decrypted
  }
  
  ; Decryption failed, return original message
  return %message
}


; === INCOMING PRIVATE MESSAGES ===
on ^*:TEXT:*:?:{
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_incoming($nick, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    ; Check if we should display the decrypted message
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted != 0) {
      ; Get encryption mark from config
      var %mark_pos = $fish11_GetIniIntValue(mark_position 1)
      var %mark_enc = $eval($fish11_GetIniValue(mark_encrypted), 1)
      if (%mark_enc == $null) { %mark_enc = $chr(183) }

      if (%mark_pos == 2) {
        ; Prefix mark
        echo $color(Message text) -t $nick %mark_enc $+ < $+ $nick $+ > %decrypted
      }
      else {
        ; Suffix mark (default)
        echo $color(Message text) -t $nick < $+ $nick $+ > %decrypted $+ $chr(32) $+ %mark_enc
      }
    }
    haltdef
    halt
  }
}


; === INCOMING CHANNEL MESSAGES ===
on ^*:TEXT:*:#:{
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_channel($chan, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    ; Check if we should display the decrypted message
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted != 0) {
      ; Get encryption mark from config
      var %mark_pos = $fish11_GetIniIntValue(mark_position 1)
      var %mark_enc = $eval($fish11_GetIniValue(mark_encrypted), 1)
      if (%mark_enc == $null) { %mark_enc = $chr(183) }

      if (%mark_pos == 2) {
        ; Prefix mark
        echo $color(Message text) -t $chan %mark_enc $+ < $+ $nick $+ > %decrypted
      }
      else {
        ; Suffix mark (default)
        echo $color(Message text) -t $chan < $+ $nick $+ > %decrypted $+ $chr(32) $+ %mark_enc
      }
    }
    haltdef
    halt
  }
}


; === INCOMING PRIVATE NOTICES ===
on ^*:NOTICE:*:?:{
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_incoming($nick, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted != 0) {
      var %mark_pos = $fish11_GetIniIntValue(mark_position 1)
      var %mark_enc = $eval($fish11_GetIniValue(mark_encrypted), 1)
      if (%mark_enc == $null) { %mark_enc = $chr(183) }

      if (%mark_pos == 2) {
        echo $color(Mode text) -t $nick %mark_enc $+ - $+ $nick $+ - %decrypted
      }
      else {
        echo $color(Mode text) -t $nick - $+ $nick $+ - %decrypted $+ $chr(32) $+ %mark_enc
      }
    }
    haltdef
    halt
  }
}


; === INCOMING PRIVATE ACTIONS ===
on ^*:ACTION:*:?:{
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_incoming($nick, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted != 0) {
      var %mark_pos = $fish11_GetIniIntValue(mark_position 1)
      var %mark_enc = $eval($fish11_GetIniValue(mark_encrypted), 1)
      if (%mark_enc == $null) { %mark_enc = $chr(183) }

      if (%mark_pos == 2) {
        echo $color(Action text) -t $nick * %mark_enc $+ $nick %decrypted
      }
      else {
        echo $color(Action text) -t $nick * $nick %decrypted $+ $chr(32) $+ %mark_enc
      }
    }
    haltdef
    halt
  }
}


; === INCOMING CHANNEL ACTIONS ===
on ^*:ACTION:*:#:{
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_channel($chan, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted != 0) {
      var %mark_pos = $fish11_GetIniIntValue(mark_position 1)
      var %mark_enc = $eval($fish11_GetIniValue(mark_encrypted), 1)
      if (%mark_enc == $null) { %mark_enc = $chr(183) }

      if (%mark_pos == 2) {
        echo $color(Action text) -t $chan * %mark_enc $+ $nick %decrypted
      }
      else {
        echo $color(Action text) -t $chan * $nick %decrypted $+ $chr(32) $+ %mark_enc
      }
    }
    haltdef
    halt
  }
}


; === INCOMING CHANNEL NOTICES ===
on ^*:NOTICE:*:#:{
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_channel($chan, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted != 0) {
      var %mark_pos = $fish11_GetIniIntValue(mark_position 1)
      var %mark_enc = $eval($fish11_GetIniValue(mark_encrypted), 1)
      if (%mark_enc == $null) { %mark_enc = $chr(183) }

      if (%mark_pos == 2) {
        echo $color(Mode text) -t $chan %mark_enc $+ - $+ $chan $+ - %decrypted
      }
      else {
        echo $color(Mode text) -t $chan - $+ $chan $+ - %decrypted $+ $chr(32) $+ %mark_enc
      }
    }
    haltdef
    halt
  }
}


; === MANUAL DECRYPTION COMMANDS ===
alias fish11_decrypt_msg {
  if ($1 == $null || $2- == $null) {
    echo 4 -a Syntax: /fish11_decrypt_msg <sender> <encrypted_message>
    return
  }
  
  var %sender = $1
  var %message = $2-
  
  var %decrypted = $fish11_try_decrypt_incoming(%sender, %message)
  
  if (%decrypted != %message) {
    echo $color(Mode text) -at *** FiSH_11 Decrypted: %decrypted
  }
  else {
    echo $color(Error) -at *** FiSH_11: failed to decrypt message from %sender
  }
}

; Short alias for manual decryption
alias fdec { fish11_decrypt_msg $1- }


;*******************************
;* FiSH_11 Channel Encryption   *
;*******************************
; Channel encryption (FCEP-1) and manual channel key management

; === CHANNEL JOIN HANDLING ===
on *:JOIN:#:{
  ; Only process our own joins
  if ($nick != $me) return
  
  ; Get channel key if it exists
  var %theKey = $dll(%Fish11DllFile, FiSH11_FileGetKey, $chan)
  if (%theKey != $null) {
    echo $color(Mode text) -at *** FiSH_11: found encryption key for $chan

    ; Check if topic encryption is enabled for this channel
    var %encryptTopic = $fish11_GetChannelIniValue($chan, encrypt_topic)
    if (%encryptTopic == 1) {
      echo $color(Mode text) -at *** FiSH_11: topic encryption enabled for $chan
    }
  }
  unset %theKey
}


; === FCEP-1 CHANNEL ENCRYPTION PROTOCOL HANDLERS ===
on ^*:NOTICE:+FiSH-CEP-KEY*:?:{
  var %num_tokens = $numtok($1-, 32)
  
  ; Validate message format
  if (%num_tokens < 4) {
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FISH_11 : FCEP-1 ERROR : Invalid +FiSH-CEP-KEY format from $nick (expected 4 tokens, got %num_tokens $+ )
    halt
  }
  
  var %channel = $2
  var %coordinator = $3
  var %wrapped_key = $4
  
  ; SECURITY: Verify sender authenticity
  if ($nick != %coordinator) {
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 SECURITY WARNING : key distribution from $nick claims to be from %coordinator - REJECTED
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 : this may indicate an impersonation attack attempt!
    halt
  }
  
  ; Validate channel name format
  if (!$regex(%channel, /^[#&]/)) {
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 ERROR : invalid channel name format: %channel (must start with # or &)
    halt
  }
  
  ; Verify we have a pre-shared key with the coordinator
  var %existing_key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %coordinator)
  
  if ($left(%existing_key, 6) == Error: || $len(%existing_key) < 4) {
    if ($left(%existing_key, 6) == Error:) {
      echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 ERROR: $right(%existing_key, $calc($len(%existing_key) - 6))
    }
    else {
      echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 ERROR: no pre-shared key found for coordinator %coordinator
      echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 : you must establish a key with %coordinator first using /fish11_X25519_INIT %coordinator
    }
    halt
  }
  
  ; Process the channel key via DLL
  var %result = $dll(%Fish11DllFile, FiSH11_ProcessChannelKey, %channel %coordinator $nick %wrapped_key)
  
  if (%result && $left(%result, 6) != Error:) {
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 : %result
  }
  else {
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 ERROR: %result
  }
  
  halt
}


; === FCEP-1 CHANNEL ENCRYPTION COMMANDS ===
alias fish11_initchannel {
  if ($1 == $null || $2 == $null) {
    echo $color(Error) -at *** FiSH_11 FCEP-1: Usage: /fish11_initchannel <#channel> <nick1> [nick2] ...
    echo $color(Mode text) -at *** FiSH_11 FCEP-1: Example: /fish11_initchannel #secret alice bob charlie
    echo $color(Mode text) -at *** FiSH_11 FCEP-1: Note: You must have pre-shared keys with all listed members (use /fish11_X25519_INIT first)
    return
  }
  
  var %channel = $1
  var %members = $2-
  
  ; Validate channel name
  if (!$regex(%channel, /^[#&]/)) {
    echo $color(Error) -at *** FiSH_11 FCEP-1 ERROR: Invalid channel name %channel (must start with # or &)
    return
  }
  
  echo $color(Mode text) -at *** FiSH_11 FCEP-1: Generating channel key for %channel
  echo $color(Mode text) -at *** FiSH_11 FCEP-1: Members to receive key: %members
  
  var %result = $dll(%Fish11DllFile, FiSH11_InitChannelKey, %channel %members)
  
  if ($left(%result, 6) == Error:) {
    echo $color(Error) -at *** FiSH_11 FCEP-1 ERROR: %result
    return
  }
  
  var %num_parts = $numtok(%result, 124)
  var %i = 1
  var %has_commands = $false
  
  while (%i <= %num_parts) {
    var %part = $gettok(%result, %i, 124)
    if ($left(%part, 1) == /) {
      if ($left(%part, 8) == /notice ) {
        %part
        %has_commands = $true
      }
      else {
        echo $color(Error) -at *** FiSH_11 FCEP-1: SECURITY WARNING - unexpected command from DLL: %part
      }
    }
    else {
      echo $color(Mode text) -at *** FiSH_11 FCEP-1: %part
    }
    inc %i
  }
  
  if (!%has_commands) {
    echo $color(Error) -at *** FiSH_11 FCEP-1 ERROR: No distribution commands generated
  }
}

; Shorthand aliases for channel encryption
alias fcep { fish11_initchannel $1- }
alias chankey { fish11_initchannel $1- }
alias fcep11 { fish11_initchannel $1- }


; === CHANNEL SETTINGS DIALOG ===
alias fish11_channel_settings {
  if ($window($active).type != channel) {
    echo $color(Mode text) -at *** FiSH_11: This command can only be used in channel windows
    return
  }
  
  var %choice = $input(Add Channel Key Encryption for $active $+ :, pvq, FiSH_11 Add Channel Key)
  if (%choice == $null) return
  
  if (%choice == 1) {
    fish11_set_manual_key_dialog $active
  }
  elseif (%choice == 2) {
    fish11_init_fcep_dialog $active
  }
}

alias fcs { fish11_channel_settings }

alias fish11_set_manual_key_dialog {
  if ($window($active).type != channel) {
    echo $color(Error) -at *** FiSH_11: Manual key can only be set for channels. Current window: $active (type: $window($active).type)
    return
  }
  
  var %channel = $active
  var %key = $input(Enter 44-character base64 manual key for %channel $+ :, pvq, FiSH_11 Manual Channel Key)

  if (%key != $null) {
    fish11_setkey_manual %channel %key
  }
}

alias fish11_init_fcep_dialog {
  if ($window($active).type != channel) {
    echo $color(Error) -at *** FiSH_11: FCEP-1 key can only be set for channels. Current window: $active (type: $window($active).type)
    return
  }
  
  var %channel = $active
  var %members = $input(Enter members to invite (space-separated) for %channel $+ :, pvq, FiSH_11 FCEP-1 Channel Setup)

  if (%members != $null) {
    fish11_initchannel %channel %members
  }
}

; Display channel key information
alias fish11_show_channel_key_info {
  var %channel = $1

  var %hasManualKey = $dll(%Fish11DllFile, FiSH11_HasManualChannelKey, %channel)
  var %hasRatchetKey = $dll(%Fish11DllFile, FiSH11_HasRatchetChannelKey, %channel)
  var %encryptTopic = $fish11_GetChannelIniValue(%channel, encrypt_topic)

  window -dCo +l @FiSH-ChannelInfo -1 -1 400 150
  titlebar @FiSH-ChannelInfo Channel Encryption Info for %channel

  aline @FiSH-ChannelInfo Channel: %channel
  aline @FiSH-ChannelInfo $chr(160)
  aline @FiSH-ChannelInfo Manual Key: $iif(%hasManualKey == 1, Set, Not set)
  aline @FiSH-ChannelInfo FCEP/Ratchet Key: $iif(%hasRatchetKey == 1, Set, Not set)
  aline @FiSH-ChannelInfo Topic Encryption: $iif(%encryptTopic == 1, Enabled, Disabled)
  aline @FiSH-ChannelInfo $chr(160)

  if (%hasManualKey == 1 || %hasRatchetKey == 1) {
    aline @FiSH-ChannelInfo Status: Channel encryption is ACTIVE
    aline @FiSH-ChannelInfo All messages and topics will be encrypted
  }
  else {
    aline @FiSH-ChannelInfo Status: Channel encryption is INACTIVE
    aline @FiSH-ChannelInfo Messages and topics will be sent in plain text
  }

  button @FiSH-ChannelInfo "Close", 1, 150 120 100 25
  var %result = $input(,pv,@FiSH-ChannelInfo)
  window -c @FiSH-ChannelInfo
}

; Remove channel key
alias fish11_remove_channel_key {
  var %channel = $1
  var %had_keys = 0

  var %manual = $dll(%Fish11DllFile, FiSH11_RemoveManualChannelKey, %channel)
  if (%manual && $left(%manual, 6) != Error:) { %had_keys = 1 }

  var %ratchet = $dll(%Fish11DllFile, FiSH11_RemoveRatchetChannelKey, %channel)
  if (%ratchet && $left(%ratchet, 6) != Error:) { %had_keys = 1 }

  fish11_SetChannelIniValue %channel encrypt_topic 0

  if (%had_keys) {
    echo $color(Mode text) -at *** FiSH_11: encryption keys removed for %channel
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: no encryption keys found for %channel
  }
}


;*******************************
;* FiSH_11 Master Key           *
;*******************************
; Master key management for encrypting configuration

; === MASTER KEY MANAGEMENT ===

alias fish11_check_masterkey {
  var %is_unlocked = $dll(%Fish11DllFile, FiSH11_MasterKeyIsUnlocked, $null)

  if (%is_unlocked != 1) {
    echo $color(Mode text) -at *** FiSH_11: master key is locked. Configuration and logs are NOT encrypted.
    echo $color(Mode text) -at *** FiSH_11: use /fish11_unlock to unlock the master key.
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: master key is unlocked. Configuration and logs ARE encrypted.
  }
}

alias fish11_unlock {
  var %password = $1-
  
  if (%password == $null) {
    %password = $input(Enter master key password:, pvq, FiSH_11 Master Key, )
  }
  
  if (%password == $null) {
    echo $color(Error) -at *** FiSH_11: master key unlock cancelled.
    return
  }
  
  var %result = $dll(%Fish11DllFile, FiSH11_MasterKeyUnlock, %password)
  
  unset %password
  
  if (%result) {
    echo $color(Mode text) -at *** FiSH_11: %result
  }
  else {
    echo $color(Error) -at *** FiSH_11: failed to unlock master key
  }
}

alias fish11_lock {
  var %result = $dll(%Fish11DllFile, FiSH11_MasterKeyLock, $null)
  
  if (%result) {
    echo $color(Mode text) -at *** FiSH_11: %result
  }
  else {
    echo $color(Error) -at *** FiSH_11: Failed to lock master key
  }
}

alias fish11_masterkey_status {
  var %result = $dll(%Fish11DllFile, FiSH11_MasterKeyStatus, $null)
  
  if (%result) {
    echo $color(Mode text) -at *** FiSH_11: %result
  }
  else {
    echo $color(Error) -at *** FiSH_11: Failed to get master key status
  }
}

alias fish11_require_masterkey {
  var %is_unlocked = $dll(%Fish11DllFile, FiSH11_MasterKeyIsUnlocked, $null)
  
  while (%is_unlocked != 1) {
    var %password = $input(Master key is locked. Enter password to unlock :, pvq, FiSH_11 Master Key Required, )
    
    if (%password == $null) {
      echo $color(Error) -at *** FiSH_11: master key unlock is required. Cancelling operation.
      return
    }
    
    var %result = $dll(%Fish11DllFile, FiSH11_MasterKeyUnlock, %password)
    unset %password
    
    %is_unlocked = $dll(%Fish11DllFile, FiSH11_MasterKeyIsUnlocked, $null)
    
    if (%is_unlocked == yes) {
      echo $color(Mode text) -at *** FiSH_11: master key unlocked successfully
    }
    else {
      echo $color(Error) -at *** FiSH_11: incorrect password. Try again.
    }
  }
}


;*******************************
;* FiSH_10 Legacy Compatibility *
;*******************************
; DH1080 key exchange and Blowfish encryption for backward compatibility

; === LEGACY FiSH 10 KEY MANAGEMENT ===

alias fish10_setkey {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish10_setkey <target> <hex_key>
    return
  }
  var %msg = $dll(%Fish11DllFile, FiSH10_SetKey, $1 $2-)
  if (%msg && $left(%msg, 6) != Error:) {
    echo -a *** FiSH_10: %msg
  }
  else {
    echo -a *** FiSH_10: error setting key - %msg
  }
}

alias fish10_delkey {
  if ($1 == $null) var %target = $active
  else var %target = $1
  var %msg = $dll(%Fish11DllFile, FiSH10_DelKey, %target)
  if (%msg && $left(%msg, 6) != Error:) {
    echo -a *** FiSH_10: %msg
  }
  else {
    echo -a *** FiSH_10: error removing key - %msg
  }
}

alias fish10_showkey {
  if ($1 == $null) var %target = $active
  else var %target = $1
  var %key = $dll(%Fish11DllFile, FiSH10_GetKey, %target)
  if ($left(%key, 6) == Error:) {
    echo -a *** FiSH_10: error retrieving key for %target : %key
  }
  elseif (%key == $null) {
    echo -a *** FiSH_10: no key found for %target
  } else {
    echo -a *** FiSH_10: key for %target : %key
  }
}

alias fish10_usechankey {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish10_usechankey <target> <source_channel>
    return
  }
  
  var %target = $1
  var %source = $2
  
  var %key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %source)
  
  if (%key == $null || $len(%key) < 4) {
    echo $color(Error) -at *** FiSH_10: no valid key found for %source
    return
  }
  
  fish10_setkey %target %key
  echo $color(Mode text) -at *** FiSH_10: using same key as %source for %target
}


; === LEGACY DH1080 KEY EXCHANGE ===

alias fish10_keyx {
  if ($1 == $null) var %target = $active
  else var %target = $1
  
  hadd -m fish10.dh %target 1
  
  var %pub = $dll(%Fish11DllFile, FiSH10_DH1080_GenerateKeyPair, %target)
  
  if ($len(%pub) > 100 && $right(%pub, 1) == A) {
    .notice %target DH1080_INIT %pub
    echo $color(Mode text) -tm %target *** FiSH_10: sent DH1080_INIT to %target $+ , waiting for reply...
    
    if (%KEY_EXCHANGE_TIMEOUT_SECONDS == $null) { var %timeout = 10 }
    else { var %timeout = %KEY_EXCHANGE_TIMEOUT_SECONDS }
    .timer.fish10_dh1080_ $+ %target 1 %timeout fish10_timeout_keyexchange %target
  }
  else {
    hdel fish10.dh %target
    echo $color(Error) -at *** FiSH_10: DH1080 init failed - %pub
  }
}

alias fish10_timeout_keyexchange {
  if ($1 == $null) return
  var %contact = $1
  
  if ($hget(fish10.dh, %contact) == 1) {
    hdel fish10.dh %contact
    echo $color(Mode text) -at *** FiSH_10: key exchange with %contact timed out
  }
}


; === LEGACY DH1080 NOTICE HANDLERS ===

on ^*:NOTICE:DH1080_INIT*:?:{
  var %their_pub = $2

  if (!$regex(%their_pub, /^[A-Za-z0-9+\/=]+$/)) {
    echo $color(Error) -tm $nick *** FiSH_10: received invalid DH1080_INIT format from $nick
    halt
  }

  echo $color(Mode text) -tm $nick *** FiSH_10: received DH1080_INIT from $nick, responding...

  var %our_pub = $dll(%Fish11DllFile, FiSH10_DH1080_GenerateKeyPair, $nick)
  
  if ($left(%our_pub, 6) == Error:) {
    echo $color(Error) -tm $nick *** FiSH_10: key generation failed - %our_pub
    halt
  }

  var %secret = $dll(%Fish11DllFile, FiSH10_DH1080_ComputeSecret, $nick %their_pub)

  if ($left(%secret, 6) == Error:) {
    echo $color(Error) -tm $nick *** FiSH_10: key exchange failed - %secret
    halt
  }

  .notice $nick DH1080_FINISH %our_pub

  echo $color(Mode text) -tm $nick *** FiSH_10: key exchange complete with $nick
  echo $color(Error) -tm $nick *** FiSH_10 WARNING: key exchange complete, but the identity of $nick is NOT VERIFIED.
  halt
}

on ^*:NOTICE:DH1080_FINISH*:?:{
  if ($hget(fish10.dh, $nick) != 1) {
    echo -at *** FiSH_10: received DH1080_FINISH but no key exchange was in progress with $nick
    halt
  }

  var %their_pub = $2

  if (!$regex(%their_pub, /^[A-Za-z0-9+\/=]+$/)) {
    echo $color(Error) -tm $nick *** FiSH_10: received invalid DH1080_FINISH format from $nick
    hdel fish10.dh $nick
    halt
  }
  
  var %secret = $dll(%Fish11DllFile, FiSH10_DH1080_ComputeSecret, $nick %their_pub)
  
  hdel fish10.dh $nick
  
  if ($left(%secret, 6) == Error:) {
    echo $color(Error) -tm $nick *** FiSH_10: key exchange failed - %secret
    halt
  }

  echo $color(Mode text) -tm $nick *** FiSH_10: key exchange complete with $nick
  echo $color(Error) -tm $nick *** FiSH_10 WARNING: key exchange complete, but the identity of $nick is NOT VERIFIED.
  halt
}


; === LEGACY TOPIC MANAGEMENT ===

alias fish10_settopic {
  if ($1 == $null || $2- == $null) {
    echo 4 -a Syntax: /fish10_settopic <#channel> <topic>
    return
  }

  var %channel = $1
  var %topic = $2-

  if (!$regex(%channel, /^[#&]/)) {
    echo $color(Error) -at *** FiSH_10 ERROR: Invalid channel name %channel (must start with # or &)
    return
  }

  var %result = $dll(%Fish11DllFile, FiSH10_SetTopic, $+(%channel, $chr(32), %topic))

  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_10: %result
  }
  else {
    var %error_msg = $iif(%result, %result, "Unknown error - could not set topic for %channel")
    echo $color(Error) -at *** FiSH_10: error setting topic for %channel - %error_msg
  }
}

alias fish10_gettopic {
  if ($1 == $null) {
    echo 4 -a Syntax: /fish10_gettopic <#channel>
    return
  }

  var %channel = $1

  if (!$regex(%channel, /^[#&]/)) {
    echo $color(Error) -at *** FiSH_10 ERROR: Invalid channel name %channel (must start with # or &)
    return
  }

  var %result = $dll(%Fish11DllFile, FiSH10_GetTopic, %channel)

  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_10: Topic for %channel is: %result
  }
  else {
    var %error_msg = $iif(%result, %result, "Unknown error - could not get topic for %channel")
    echo $color(Error) -at *** FiSH_10: error getting topic for %channel - %error_msg
  }
}

alias fish10_removetopic {
  if ($1 == $null) {
    echo 4 -a Syntax: /fish10_removetopic <#channel>
    return
  }

  var %channel = $1

  if (!$regex(%channel, /^[#&]/)) {
    echo $color(Error) -at *** FiSH_10 ERROR: Invalid channel name %channel (must start with # or &)
    return
  }

  var %result = $dll(%Fish11DllFile, FiSH10_RemoveTopic, %channel)

  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_10: %result
  }
  else {
    var %error_msg = $iif(%result, %result, "Unknown error - could not remove topic for %channel")
    echo $color(Error) -at *** FiSH_10: error removing topic for %channel - %error_msg
  }
}


;*******************************
;* FiSH_11 Menus                *
;*******************************
; All mIRC menus for FiSH_11

; === MENUS ===

; Menu for channel windows
menu channel {
  -
  FiSH_11 channel encryption
  .Add a channel key encryption
  ..Manual key : fish11_set_manual_key_dialog $chan
  ..FCEP-1 key : fish11_init_fcep_dialog $chan
  .Encrypt topic
  ..Enable topic encryption :fish11_SetChannelIniValue $chan encrypt_topic 1
  ..Disable topic encryption :fish11_SetChannelIniValue $chan encrypt_topic 0
  .-
  .Show channel key info : fish11_show_channel_key_info $chan
  .Remove channel key : fish11_remove_channel_key $chan
  .-
  .Show key :fish11_showkey $chan
  .Show fingerprint :fish11_showfingerprint $chan
  .Copy fingerprint to clipboard :{
    fish11_showfingerprint $chan
    var %fp = %fish11.lastfingerprint. $+ [ $chan ]
    if (%fp != $null) {
      clipboard %fp
      echo $color(Mode text) -at *** FiSH_11: fingerprint for $chan copied to clipboard
    }
  }
  .-
  .Encrypt message :{
    var %msg = $?="Enter message to encrypt:"
    if (%msg) {
      var %encrypted = $fish11_encrypt($chan,%msg)
      echo $color(Mode text) -at *** FiSH: encrypted message: %encrypted
    }
  }
  .Decrypt message :{
    var %msg = $?="Enter message to decrypt:"
    if (%msg) {
      var %decrypted = $fish11_decrypt($chan,%msg)
      echo $color(Mode text) -at *** FiSH: decrypted message: %decrypted
    }
  }
  .Set topic (encrypted) :{
    var %topic = $?="Enter encrypted topic for " $+ $chan $+ ":"
    if (%topic != $null) etopic %topic
  }
  .Set topic (plaintext) :{
    var %topic = $?="Enter plaintext topic for " $+ $chan $+ ":"
    if (%topic != $null) settopic $chan %topic
  }
  .Get topic (plaintext) :{
    var %result = $gettopic($chan)
    if (%result != $null) {
      echo $color(Mode text) -at *** FiSH_11: Topic for $chan is: %result
    }
  }
  -
  FiSH_10 legacy (Blowfish)
  .Show legacy key :fish10_showkey $chan
  .Set legacy key... :{ var %key = $?="Enter hex Blowfish key (4-56 bytes):" | if (%key != $null) fish10_setkey $chan %key }
  .Remove legacy key :fish10_delkey $chan
}

; Menu for query windows
menu query {
  -
  FiSH_11
  .X25519 keyXchange: fish11_X25519_INIT $1
  .-
  .Show key :fish11_showkey $1
  .Show fingerprint :fish11_showfingerprint $1
  .Copy fingerprint to clipboard :{
    fish11_showfingerprint $1
    var %fp = %fish11.lastfingerprint. $+ [ $1 ]
    if (%fp != $null) {
      clipboard %fp
      echo $color(Mode text) -at *** FiSH_11: fingerprint for $1 copied to clipboard
    }
  }
  .-
  .Set manual key... :{ var %key = $?="Enter manual key for " $+ $1 $+ ":" | if (%key != $null) fish11_setkey_manual $1 %key }
  .Set new key :{ var %key = $?="Enter new key for " $+ $1 $+ ":" | if (%key != $null) fish11_setkey $1 %key }
  .Set new key (UTF-8) :{ var %key = $?="Enter new key for " $+ $1 $+ " (UTF-8):" | if (%key != $null) fish11_setkey_utf8 $1 %key }
  .Remove key :fish11_removekey $1
  .-
  .Encrypt message :{
    var %msg = $?="Enter message to encrypt:"
    if (%msg) {
      var %encrypted = $fish11_encrypt($1,%msg)
      echo $color(Mode text) -at *** FiSH: encrypted message: %encrypted
    }
  }
  .Decrypt message :{
    var %msg = $?="Enter message to decrypt:"
    if (%msg) {
      var %decrypted = $fish11_decrypt($1,%msg)
      echo $color(Mode text) -at *** FiSH: decrypted message: %decrypted
    }
  }
  -
  FiSH_10 legacy (DH1080)
  .DH1080 keyXchange: fish10_keyx $1
  .-
  .Show legacy key :fish10_showkey $1
  .Set legacy key... :{ var %key = $?="Enter hex Blowfish key (4-56 bytes) for " $+ $1 $+ ":" | if (%key != $null) fish10_setkey $1 %key }
  .Remove legacy key :fish10_delkey $1
}

; Menu for nicklist
menu nicklist {
  -
  FiSH_11
  .X25519 keyXchange: fish11_X25519_INIT $1
  .-
  .Show key :fish11_showkey $1
  .Show fingerprint :fish11_showfingerprint $1
  .-
  .Set manual key... :{ var %key = $?="Enter manual key for " $+ $1 $+ ":" | if (%key != $null) fish11_setkey_manual $1 %key }
  .Set new key :{ var %key = $?="Enter new key for " $+ $1 $+ ":" | if (%key != $null) fish11_setkey $1 %key }
  .Set new key (UTF-8) :{ var %key = $?="Enter new key for " $+ $1 $+ " (UTF-8):" | if (%key != $null) fish11_setkey_utf8 $1 %key }
  .Remove key :fish11_removekey $1
  .Use same key as $chan :fish11_usechankey $1 $chan
  .-
  .Encrypt message :{
    var %msg = $?="Enter message to encrypt:"
    if (%msg) {
      var %encrypted = $fish11_encrypt($1,%msg)
      echo $color(Mode text) -at *** FiSH: encrypted message: %encrypted
    }
  }
  .Decrypt message :{
    var %msg = $?="Enter message to decrypt:"
    if (%msg) {
      var %decrypted = $fish11_decrypt($1,%msg)
      echo $color(Mode text) -at *** FiSH: decrypted message: %decrypted
    }
  }
  -
  FiSH_10 legacy (DH1080)
  .DH1080 keyXchange: fish10_keyx $1
  .-
  .Show legacy key :fish10_showkey $1
  .Set legacy key... :{ var %key = $?="Enter hex Blowfish key (4-56 bytes) for " $+ $1 $+ ":" | if (%key != $null) fish10_setkey $1 %key }
  .Remove legacy key :fish10_delkey $1
  .Use same legacy key as $chan :fish10_usechankey $1 $chan
}

; Common menu available in all windows
menu status,channel,nicklist,query {
  FiSH_11
  .Core version :fish11_version
  .Injection version : fish11_injection_version
  .Help :fish11_help
  .-
  .Master key
  ..Unlock master key :fish11_unlock
  ..Lock master key :fish11_lock
  ..Show master key status :fish11_masterkey_status
  .-
  .Set topic (encrypted) :{
    ; Only allow in channel windows
    if ($window($active).type != channel) {
      echo $color(Mode text) -at *** FiSH_11: etopic can only be used in channel windows
      return
    }
    var %topic = $?="Enter encrypted topic for " $+ $active $+ ":"
    if (%topic != $null) etopic %topic
  }
  .Add channel key encryption :{
    ; Only allow in channel windows (more robust check)
    if ($window($active).type != channel) {
      echo $color(Mode text) -at *** FiSH_11: This command can only be used in channel windows
      return
    }
    ; Open a dialog to choose encryption method
    var %choice = $input(Add Channel Key Encryption for $active $+ :, pvq, FiSH_11 Add Channel Key)
    if (%choice == $null) return
    
    if (%choice == 1) {
      ; Set Manual Key
      fish11_set_manual_key_dialog $active
    }
    elseif (%choice == 2) {
      ; Set FCEP-1 Key
      fish11_init_fcep_dialog $active
    }
  }
  .List all keys :fish11_file_list_keys
  .Test encryption :fish11_test_crypt
  .-
  .Set plain-prefix :{ var %prefix = $?="Enter new plain-prefix:" | if (%prefix != $null) fish11_prefix %prefix }
  .Auto-KeyXchange $+ $chr(32) $+ %autokeyx
  ..Enable :set %autokeyx [On]
  ..Disable :set %autokeyx [Off]
  .Misc config
  ..Encrypt outgoing [Status]
  ...Enable :fish11_SetIniIntValue process_outgoing 1
  ...Disable :fish11_SetIniIntValue process_outgoing 0
  ..Decrypt incoming [Status]
  ...Enable :fish11_SetIniIntValue process_incoming 1
  ...Disable :fish11_SetIniIntValue process_incoming 0
  ..-
  ..Crypt-mark (Incoming)
  ...Prefix :fish11_SetIniIntValue mark_position 2
  ...Suffix :fish11_SetIniIntValue mark_position 1
  ...Disable :fish11_SetIniIntValue mark_position 0
  ..Crypt-mark (Outgoing) $+ $chr(32) $+ %mark_outgoing
  ...Enable :set %mark_outgoing [On]
  ...Disable :set %mark_outgoing [Off]
  ...-
  ...Style 1 :{
    set %mark_style 1
    set %mark_outgoing [On]
    echo $color(Mode text) -at *** FiSH: outgoing mark style set to 1 (suffix)
  }
  ...Style 2 :{
    set %mark_style 2
    set %mark_outgoing [On]
    echo $color(Mode text) -at *** FiSH: outgoing mark style set to 2 (prefix)
  }
  ...Style 3 :{
    set %mark_style 3
    set %mark_outgoing [On]
    echo $color(Mode text) -at *** FiSH: outgoing mark style set to 3 (colored brackets)
  }
  ..NickTracker $+ $chr(32) $+ %NickTrack
  ...Enable :{ set %NickTrack [On] | echo $color(Mode text) -at *** FiSH: nick tracking enabled }
  ...Disable :{ set %NickTrack [Off] | echo $color(Mode text) -at *** FiSH: nick tracking disabled }
  ..Encrypt NOTICE [Status]
  ...Enable :fish11_SetIniIntValue encrypt_notice 1
  ...Disable :fish11_SetIniIntValue encrypt_notice 0
  ..Encrypt ACTION [Status]
  ...Enable :fish11_SetIniIntValue encrypt_action 1
  ...Disable :fish11_SetIniIntValue encrypt_action 0
  ..No legacy FiSH 10 [Status]
  ...Enable :fish11_SetIniIntValue no_fish10_legacy 1
  ...Disable :fish11_SetIniIntValue no_fish10_legacy 0
  ..-
  ..Open config file :fish11_ViewIniFile
  ..-
  ..FiSH_11 - secure IRC encryption :shell -o https://github.com/ggielly/fish_11
  .Backup and restore
  ..Create backup now :fish11_ScheduleBackup
  ..Restore from backup :echo $color(Error) -at *** FiSH: restore functionality not yet implemented in DLL
  ..Schedule daily backup :echo $color(Error) -at *** FiSH: scheduled backup not yet implemented in DLL
  ..Stop scheduled backups :echo $color(Error) -at *** FiSH: scheduled backups not yet implemented in DLL
  .Debug
  ..Show debug info :fish11_debug
  ..View INI file :fish11_ViewIniFile
  ..Show encryption stats :fish11_stats

  -
  FiSH_10 legacy compatibility
  .DH1080 key exchange :fish10_keyx $active
  .Show legacy key :fish10_showkey $active
  .Set legacy key... :{ var %key = $?="Enter hex Blowfish key (4-56 bytes):" | if (%key != $null) fish10_setkey $active %key }
  .Remove legacy key :fish10_delkey $active
  .-
  .Set topic (encrypted) :{
    ; Only allow in channel windows
    if ($window($active).type != channel) {
      echo $color(Mode text) -at *** FiSH_10: etopic can only be used in channel windows
      return
    }
    var %topic = $?="Enter encrypted topic for " $+ $active $+ ":"
    if (%topic != $null) etopic %topic
  }
  .-
  .About FiSH_10 compatibility :{
    echo $color(Mode text) -at *** FiSH_10 Legacy Compatibility
    echo $color(Mode text) -at *** Supports DH1080 key exchange and Blowfish ECB encryption
    echo $color(Mode text) -at *** Compatible with mIRC FiSH 10.x and other FiSH implementations
    echo $color(Mode text) -at *** Use DH1080 for automatic key exchange or set keys manually
  }
}


; Window context menus
menu @fishdebug {
  &Copy to Clipboard: fishdebug.clip
  -
  &Refresh:{ clear @fishdebug | fish11_debug }
  C&lose:{ window -c @fishdebug }
}


menu @iniviewer {
  &Save Changes:{ 
    var %temp_file = $+($mircdir, fish_11.tmp)
    var %backup_file = %fish_config_file $+ .bak
    
    .remove %temp_file
    var %i = 1
    while (%i <= $line(@iniviewer, 0)) {
      write %temp_file $line(@iniviewer, %i)
      inc %i
    }

    if (!$isfile(%temp_file)) {
      echo $color(Error) -at *** FiSH: error writing temporary file. Save aborted.
      return
    }
    
    .rename %fish_config_file %backup_file
    .rename %temp_file %fish_config_file
    
    if ($isfile(%fish_config_file)) {
      echo $color(Mode text) -at *** FiSH: configuration saved
      .remove %backup_file
    } else {
      echo $color(Error) -at *** FiSH: error saving config, restoring from backup.
      .rename %backup_file %fish_config_file
    }
  }
  &Refresh:{ 
    clear @iniviewer
    var %i = 1
    while (%i <= $lines(%fish_config_file)) {
      aline @iniviewer $read(%fish_config_file, %i)
      inc %i
    }
  }
  -
  C&lose:{ window -c @iniviewer }
}


;*******************************
;* FiSH_11 Utilities            *
;*******************************
; Helper functions, debug, backup, and utility aliases

; === WINDOW ACTIVATION HANDLER ===
on *:ACTIVE:*: {
  if ($window($active).type isin query channel) {
    fish11_UpdateStatusIndicator
  }
}


; === STATUS INDICATOR ===
alias fish11_UpdateStatusIndicator {
  var %active = $active
  
  if (!$window(%active).type) || ($window(%active).type !isin query channel) return
  
  var %key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %active)
  
  if ($len(%key) > 1) {
    var %colored_fp = $fish11_GetColoredFingerprint(%active)
    
    if (%colored_fp != $null) {
      if (!$window(@FiSH_Status)) { window -hn @FiSH_Status }
      aline -p @FiSH_Status * $timestamp $+ %active is encrypted (Key: %colored_fp $+ )
      
      echo -at ** FiSH_11: %active [Fingerprint: %colored_fp $+ ]
    }
  }
  else {
    if (!$window(@FiSH_Status)) { window -hn @FiSH_Status }
    aline -p @FiSH_Status * $timestamp $+ %active is not encrypted
    echo -at *** FiSH_11: %active [No encryption]
    
    unset %fish11.lastfingerprint. $+ [ %active ]
  }
}


; === INI CONFIG HELPERS ===
alias fish11_GetIniValue {
  return $dll(%Fish11DllFile, INI_GetString, $1 $2-)
}

alias fish11_SetIniValue {
  var %result = $dll(%Fish11DllFile, INI_SetString, $1 $2-)
  if ($left(%result, 6) == Error:) {
    echo $color(Error) -at *** FiSH_11: failed to set $1 = $2- $+ : %result
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: $1 set to $2-
  }
}

alias fish11_GetIniBoolValue {
  return $dll(%Fish11DllFile, INI_GetBool, $1 $2-)
}

alias fish11_SetIniIntValue {
  var %result = $dll(%Fish11DllFile, INI_SetInt, $1 $2-)
  if ($left(%result, 6) == Error:) {
    echo $color(Error) -at *** FiSH_11: failed to set $1 = $2- $+ : %result
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: $1 set to $2-
  }
}

alias fish11_GetChannelIniValue {
  return $dll(%Fish11DllFile, INI_GetString, channel_ $+ $1 $+ _ $+ $2 $3-)
}

alias fish11_SetChannelIniValue {
  var %result = $dll(%Fish11DllFile, INI_SetString, channel_ $+ $1 $+ _ $+ $2 $3-)
  if ($left(%result, 6) == Error:) {
    echo $color(Error) -at *** FiSH_11: failed to set $2 for $1 $+ : %result
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: $2 set to $3- for $1
  }
}


; === PLAIN PREFIX ===
alias fish11_prefix {
  if ($1 != $null) {
    var %value = " $+ $1- $+ "
    fish11_SetIniValue plain_prefix %value
    echo $color(Mode text) -at *** FiSH: plain-prefix set to $1-
  }
}


; === BACKUP FUNCTIONALITY ===
alias fish11_ScheduleBackup {
  echo $color(Error) -at *** FiSH: backup functionality not yet implemented in DLL
  echo $color(Mode text) -at *** FiSH: use /fish11_file_list_keys to export keys manually
}


; === HELP AND VERSION ===
alias fish11_help {
  var %helpText
  if ($dll(%Fish11DllFile, FiSH11_Help, &%helpText)) {
    echo $color(Mode text) -at *** FiSH help: %helpText
  }
  else {
    echo $color(Mode text) -at *** FiSH: help information unavailable
  }

  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** FiSH_11 Master Key commands:
  echo $color(Mode text) -at *** /fish11_unlock [password] - Unlock master key (encrypts config/logs)
  echo $color(Mode text) -at *** /fish11_lock - Lock master key (clears from memory)
  echo $color(Mode text) -at *** /fish11_masterkey_status - Show master key status

  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** FiSH_11 Key TTL (Expiration):
  echo $color(Mode text) -at *** /fish11_keyttl <nickname> - Show remaining lifetime of exchange key
  echo $color(Mode text) -at ***   Shorthand: /fkeyttl

  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** FiSH_11 FCEP-1 (Channel Encryption v1) commands:
  echo $color(Mode text) -at *** /fish11_initchannel <#channel> <nick1> [nick2] ... - Initialize encrypted channel
  echo $color(Mode text) -at ***   Shorthand: /fcep or /chankey

  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** FiSH_11 Incoming Decryption:
  echo $color(Mode text) -at *** /fish11_decrypt_msg <sender> <encrypted_message> - Manually decrypt a message
  echo $color(Mode text) -at ***   Shorthand: /fdec
}

alias fish11_version {
  var %raw_version_info = $dll(%Fish11DllFile, FiSH11_GetVersion, $null)
  
  if (!%raw_version_info) {
    echo -ts *** FiSH_11: ERROR - could not get version info from DLL.
    return
  }

  var %version_string = $gettok(%raw_version_info, 1, 124)
  var %build_type = $gettok(%raw_version_info, 2, 124)

  echo -ts *** %version_string ***

  if (%build_type == DEBUG) {
    echo 4 -ts $chr(3)4 *** SECURITY WARNING : you're running a DEBUG version which logs EVERYTHING (keys, private messages, etc.) ON YOUR DISK.
    echo 4 -ts $chr(3)4 *** DO NOT USE THIS VERSION IN REAL LIFE.
  }
  else {
    echo 4 -ts $chr(3)3 *** You are running a RELEASE version. Sensitive data is NOT logged.
    echo 4 -ts $chr(3)3 *** Logging can be configured in your fish_11.ini file.
  }
}

alias fish11_injection_version {
  var %inject_version = $dll(%Fish11InjectDllFile, FiSH11_InjectVersion, $null)
  echo -ts *** %inject_version ***
}


; === DEBUG FUNCTIONALITY ===
alias fish11_debug {
  var %w = @fishdebug
  var %a = aline -ph %w

  var %f1 = fishdebug
  var %f2 = $rand(0,9999)
  var %test_key = SGVsbG9Xb3JsZDEyMzQ1Njc4OTAxMjM0NTY=
  noop $iif($isfile(%Fish11DllFile),$dll(%Fish11DllFile,FiSH11_SetKey,$+($network," ",%f1,%f2," ",%test_key)))

  if (!$window(%w)) {
    window -a %w -1 -1 550 300 Courier New 12
  } 
  else {
    clear %w
    window -a %w
  }

  %a ---------FISH DEBUG---------
  %a $cr
  %a ::VERSION
  %a mIRC version: $version
  %a SSL version: $sslversion
  %a SSL ready: $sslready
  %a SSL mode: $iif($readini($mircini,ssl,load),$v1,default)
  %a $cr
  %a ::mIRC
  %a mIRC dir: $mircdir
  %a mIRC.exe: $mircexe
  %a mIRC.ini: $mircini
  %a Portable: $iif($readini($mircini,about,portable),$v1,NotFound)
  %a $cr
  %a ::Files
  %a fish_11.dll: %Fish11DllFile - $isfile(%Fish11DllFile)
  %a version string: $iif($isfile(%Fish11DllFile),$dll(%Fish11DllFile,FiSH11_GetVersion),NotFound)
  %a fish_11.toml: %fish_config_file - $isfile(%fish_config_file)
  %a $cr
  %a ::INI Configuration
  %a Process incoming: $fish11_GetIniValue(process_incoming)
  %a Process outgoing: $fish11_GetIniValue(process_outgoing)
  %a Plain prefix: $fish11_GetIniValue(plain_prefix)
  %a Mark position: $fish11_GetIniValue(mark_position)
  %a Encrypt notice: $fish11_GetIniValue(encrypt_notice)
  %a Encrypt action: $fish11_GetIniValue(encrypt_action)
  %a No fish10 legacy: $fish11_GetIniValue(no_fish10_legacy)
  %a $cr
  %a ::Variables
  %a fish_config_file: %fish_config_file
  %a FiSH_dll: %Fish11DllFile
  %a $cr
  %a ::Testing
  %a >> Writing key to config
  %a << Reading back key, you should see a 'HelloWorld' on the next line.
  %a !! FileGetKey: $iif($dll(%Fish11DllFile,FiSH11_FileGetKey, $+($network," ",%f1," ",%f2)),$v1,NotFound)
  %a << Deleting key from config
  noop $dll(%Fish11DllFile,FiSH11_FileDelKey,$+($network," ",%f1," ",%f2))
}


; Debug: capture raw return from FiSH11_ExchangeKey and display hex/quoted output
alias fish11_debug_exchange {
  if ($1 == $null) { echo 4 -a Usage: /fish11_debug_exchange <nick> | return }
  var %nick = $1

  var %raw_exch = $dll(%Fish11DllFile, FiSH11_ExchangeKey, %nick)

  echo 4 -a *** FiSH_11 DEBUG: raw quoted return: $qt(%raw_exch)

  var %visible = $replace(%raw_exch, $chr(13) $+ $chr(10), <CRLF>, $chr(13), <CR>, $chr(10), <LF>, $chr(9), <TAB>)
  echo 4 -a *** FiSH_11 DEBUG: visible: %visible

  var %limited = $left(%raw_exch, 200)
  var %codes = $null
  var %i = 1
  while (%i <= $len(%limited)) {
    var %c = $mid(%limited, %i, 1)
    var %codes = %codes $+ $asc(%c) $+ " "
    inc %i
  }
  echo 4 -a *** FiSH_11 DEBUG: decimal codes (first 200 chars): %codes
}


; === INI FILE VIEWER ===
alias fish11_ViewIniFile {
  var %w = @iniviewer
  
  if (!$isfile(%fish_config_file)) {
    echo $color(Mode text) -at *** FiSH: config file not found: %fish_config_file
    return
  }
  
  if (!$window(%w)) {
    window -a %w -1 -1 550 500 Courier New 10
  } 
  else {
    clear %w
    window -a %w
  }
  
  titlebar %w FiSH 11 Configuration - %fish_config_file
  
  var %i = 1
  while (%i <= $lines(%fish_config_file)) {
    aline %w $read(%fish_config_file, %i)
    inc %i
  }
}


; === HELPER FUNCTIONS ===
alias -l fishdebug.clip {
  clipboard
  var %i = 1
  while ($line(@fishdebug,%i)) { 
    clipboard -an $v1
    inc %i 
  }
}

alias statusmsg {
  echo 4 -s [FiSH_11] $1-
}


; === TOPIC MANAGEMENT ===

alias etopic {
  if ($window($active).type != channel) {
    echo $color(Mode text) -at *** FiSH_11: etopic can only be used in channel windows
    return
  }

  var %channelKey = $dll(%Fish11DllFile, FiSH11_FileGetKey, $active)
  if ($left(%channelKey, 6) == Error: || $left(%channelKey, 3) == no ) { set %channelKey $null }

  var %hasLegacyKey = $dll(%Fish11DllFile, FiSH10_HasKey, $active)

  if (%channelKey == $null && %hasLegacyKey != 1) {
    echo $color(Mode text) -at *** FiSH_11: no encryption key found for $active, topic will be sent in plain text
  } else {
    echo $color(Mode text) -at *** FiSH_11: topic will be encrypted for $active $iif(%hasLegacyKey == 1, (FiSH 10 legacy))
  }

  /topic $1-

  unset %channelKey
}

alias settopic {
  if ($1 == $null || $2- == $null) {
    echo 4 -a Syntax: /settopic <#channel> <topic>
    return
  }

  var %channel = $1
  var %topic = $2-

  if (!$regex(%channel, /^[#&]/)) {
    echo $color(Error) -at *** FiSH_11 ERROR: Invalid channel name %channel (must start with # or &)
    return
  }

  var %result = $dll(%Fish11DllFile, FiSH11_SetTopic, $+(%channel, $chr(32), %topic))

  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_11: %result
  }
  else {
    var %error_msg = $iif(%result, %result, "Unknown error - could not set topic for %channel")
    echo $color(Error) -at *** FiSH_11: error setting topic for %channel - %error_msg
  }
}

alias gettopic {
  if ($1 == $null) {
    echo 4 -a Syntax: /gettopic <#channel>
    return
  }

  var %channel = $1

  if (!$regex(%channel, /^[#&]/)) {
    echo $color(Error) -at *** FiSH_11 ERROR: Invalid channel name %channel (must start with # or &)
    return
  }

  var %result = $dll(%Fish11DllFile, FiSH11_GetTopic, %channel)

  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_11: Topic for %channel is: %result
  }
  else {
    var %error_msg = $iif(%result, %result, "Unknown error - could not get topic for %channel")
    echo $color(Error) -at *** FiSH_11: error getting topic for %channel - %error_msg
  }
}

alias removetopic {
  if ($1 == $null) {
    echo 4 -a Syntax: /removetopic <#channel>
    return
  }

  var %channel = $1

  if (!$regex(%channel, /^[#&]/)) {
    echo $color(Error) -at *** FiSH_11 ERROR: Invalid channel name %channel (must start with # or &)
    return
  }

  var %result = $dll(%Fish11DllFile, FiSH11_RemoveTopic, %channel)

  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_11: %result
  }
  else {
    var %error_msg = $iif(%result, %result, "Unknown error - could not remove topic for %channel")
    echo $color(Error) -at *** FiSH_11: error removing topic for %channel - %error_msg
  }
}


; === ENCRYPTION STATISTICS ===
alias fish11_stats {
  var %stats = $dll(%Fish11DllFile, FiSH11_GetEncryptionStats, $null)
  if (%stats) {
    echo $color(Mode text) -at *** FiSH_11 Encryption Statistics:
    echo $color(Mode text) -at %stats
  }
  else {
    echo $color(Error) -at *** FiSH_11: failed to retrieve encryption statistics
  }
}

; Short alias for statistics
alias fish_stats { fish11_stats }
