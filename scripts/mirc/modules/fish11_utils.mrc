;*******************************
;* FiSH_11 Utilities            *
;*******************************
; Helper functions, debug, backup, and utility aliases
; Written by GuY, 2025. Licensed under GPL-v3.

; === WINDOW ACTIVATION HANDLER ===
on *:ACTIVE:*: {
  if ($window($active).type isin query channel) {
    fish11_UpdateStatusIndicator
  }
}


; === STATUS INDICATOR ===
; Status indicator update
alias fish11_UpdateStatusIndicator {
  var %active = $active
  
  ; Don't update for non-chat windows
  if (!$window(%active).type) || ($window(%active).type !isin query channel) return
  
  ; Check if we have a key for this target
  var %key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %active)
  
  ; Update status text accordingly
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
    
    ; Clear any stored fingerprint
    unset %fish11.lastfingerprint. $+ [ %active ]
  }
}


; === INI CONFIG HELPERS ===
; For string values (plain_prefix, mark_encrypted, encryption_prefix)
alias fish11_GetIniValue {
  return $dll(%Fish11DllFile, INI_GetString, $1 $2-)
}

alias fish11_SetIniValue {
  noop $dll(%Fish11DllFile, INI_SetString, $1 $2-)
}

; For boolean/integer values (process_outgoing, process_incoming, encrypt_notice, etc.)
alias fish11_GetIniBoolValue {
  return $dll(%Fish11DllFile, INI_GetBool, $1 $2-)
}

alias fish11_SetIniIntValue {
  noop $dll(%Fish11DllFile, INI_SetInt, $1 $2-)
}

alias fish11_GetChannelIniValue {
  return $dll(%Fish11DllFile, INI_GetString, channel_ $+ $1 $+ _ $+ $2 $3-)
}

alias fish11_SetChannelIniValue {
  noop $dll(%Fish11DllFile, INI_SetString, channel_ $+ $1 $+ _ $+ $2 $3-)
}


; === PLAIN PREFIX ===
; Set plain message prefix
alias fish11_prefix {
  if ($1 != $null) {
    ; Add quotes for INI string value
    var %value = " $+ $1- $+ "
    fish11_SetIniValue plain_prefix %value
    echo $color(Mode text) -at *** FiSH: plain-prefix set to $1-
  }
}


; === BACKUP FUNCTIONALITY ===
; Note: FiSH11_BackupKeys/RestoreKeys not yet implemented in DLL
; This is a placeholder for future implementation
alias fish11_ScheduleBackup {
  echo $color(Error) -at *** FiSH: backup functionality not yet implemented in DLL
  echo $color(Mode text) -at *** FiSH: use /fish11_file_list_keys to export keys manually
}


; === HELP AND VERSION ===
; Show help and version information
alias fish11_help {
  var %helpText
  if ($dll(%Fish11DllFile, FiSH11_Help, &%helpText)) {
    echo $color(Mode text) -at *** FiSH help: %helpText
  }
  else {
    echo $color(Mode text) -at *** FiSH: help information unavailable
  }

  ; Add Keychain help
  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** FiSH_11 Keychain commands:
  echo $color(Mode text) -at *** /fish11_unlock [password] - Unlock keychain (encrypts config/logs)
  echo $color(Mode text) -at *** /fish11_lock - Lock keychain (clears from memory)
  echo $color(Mode text) -at *** /fish11_masterkey_status - Show keychain status
  echo $color(Mode text) -at ***   When unlocked: configuration and logs are encrypted with Argon2id + ChaCha20-Poly1305
  echo $color(Mode text) -at ***   When locked: configuration and logs are stored in plaintext

  ; Add Key TTL help
  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** FiSH_11 Key TTL (Expiration):
  echo $color(Mode text) -at *** /fish11_keyttl <nickname> - Show remaining lifetime of exchange key
  echo $color(Mode text) -at ***   Shorthand: /fkeyttl
  echo $color(Mode text) -at ***   Exchange keys expire after 24 hours; manually set keys never expire

  ; Add FCEP-1 help
  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** FiSH_11 FCEP-1 (Channel Encryption v1) commands:
  echo $color(Mode text) -at *** /fish11_initchannel <#channel> <nick1> [nick2] ... - Initialize encrypted channel
  echo $color(Mode text) -at ***   Shorthand: /fcep or /chankey
  echo $color(Mode text) -at ***   Example: /fish11_initchannel #secret alice bob charlie
  echo $color(Mode text) -at ***   Note: all members must have pre-shared keys with you first
  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** FCEP-1 automatically decrypts incoming channel messages
  echo $color(Mode text) -at *** Channel names are case-insensitive (#Secret = #secret)

  ; Add incoming decryption help
  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** FiSH_11 Incoming Decryption:
  echo $color(Mode text) -at *** Incoming messages are decrypted automatically by fish_11_inject.dll
  echo $color(Mode text) -at *** If inject DLL is not loaded, fallback handlers will attempt decryption
  echo $color(Mode text) -at *** /fish11_decrypt_msg <sender> <encrypted_message> - Manually decrypt a message
  echo $color(Mode text) -at ***   Shorthand: /fdec
  echo $color(Mode text) -at *** Configure incoming decryption in fish_11.ini: process_incoming = 1

  ; Add plaintext topic commands
  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** FiSH_11 Plaintext Topic commands:
  echo $color(Mode text) -at *** /settopic <#channel> <topic> - Set a plaintext topic for a channel
  echo $color(Mode text) -at *** /gettopic <#channel> - Get the plaintext topic for a channel
  echo $color(Mode text) -at *** /removetopic <#channel> - Remove the plaintext topic for a channel
  echo $color(Mode text) -at *** /etopic <topic> - Encrypt and set a topic for the current channel
  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** Plaintext topics are stored in the configuration file and can be retrieved later

  ; Add legacy fish10 topic commands
  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** FiSH_10 Legacy Topic commands:
  echo $color(Mode text) -at *** /fish10_settopic <#channel> <topic> - Set a plaintext topic in legacy format
  echo $color(Mode text) -at *** /fish10_gettopic <#channel> - Get a plaintext topic from legacy format
  echo $color(Mode text) -at *** /fish10_removetopic <#channel> - Remove a plaintext topic from legacy format
  echo $color(Mode text) -at $chr(160)
  echo $color(Mode text) -at *** Legacy topics are stored in the configuration file with fish10 compatibility
}

alias fish11_version {
  var %raw_version_info = $dll(%Fish11DllFile, FiSH11_GetVersion, $null)
  
  if (!%raw_version_info) {
    echo -ts *** FiSH_11: ERROR - could not get version info from DLL.
    return
  }

  ; Parse the raw string: VERSION|BUILD_TYPE
  ; 124 is ASCII for |
  var %version_string = $gettok(%raw_version_info, 1, 124)
  var %build_type = $gettok(%raw_version_info, 2, 124)

  ; Display the base version info
  echo -ts *** %version_string ***

  ; Display context-specific warning or info message
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
  noop $iif($isfile(%Fish11DllFile),$dll(%Fish11DllFile,FiSH11_SetKey,$+($network,%f1,%f2,HelloWorld)))

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

  ; Use $dll(...) to capture returned identifier string directly
  var %raw_exch = $dll(%Fish11DllFile, FiSH11_ExchangeKey, %nick)

  ; Show quoted version so we can see whitespace/newlines
  echo 4 -a *** FiSH_11 DEBUG: raw quoted return: $qt(%raw_exch)

  ; Replace common control chars with visible markers for quick glance
  var %visible = $replace(%raw_exch, $chr(13) $+ $chr(10), <CRLF>, $chr(13), <CR>, $chr(10), <LF>, $chr(9), <TAB>)
  echo 4 -a *** FiSH_11 DEBUG: visible: %visible

  ; Print decimal codes for each character (limit 200 chars to avoid flooding)
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


; === INI HELPER FUNCTIONS (for compatibility with older scripts) ===
alias INI_GetString {
  ; Arguments: $1 = key, $2 = default value
  var %config_path = $+($scriptdir,fish_11.ini)
  var %value = $readini(%config_path, FiSH11, $1)
  if (%value == $null) { return $2 }
  return %value
}

alias INI_GetInt {
  ; Arguments: $1 = key, $2 = default value
  var %config_path = $+($scriptdir,fish_11.ini)
  var %value = $readini(%config_path, FiSH11, $1)
  if (%value == $null) { return $2 }
  return %value
}


; === TOPIC MANAGEMENT ===

; Encrypted topic alias - transparently encrypts the topic via the injection hook
alias etopic {
  ; Check if we're in a channel window
  if ($window($active).type != channel) {
    echo $color(Mode text) -at *** FiSH_11: etopic can only be used in channel windows
    return
  }

  ; Check if there's a key for this channel (both traditional and FCEP-1)
  var %channelKey = $dll(%Fish11DllFile, FiSH11_FileGetKey, $active)
  ; Robust error check: if it doesn't look like a valid key or starts with error indicators
  if ($left(%channelKey, 6) == Error: || $left(%channelKey, 3) == no ) { set %channelKey $null }

  var %hasLegacyKey = $dll(%Fish11DllFile, FiSH10_HasKey, $active)

  if (%channelKey == $null && %hasLegacyKey != 1) {
    ; No key exists, but the engine may still try to encrypt if a channel key exists
    ; This will be handled by the engine registration code
    echo $color(Mode text) -at *** FiSH_11: no encryption key found for $active, topic will be sent in plain text
  } else {
    echo $color(Mode text) -at *** FiSH_11: topic will be encrypted for $active $iif(%hasLegacyKey == 1, (FiSH 10 legacy))
  }

  ; Execute the topic command - encryption will be handled by the engine
  /topic $1-

  ; Clean up variables
  unset %channelKey
}

; Set a plaintext topic for a channel
alias settopic {
  if ($1 == $null || $2- == $null) {
    echo 4 -a Syntax: /settopic <#channel> <topic>
    return
  }

  var %channel = $1
  var %topic = $2-

  ; Validate channel name
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

; Get a plaintext topic for a channel
alias gettopic {
  if ($1 == $null) {
    echo 4 -a Syntax: /gettopic <#channel>
    return
  }

  var %channel = $1

  ; Validate channel name
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

; Remove a plaintext topic for a channel
alias removetopic {
  if ($1 == $null) {
    echo 4 -a Syntax: /removetopic <#channel>
    return
  }

  var %channel = $1

  ; Validate channel name
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
; Show encryption statistics
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
