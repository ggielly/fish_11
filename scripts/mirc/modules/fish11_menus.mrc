;*******************************
;* FiSH_11 Menus                *
;*******************************
; All mIRC menus for FiSH_11
; Written by GuY, 2025. Licensed under GPL-v3.

; === MENUS ===

; Menu for channel windows
menu channel {
  -
  FiSH_11 channel encryption
  .Add a channel key encryption
  ..Manual key : fish11_set_manual_key_dialog $chan
  ..FCEP-1 key : fish11_init_fcep_dialog $chan
  ..FCEP-2 group : fish11_fcep2_create_group $chan
  .FCEP-2 group management
  ..Show group state : fish11_fcep2_state $chan
  ..Sync group : fish11_fcep2_sync $chan
  ..Export group state : fish11_fcep2_export $chan
  ..Import group state :{ var %data = $?="Enter base64 export data:" | if (%data) fish11_fcep2_import $chan %data }
  ..-
  ..Add member :{ var %kp = $?="Enter KeyPackage (base64):" | if (%kp) { fish11_fcep2_propose $chan ADD %kp | fish11_fcep2_commit $chan } }
  ..Remove member :{ var %dev = $?="Enter device ID (hex):" | if (%dev) fish11_fcep2_remove $chan %dev }
  ..-
  ..Set encryption policy
  ...Always encrypt : fish11_fcep2_policy $chan ALWAYS
  ...Require all members : fish11_fcep2_policy $chan REQUIRE_ALL
  ...Best effort : fish11_fcep2_policy $chan BEST_EFFORT
  ...Disabled : fish11_fcep2_policy $chan DISABLED
  ..-
  ..Resolve conflict : fish11_fcep2_resolve $chan
  ..Show diagnostics : fish11_fcep2_diag 10
  .Encrypt topic
  ..Enable topic encryption :{ fish11_SetChannelIniValue $chan encrypt_topic 1 | echo $color(Mode text) -at *** FiSH: topic encryption enabled for $chan }
  ..Disable topic encryption :{ fish11_SetChannelIniValue $chan encrypt_topic 0 | echo $color(Mode text) -at *** FiSH: topic encryption disabled for $chan }
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
  .FCEP-2 (MLS)
  ..FCEP-2 Help :fish11_fcep2_help
  ..Initialize device :fish11_fcep2_init_device
  ..Generate KeyPackage :fish11_fcep2_gen_keypackage
  ..Fill KeyPackage pool :fish11_fcep2_fill_pool
  ..-
  ..Create FCEP-2 group :{ if ($window($active).type == channel) { fish11_fcep2_create_group $active } else { echo $color(Mode text) -at *** FiSH_11: select a channel first } }
  ..Show group state :{ if ($window($active).type == channel) { fish11_fcep2_state $active } else { echo $color(Mode text) -at *** FiSH_11: select a channel first } }
  ..Sync group :{ if ($window($active).type == channel) { fish11_fcep2_sync $active } else { echo $color(Mode text) -at *** FiSH_11: select a channel first } }
  ..-
  ..Export group state :{ if ($window($active).type == channel) { fish11_fcep2_export $active } else { echo $color(Mode text) -at *** FiSH_11: select a channel first } }
  ..Import group state :{ if ($window($active).type == channel) { var %data = $?="Enter base64 export data:" | if (%data) fish11_fcep2_import $active %data } else { echo $color(Mode text) -at *** FiSH_11: select a channel first } }
  ..-
  ..Show diagnostics :fish11_fcep2_diag 10
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
  ...Enable :{ fish11_SetIniIntValue process_outgoing 1 | echo $color(Mode text) -at *** FiSH: outgoing message encryption enabled }
  ...Disable :{ fish11_SetIniIntValue process_outgoing 0 | echo $color(Mode text) -at *** FiSH: outgoing message encryption disabled }
  ..Decrypt incoming [Status]
  ...Enable :{ fish11_SetIniIntValue process_incoming 1 | echo $color(Mode text) -at *** FiSH: incoming message decryption enabled }
  ...Disable :{ fish11_SetIniIntValue process_incoming 0 | echo $color(Mode text) -at *** FiSH: incoming message decryption disabled }
  ..-
  ..Crypt-mark (Incoming)
  ...Prefix :{ fish11_SetIniIntValue mark_position 2 | echo $color(Mode text) -at *** FiSH: encryption mark set to prefix }
  ...Suffix :{ fish11_SetIniIntValue mark_position 1 | echo $color(Mode text) -at *** FiSH: encryption mark set to suffix }
  ...Disable :{ fish11_SetIniIntValue mark_position 0 | echo $color(Mode text) -at *** FiSH: encryption mark disabled }
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
  ...Enable :{ fish11_SetIniIntValue encrypt_notice 1 | echo $color(Mode text) -at *** FiSH: NOTICE encryption enabled }
  ...Disable :{ fish11_SetIniIntValue encrypt_notice 0 | echo $color(Mode text) -at *** FiSH: NOTICE encryption disabled }
  ..Encrypt ACTION [Status]
  ...Enable :{ fish11_SetIniIntValue encrypt_action 1 | echo $color(Mode text) -at *** FiSH: ACTION encryption enabled }
  ...Disable :{ fish11_SetIniIntValue encrypt_action 0 | echo $color(Mode text) -at *** FiSH: ACTION encryption disabled }
  ..No legacy FiSH 10 [Status]
  ...Enable :{ fish11_SetIniIntValue no_fish10_legacy 1 | echo $color(Mode text) -at *** FiSH: legacy FiSH 10 compatibility disabled }
  ...Disable :{ fish11_SetIniIntValue no_fish10_legacy 0 | echo $color(Mode text) -at *** FiSH: legacy FiSH 10 compatibility enabled }
  ..-
  ..Open config file :fish11_ViewIniFile
  ..-
  ..FiSH_11 - secure IRC encryption :shell -o https://github.com/ggielly/fish_11
  .Backup and restore
  ..Create backup now :fish11_ScheduleBackup
  ..Restore from backup :echo $color(Error) -at *** FiSH: restore functionality not yet implemented in DLL
  ..Schedule daily backup :echo $color(Error) -at *** FiSH: scheduled backup not yet implemented in DLL
  ..Stop scheduled backups :echo $color(Error) -at *** FiSH: scheduled backup not yet implemented in DLL
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
    
    ; Write the content of the window to a temporary file
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
    
    ; Safely replace the old config file with the new one
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
