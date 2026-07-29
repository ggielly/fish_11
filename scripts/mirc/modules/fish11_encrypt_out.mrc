;*******************************
;* FiSH_11 Outgoing Encryption  *
;*******************************
; Message encryption for outgoing messages
; Written by GuY, 2025. Licensed under GPL-v3.

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
  ; Check for: FCEP-2 group, FCEP-1 channel key, manual channel key, legacy key, or private key
  
  var %encrypted = $null
  
  ; Check if target is a channel with FCEP-2 group
  if ($left(%target, 1) == # || $left(%target, 1) == &) {
    ; Check for FCEP-2 group first
    var %fcep2_gid = $dll(%Fish11DllFile, FiSH11_FCEP2_GetGroupState, %target)
    if ($left(%fcep2_gid, 5) == STATE) {
      ; FCEP-2 group exists - use FCEP-2 encryption
      %encrypted = $dll(%Fish11DllFile, FiSH11_FCEP2_EncryptMsg, %target %message)
    }
    else {
      ; No FCEP-2 group - try FiSH 11 encryption (handles both manual and FCEP-1 keys)
      %encrypted = $dll(%Fish11DllFile, FiSH11_EncryptMsg, %target %message)
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
    if (%mark_outgoing == [On]) {
      if (%mark_style == 1) {
        ; Suffix style
        echo $color(own text) -t $active < $+ $me $+ > %message $+ $chr(183)
      }
      else if (%mark_style == 2) {
        ; Prefix style
        echo $color(own text) -t $active $chr(183) $+ < $+ $me $+ > %message
      }
      else if (%mark_style == 3) {
        ; Colored brackets style
        echo $color(own text) -t $active $chr(91) $+ $chr(43) $+ $chr(93) < $+ $me $+ > %message
      }
    }
    else {
      ; Display message without encryption mark
      echo $color(own text) -t $active < $+ $me $+ > %message
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
