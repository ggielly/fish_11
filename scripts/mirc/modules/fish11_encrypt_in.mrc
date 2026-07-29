;*******************************
;* FiSH_11 Incoming Decryption  *
;*******************************
; Fallback handlers for incoming encrypted messages.
; NOTE: The fish_11_inject.dll handles most incoming decryption
; transparently by hooking SSL_Read. These handlers provide a
; fallback for cases where the injection DLL is not loaded.
; Written by GuY, 2025. Licensed under GPL-v3.

; === HELPER: Decrypt incoming message ===
; Attempts to decrypt an encrypted message from a sender
; Returns decrypted message or original message if decryption fails
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
; Attempts to decrypt an encrypted channel message
; Returns decrypted message or original message if decryption fails
alias -l fish11_try_decrypt_channel {
  var %channel = $1
  var %message = $2-
  
  ; Check if process_incoming is enabled
  var %process_incoming = $dll(%Fish11DllFile, INI_GetBool, process_incoming 1)
  if (%process_incoming == 0) return %message
  
  ; Check for FCEP-2 prefix first
  if ($left(%message, 7) == +FCEP2 ) {
    ; FCEP-2 message - process via FCEP-2 handler
    var %result = $fish11_fcep2_process($nick, %channel, %message)
    if (%result != $null) {
      return %result
    }
    return %message
  }
  
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
on *:TEXT:*:?:{
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_incoming($nick, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    ; Check if we should display the decrypted message
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted == 1) {
      echo $color(Message text) -dm $nick *** Decrypted: %decrypted
    }
    ; Let the inject DLL or normal processing handle the rest
  }
}


; === INCOMING CHANNEL MESSAGES ===
on *:TEXT:*:#:{
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_channel($chan, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    ; Check if we should display the decrypted message
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted == 1) {
      echo $color(Message text) -dm $chan *** Decrypted: %decrypted
    }
    ; Let the inject DLL or normal processing handle the rest
  }
}


; === INCOMING PRIVATE NOTICES ===
on *:NOTICE:*:?:{
  ; Check for FCEP-2 device-scoped messages (+FCEP2 W/K/R/S/X)
  if ($left($1-, 7) == +FCEP2 ) {
    ; FCEP-2 device-scoped message - process via FCEP-2 handler
    var %result = $fish11_fcep2_process($nick, $me, $1-)
    if (%result != $null) {
      echo $color(Mode text) -dm $nick *** FCEP-2: %result
    }
    halt
  }
  
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_incoming($nick, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    ; Check if we should display the decrypted message
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted == 1) {
      echo $color(Mode text) -dm $nick *** Decrypted notice: %decrypted
    }
    ; Let the inject DLL or normal processing handle the rest
  }
}


; === INCOMING PRIVATE ACTIONS ===
on *:ACTION:*:?:{
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_incoming($nick, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    ; Check if we should display the decrypted message
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted == 1) {
      echo $color(Action text) -dm $nick *** Decrypted action: %decrypted
    }
    ; Let the inject DLL or normal processing handle the rest
  }
}


; === INCOMING CHANNEL ACTIONS ===
on *:ACTION:*:#:{
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_channel($chan, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    ; Check if we should display the decrypted message
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted == 1) {
      echo $color(Action text) -dm $chan *** Decrypted action: %decrypted
    }
    ; Let the inject DLL or normal processing handle the rest
  }
}


; === INCOMING CHANNEL NOTICES ===
on *:NOTICE:*:#:{
  ; Try to decrypt the message
  var %decrypted = $fish11_try_decrypt_channel($chan, $1-)
  
  ; If decryption changed the message, display it and halt
  if (%decrypted != $1-) {
    ; Check if we should display the decrypted message
    var %show_decrypted = $dll(%Fish11DllFile, INI_GetBool, show_decrypted_messages 1)
    if (%show_decrypted == 1) {
      echo $color(Mode text) -dm $chan *** Decrypted notice: %decrypted
    }
    ; Let the inject DLL or normal processing handle the rest
  }
}


; === MANUAL DECRYPTION COMMANDS ===
; Allow users to manually decrypt a message
; Usage: /fish11_decrypt_msg <sender> <encrypted_message>
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
