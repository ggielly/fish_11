;***********************
;* FiSH_11 Startup     *
;***********************
; Initialization and DLL loading for FiSH_11
; Written by GuY, 2025. Licensed under GPL-v3.

; === INITIALIZATION AND STARTUP ===
on *:START: {
  .fish11_startup
}

alias fish11_startup {
  echo 4 -a *** FiSH_11 SECURITY NOTICE *** This script relies on 2 external DLL files. Only use trusted, signed versions from official sources.  ***
  echo 4 -a *** FiSH_11 SECURITY NOTICE *** Never run this script if you suspect your system has been compromised.                                ***

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
      echo 4 -ts $chr(3)4 *** SECURITY WARNING : you're running a DEBUG version which logs EVERYTHING (keys, private messages, etc.) ON YOUR DISK.
      echo 4 -ts $chr(3)4 *** DO NOT USE THIS VERSION IN REAL LIFE.
      echo 4 -ts $chr(3)4 *** 
      echo 4 -ts $chr(3)4 *** WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING ***
    }
    else {
      echo 4 -ts $chr(3)3 *** You are running a RELEASE version. Sensitive data is NOT logged.
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

  ; Check if keychain is unlocked, if not prompt user
  .fish11_check_masterkey

  ; Initialize FCEP-2 device identity
  .fish11_fcep2_init_device
}
