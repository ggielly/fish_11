;*******************************
;* FiSH_11 FCEP-2 Protocol     *
;*******************************
; FCEP-2 (MLS over IRC Transport Profile) implementation
; Provides multi-party encrypted channels using MLS group key establishment
; Written by GuY, 2026. Licensed under GPL-v3.

; === FCEP-2 DEVICE INITIALIZATION ===
; Initializes the local MLS device identity. Called once at startup.
alias fish11_fcep2_init_device {
  var %label = $iif($1-, $1-, mIRC_User)
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_InitDevice, %label)
  if ($left(%result, 2) == OK) {
    var %dev_id = $gettok(%result, 2, 32)
    var %fp = $gettok(%result, 3, 32)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: device initialized (id: %dev_id $+ )
    set %fcep2.device_id %dev_id
    set %fcep2.fingerprint %fp
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: failed to initialize device: %result
  }
}

; === FCEP-2 GROUP CREATION ===
; Creates a new FCEP-2 MLS group for a channel
; Usage: /fcep2_create <#channel> [keypackage1] [keypackage2] ...
alias fish11_fcep2_create_group {
  if (!$1) {
    echo 4 -a Syntax: /fcep2_create <#channel> [keypackage1] [keypackage2] ...
    return
  }
  
  var %channel = $1
  var %args = $1-
  
  echo $color(Mode text) -ts *** FiSH_11 FCEP-2: creating group for %channel $+ ...
  
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_CreateGroup, %args)
  
  if ($left(%result, 13) == GROUP_CREATED) {
    var %gid = $gettok(%result, 2, 32)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: group created for %channel (gid: %gid $+ )
    
    ; Store the group binding
    set %fcep2.group. $+ [ %channel ] %gid
    
    ; Check for welcome messages
    var %welcomes = $gettok(%result, 4-, 32)
    if (%welcomes != $null) {
      echo $color(Mode text) -ts *** FiSH_11 FCEP-2: sending Welcome messages to members...
      ; Welcomes would be sent as NOTICE to each member
      ; This is handled by the relay or mIRC script
    }
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 KEYPACKAGE GENERATION ===
; Generates a signed KeyPackage for distribution
; Usage: /fcep2_genkeypackage [label]
alias fish11_fcep2_gen_keypackage {
  var %label = $iif($1-, $1-, mIRC_User)
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_GenKeyPackage, %label)
  
  if ($left(%result, 10) == KEYPACKAGE) {
    var %kp = $gettok(%result, 2, 32)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: KeyPackage generated
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: KeyPackage: %kp
    return %kp
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
    return $null
  }
}

; === FCEP-2 ENCRYPT MESSAGE ===
; Encrypts a message for a channel using FCEP-2
; Usage: /fcep2_encrypt <#channel> <message>
alias fish11_fcep2_encrypt {
  if (!$1 || !$2-) {
    echo 4 -a Syntax: /fcep2_encrypt <#channel> <message>
    return
  }
  
  var %channel = $1
  var %message = $2-
  
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_EncryptMsg, %channel %message)
  
  if (%result != $null && $left(%result, 5) != Error) {
    return %result
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: encryption failed: %result
    return $null
  }
}

; === FCEP-2 DECRYPT MESSAGE ===
; Decrypts a FCEP-2 envelope line
; Usage: /fcep2_decrypt <#channel> <fcep2_line>
alias fish11_fcep2_decrypt {
  if (!$1 || !$2-) {
    echo 4 -a Syntax: /fcep2_decrypt <#channel> <fcep2_line>
    return
  }
  
  var %channel = $1
  var %line = $2-
  
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_DecryptMsg, %channel %line)
  
  if (%result != $null && $left(%result, 6) != Error:) {
    return %result
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: decryption failed: %result
    return $null
  }
}

; === FCEP-2 PROCESS INCOMING MESSAGE ===
; Processes an incoming FCEP-2 envelope from IRC
; Usage: called by event handlers, not directly by users
alias -l fish11_fcep2_process {
  var %source = $1
  var %target = $2
  var %line = $3-
  
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_ProcessMessage, %source %target %line)
  
  ; Parse result prefix
  if ($left(%result, 9) == DECRYPTED) {
    ; DECRYPTED <nick> <channel> <plaintext>
    var %nick = $gettok(%result, 2, 32)
    var %chan = $gettok(%result, 3, 32)
    var %plaintext = $gettok(%result, 4-, 32)
    echo $color(Message text) -dm %chan *** %nick $+ : %plaintext
  }
  elseif ($left(%result, 6) == JOINED) {
    ; JOINED <channel> <group_id_b64>
    var %chan = $gettok(%result, 2, 32)
    var %gid = $gettok(%result, 3, 32)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: joined group for %chan (gid: %gid $+ )
    set %fcep2.group. $+ [ %chan ] %gid
  }
  elseif ($left(%result, 13) == FRAGMENT_WAIT) {
    ; FRAGMENT_WAIT <n>/<total>
    ; Do not display, just wait for more fragments
  }
  elseif ($left(%result, 8) == DEFERRED) {
    ; DEFERRED <group_id> <kind>
    ; Message queued for later delivery
  }
  elseif ($left(%result, 17) == DUPLICATE_SKIPPED) {
    ; DUPLICATE_SKIPPED - do not display
  }
  elseif ($left(%result, 17) == PROPOSAL_RECEIVED) {
    ; PROPOSAL_RECEIVED from <nick>
    var %from = $gettok(%result, 3, 32)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: proposal received from %from
  }
  elseif ($left(%result, 14) == COMMIT_APPLIED) {
    ; COMMIT_APPLIED epoch=<n>
    var %epoch = $gettok(%result, 2, 61)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: commit applied, epoch=%epoch
  }
  elseif ($left(%result, 17) == CONFLICT_DETECTED) {
    ; CONFLICT_DETECTED epoch=<n>
    echo 4 -ts *** FiSH_11 FCEP-2 WARNING: commit conflict detected!
  }
  elseif ($left(%result, 15) == COMMIT_REJECTED) {
    ; COMMIT_REJECTED <reason>
    var %reason = $gettok(%result, 2-, 32)
    echo 4 -ts *** FiSH_11 FCEP-2: commit rejected: %reason
  }
  elseif ($left(%result, 12) == SYNC_APPLIED) {
    ; SYNC_APPLIED epoch=<n>
    var %epoch = $gettok(%result, 2, 61)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: sync applied, epoch=%epoch
  }
  elseif ($left(%result, 14) == SYNC_NO_CHANGE) {
    ; SYNC_NO_CHANGE - no action needed
  }
  elseif ($left(%result, 13) == SYNC_RESPONSE) {
    ; SYNC_RESPONSE <b64> - send as NOTICE to requester
    var %resp = $gettok(%result, 2, 32)
    .notice %source +FCEP2 S %resp
  }
  elseif ($left(%result, 19) == KEYPACKAGE_RESPONSE) {
    ; KEYPACKAGE_RESPONSE <b64_kp> ...
    var %kps = $gettok(%result, 2-, 32)
    .notice %source +FCEP2 K %kps
  }
  else {
    ; Unknown result - log for debugging
    echo -s *** FiSH_11 FCEP-2 DEBUG: unhandled result: %result
  }
}

; === FCEP-2 PROPOSAL SUBMISSION ===
; Submits a proposal for a group operation
; Usage: /fcep2_propose <#channel> <ADD|REMOVE|UPDATE> [arg]
alias fish11_fcep2_propose {
  if (!$1 || !$2) {
    echo 4 -a Syntax: /fcep2_propose <#channel> <ADD|REMOVE|UPDATE> [keypackage_or_device_id]
    return
  }
  
  var %channel = $1
  var %op = $2
  var %arg = $3-
  
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_SubmitProposal, %channel %op %arg)
  
  if ($left(%result, 15) == PROPOSAL_CACHED) {
    var %pid = $gettok(%result, 2, 32)
    var %pending = $gettok(%result, 3, 32)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: proposal cached (id: %pid $+ , %pending $+ )
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 SEND COMMIT ===
; Commits pending proposals for a channel
; Usage: /fcep2_commit <#channel>
alias fish11_fcep2_commit {
  if (!$1) {
    echo 4 -a Syntax: /fcep2_commit <#channel>
    return
  }
  
  var %channel = $1
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_SendCommit, %channel)
  
  if ($left(%result, 11) == COMMIT_SENT) {
    var %epoch = $gettok(%result, 2, 61)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: commit sent, epoch=%epoch
    
    ; The result contains the envelope lines after "epoch=N "
    ; These should be sent as PRIVMSG to the channel
    var %envelopes = $gettok(%result, 3-, 32)
    if (%envelopes != $null) {
      .msg %channel %envelopes
    }
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 REMOVE DEVICE ===
; Removes a device from a channel's group
; Usage: /fcep2_remove <#channel> <device_id_hex>
alias fish11_fcep2_remove {
  if (!$1 || !$2) {
    echo 4 -a Syntax: /fcep2_remove <#channel> <device_id_hex>
    return
  }
  
  var %channel = $1
  var %dev_id = $2
  
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_RemoveDevice, %channel %dev_id)
  
  if ($left(%result, 17) == REMOVAL_COMMITTED) {
    var %epoch = $gettok(%result, 2, 61)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: device removed, epoch=%epoch
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 SYNC GROUP ===
; Requests synchronization for a channel
; Usage: /fcep2_sync <#channel>
alias fish11_fcep2_sync {
  if (!$1) {
    echo 4 -a Syntax: /fcep2_sync <#channel>
    return
  }
  
  var %channel = $1
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_SyncGroup, %channel)
  
  if ($left(%result, 12) == SYNC_REQUEST) {
    var %envelope = $gettok(%result, 2-, 32)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: sync request generated
    ; Send as NOTICE to known peers or relay
    ; For now, display it
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: %envelope
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 GET GROUP STATE ===
; Queries the current state of a channel's FCEP-2 group
; Usage: /fcep2_state <#channel>
alias fish11_fcep2_state {
  if (!$1) {
    echo 4 -a Syntax: /fcep2_state <#channel>
    return
  }
  
  var %channel = $1
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_GetGroupState, %channel)
  
  if ($left(%result, 5) == STATE) {
    ; STATE channel=<ch> group_id=<gid> epoch=<n> in_conflict=<bool>
    var %ch = $gettok(%result, 2, 61)
    var %gid = $gettok(%result, 4, 61)
    var %epoch = $gettok(%result, 6, 61)
    var %conflict = $gettok(%result, 8, 61)
    
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2 Group State:
    echo $color(Mode text) -ts   Channel: %ch
    echo $color(Mode text) -ts   Group ID: %gid
    echo $color(Mode text) -ts   Epoch: %epoch
    echo $color(Mode text) -ts   In Conflict: %conflict
  }
  elseif ($left(%result, 8) == NO_GROUP) {
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: no group for %channel
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 RESOLVE CONFLICT ===
; Resolves a commit conflict for a channel
; Usage: /fcep2_resolve <#channel>
alias fish11_fcep2_resolve {
  if (!$1) {
    echo 4 -a Syntax: /fcep2_resolve <#channel>
    return
  }
  
  var %channel = $1
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_ResolveConflict, %channel)
  
  if ($left(%result, 2) == OK) {
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: conflict resolved for %channel
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 SET TRUST ===
; Sets trust state for a device
; Usage: /fcep2_trust <device_id_hex> <UNKNOWN|TOFU|VERIFIED|CHANGED|REVOKED>
alias fish11_fcep2_trust {
  if (!$1 || !$2) {
    echo 4 -a Syntax: /fcep2_trust <device_id_hex> <UNKNOWN|TOFU|VERIFIED|CHANGED|REVOKED>
    return
  }
  
  var %dev_id = $1
  var %trust = $2
  
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_SetTrust, %dev_id %trust)
  
  if ($left(%result, 2) == OK) {
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: trust set to %trust for %dev_id
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 EXPORT STATE ===
; Exports group state for backup
; Usage: /fcep2_export <#channel>
alias fish11_fcep2_export {
  if (!$1) {
    echo 4 -a Syntax: /fcep2_export <#channel>
    return
  }
  
  var %channel = $1
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_ExportState, %channel)
  
  if ($left(%result, 6) == EXPORT) {
    var %data = $gettok(%result, 2, 32)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: state exported for %channel
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: export data: %data
    ; Copy to clipboard for easy sharing
    clipboard %data
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: export data copied to clipboard
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 IMPORT STATE ===
; Imports group state from backup
; Usage: /fcep2_import <#channel> <base64_data>
alias fish11_fcep2_import {
  if (!$1 || !$2) {
    echo 4 -a Syntax: /fcep2_import <#channel> <base64_data>
    return
  }
  
  var %channel = $1
  var %data = $2-
  
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_ImportState, %channel %data)
  
  if ($left(%result, 8) == IMPORTED) {
    var %epoch = $gettok(%result, 2, 61)
    var %members = $gettok(%result, 4, 61)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: state imported for %channel (epoch=%epoch $+ , members=%members $+ )
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 FILL KEYPACKAGE POOL ===
; Pre-generates KeyPackages for future group additions
; Usage: /fcep2_fillpool [count]
alias fish11_fcep2_fill_pool {
  var %count = $iif($1, $1, 10)
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_FillKeyPackagePool, %count)
  
  if ($left(%result, 11) == POOL_FILLED) {
    var %filled = $gettok(%result, 2, 61)
    var %ready = $gettok(%result, 4, 61)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: pool filled (%filled generated, %ready ready)
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 SET ENCRYPTION POLICY ===
; Sets encryption policy for a channel
; Usage: /fcep2_policy <#channel> <ALWAYS|REQUIRE_ALL|BEST_EFFORT|DISABLED>
alias fish11_fcep2_policy {
  if (!$1 || !$2) {
    echo 4 -a Syntax: /fcep2_policy <#channel> <ALWAYS|REQUIRE_ALL|BEST_EFFORT|DISABLED>
    return
  }
  
  var %channel = $1
  var %policy = $2
  
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_SetEncryptionPolicy, %channel %policy)
  
  if ($left(%result, 10) == POLICY_SET) {
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: policy set to %policy for %channel
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 GET DIAGNOSTICS ===
; Gets diagnostic events for a channel
; Usage: /fcep2_diag [count]
alias fish11_fcep2_diag {
  var %count = $iif($1, $1, 10)
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_GetDiagnostics, * %count)
  
  if ($left(%result, 11) == DIAGNOSTICS) {
    var %count = $gettok(%result, 2, 32)
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2 Diagnostics (%count events):
    var %i = 3
    while (%i <= $numtok(%result, 32)) {
      var %line = $gettok(%result, %i-, 32)
      echo $color(Mode text) -ts   %line
      break
    }
  }
  else {
    echo $color(Mode text) -ts *** FiSH_11 FCEP-2: no diagnostics available
  }
}

; === FCEP-2 REQUEST KEYPACKAGE ===
; Requests KeyPackages from the pool
; Usage: /fcep2_requestkp [device_id|ALL]
alias fish11_fcep2_request_kp {
  var %target = $iif($1, $1, ALL)
  var %result = $dll(%Fish11DllFile, FiSH11_FCEP2_RequestKeyPackage, * %target)
  
  if ($left(%result, 19) == KEYPACKAGE_RESPONSE) {
    var %kps = $gettok(%result, 2-, 32)
    if (%kps == NONE) {
      echo $color(Mode text) -ts *** FiSH_11 FCEP-2: no KeyPackages available
    }
    else {
      echo $color(Mode text) -ts *** FiSH_11 FCEP-2: KeyPackages available
      echo $color(Mode text) -ts *** FiSH_11 FCEP-2: %kps
    }
  }
  else {
    echo 4 -ts *** FiSH_11 FCEP-2 ERROR: %result
  }
}

; === FCEP-2 HELP ===
; Displays FCEP-2 help information
alias fish11_fcep2_help {
  echo $color(Mode text) -ts *** FiSH_11 FCEP-2 Commands:
  echo $color(Mode text) -ts   /fcep2_create <#channel>        - Create a new FCEP-2 group
  echo $color(Mode text) -ts   /fcep2_genkeypackage [label]    - Generate a KeyPackage
  echo $color(Mode text) -ts   /fcep2_encrypt <#channel> <msg> - Encrypt a message
  echo $color(Mode text) -ts   /fcep2_decrypt <#channel> <line> - Decrypt a FCEP-2 line
  echo $color(Mode text) -ts   /fcep2_propose <#channel> <OP>  - Submit a proposal (ADD/REMOVE/UPDATE)
  echo $color(Mode text) -ts   /fcep2_commit <#channel>        - Send pending proposals
  echo $color(Mode text) -ts   /fcep2_remove <#channel> <dev>  - Remove a device
  echo $color(Mode text) -ts   /fcep2_sync <#channel>          - Request synchronization
  echo $color(Mode text) -ts   /fcep2_state <#channel>         - Show group state
  echo $color(Mode text) -ts   /fcep2_resolve <#channel>       - Resolve commit conflict
  echo $color(Mode text) -ts   /fcep2_trust <dev> <STATE>      - Set device trust
  echo $color(Mode text) -ts   /fcep2_export <#channel>        - Export group state
  echo $color(Mode text) -ts   /fcep2_import <#channel> <data> - Import group state
  echo $color(Mode text) -ts   /fcep2_fillpool [count]         - Fill KeyPackage pool
  echo $color(Mode text) -ts   /fcep2_policy <#channel> <POL>  - Set encryption policy
  echo $color(Mode text) -ts   /fcep2_diag [count]             - Show diagnostics
  echo $color(Mode text) -ts   /fcep2_requestkp [target]       - Request KeyPackages
  echo $color(Mode text) -ts   /fcep2_help                     - Show this help
}
