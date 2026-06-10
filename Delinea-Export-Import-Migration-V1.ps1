<#
.SYNOPSIS
    Delinea Secret Server Cross-Tenant Migration Tool V1 (Unofficial) — a GUI-based utility for
    exporting, importing, and migrating secrets, folders, permissions, templates,
    and settings between Delinea Secret Server tenants (cloud or on-premises).

.DISCLAIMER
    This is a generic unofficial tool created for Delinea cross-tenant migration use cases.
    It does not contain any proprietary or company-specific logic.
    Ensure you follow your organization's security and compliance policies before use.

.DESCRIPTION
    A comprehensive, production-ready GUI tool for migrating secrets and related
    metadata between Delinea Secret Server tenants. Supports multi-tenant
    configurations with independent source and target credentials.

    EXPORT CAPABILITIES:
    - Export secrets to JSON, XML (web-portal compatible), CSV, or ZIP bundle
    - Full tenant export, folder-specific export, or search-based export
    - Incremental export (skip previously exported secrets)
    - Export child folders via v1 export service with recursive BFS traversal
    - Password history export (field-level history capture)
    - File attachment export (base64, binary download, multiple endpoint fallbacks)
    - Secret settings export (checkout, comments, session recording, approval,
      OTP, expiration, password requirements, permissions inheritance)
    - Folder and secret-level ACL export
    - Template definitions export (embedded XML for template migration)

    IMPORT CAPABILITIES:
    - Import from JSON, CSV, XML, or ZIP archive (auto-detected)
    - Folder tree migration with hierarchy preservation or flat import
    - Template mapping with 7+ matching strategies (name, suffix, fuzzy, manual)
    - Field ID translation for non-matching template schemas
    - Principal (user/group) remapping by UserName, DisplayName@Domain, or DisplayName
    - Duplicate secret handling: Skip, Update existing, or Create New
    - Password history import and attachment upload to target
    - Secret settings application during import
    - Robust folder tree creation with retry-on-error and multi-method lookup
    - Skip-not-fallback: secrets never placed in wrong folder on folder error

    DUPLICATE DETECTION (ENHANCED):
    - Uses GET /secrets endpoint for full visibility (not /secrets/lookup)
    - Cached per-folder secret name index for fast lookups
    - Fallback targeted search by name (filter.searchText) when bulk listing
      misses entries due to API visibility limitations
    - Case-insensitive and whitespace-tolerant name matching
    - Index auto-updates as secrets are created during import

    PERMISSION & ACL HANDLING:
    - Copy folder ACLs with inheritance control (never breaks inheritance)
    - Copy secret ACLs (bulk + individual fallback for reliability)
    - Principal cache and permission cache for performance
    - Access control pre-checks before operations
    - Permission skip with detailed logging for missing groups/users

    TEMPLATE MANAGEMENT:
    - Source vs. target template comparison (side-by-side analysis)
    - Field-level and settings-level difference reporting
    - Template comparison CSV export
    - Import missing templates from export data
    - Select All checkbox for bulk template selection in mapping grid
    - Parallel HTTP calls (HttpClient) for fast template retrieval and filtering

    PERFORMANCE OPTIMIZATIONS:
    - Parallel HTTP requests via System.Net.Http.HttpClient for template fetching
    - Batch parallel secret-existence checks (15 concurrent per batch)
    - Batch parallel template detail retrieval (10 concurrent per batch)
    - Folder permission caching to avoid redundant API calls
    - Template field index caching per import session

    SAFETY & ROLLBACK:
    - Dry-run mode for all operations (simulate without changes)
    - Rollback support for created folders and secrets
    - Cleanup Last Import with optional rollback of updated secrets
    - Pre-import validation (permissions, templates, folders, field compatibility)

    AUTHENTICATION & SECURITY:
    - OAuth2 password grant flow with multiple token attribute support
    - Token caching with TTL-based expiration
    - DPAPI encryption for stored passwords
    - Secure password input (MaskedTextBox)
    - Auto-elevation to administrator (supports ps2exe compiled .exe)

    CONFIGURATION & LOGGING:
    - JSON configuration file with load/save/import/export
    - DPAPI-encrypted credential storage in config
    - Multi-level logging (DEBUG, INFO, WARN, ERROR) to file and UI
    - Verbose HTTP request/response logging (optional)
    - Real-time log display across all GUI tabs

    GUI FEATURES:
    - Settings tab (source/target credentials and configuration)
    - Actions tab (export, import, verify, cleanup, secret count)
    - Tools tab (permission remapping, template mapping utilities)
    - Template Check tab (comparison, mapping, CSV export, Select All)
    - Theme support (Ocean and other color schemes)
    - Config browse/save/load buttons, log file selection

    ADDITIONAL FEATURES:
    - API connectivity verification (Verify button)
    - Get # Secrets count (quick enumeration without full export)
    - Pagination handling for large datasets
    - Caching (templates, folders, principals, permissions)
    - Configurable timeouts (10s for permissions, 100s general)
    - Multi-method folder lookup (parentFolderId listing, searchText, folders/lookup)

.NOTES
    File Name      : Delinea-Export-Import-Migration-V1.ps1
    Author         : Vijaya Mohan Reddy Madduri
    Version        : 1.0
    Prerequisite   : PowerShell 5.1 or later, .NET Framework 4.5+
    Copyright      : (c) 2026. All rights reserved.

.EXAMPLE
    .\Delinea-Export-Import-Migration-V1.ps1
    
    Launches the GUI migration tool. Configure source and target tenant 
    credentials, select options, and use Export/Import buttons.
#>

# Optional: double-check unblock (harmless if already unblocked)
$MyInvocation.MyCommand.Path | Unblock-File -ErrorAction SilentlyContinue

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Detect if running as compiled exe (ps2exe)
$script:IsCompiledExe = $false
$script:ExePath = $null
try {
    $script:ExePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ($script:ExePath -and $script:ExePath -match '\.exe$' -and $script:ExePath -notmatch 'powershell\.exe$|pwsh\.exe$') {
        $script:IsCompiledExe = $true
    }
} catch {}

# Prevent relaunch loop
if (-not $isAdmin -and -not $env:__RELAUNCHED_ELEVATED) {
    $env:__RELAUNCHED_ELEVATED = '1'

    try {
        $selfPath = $null
        
        # For ps2exe compiled exe, use the process path
        if ($script:IsCompiledExe -and $script:ExePath) {
            $selfPath = $script:ExePath
        }
        elseif ($PSCommandPath -and (Test-Path $PSCommandPath -ErrorAction SilentlyContinue)) {
            $selfPath = $PSCommandPath
        }
        elseif ($MyInvocation.MyCommand.Path -and (Test-Path $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue)) {
            $selfPath = $MyInvocation.MyCommand.Path
        }
        else {
            # Fallback for other scenarios
            try {
                $proc = Get-Process -Id $PID -ErrorAction SilentlyContinue
                if ($proc.Path) {
                    $selfPath = $proc.Path
                }
            } catch {}
        }

        if (-not $selfPath) {
            Write-Warning "Cannot determine script/exe path for elevation. Run as Administrator manually."
            Start-Sleep -Seconds 3
            exit 1
        }

        $isExe = $selfPath -match '\.exe$' -and $selfPath -notmatch 'powershell\.exe$|pwsh\.exe$'

        if ($isExe) {
            Start-Process -FilePath $selfPath -Verb RunAs -ErrorAction Stop
        }
        else {
            $argList = @(
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-File', "`"$selfPath`""
            )
            
            if ($args -and $args.Count -gt 0) {
                $argList += $args
            }
            
            Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -ErrorAction Stop
        }
        
        exit
    }
    catch {
        Write-Warning "Failed to elevate: $_"
        Write-Warning "Please right-click the script/exe and select 'Run as Administrator'"
        Start-Sleep -Seconds 5
        exit 1
    }
}

#requires -Version 5.1
Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'
# Initialize script-scoped flags used by auto-token-refresh logic (StrictMode requires explicit init)
$script:SSRefreshInProgress = $false
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Increase connection pool to allow faster parallel/sequential HTTP calls to the same host
[Net.ServicePointManager]::DefaultConnectionLimit = 50
[Net.ServicePointManager]::Expect100Continue = $false

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.Web.Extensions

# =================== FAST JSON HELPERS (for large files) ===================
# PowerShell's ConvertFrom-Json / ConvertTo-Json are extremely slow on large files (100MB+).
# JavaScriptSerializer is 10-50x faster for serialization/deserialization of large JSON.
# The C# helper below converts Dictionary/ArrayList trees to PSObject in compiled .NET (100x faster than PS loops).

if (-not ([System.Management.Automation.PSTypeName]'FastJsonConverter').Type) {
$_smaPath = [System.Management.Automation.PSObject].Assembly.Location
Add-Type -Language CSharp -ReferencedAssemblies $_smaPath -TypeDefinition @"
using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;

public static class FastJsonConverter
{
    public static PSObject ConvertToPSObject(object obj)
    {
        object result = ConvertRecursive(obj);
        if (result is PSObject) return (PSObject)result;
        PSObject wrapper = new PSObject();
        wrapper.Properties.Add(new PSNoteProperty("Value", result));
        return wrapper;
    }

    public static object ConvertRecursive(object obj)
    {
        if (obj == null) return null;

        var dict = obj as Dictionary<string, object>;
        if (dict != null)
        {
            PSObject pso = new PSObject();
            foreach (var kvp in dict)
            {
                pso.Properties.Add(new PSNoteProperty(kvp.Key, ConvertRecursive(kvp.Value)));
            }
            return pso;
        }

        var arr = obj as object[];
        if (arr != null)
        {
            object[] result = new object[arr.Length];
            for (int i = 0; i < arr.Length; i++)
            {
                result[i] = ConvertRecursive(arr[i]);
            }
            return result;
        }

        var list = obj as ArrayList;
        if (list != null)
        {
            object[] result = new object[list.Count];
            for (int i = 0; i < list.Count; i++)
            {
                result[i] = ConvertRecursive(list[i]);
            }
            return result;
        }

        return obj;
    }
}
"@
}

function Read-LargeJson([string]$Path) {
  <#
  .SYNOPSIS
    Reads a large JSON file efficiently using JavaScriptSerializer.
    Returns nested Dictionary/ArrayList objects (not PSCustomObject).
  #>
  $fileSizeMB = [math]::Round((Get-Item $Path).Length / 1MB, 1)
  Write-Log ("Read-LargeJson: Loading {0} ({1} MB)..." -f $Path, $fileSizeMB) 'INFO'
  if($fileSizeMB -gt 50){ Write-Log "  Large file detected - using fast JSON parser..." 'INFO' }
  
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $raw = [System.IO.File]::ReadAllText($Path)
  Write-Log ("  File read into memory ({0:N1}s)" -f $sw.Elapsed.TotalSeconds) 'DEBUG'
  
  $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
  $ser.MaxJsonLength = [int]::MaxValue
  $ser.RecursionLimit = 200
  $result = $ser.DeserializeObject($raw)
  $raw = $null  # Free the string immediately
  [GC]::Collect()
  Write-Log ("  JSON deserialized ({0:N1}s total)" -f $sw.Elapsed.TotalSeconds) 'INFO'
  return $result
}

function Write-LargeJson($Object, [string]$Path, [switch]$Pretty) {
  <#
  .SYNOPSIS
    Writes a large object to JSON file efficiently using JavaScriptSerializer.
    Accepts Dictionary/ArrayList objects, hashtables, ordered dictionaries, or PSCustomObjects.
    PSCustomObjects are converted to dictionaries first for proper serialization.
  #>
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  if ($Pretty) {
    # Use ConvertTo-Json for pretty-printing (slower, but indented)
    $jsonText = $Object | ConvertTo-Json -Depth 30
    Write-Log ("  Write-LargeJson: Pretty-printing with ConvertTo-Json... ({0:N1}s)" -f $sw.Elapsed.TotalSeconds) 'DEBUG'
  } else {
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $ser.MaxJsonLength = [int]::MaxValue
    $ser.RecursionLimit = 200
    # Skip conversion if already in serializer-friendly format (Dictionary/ArrayList/object[])
    if ($Object -is [System.Collections.Generic.Dictionary[string,object]] -or $Object -is [object[]] -or $Object -is [System.Collections.ArrayList]) {
      $converted = $Object
    } else {
      $converted = Convert-PSObjectToDict $Object
    }
    Write-Log ("  Write-LargeJson: Serializing... ({0:N1}s)" -f $sw.Elapsed.TotalSeconds) 'DEBUG'
    $jsonText = $ser.Serialize($converted)
  }
  Write-Log ("  Write-LargeJson: Writing {0:N1} MB to disk..." -f ($jsonText.Length / 1MB)) 'DEBUG'
  [System.IO.File]::WriteAllText($Path, $jsonText, [System.Text.Encoding]::UTF8)
  Write-Log ("  Write-LargeJson: Complete ({0:N1}s)" -f $sw.Elapsed.TotalSeconds) 'DEBUG'
}

function Convert-PSObjectToDict($obj) {
  <#
  .SYNOPSIS
    Recursively converts PSCustomObject/OrderedDictionary to Dictionary<string,object>
    for use with JavaScriptSerializer.Serialize(). Passes through native types and
    Dictionary objects unchanged.
  #>
  if ($null -eq $obj) { return $null }
  # Already a serializer-friendly dictionary
  if ($obj -is [System.Collections.Generic.Dictionary[string,object]]) { return $obj }
  # PSCustomObject - convert to dictionary
  if ($obj -is [System.Management.Automation.PSCustomObject]) {
    $dict = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    foreach ($prop in $obj.PSObject.Properties) {
      if ($prop.MemberType -notin @('NoteProperty','Property','ScriptProperty')) { continue }
      $dict[$prop.Name] = Convert-PSObjectToDict $prop.Value
    }
    return $dict
  }
  # Ordered dictionary or hashtable
  if ($obj -is [System.Collections.IDictionary]) {
    $dict = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    foreach ($key in $obj.Keys) {
      $dict[[string]$key] = Convert-PSObjectToDict $obj[$key]
    }
    return $dict
  }
  # Arrays and lists
  if ($obj -is [System.Collections.IEnumerable] -and $obj -isnot [string]) {
    $arr = New-Object System.Collections.ArrayList
    foreach ($item in $obj) { [void]$arr.Add((Convert-PSObjectToDict $item)) }
    return $arr
  }
  # Primitive types - pass through
  return $obj
}

function ConvertFrom-LargeJson([string]$JsonString) {
  <#
  .SYNOPSIS
    Deserializes a JSON string efficiently. For use when you already have the string in memory.
  #>
  $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
  $ser.MaxJsonLength = [int]::MaxValue
  $ser.RecursionLimit = 200
  return $ser.DeserializeObject($JsonString)
}

function ConvertTo-LargeJson($Object) {
  <#
  .SYNOPSIS
    Serializes an object to JSON string efficiently.
  #>
  $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
  $ser.MaxJsonLength = [int]::MaxValue
  $ser.RecursionLimit = 200
  return $ser.Serialize($Object)
}

function Read-LargeJsonAsPSObject([string]$Path) {
  <#
  .SYNOPSIS
    Reads a large JSON file using JavaScriptSerializer (fast) then converts to PSCustomObject
    using compiled C# converter (fast) so the rest of the codebase can use .Property access.
    10-50x faster than ConvertFrom-Json for files > 50MB.
  #>
  $fileSizeMB = [math]::Round((Get-Item $Path).Length / 1MB, 1)
  Write-Log ("Read-LargeJsonAsPSObject: Reading {0} ({1} MB)..." -f $Path, $fileSizeMB) 'INFO'
  
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $raw = [System.IO.File]::ReadAllText($Path)
  Write-Log ("  File read complete ({0:N1}s)" -f $sw.Elapsed.TotalSeconds) 'DEBUG'
  
  $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
  $ser.MaxJsonLength = [int]::MaxValue
  $ser.RecursionLimit = 200
  $dict = $ser.DeserializeObject($raw)
  $raw = $null  # Free memory immediately
  [GC]::Collect()
  Write-Log ("  JSON deserialized ({0:N1}s)" -f $sw.Elapsed.TotalSeconds) 'DEBUG'
  
  # Use compiled C# converter (100x faster than PowerShell recursive loops)
  # Fallback to PowerShell converter if C# type not available
  if (([System.Management.Automation.PSTypeName]'FastJsonConverter').Type) {
    $result = [FastJsonConverter]::ConvertRecursive($dict)
  } else {
    Write-Log "  WARNING: FastJsonConverter not available, using PowerShell fallback (slower)" 'WARN'
    $result = Convert-DictToPSObject $dict
  }
  $dict = $null
  [GC]::Collect()
  Write-Log ("  Conversion to PSObject complete ({0:N1}s total)" -f $sw.Elapsed.TotalSeconds) 'INFO'
  
  return $result
}

function Convert-DictToPSObject($obj) {
  <#
  .SYNOPSIS
    Recursively converts Dictionary<string,object>/ArrayList from JavaScriptSerializer
    to PSCustomObject/arrays that the rest of the script can use normally.
  #>
  if ($null -eq $obj) { return $null }
  if ($obj -is [System.Collections.Generic.Dictionary[string,object]]) {
    $pso = New-Object PSCustomObject
    foreach ($key in $obj.Keys) {
      $pso | Add-Member -NotePropertyName $key -NotePropertyValue (Convert-DictToPSObject $obj[$key])
    }
    return $pso
  }
  if ($obj -is [object[]]) {
    $arr = [System.Collections.ArrayList]::new($obj.Length)
    foreach ($item in $obj) { [void]$arr.Add((Convert-DictToPSObject $item)) }
    return @($arr)
  }
  return $obj
}

function Pt([int]$x,[int]$y){ New-Object System.Drawing.Point -ArgumentList $x,$y }
function Sz([int]$w,[int]$h){ New-Object System.Drawing.Size  -ArgumentList $w,$h }

# =================== DIRECTORIES & PATHS ===================

# Determine script root directory - works for both ps1 and ps2exe compiled exe
$ScriptRoot = $null
if ($script:IsCompiledExe -and $script:ExePath) {
    # For ps2exe compiled exe, use the exe's directory
    $ScriptRoot = Split-Path -Parent $script:ExePath
}
elseif (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $ScriptRoot = $PSScriptRoot
}
else {
    $p = $null
    if ($MyInvocation -and $MyInvocation.MyCommand) {
        if (($MyInvocation.MyCommand | Get-Member -Name Path -MemberType Properties -ErrorAction SilentlyContinue)) { 
            $p = $MyInvocation.MyCommand.Path 
        }
    }
    $ScriptRoot = if ($p) { Split-Path -Parent $p } else { (Get-Location).Path }
}

$script:BaseDir = Join-Path $ScriptRoot 'DelineaMigration'
if(-not (Test-Path $script:BaseDir)){ New-Item -ItemType Directory -Path $script:BaseDir | Out-Null }
$script:AttachmentRoot = Join-Path $script:BaseDir 'Attachments'
if(-not (Test-Path $script:AttachmentRoot)){ New-Item -ItemType Directory -Path $script:AttachmentRoot | Out-Null }
$script:CreatedFolderCache = @{}
$DefaultConfigPath = Join-Path $BaseDir 'delinea-migrate.config.json'
$script:ConfigPath = $DefaultConfigPath

# =================== EARLY HELPER FUNCTIONS (must be defined before use) ===================

function Ensure-Dir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ return }

  $pathToCreate = $p
  try{
    if([IO.Path]::HasExtension($p)){
      $parent = Split-Path -Parent $p
      if($parent){ $pathToCreate = $parent }
    }
  } catch {}

  if(-not (Test-Path $pathToCreate)){
    New-Item -ItemType Directory -Path $pathToCreate | Out-Null
  }
}

function Has-Prop($o,[string]$name){ 
  return ($null -ne $o -and $o.PSObject.Properties.Name -contains $name) 
}

function Get-PropValue($o,[string[]]$names,$default=$null){
  foreach($n in $names){
    if(Has-Prop $o $n){
      $v=$o.$n
      if($null -ne $v -and ('' + $v) -ne ''){ return $v }
      return $v
    }
  }
  $default
}

# =================== CONFIGURATION ===================

function Get-DefaultConfig {
  [ordered]@{
    TokenPath  = "/oauth2/token"
    ExportFile = (Join-Path $BaseDir "secrets-export.json")
    LogFile    = (Join-Path $BaseDir "delinea-migrate.log")
    LogFileDateStamp = $true
    ExportCsvFile = (Join-Path $BaseDir "secrets-export.csv")
    TemplateCsvPath = ""
    RemapCsvPath = ""
    Auth       = [ordered]@{ StorePassword = $true }
    Theme      = "Ocean"
    Src = [ordered]@{
      TenantBase="https://src-tnt.secretservercloud.com"; Username="Administrator"; PasswordDpapi=""; SSApiBase="https://src-tnt.secretservercloud.com/api/v1"
      TokenUrl=""
      SearchText="*"; FolderId=$null
      MaxSecrets=$null
      IncludeHistory=$true
      ExportTemplates=$false
      UseV1ExportService=$false
      ExportChildFolders=$false
      ExportJson=$true
      ExportXml=$false
      ExportCsv=$false
      ExportZip=$false
      EncryptPasswords=$false
    }
    Crypto = [ordered]@{
      DecryptPasswords=$false
    }
    Tgt = [ordered]@{
      VerboseHttp=$false
      TenantBase="https://tgt-tnt.secretservercloud.com"; Username="Administrator"; PasswordDpapi=""; SSApiBase="https://tgt-tnt.secretservercloud.com/api/v1"
      TokenUrl=""
      TargetFolderId=0; OverwriteIfExists=$true
      FolderTreeMigration=$false; TargetRootFolderId=1
      SecretTypeMapByName=$false
      ImportTemplates=$false
      TemplateSuffix='MIGRATED'
      DuplicateSecretAction = "Skip"
      CopyFolderAcls=$false
      CopySecretAcls=$false
      CopySecretSettings=$false
      CopyAttachments=$false
      RemapPrincipals=$false
      DryRun=$false
      SkipPasswordValidation=$false
      SyncTemplateFields=$false
      StopOnError=$false
      ApplyPasswordHistory=$true
      CleanupRollbackUpdatedSecrets=$false
      RollbackDir=(Join-Path $BaseDir "rollback")
    }
  }
}

function Copy-PropsIfMissing($dst,$src){
  foreach($p in $src.PSObject.Properties){
    if($p.MemberType -notin @('NoteProperty','Property')){ continue }
    $n=$p.Name
    if($dst.PSObject.Properties.Name -notcontains $n){ $dst | Add-Member -NotePropertyName $n -NotePropertyValue $p.Value }
    else{
      $dv=$dst.$n; $sv=$p.Value
      if($null -ne $dv -and $null -ne $sv -and $dv.GetType().Name -eq 'PSCustomObject' -and $sv.GetType().Name -eq 'PSCustomObject'){ Copy-PropsIfMissing $dv $sv }
    }
  }
}

function Save-Config($cfg){
  if(-not $cfg){ throw "Save-Config: cfg is null." }
  Ensure-Dir $script:ConfigPath
  ($cfg | ConvertTo-Json -Depth 30) | Set-Content -Path $script:ConfigPath -Encoding UTF8
}

function Load-Config(){
  if(Test-Path $script:ConfigPath){
    $cfg=Get-Content $script:ConfigPath -Raw | ConvertFrom-Json
    $def=Get-DefaultConfig | ConvertTo-Json -Depth 30 | ConvertFrom-Json
    Copy-PropsIfMissing $cfg $def

    if(-not $cfg.TokenPath -or [string]::IsNullOrWhiteSpace([string]$cfg.TokenPath)){ $cfg.TokenPath = "/oauth2/token" }
    if(-not $cfg.Theme -or [string]::IsNullOrWhiteSpace([string]$cfg.Theme)){ $cfg.Theme = "Ocean" }

    if(-not $cfg.LogFile -or [string]::IsNullOrWhiteSpace([string]$cfg.LogFile)){ $cfg.LogFile = (Join-Path $BaseDir "delinea-migrate.log") }
    # Apply date stamp to log file at load time so only one log file is created
    if([bool]$cfg.LogFileDateStamp){
      $logBase = $cfg.LogFile -replace '_\d{8}_\d{6}\.log$','.log'
      $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
      $cfg.LogFile = $logBase -replace '\.log$',("_{0}.log" -f $stamp)
    }
    if(-not $cfg.ExportFile -or [string]::IsNullOrWhiteSpace([string]$cfg.ExportFile)){ $cfg.ExportFile = (Join-Path $BaseDir "secrets-export.json") }
    if(-not $cfg.ExportCsvFile -or [string]::IsNullOrWhiteSpace([string]$cfg.ExportCsvFile)){ $cfg.ExportCsvFile = (Join-Path $BaseDir "secrets-export.csv") }

    if(-not $cfg.Tgt.RollbackDir -or [string]::IsNullOrWhiteSpace($cfg.Tgt.RollbackDir)){
      $cfg.Tgt.RollbackDir = (Join-Path $BaseDir "rollback")
    }

    return $cfg
  } else {
    $c=Get-DefaultConfig
    Save-Config $c
    return (Get-Content $script:ConfigPath -Raw | ConvertFrom-Json)
  }
}
$Global:Config = Load-Config
# =================== LOGGING ===================

$script:MinLogLevel = 'INFO'
$script:LogTextBox=$null
$script:LogMirrorTextBox=$null   # Optional secondary TextBox (e.g. Reconcile tab) to mirror Write-Log output to
$script:LogDirEnsured=$false

function Set-MinLogLevel([ValidateSet('DEBUG','INFO','WARN','ERROR')]$Level){
  $script:MinLogLevel = $Level
}

function Write-Log([string]$msg,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$level='INFO'){
  $order = @{ 'DEBUG'=0; 'INFO'=1; 'WARN'=2; 'ERROR'=3 }
  if($order[$level] -lt $order[$script:MinLogLevel]){ return }

  $ts=Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'
  $line="{0}`t| {1}`t| {2}" -f $ts,$level,$msg

  if($script:LogTextBox -and -not $script:LogTextBox.IsDisposed){
    try{
      if($script:LogTextBox -is [System.Windows.Forms.RichTextBox]){
        # Determine color by level / keyword
        $defaultColor = $script:LogTextBox.ForeColor
        $color = $defaultColor
        switch($level){
          'ERROR' { $color = [System.Drawing.Color]::FromArgb(220,40,40) }    # red
          'WARN'  { $color = [System.Drawing.Color]::FromArgb(210,120,0) }    # dark orange
          'DEBUG' { $color = [System.Drawing.Color]::Gray }
          default {
            # INFO: green if message looks like a success outcome
            if($msg -match '(?i)\b(success|succeeded|completed|created|applied|imported|exported|done|OK)\b' `
               -or $msg -match '\[OK\]'){
              $color = [System.Drawing.Color]::FromArgb(0,140,0)               # green
            }
          }
        }
        $start = $script:LogTextBox.TextLength
        $script:LogTextBox.AppendText($line + [Environment]::NewLine)
        $script:LogTextBox.Select($start, ($script:LogTextBox.TextLength - $start))
        $script:LogTextBox.SelectionColor = $color
        $script:LogTextBox.Select($script:LogTextBox.TextLength, 0)
        $script:LogTextBox.SelectionColor = $defaultColor
        $script:LogTextBox.ScrollToCaret()
      } else {
        $script:LogTextBox.AppendText($line + [Environment]::NewLine)
      }
    } catch {}
  }

  # Mirror to a secondary TextBox/RichTextBox (e.g. Reconcile tab log) when set,
  # so users don't have to switch back to the Actions tab to watch progress. If
  # the mirror is a RichTextBox we apply the same per-level coloring as the
  # main Actions log; plain TextBox stays uncolored.
  if($script:LogMirrorTextBox -and -not $script:LogMirrorTextBox.IsDisposed){
    try{
      if($script:LogMirrorTextBox -is [System.Windows.Forms.RichTextBox]){
        $mDefault = $script:LogMirrorTextBox.ForeColor
        $mColor = $mDefault
        switch($level){
          'ERROR' { $mColor = [System.Drawing.Color]::FromArgb(220,40,40) }
          'WARN'  { $mColor = [System.Drawing.Color]::FromArgb(210,120,0) }
          'DEBUG' { $mColor = [System.Drawing.Color]::Gray }
          default {
            if($msg -match '(?i)\b(success|succeeded|completed|created|applied|imported|exported|done|OK)\b' `
               -or $msg -match '\[OK\]'){
              $mColor = [System.Drawing.Color]::FromArgb(0,140,0)
            }
          }
        }
        $mStart = $script:LogMirrorTextBox.TextLength
        $script:LogMirrorTextBox.AppendText($line + [Environment]::NewLine)
        $script:LogMirrorTextBox.Select($mStart, ($script:LogMirrorTextBox.TextLength - $mStart))
        $script:LogMirrorTextBox.SelectionColor = $mColor
        $script:LogMirrorTextBox.Select($script:LogMirrorTextBox.TextLength, 0)
        $script:LogMirrorTextBox.SelectionColor = $mDefault
        $script:LogMirrorTextBox.ScrollToCaret()
      } else {
        $script:LogMirrorTextBox.AppendText($line + [Environment]::NewLine)
        $script:LogMirrorTextBox.SelectionStart = $script:LogMirrorTextBox.TextLength
        $script:LogMirrorTextBox.ScrollToCaret()
      }
    } catch {}
  }

  if($Global:Config -and $Global:Config.LogFile){
    try{
      if(-not $script:LogDirEnsured){ Ensure-Dir $Global:Config.LogFile; $script:LogDirEnsured=$true }
      [IO.File]::AppendAllText($Global:Config.LogFile, $line + [Environment]::NewLine, [Text.Encoding]::UTF8)
    } catch {}
  }
}

function Log-ConfigSummary([string]$phase){
  $src = $Global:Config.Src; $tgt = $Global:Config.Tgt
  $isExport = ($phase -match 'EXPORT')
  $isImport = ($phase -match 'IMPORT')

  # Helper to safely read a property (returns $default if missing)
  $gp = {
    param($obj,[string[]]$names,$default)
    foreach($n in $names){
      try{
        if($obj -and ($obj.PSObject.Properties.Name -contains $n)){
          $v = $obj.$n
          if($null -ne $v){ return $v }
        }
      } catch {}
    }
    return $default
  }

  # Live checkbox state (some options aren't persisted to $Global:Config)
  $cbState = {
    param([string]$varName,$default=$false)
    try{
      $cb = Get-Variable -Name $varName -Scope Script -ValueOnly -ErrorAction SilentlyContinue
      if($cb -and $cb.PSObject.Properties.Name -contains 'Checked'){ return [bool]$cb.Checked }
    } catch {}
    return $default
  }

  Write-Log ("[{0}] ============== RUN CONFIGURATION ==============" -f $phase) 'INFO'
  Write-Log ("[{0}] SRC: TenantBase={1}, User={2}, API={3}" -f $phase,$src.TenantBase,$src.Username,$src.SSApiBase) 'INFO'
  Write-Log ("[{0}] SRC: SearchText='{1}', FolderId={2}, MaxSecrets={3}" -f $phase,$src.SearchText,$src.FolderId,$src.MaxSecrets) 'INFO'
  Write-Log ("[{0}] TGT: TenantBase={1}, User={2}, API={3}" -f $phase,$tgt.TenantBase,$tgt.Username,$tgt.SSApiBase) 'INFO'
  Write-Log ("[{0}] TGT: TargetFolderId={1}, TargetRootFolderId={2}, FolderTreeMigration={3}" -f $phase,$tgt.TargetFolderId,$tgt.TargetRootFolderId,$tgt.FolderTreeMigration) 'INFO'

  # Common options (apply to both flows)
  Write-Log ("[{0}] OPTS: CopyFolderAcls={1}, CopySecretAcls={2}, CopySecretSettings={3}, CopyAttachments={4}" -f `
    $phase,$tgt.CopyFolderAcls,$tgt.CopySecretAcls,$tgt.CopySecretSettings,$tgt.CopyAttachments) 'INFO'
  Write-Log ("[{0}] OPTS: RemapPrincipals={1}, DryRun={2}, VerboseHttp={3}" -f `
    $phase,$tgt.RemapPrincipals,$tgt.DryRun,(& $cbState 'cbVerboseHttp' $false)) 'INFO'

  if($isExport){
    Write-Log ("[{0}] EXPORT OPTS: IncludeHistory={1}, ExportTemplates={2}, UseV1ExportService={3}, ExportChildFolders={4}" -f `
      $phase,$src.IncludeHistory,$src.ExportTemplates,(& $gp $src @('UseV1ExportService') $false),(& $gp $src @('ExportChildFolders') $false)) 'INFO'
    Write-Log ("[{0}] EXPORT OPTS: Incremental={1}, EncryptPasswords={2}" -f `
      $phase,(& $cbState 'cbIncremental' $false),(& $cbState 'cbEncryptPasswords' $false)) 'INFO'
    Write-Log ("[{0}] EXPORT OPTS: Outputs -> JSON={1}, XML={2}, CSV={3}, ZIP={4}" -f `
      $phase,$src.ExportJson,$src.ExportXml,$src.ExportCsv,$src.ExportZip) 'INFO'
    Write-Log ("[{0}] EXPORT OPTS: ExportFile={1}" -f $phase,$Global:Config.ExportFile) 'INFO'
  }

  if($isImport){
    $dupAct = (& $gp $tgt @('DuplicateSecretAction') 'Skip')
    Write-Log ("[{0}] IMPORT OPTS: DuplicateSecretAction={1}, OverwriteIfExists={2}, SecretTypeMapByName={3}" -f `
      $phase,$dupAct,$tgt.OverwriteIfExists,$tgt.SecretTypeMapByName) 'INFO'
    Write-Log ("[{0}] IMPORT OPTS: ImportTemplates={1}, DisableInheritPermissions={2}, DecryptPasswords={3}" -f `
      $phase,(& $gp $tgt @('ImportTemplates') $false),(& $gp $tgt @('DisableInheritPermissions') $false),(& $cbState 'cbDecryptPasswords' $false)) 'INFO'
    Write-Log ("[{0}] IMPORT OPTS: TemplateSuffix='{1}', SyncTemplateFields={2}, SkipPasswordValidation={3}, StopOnError={4}, ApplyPasswordHistory={5}" -f `
      $phase,(& $gp $tgt @('TemplateSuffix') ''),(& $cbState 'chkSyncTemplateFields' $false),(& $cbState 'cbSkipPwdVal' $false),(& $cbState 'cbStopOnError' $false),(& $cbState 'cbApplyPwdHistory' $true)) 'INFO'
    Write-Log ("[{0}] IMPORT OPTS: CleanupRollbackUpdatedSecrets={1}" -f `
      $phase,(& $gp $tgt @('CleanupRollbackUpdatedSecrets') $false)) 'INFO'
    Write-Log ("[{0}] IMPORT OPTS: InputFile={1}" -f $phase,$Global:Config.ExportFile) 'INFO'
  }

  Write-Log ("[{0}] ===============================================" -f $phase) 'INFO'
}

# =================== CRYPTOGRAPHY ===================

function ProtectPwd([Security.SecureString]$p){ $p | ConvertFrom-SecureString }
function UnprotectPwd([string]$s){ $s | ConvertTo-SecureString }
function Plain([Security.SecureString]$s){
  $b=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
  try{ [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
  finally{ [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

# Encrypt password field value using DPAPI
function Encrypt-PasswordValue([string]$plainValue){
  if([string]::IsNullOrWhiteSpace($plainValue)){ return $plainValue }
  try{
    $secureString = $plainValue | ConvertTo-SecureString -AsPlainText -Force
    $encrypted = $secureString | ConvertFrom-SecureString
    return $encrypted
  }
  catch{
    Write-Log ("ENCRYPT: Failed to encrypt password value: {0}" -f $_.Exception.Message) 'WARN'
    return $plainValue
  }
}

# Decrypt password field value using DPAPI
function Decrypt-PasswordValue([string]$encryptedValue){
  if([string]::IsNullOrWhiteSpace($encryptedValue)){ return $encryptedValue }
  try{
    # Try to decrypt - if it's already plain text, this will fail and we return original
    $secureString = $encryptedValue | ConvertTo-SecureString -ErrorAction Stop
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    return $plain
  }
  catch{
    # If decryption fails, assume it's already plain text or invalid
    Write-Log ("DECRYPT: Value is not encrypted or decryption failed, using as-is: {0}" -f $_.Exception.Message) 'DEBUG'
    return $encryptedValue
  }
}

# =================== TOKEN MANAGEMENT ===================
# Permission cache variables
$script:TgtGroupCacheLoaded = $false
$script:TgtUserCacheLoaded = $false
$script:TgtGroupNameToIdCache = @{}
$script:TgtUserNameToIdCache = @{}
$script:CreatedFolderCache = @{}
$script:PermissionCheckCache = @{}
$script:FolderPermAddedCache = @{}
$script:FolderInheritanceBrokenCache = @{}
$Global:TokenCache=@{Src=$null;Tgt=$null}

function Normalize-TokenPath([string]$p){
    if ([string]::IsNullOrWhiteSpace($p)) {
        return "/oauth2/token"
    }

    # Trim whitespace
    $p = $p.Trim()

    # If user supplied a FULL URL (https://...), return it unchanged
    if ($p -match '^https?://') {
        return $p
    }

    # Ensure leading slash
    if (-not $p.StartsWith('/')) {
        $p = "/$p"
    }

    return $p
}

function GetPwdFromUiOrConfig([string]$which,$cfg,[System.Windows.Forms.MaskedTextBox]$tb){
  # First try: UI textbox (most reliable)
  if($tb -and -not [string]::IsNullOrWhiteSpace($tb.Text)){
    Write-Log ("{0}: Using password from UI textbox" -f $which) 'DEBUG'
    return ($tb.Text | ConvertTo-SecureString -AsPlainText -Force)
  }

  # Second try: DPAPI stored password
  $dp = $null
  try{ 
    $dp = [string](Get-PropValue $cfg @('PasswordDpapi') $null) 
  } catch { 
    $dp = $null 
  }

  if($Global:Config.Auth.StorePassword -and -not [string]::IsNullOrWhiteSpace($dp)){
    try{ 
      Write-Log ("{0}: Using DPAPI stored password" -f $which) 'DEBUG'
      return (UnprotectPwd $dp) 
    }
    catch{ 
      Write-Log ("{0}: DPAPI password not decryptable: {1}" -f $which,$_.Exception.Message) 'WARN' 
    }
  }

  throw "$which Password is required. Enter it in the UI password field (or enable DPAPI store + Save config)."
}

function GetTokenObj(
  [string]$tenantBase,
  [string]$tokenUrl,
  [string]$username,
  [Security.SecureString]$pwd
){
  $u = $null
  if(-not [string]::IsNullOrWhiteSpace($tokenUrl)){
    $u = [string]$tokenUrl
  } else {
    $u = ($tenantBase.TrimEnd('/') + (Normalize-TokenPath $Global:Config.TokenPath))
  }

  $body=@{
    grant_type='password'
    username=$username
    password=(Plain $pwd)
  }
  
  Write-Log ("Requesting token for user: {0}" -f $username) 'DEBUG'
  
  # Retry-with-backoff: SS Cloud's token endpoint rate-limits the password
  # grant flow (typically ~10/min per tenant). During long migrations many
  # token refreshes can collide and return HTTP 400/429/5xx. Treat these as
  # transient and back off; only 401/403 are treated as hard credential
  # failures with no retry.
  $r = $null
  $__delays = @(0, 30, 60, 90)   # 4 attempts: immediate, +30s, +60s, +90s
  $__lastErr = $null
  $__lastStatus = 0
  for($__ai = 0; $__ai -lt $__delays.Count; $__ai++){
    if($__delays[$__ai] -gt 0){
      Write-Log ("Token retry {0}/{1} for user '{2}': sleeping {3}s after HTTP {4}..." -f ($__ai+1),($__delays.Count-1),$username,$__delays[$__ai],$__lastStatus) 'WARN'
      try{ Start-Sleep -Seconds $__delays[$__ai] } catch {}
    }
    try{
      $r = Invoke-RestMethod -Method Post -Uri $u -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
      $__lastErr = $null
      break
    }
    catch{
      $__lastErr = $_
      $__lastStatus = 0
      try{ $__lastStatus = $_.Exception.Response.StatusCode.value__ } catch {}
      # Hard credential failures: don't retry.
      if($__lastStatus -eq 401 -or $__lastStatus -eq 403){ break }
      # 400/408/429/5xx are treated as transient (SS Cloud uses 400 for rate-limited password grants).
      if(-not ($__lastStatus -eq 0 -or $__lastStatus -eq 400 -or $__lastStatus -eq 408 -or $__lastStatus -eq 429 -or $__lastStatus -ge 500)){
        break
      }
    }
  }
  if($__lastErr){
    $statusCode = $__lastStatus
    $statusDesc = ''
    try{ $statusDesc = [string]$__lastErr.Exception.Response.StatusDescription } catch {}
    
    $errorMsg = ''
    switch($statusCode){
      400 {
        $errorMsg = "Authentication failed (HTTP 400) after $($__delays.Count) attempts. SS Cloud may be rate-limiting the token endpoint, OR the credentials are invalid. Verify the password in the UI and wait 1-2 minutes before retrying."
      }
      401 {
        $errorMsg = 'Authentication failed: Unauthorized. Check username and password.'
      }
      403 {
        $errorMsg = 'Authentication failed: Account is disabled or locked. Contact your administrator.'
      }
      404 {
        $errorMsg = "Authentication failed: Token endpoint not found. Check Tenant Base URL and Token Path (current: $u)"
      }
      429 {
        $errorMsg = "Authentication failed (HTTP 429) after $($__delays.Count) attempts. SS Cloud rate limit hit on the token endpoint. Wait a few minutes before retrying."
      }
      default {
        if($statusCode -gt 0){
          $errorMsg = "Authentication failed (HTTP $statusCode): $statusDesc. Check Tenant Base URL, Username, and Password."
        }
        else{
          $errorMsg = "Cannot connect to tenant: $u. Check your internet connection and Tenant Base URL."
        }
      }
    }
    
    Write-Log $errorMsg 'ERROR'
    throw $errorMsg
  }

  $tok = $null
  foreach($k in @('access_token','accessToken','token','Token','id_token','idToken')){
    if($r -and $r.PSObject.Properties.Name -contains $k){ 
      $tok = [string]$r.$k
      break 
    }
  }
  
  if([string]::IsNullOrWhiteSpace($tok)){ 
    throw "Token endpoint did not return access_token. Check your Delinea tenant configuration." 
  }

  $exp=3600
  foreach($k in @('expires_in','expiresIn','expires','expiresSeconds')){
    if($r -and $r.PSObject.Properties.Name -contains $k){ 
      try{ 
        $exp = [int]$r.$k
        break 
      } catch {}
    }
  }

  Write-Log ("Token acquired successfully for user: {0} (TTL={1}s)" -f $username,$exp) 'DEBUG'

  # Use a 300-second safety buffer (5 min). SS Cloud tokens are typically
  # 30 min; refreshing 5 min early avoids 401 races during long migrations
  # where many requests can land within the last few seconds of validity.
  $__buf = 300
  if($exp -le 600){ $__buf = [int]([math]::Min(60,[math]::Floor($exp/2))) } # very-short-TTL tokens: half the TTL, cap 60s.
  [pscustomobject]@{ 
    access_token=$tok
    expires_utc=[DateTime]::UtcNow.AddSeconds([math]::Max(30,$exp-$__buf)) 
  }
}

function Token([ValidateSet('Src','Tgt')]$side,[System.Windows.Forms.MaskedTextBox]$tbPwd){
  $cfg = if($side -eq 'Src'){ $Global:Config.Src } else { $Global:Config.Tgt }
  $which = if($side -eq 'Src'){ 'Source' } else { 'Target' }
  
  # Check cache first
  $c = $Global:TokenCache[$side]
  if($c -and [DateTime]::UtcNow -lt $c.expires_utc){ 
    # Only log token cache hit at TRACE level (not written to log by default)
    # Uncomment line below if you need to debug token usage:
    # Write-Log ("Token ({0}): Using cached token (expires {1})" -f $which,$c.expires_utc) 'DEBUG'
    return $c.access_token 
  }

  # Validate required config
  if([string]::IsNullOrWhiteSpace($cfg.TenantBase)){
    throw "$which Tenant Base URL is not configured."
  }
  if([string]::IsNullOrWhiteSpace($cfg.Username)){
    throw "$which Username is not configured."
  }

  # Get password
  $ss = $null
  try{
    $ss = GetPwdFromUiOrConfig $which $cfg $tbPwd
  }
  catch{
    throw "$which password error: $_"
  }
  
  if($null -eq $ss){
    throw "$which Password is required but not available."
  }

  # Get token URL
  $tokenUrl = $null
  try{ $tokenUrl = [string](Get-PropValue $cfg @('TokenUrl','tokenUrl') $null) } catch {}

  Write-Log ("Token ({0}): Requesting new token for user '{1}'" -f $which,$cfg.Username) 'DEBUG'
  
  $o = GetTokenObj $cfg.TenantBase $tokenUrl $cfg.Username $ss
  $Global:TokenCache[$side] = $o
  
  Write-Log ("Token ({0}): New token acquired, expires at {1}" -f $which,$o.expires_utc) 'DEBUG'
  
  return $o.access_token
}

# ===== Universal token refresh helpers (shared by every lengthy handler) =====
function Update-MigrationTokens {
  [CmdletBinding()]
  param(
    [ref]$SrcRef,
    [ref]$TgtRef,
    [switch]$Force,
    [string]$Reason = ''
  )
  if($Force){
    try{ $Global:TokenCache.Src = $null } catch {}
    try{ $Global:TokenCache.Tgt = $null } catch {}
  }
  # Look up the password masked-textboxes in script scope so this works from
  # any Add_Click handler regardless of nesting/closure scope.
  $__tbSrc = $null; $__tbTgt = $null
  try{ $__tbSrc = Get-Variable -Name 'tbSrcPwd' -Scope Script -ValueOnly -ErrorAction SilentlyContinue } catch {}
  try{ $__tbTgt = Get-Variable -Name 'tbTgtPwd' -Scope Script -ValueOnly -ErrorAction SilentlyContinue } catch {}
  if($SrcRef){
    try{
      $SrcRef.Value = Token Src $__tbSrc
    } catch {
      try{ Write-Log ("Token refresh FAILED (Src{0}): {1}" -f ($(if($Reason){" /$Reason"}else{''})),$_.Exception.Message) 'WARN' } catch {}
      throw
    }
  }
  if($TgtRef){
    try{
      $TgtRef.Value = Token Tgt $__tbTgt
    } catch {
      try{ Write-Log ("Token refresh FAILED (Tgt{0}): {1}" -f ($(if($Reason){" /$Reason"}else{''})),$_.Exception.Message) 'WARN' } catch {}
      throw
    }
  }
  if($Force -and $Reason){
    try{ Write-Log ("Token force-refresh OK ({0}){1}{2}" -f $Reason,
      $(if($SrcRef){' src'} else {''}),
      $(if($TgtRef){' tgt'} else {''})) 'INFO' } catch {}
  }
}

# Returns $true if the message looks like a 401/Unauthorized/expired-token
# error from any SS REST surface (`SS`, raw IRM, HttpClient).
function Test-IsTokenAuthError {
  param([string]$Message)
  if([string]::IsNullOrWhiteSpace($Message)){ return $false }
  return ($Message -match '(?i)\b401\b|Unauthorized|invalid_token|token.*(expired|invalid)|access.*denied')
}

# Wrap any SS-calling action in 401 detect-and-retry. On 401-ish errors,
# force-refreshes whichever side(s) you pass [ref] for, and runs $Action once
# more. $Action is invoked AT MOST twice. Non-401 errors are rethrown.
function Invoke-WithTokenRetry {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][scriptblock]$Action,
    [ref]$SrcRef,
    [ref]$TgtRef,
    [string]$Context = ''
  )
  try {
    return & $Action
  } catch {
    $__msg = [string]$_.Exception.Message
    if(Test-IsTokenAuthError $__msg){
      try{ Write-Log ("Auth 401 in [{0}]: refreshing tokens and retrying once ({1})" -f $Context,$__msg) 'WARN' } catch {}
      Update-MigrationTokens -SrcRef $SrcRef -TgtRef $TgtRef -Force -Reason $Context
      return & $Action
    }
    throw
  }
}

function Test-ApiBaseReachable([string]$apiBase,[string]$tok){
  # lightweight call to confirm host+path works
  try{
    $null = SS $apiBase GET 'folders' $tok $null @{ 'filter.page'=1; 'filter.pageSize'=1 }
    return $true
  } catch {
    return $false
  }
}
# =================== HTTP & REST ===================

$script:VerboseHttp = $false

function Set-VerboseHttp([bool]$Enabled){
  $script:VerboseHttp = $Enabled
  Set-MinLogLevel ($(if($Enabled){'DEBUG'}else{'INFO'}))
  Write-Log ("Verbose HTTP logging set to {0}" -f $script:VerboseHttp) 'INFO'
}

function Get-FriendlyErrorMessage {
  param(
    [Parameter(Mandatory)]$ErrorRecord,
    [string]$Method,
    [string]$Uri,
    [switch]$SuppressExpected400  # NEW: allow caller to suppress expected 400s
  )
  
  $statusCode = 0
  $errorCode = ""
  $errorMessage = ""
  $resourceType = ""
  $resourceId = ""
  
  try{
    $statusCode = $ErrorRecord.Exception.Response.StatusCode.value__
  } catch {}
  
  $responseBody = $null
  # PS 5.1: Invoke-RestMethod surfaces the 4xx/5xx body on $_.ErrorDetails.Message.
  # Prefer this since Response.GetResponseStream() may already be consumed.
  try{
    if($ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace([string]$ErrorRecord.ErrorDetails.Message)){
      $responseBody = [string]$ErrorRecord.ErrorDetails.Message
    }
  } catch {}
  try{
    $resp = $ErrorRecord.Exception.Response
    if($resp -and [string]::IsNullOrWhiteSpace($responseBody)){
      $reader = New-Object IO.StreamReader($resp.GetResponseStream())
      $responseBody = $reader.ReadToEnd()
      $reader.Close()
    }
    if(-not [string]::IsNullOrWhiteSpace($responseBody)){
  try{
    # Parse JSON safely. Some tenants return non-JSON (HTML/text) for errors.
    $errorObj = $responseBody | ConvertFrom-Json -ErrorAction Stop

    if($null -ne $errorObj){
      if(($errorObj.PSObject.Properties.Name -contains 'errorCode') -and $errorObj.errorCode){
        $errorCode = [string]$errorObj.errorCode
      }
      if(($errorObj.PSObject.Properties.Name -contains 'message') -and $errorObj.message){
        $errorMessage = [string]$errorObj.message
      }
      if(($errorObj.PSObject.Properties.Name -contains 'exceptionMessage') -and $errorObj.exceptionMessage){
        $errorMessage = [string]$errorObj.exceptionMessage
      }
      # Delinea/ASP.NET ModelState validation errors are nested. Flatten them so the
      # actual field-level cause (e.g. "items[2].itemValue is required") becomes visible.
      if(($errorObj.PSObject.Properties.Name -contains 'modelState') -and $errorObj.modelState){
        try{
          $msParts = @()
          foreach($p in $errorObj.modelState.PSObject.Properties){
            $vals = @($p.Value) | ForEach-Object { [string]$_ }
            $msParts += ("{0}: {1}" -f $p.Name, ($vals -join '; '))
          }
          if($msParts.Count -gt 0){
            $errorMessage = (($errorMessage,'modelState=[' + ($msParts -join ' | ') + ']') | Where-Object { $_ }) -join ' '
          }
        } catch {}
      }
      # As a last resort if none of the friendly fields were populated, surface the raw JSON
      # so the user can see exactly what the server returned.
      if([string]::IsNullOrWhiteSpace($errorMessage)){
        $errorMessage = [string]$responseBody
      }
    }
  }
  catch{
    # Not JSON (or parse failed): keep raw body so you can see the real server error.
    if([string]::IsNullOrWhiteSpace($errorMessage)){
      $errorMessage = [string]$responseBody
    }
  }
}
  } catch {}
  
  try{
    if($Uri -match '/folders/(\d+)'){ $resourceType = "Folder"; $resourceId = $Matches[1] }
    elseif($Uri -match '/secrets/(\d+)'){ $resourceType = "Secret"; $resourceId = $Matches[1] }
    elseif($Uri -match '/folder-permissions'){ $resourceType = "Folder Permission" }
    elseif($Uri -match '/secret-permissions'){ $resourceType = "Secret Permission" }
    elseif($Uri -match '/folders'){ $resourceType = "Folder" }
    elseif($Uri -match '/secrets'){ $resourceType = "Secret" }
    elseif($Uri -match '/users'){ $resourceType = "User" }
    elseif($Uri -match '/groups'){ $resourceType = "Group" }
  } catch {}
  
  # NEW: If caller wants to suppress expected 400s, return minimal message
  if($SuppressExpected400 -and $statusCode -eq 400){
    if($Uri -match '/(folder-permissions|secret-permissions|settings)'){
      return "Expected 400 (permissions/settings not available)"
    }
  }
  
  $msg = ""
  
  switch($statusCode){
    401 {
      $msg = "Authentication failed. Check your username and password."
    }
    403 {
      $msg = if($resourceType -and $resourceId){
        "Access denied to $resourceType (ID: $resourceId). Your account does not have permission for this operation."
      } else {
        "Access denied. Your account does not have permission for this operation."
      }
    }
    404 {
      $msg = if($resourceType -and $resourceId){
        "$resourceType (ID: $resourceId) not found. It may have been deleted or you may not have access to it."
      } else {
        "Resource not found (404). Check that the item exists and you have access to it."
      }
    }
    400 {
      $msg = if($errorMessage){ "Invalid request: $errorMessage" } else { "Invalid request (400)" }
    }
    405 {
      $msg = "Operation not allowed: $Method is not supported."
    }
    409 {
      $msg = "Conflict: Item may already exist or operation conflicts with current state."
    }
    500 {
      $msg = "Server error (500). Contact Delinea support if this persists."
    }
    default {
      $msg = if($errorMessage){ "Error ($statusCode): $errorMessage" } else { "HTTP $statusCode error occurred." }
    }
  }
  
  return $msg
}

# REPLACE the SS function (around line 1150) with this version:

function SS([string]$base,[ValidateSet('GET','POST','PUT','PATCH','DELETE')]$m,[string]$path,[string]$tok,$body,$q){
  $uri=$base.TrimEnd('/') + '/' + $path.TrimStart('/')
  if($q){
    $pairs=@()
    foreach($kv in $q.GetEnumerator()){
      $pairs += ("{0}={1}" -f $kv.Key,[uri]::EscapeDataString([string]$kv.Value))
    }
    $qs=($pairs -join '&')
    if($qs){ $uri="$uri`?$qs" }
  }
  $h=@{Authorization="Bearer $tok"}

  if($script:VerboseHttp){
    Write-Log "$m $uri" 'DEBUG'
  }

  try{
    # Use 10-second timeout for permission endpoints to avoid long waits on 400 errors
    $timeout = if($uri -match '/(folder-permissions|secret-permissions)' -and $m -eq 'POST'){ 10 } else { 100 }
    
    if($PSBoundParameters.ContainsKey('body') -and $null -ne $body){
      # PS 5.1's Invoke-RestMethod transmits string -Body using the local
      # ANSI codepage (Windows-1252 on en-US), which mangles non-ASCII chars
      # like smart quotes, en/em dashes, ®, ©, etc. into garbage bytes.
      # Server-side field validators then reject the resulting content with
      # generic 'An error has occurred' (HTTP 400, empty response body).
      # Sending the JSON as a UTF-8 byte[] forces the wire format to match
      # what SS Cloud expects (application/json; charset=utf-8).
      $__json  = $body | ConvertTo-Json -Depth 80
      $__bytes = [System.Text.Encoding]::UTF8.GetBytes($__json)
      return Invoke-RestMethod -Method $m -Uri $uri -Headers $h -ContentType 'application/json; charset=utf-8' -Body $__bytes -TimeoutSec $timeout
    } else {
      return Invoke-RestMethod -Method $m -Uri $uri -Headers $h -TimeoutSec $timeout
    }
  }
  catch {
    # AUTO TOKEN REFRESH: If 401 Unauthorized, the cached token likely expired mid-run.
    # Identify which side (Src/Tgt) owns this token, invalidate its cache, re-acquire
    # a fresh token and retry the request exactly once. Guard prevents infinite recursion.
    $__sc = 0
    try{ $__sc = $_.Exception.Response.StatusCode.value__ } catch {}
    if($__sc -eq 401 -and -not $script:SSRefreshInProgress){
      $__side = $null
      try{
        if($Global:TokenCache.Src -and $Global:TokenCache.Src.access_token -eq $tok){ $__side='Src' }
        elseif($Global:TokenCache.Tgt -and $Global:TokenCache.Tgt.access_token -eq $tok){ $__side='Tgt' }
      } catch {}
      if($__side){
        $script:SSRefreshInProgress = $true
        try{
          Write-Log ("Token ({0}) expired (401) - auto-refreshing and retrying request: {1} {2}" -f $__side,$m,$uri) 'WARN'
          $Global:TokenCache[$__side] = $null
          $__pwdTb = $null
          try{
            if($__side -eq 'Src'){ $__pwdTb = Get-Variable -Name 'tbSrcPwd' -Scope Script -ValueOnly -ErrorAction SilentlyContinue }
            else                 { $__pwdTb = Get-Variable -Name 'tbTgtPwd' -Scope Script -ValueOnly -ErrorAction SilentlyContinue }
          } catch {}
          $__newTok = Token $__side $__pwdTb
          if(-not [string]::IsNullOrWhiteSpace($__newTok)){
            return (SS $base $m $path $__newTok $body $q)
          }
        }
        catch{
          Write-Log ("Token ({0}) auto-refresh failed: {1}" -f $__side,$_.Exception.Message) 'WARN'
        }
        finally{
          $script:SSRefreshInProgress = $false
        }
      }
    }

    # Suppress expected 400s for permissions/settings/groups GET endpoints
    $suppress400GET = (($uri -match '/(folder-permissions|secret-permissions|settings|groups/)') -and $m -eq 'GET')
    
    # Suppress expected 404s for password history endpoints
    $suppress404History = (($uri -match '/secrets/\d+/fields/[^/]+/history') -and $m -eq 'GET')

    # Suppress errors from password history fallback strategies (400/403/404/405 on history-related calls)
    $suppressHistoryFallback = ($uri -match '/secrets/\d+/(fields|restricted|audits|check-out|check-in|restricted/fields)')
    
    $friendlyMsg = Get-FriendlyErrorMessage -ErrorRecord $_ -Method $m -Uri $uri -SuppressExpected400:$suppress400GET
    
    # Only log ERROR if it's NOT an expected/suppressed error
    $statusCode = 0
    try{ $statusCode = $_.Exception.Response.StatusCode.value__ } catch {}
    
    if($suppress400GET -and $statusCode -eq 400){
      # Don't log at all for expected 400s on GET requests
    } elseif($suppress404History -and $statusCode -eq 404){
      # Don't log ERROR for expected 404s on password history endpoints
    } elseif($suppressHistoryFallback -and $statusCode -in @(400,403,404,405)){
      # Don't log ERROR for password history fallback strategy failures
    } else {
      Write-Log $friendlyMsg 'ERROR'
    }
    
    throw $friendlyMsg
  }
}

function Get-AccessibleFolders([string]$apiBase,[string]$tok){
  $byId = @{}  # id -> object

  $endpoints = @(
    @{ path='folders';        pageKey='filter.page'; pageSizeKey='filter.pageSize' },
    @{ path='folders/lookup'; pageKey='filter.page'; pageSizeKey='filter.pageSize' }
  )

  foreach($ep in $endpoints){
    $page = 1
    $pageSize = 200

    while($true){
      try{
        $q = @{
          ($ep.pageKey)     = $page
          ($ep.pageSizeKey) = $pageSize
        }

        # Use SS wrapper so errors are consistent and logged
        $resp = SS $apiBase GET $ep.path $tok $null $q
        $recs = @(Get-Records $resp)

        foreach($f in $recs){
          $fid = 0
          try{ $fid = [int](Get-PropValue $f @('id','folderId','Id','FolderId') 0) } catch {}
          if($fid -le 0){ continue }

          $fname = [string](Get-PropValue $f @('folderName','FolderName','name','Name') $null)
          if([string]::IsNullOrWhiteSpace($fname)){ $fname = "Folder $fid" }

          if(-not $byId.ContainsKey($fid)){
            $byId[$fid] = [pscustomobject]@{ Id = $fid; Name = $fname }
          }
        }

        if($recs.Count -lt $pageSize){ break }  # last page
        $page++

        if($page -gt 2000){
          Write-Log ("Get-AccessibleFolders: safety stop paging endpoint '{0}' at page={1}" -f $ep.path,$page) 'WARN'
          break
        }
      }
      catch{
        # If one endpoint fails, try the next one
        Write-Log ("Get-AccessibleFolders: endpoint '{0}' failed: {1}" -f $ep.path,$_) 'WARN'
        break
      }
    }
  }

  return @($byId.Values | Sort-Object -Property Id)
}

function Get-ValidSourceFolderId([string]$apiBase,[string]$tok,[int]$requestedFolderId){
  if($requestedFolderId -le 0){
    Write-Log "No source folder specified. Attempting to find accessible folders..." 'INFO'
    
    try{
      $accessible = Get-AccessibleFolders -apiBase $apiBase -tok $tok
      
            foreach($f in $accessible){
        if($f.Name -match '^Personal Folders$'){
          Write-Log ("Using accessible folder: '{0}' (ID: {1})" -f $f.Name, $f.Id) 'INFO'
          return [int]$f.Id
        }
      }
      foreach($f in $accessible){
        if($f.Name -match 'Migration'){
          Write-Log ("Using accessible folder: '{0}' (ID: {1})" -f $f.Name, $f.Id) 'INFO'
          return [int]$f.Id
        }
      }
    } catch {}
    
    throw "No accessible folders found. Please specify a valid Source Folder ID."
  }
  
  try{
    $folder = SS $apiBase GET ("folders/{0}" -f $requestedFolderId) $tok $null $null
    Write-Log ("Source folder validated: ID={0}" -f $requestedFolderId) 'INFO'
    return [int]$requestedFolderId
  }
  catch{
    Write-Log ("Source folder ID {0} is not accessible." -f $requestedFolderId) 'WARN'
    
    $accessible = Get-AccessibleFolders -apiBase $apiBase -tok $tok
    if($accessible.Count -gt 0){
      Write-Log ("Using accessible folder instead: '{0}' (ID: {1})" -f $accessible[0].Name, $accessible[0].Id) 'INFO'
      return [int]$accessible[0].Id
    }
    
    throw "Requested folder ID {0} is not accessible and no alternatives found." -f $requestedFolderId
  }
}

function Get-DescendantFolderIds([string]$ApiBase,[string]$Tok,[int]$RootFolderId){
  $all = @($RootFolderId)
  $visited = New-Object 'System.Collections.Generic.HashSet[int]'
  [void]$visited.Add($RootFolderId)
  
  $queue = New-Object System.Collections.Generic.Queue[int]
  $queue.Enqueue($RootFolderId)
  
  while($queue.Count -gt 0){
    $currentId = $queue.Dequeue()
    
    try{
      $page = 1
      $children = @()
      
      do{
        $r = SS $ApiBase GET 'folders' $Tok $null @{
          'filter.parentFolderId' = $currentId
          'filter.page' = $page
          'filter.pageSize' = 200
        }
        
        $recs = @(Get-Records $r)
        $children += $recs
        $page++
        
      } while($recs.Count -ge 200 -and $page -lt 100)
      
      foreach($child in $children){
        $childId = 0
        try{ 
          $childId = [int](Get-PropValue $child @('id','folderId','Id','FolderId') 0) 
        } catch {}
        
        if($childId -gt 0 -and $childId -ne $currentId){
          if(-not $visited.Contains($childId)){
            [void]$visited.Add($childId)
            $all += $childId
            $queue.Enqueue($childId)
          }
        }
      }
    }
    catch{
      Write-Log ("Could not enumerate children of folderId={0}: {1}" -f $currentId,$_) 'WARN'
    }
  }
  
  Write-Log ("Folder enumeration complete: {0} unique folders found" -f $all.Count) 'INFO'
  return $all
}
function Get-FoldersPage {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Tok,
    [Parameter(Mandatory)][int]$ParentFolderId,
    [int]$Page = 1,
    [int]$PageSize = 200
  )

  $resp = SS $ApiBase GET 'folders' $Tok $null @{
    'filter.parentFolderId' = $ParentFolderId
    'filter.page'           = $Page
    'filter.pageSize'       = $PageSize
  }

  return @(Get-Records $resp)
}
function Find-PersonalFoldersRootIds {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Tok
  )

  # Try to find "Personal Folders" folder(s) from the folders listing.
  # Tenants differ: some return it as a normal folder in "folders", others hide it.
  $roots = @()
  $page = 1
  $ps = 200

  while($page -le 20){
    $resp = SS $ApiBase GET 'folders' $Tok $null @{
      'filter.page'     = $page
      'filter.pageSize' = $ps
    }

    $recs = @(Get-Records $resp)
    foreach($f in $recs){
      $nm = [string](Get-PropValue $f @('folderName','FolderName','name','Name') $null)
      $id = Get-PropValue $f @('id','Id','folderId','FolderId') $null
      if($id -ne $null -and $nm -and $nm.Equals('Personal Folders',[System.StringComparison]::OrdinalIgnoreCase)){
        $roots += [int]$id
      }
    }

    if($recs.Count -lt $ps){ break }
    $page++
  }

  # If we couldn't find it, fall back to "accessible folders" (best effort)
  if($roots.Count -eq 0){
    Write-Log "Could not find 'Personal Folders' root by name. Falling back to accessible folders list." 'WARN'
    $acc = Get-AccessibleFolders -apiBase $ApiBase -tok $Tok
    foreach($f in @($acc)){
      if($f.Name -match 'Personal Folders'){
        $roots += [int]$f.Id
      }
    }
  }

  return @($roots | Select-Object -Unique)
}

function Get-ChildFolders-Ex {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Tok,
    [Parameter(Mandatory)][int]$ParentFolderId
  )

  $found = New-Object 'System.Collections.Generic.List[object]'
  $seenIds = New-Object 'System.Collections.Generic.HashSet[int]'
  
  # Only try filter-based endpoints (skip /folders/{id}/children which returns 404)
  $childEndpoints = @(
    @{
      type = 'filter-page'
      params = @{ 'filter.parentFolderId'=$ParentFolderId; 'filter.page'=1; 'filter.pageSize'=500; 'take'=500 }
    }
  )

  foreach($ep in $childEndpoints){
    $page = 1
    while($page -le 50){
      try{
        $params = $ep.params.Clone()
        $params['filter.page'] = $page
        $params['skip'] = (($page - 1) * 500)
        
        $resp = SS $ApiBase GET 'folders' $Tok $null $params
        $recs = @(Get-Records $resp)
        
        foreach($f in $recs){
          $fid = 0
          try{ $fid = [int](Get-PropValue $f @('id','Id','folderId','FolderId') 0) } catch {}
          
          if($fid -gt 0 -and $fid -ne $ParentFolderId -and $seenIds.Add($fid)){
            $found.Add($f) | Out-Null
          }
        }
        
        if($recs.Count -lt 500){ break }
        $page++
      }
      catch{
        # Silently skip - don't log ERROR for expected failures
        break
      }
    }
    
    if($found.Count -gt 0){ break }
  }
  
  return @($found.ToArray())
}
function Get-FolderDetails {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Tok,
    [Parameter(Mandatory)][int]$FolderId
  )
  
  try{
    $folder = SS $ApiBase GET ("folders/{0}" -f $FolderId) $Tok $null $null
    
    $name = [string](Get-PropValue $folder @('folderName','FolderName','name','Name') "Folder_$FolderId")
    $path = [string](Get-PropValue $folder @('folderPath','FolderPath','path','Path') "")
    $parentId = Get-PropValue $folder @('parentFolderId','ParentFolderId') $null
    
    return [PSCustomObject]@{
      Id = $FolderId
      Name = $name
      Path = $path
      ParentId = $parentId
      Raw = $folder
    }
  }
  catch{
    return [PSCustomObject]@{
      Id = $FolderId
      Name = "Folder_$FolderId"
      Path = ""
      ParentId = $null
      Raw = $null
    }
  }
}
function Get-AllFoldersRecursive-BFS {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Tok
  )

  $allFolders = New-Object 'System.Collections.Generic.List[int]'
  $folderDetails = New-Object 'System.Collections.Generic.Dictionary[int,PSCustomObject]'
  $visited = New-Object 'System.Collections.Generic.HashSet[int]'

  Write-Log "Get-AllFoldersRecursive-BFS: Fetching all accessible folders..." 'INFO'
  
  # Get ALL folders in one go using pagination
  $page = 1
  $pageSize = 500
  
  while($page -le 100){
    try{
      $params = @{
        'filter.page' = $page
        'filter.pageSize' = $pageSize
        'take' = $pageSize
        'skip' = (($page - 1) * $pageSize)
      }
      
      $resp = SS $ApiBase GET 'folders' $Tok $null $params
      $recs = @(Get-Records $resp)
      
      foreach($f in $recs){
        $fid = 0
        try{ $fid = [int](Get-PropValue $f @('id','folderId','Id','FolderId') 0) } catch {}
        
        if($fid -gt 0 -and $visited.Add($fid)){
          $allFolders.Add($fid) | Out-Null
          
          # Store folder details
          $fname = [string](Get-PropValue $f @('folderName','FolderName','name','Name') "Folder_$fid")
          $fpath = [string](Get-PropValue $f @('folderPath','FolderPath','path','Path') "")
          $folderDetails[$fid] = [PSCustomObject]@{ Id=$fid; Name=$fname; Path=$fpath }
        }
      }
      
      Write-Log ("Get-AllFoldersRecursive-BFS: page {0} returned {1} folders, total unique: {2}" -f $page,$recs.Count,$allFolders.Count) 'DEBUG'
      
      if($recs.Count -lt $pageSize){ break }
      $page++
    }
    catch{
      Write-Log ("Get-AllFoldersRecursive-BFS: page {0} failed: {1}" -f $page,$_.Exception.Message) 'WARN'
      break
    }
  }
  
  # Also try /folders/lookup endpoint
  $page = 1
  while($page -le 100){
    try{
      $params = @{
        'filter.page' = $page
        'filter.pageSize' = $pageSize
        'take' = $pageSize
      }
      
      $resp = SS $ApiBase GET 'folders/lookup' $Tok $null $params
      $recs = @(Get-Records $resp)
      
      foreach($f in $recs){
        $fid = 0
        try{ $fid = [int](Get-PropValue $f @('id','folderId','Id','FolderId') 0) } catch {}
        
        if($fid -gt 0 -and $visited.Add($fid)){
          $allFolders.Add($fid) | Out-Null
          
          $fname = [string](Get-PropValue $f @('folderName','FolderName','name','Name') "Folder_$fid")
          $fpath = [string](Get-PropValue $f @('folderPath','FolderPath','path','Path') "")
          $folderDetails[$fid] = [PSCustomObject]@{ Id=$fid; Name=$fname; Path=$fpath }
        }
      }
      
      if($recs.Count -lt $pageSize){ break }
      $page++
    }
    catch{
      break
    }
  }

  Write-Log ("Get-AllFoldersRecursive-BFS: Complete. Total unique folders: {0}" -f $allFolders.Count) 'INFO'
  
  # Log folder summary
  Write-Log "=== All Accessible Folders ===" 'INFO'
  foreach($fid in $allFolders){
    if($folderDetails.ContainsKey($fid)){
      $detail = $folderDetails[$fid]
      Write-Log ("  {0}: {1}" -f $fid,$detail.Name) 'DEBUG'
    }
  }
  Write-Log "==============================" 'INFO'
  
  $script:LastFolderDetailsMap = $folderDetails
  
  return @($allFolders.ToArray())
}


function Get-DescendantFolderIds-BFS {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Tok,
    [Parameter(Mandatory)][int[]]$RootFolderIds
  )

  $visited = New-Object 'System.Collections.Generic.HashSet[int]'
  $queue = New-Object 'System.Collections.Generic.Queue[int]'
  $all = New-Object 'System.Collections.Generic.List[int]'

  foreach($rid in @($RootFolderIds)){
    if($rid -gt 0 -and $visited.Add([int]$rid)){
      $queue.Enqueue([int]$rid)
      $all.Add([int]$rid) | Out-Null
    }
  }

  while($queue.Count -gt 0){
    $parentId = $queue.Dequeue()
    $children = @(Get-ChildFolders-Ex -ApiBase $ApiBase -Tok $Tok -ParentFolderId $parentId)
    foreach($c in $children){
      $cid = 0
      try{ $cid = [int](Get-PropValue $c @('id','Id','folderId','FolderId') 0) } catch {}
      if($cid -gt 0 -and $visited.Add($cid)){
        $queue.Enqueue($cid)
        $all.Add($cid) | Out-Null
      }
    }
  }

  return @($all.ToArray())
}

function Get-SourceFolderIdsForSearch {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Tok,
    [Nullable[int]]$RequestedFolderId
  )

  # If a specific folder was requested, get it and its descendants
  if($RequestedFolderId -ne $null -and $RequestedFolderId -gt 0){
    Write-Log ("Get-SourceFolderIdsForSearch: Using requested folderId={0} and descendants" -f $RequestedFolderId) 'INFO'
    return @(Get-DescendantFolderIds -ApiBase $ApiBase -Tok $Tok -RootFolderId ([int]$RequestedFolderId))
  }

  # No folder specified: get ALL folders via BFS traversal
  Write-Log "Get-SourceFolderIdsForSearch: No folder specified, traversing ALL folders via BFS..." 'INFO'
  
  $allFolderIds = @(Get-AllFoldersRecursive-BFS -ApiBase $ApiBase -Tok $Tok)
  
  if($allFolderIds.Count -eq 0){
    Write-Log "Get-SourceFolderIdsForSearch: BFS returned no folders. Returning empty." 'WARN'
    return @()
  }
  
  Write-Log ("Get-SourceFolderIdsForSearch: BFS traversal found {0} folders" -f $allFolderIds.Count) 'INFO'
  return $allFolderIds
}
function Test-SecretFileFieldHasContent([string]$apiBase,[string]$tok,[int]$secretId,[string]$slug){
  if([string]::IsNullOrWhiteSpace($slug) -or $secretId -le 0){ return $false }
  
  try{
    # Get the secret detail and check the specific field
    $secret = SS $apiBase GET ("secrets/{0}" -f $secretId) $tok $null $null
    $items = Get-PropValue $secret @('items','Items','fields','Fields') @()
    
    foreach($item in @($items)){
      $itemSlug = [string](Get-PropValue $item @('slug','Slug','fieldSlugName','FieldSlugName') $null)
      if($itemSlug -eq $slug){
        # Check for file attachment indicators
        $fileAttachId = Get-PropValue $item @('fileAttachmentId','FileAttachmentId') $null
        $filename = Get-PropValue $item @('filename','fileName','FileName') $null
        $value = Get-PropValue $item @('value','Value','itemValue','ItemValue') $null
        
        # File has content if:
        # 1. fileAttachmentId exists and > 0
        # 2. filename is not empty
        # 3. value contains file reference
        if($fileAttachId -ne $null){
          try{
            if([int]$fileAttachId -gt 0){ return $true }
          } catch {}
        }
        
        if(-not [string]::IsNullOrWhiteSpace([string]$filename)){
          return $true
        }
        
        if(-not [string]::IsNullOrWhiteSpace([string]$value) -and $value -notmatch '^\s*$'){
          return $true
        }
        
        return $false
      }
    }
    
    return $false
  }
  catch{
    Write-Log ("Test-SecretFileFieldHasContent: Error checking secretId={0} slug='{1}': {2}" -f $secretId,$slug,$_.Exception.Message) 'DEBUG'
    return $false
  }
}

# Fetches the plain-text value of a restricted (non-displayable) secret field via
# GET /api/v1/secrets/{id}/fields/{slug}. Returns the string value or $null on failure.
function SS-GetRestrictedFieldText([string]$apiBase,[string]$tok,[int]$secretId,[string]$slug){
  if([string]::IsNullOrWhiteSpace($slug)){ return $null }
  if($secretId -le 0){ return $null }

  $uri = "{0}/secrets/{1}/fields/{2}" -f $apiBase.TrimEnd('/'),$secretId,$slug
  $headers = @{ Authorization = "Bearer $tok"; Accept = "text/plain" }

  try{
    # Invoke-WebRequest returns raw content; Invoke-RestMethod may fail on plain text
    $resp = Invoke-WebRequest -Method GET -Uri $uri -Headers $headers -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
    $text = $resp.Content
    if(-not [string]::IsNullOrEmpty($text) -and $text -notmatch '^\*{3}.*\*{3}$'){
      Write-Log ("RESTRICTED-FIELD: Retrieved {0} chars for secretId={1} slug='{2}'" -f $text.Length,$secretId,$slug) 'DEBUG'
      return $text
    }
  }
  catch{
    $statusCode = 0
    try{ $statusCode = $_.Exception.Response.StatusCode.value__ } catch {}
    Write-Log ("RESTRICTED-FIELD: GET fields endpoint failed for secretId={0} slug='{1}' (HTTP {2}): {3}" -f $secretId,$slug,$statusCode,$_.Exception.Message) 'DEBUG'
  }

  # Method 2: POST /restricted/fields/{slug} (some on-prem SS versions)
  $restrictedUri = "{0}/secrets/{1}/restricted/fields/{2}" -f $apiBase.TrimEnd('/'),$secretId,$slug
  $restrictedBody = (@{
    checkIn        = $false
    comment        = 'Migration export'
    forceCheckIn   = $false
    includeInactive = $true
    noAutoCheckout = $false
  } | ConvertTo-Json)
  $restrictedHeaders = @{
    Authorization    = "Bearer $tok"
    Accept           = 'text/plain'
    'Content-Type'   = 'application/json'
  }
  try{
    $resp2 = Invoke-WebRequest -Method POST -Uri $restrictedUri -Headers $restrictedHeaders -Body $restrictedBody -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
    $text2 = $resp2.Content
    if(-not [string]::IsNullOrEmpty($text2) -and $text2 -notmatch '^\*{3}.*\*{3}$'){
      Write-Log ("RESTRICTED-FIELD: POST /restricted/fields retrieved {0} chars for secretId={1} slug='{2}'" -f $text2.Length,$secretId,$slug) 'DEBUG'
      return $text2
    }
  }
  catch{
    $sc2 = 0; try{ $sc2 = $_.Exception.Response.StatusCode.value__ } catch {}
    Write-Log ("RESTRICTED-FIELD: POST /restricted/fields failed for secretId={0} slug='{1}' (HTTP {2}): {3}" -f $secretId,$slug,$sc2,$_.Exception.Message) 'DEBUG'
  }

  # Method 3: POST /secrets/{id}/restricted — Delinea Cloud's authoritative endpoint.
  # Returns the FULL secret model (same shape as GET /secrets/{id}) but with real field
  # values even when the secret requires checkout or view-comment. Works for all field types.
  $sRestrictedUri = "{0}/secrets/{1}/restricted" -f $apiBase.TrimEnd('/'),$secretId
  $sRestrictedBody = (@{
    checkIn        = $false
    comment        = 'Migration export'
    forceCheckIn   = $false
    includeInactive = $true
    noAutoCheckout = $false
    ticketNumber   = $null
    ticketSystemId = $null
  } | ConvertTo-Json)
  $sRestrictedHdrs = @{ Authorization = "Bearer $tok"; Accept = 'application/json'; 'Content-Type' = 'application/json' }
  try{
    $sRestricted = Invoke-RestMethod -Method POST -Uri $sRestrictedUri -Headers $sRestrictedHdrs -Body $sRestrictedBody -TimeoutSec 60 -ErrorAction Stop
    # Check back in immediately to avoid leaving the secret in a checked-out state
    try{ Invoke-RestMethod -Method POST -Uri ("{0}/secrets/{1}/check-in" -f $apiBase.TrimEnd('/'),$secretId) -Headers @{Authorization="Bearer $tok"} -ContentType 'application/json' -Body '{}' -TimeoutSec 30 -ErrorAction SilentlyContinue } catch {}
    # Find the field value in the returned secret model
    $sItems = @()
    foreach($k in @('items','Items','fields','Fields')){ if($sRestricted.PSObject.Properties.Name -contains $k){ $sItems = @($sRestricted.$k); break } }
    foreach($sItem in $sItems){
      $iSlug = $null
      foreach($k in @('slug','Slug','fieldSlugName','FieldSlugName')){ if($sItem.PSObject.Properties.Name -contains $k){ $iSlug = [string]$sItem.$k; break } }
      if($iSlug -eq $slug){
        $iVal = $null
        foreach($k in @('value','Value','itemValue','ItemValue')){ if($sItem.PSObject.Properties.Name -contains $k){ $iVal = [string]$sItem.$k; break } }
        if(-not [string]::IsNullOrEmpty($iVal) -and $iVal -notmatch '^\*{3}.*\*{3}$'){
          Write-Log ("RESTRICTED-FIELD: POST /restricted returned {0} chars for secretId={1} slug='{2}'" -f $iVal.Length,$secretId,$slug) 'DEBUG'
          return $iVal
        }
        break
      }
    }
  }
  catch{
    $sc3 = 0; try{ $sc3 = $_.Exception.Response.StatusCode.value__ } catch {}
    Write-Log ("RESTRICTED-FIELD: POST /restricted failed for secretId={0} slug='{1}' (HTTP {2}): {3}" -f $secretId,$slug,$sc3,$_.Exception.Message) 'DEBUG'
  }
  return $null
}

function SS-GetFieldBytes([string]$apiBase,[string]$tok,[int]$secretId,[string]$slug){
  if([string]::IsNullOrWhiteSpace($slug)){ return $null }
  if($secretId -le 0){ return $null }
  
  Write-Log ("FILEFIELD: Attempting download for secretId={0} slug='{1}'" -f $secretId,$slug) 'DEBUG'
  
  # First, try to get the field value directly from the secret data
  # The API returns file content as base64 in the 'itemValue' when accessed correctly
  try{
    # Method 1: Get the full secret with restricted fields included
    $secretUri = "{0}/secrets/{1}" -f $apiBase.TrimEnd('/'),$secretId
    $headers = @{ 
      Authorization = "Bearer $tok"
      Accept = "application/json"
    }
    
    # Request the secret with includeInactive to ensure we get all field data
    $secretResp = Invoke-RestMethod -Method GET -Uri $secretUri -Headers $headers -ErrorAction Stop
    
    # Find the field in the items array
    $items = @()
    if($secretResp.PSObject.Properties.Name -contains 'items'){ $items = @($secretResp.items) }
    elseif($secretResp.PSObject.Properties.Name -contains 'Items'){ $items = @($secretResp.Items) }
    
    foreach($item in $items){
      $itemSlug = $null
      foreach($k in @('slug','Slug','fieldSlugName','FieldSlugName')){
        if($item.PSObject.Properties.Name -contains $k){
          $itemSlug = [string]$item.$k
          break
        }
      }
      
      if($itemSlug -eq $slug){
        # Check if this item has file content
        $isFile = $false
        try{ $isFile = [bool]$item.isFile } catch {}
        if(-not $isFile){
          try{ $isFile = [bool]$item.IsFile } catch {}
        }
        
        if($isFile){
          # For file fields, the value might be base64 encoded or we need to download separately
          $itemValue = $null
          foreach($vk in @('itemValue','ItemValue','value','Value')){
            if($item.PSObject.Properties.Name -contains $vk){
              $itemValue = $item.$vk
              break
            }
          }
          
          # If itemValue contains data, it might be base64
          # Skip the "*** Not Valid For Display ***" placeholder — fall through to download endpoints
          $isPlaceholder = ([string]$itemValue -match '^\*{3}.*\*{3}$')
          if(-not [string]::IsNullOrWhiteSpace([string]$itemValue) -and -not $isPlaceholder){
            try{
              # Try to decode as base64
              $bytes = [Convert]::FromBase64String([string]$itemValue)
              if($bytes -and $bytes.Length -gt 0){
                Write-Log ("FILEFIELD: Got {0} bytes from base64 itemValue for secretId={1} slug='{2}'" -f $bytes.Length,$secretId,$slug) 'DEBUG'
                return $bytes
              }
            }
            catch{
              # Not base64, might be text content for file field
              $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$itemValue)
              if($bytes -and $bytes.Length -gt 0){
                Write-Log ("FILEFIELD: Got {0} bytes from text itemValue for secretId={1} slug='{2}'" -f $bytes.Length,$secretId,$slug) 'DEBUG'
                return $bytes
              }
            }
          } elseif($isPlaceholder){
            Write-Log ("FILEFIELD: itemValue is restricted placeholder for secretId={0} slug='{1}'; skipping to download endpoints" -f $secretId,$slug) 'DEBUG'
          }
        }
        break
      }
    }
  }
  catch{
    Write-Log ("FILEFIELD: Method 1 (secret items) failed for secretId={0} slug='{1}': {2}" -f $secretId,$slug,$_.Exception.Message) 'DEBUG'
  }
  
  # Method 2: Try direct field download endpoint
  $downloadEndpoints = @(
    # File download specific endpoint (preferred for file/key fields)
    @{
      uri = "{0}/secrets/{1}/fields/{2}/file-download" -f $apiBase.TrimEnd('/'),$secretId,$slug
      accept = "application/octet-stream"
    },
    # Standard field endpoint (returns raw bytes for text fields)
    @{
      uri = "{0}/secrets/{1}/fields/{2}" -f $apiBase.TrimEnd('/'),$secretId,$slug
      accept = "application/octet-stream"
    },
    # Restricted field endpoint
    @{
      uri = "{0}/secrets/{1}/restricted/fields/{2}" -f $apiBase.TrimEnd('/'),$secretId,$slug
      accept = "application/octet-stream"
    }
  )
  
  $tmp = Join-Path $env:TEMP ("ss-field-" + [guid]::NewGuid().ToString("n") + ".bin")
  
  foreach($ep in $downloadEndpoints){
    try{
      $headers = @{
        Authorization = "Bearer $tok"
        Accept = $ep.accept
      }
      
      Write-Log ("FILEFIELD: Trying endpoint: {0}" -f $ep.uri) 'DEBUG'
      
      # Use Invoke-WebRequest for binary download
      $response = Invoke-WebRequest -Method GET -Uri $ep.uri -Headers $headers -UseBasicParsing -OutFile $tmp -PassThru -ErrorAction Stop
      
      if(Test-Path $tmp){
        $fileInfo = Get-Item $tmp
        if($fileInfo.Length -gt 0){
          $bytes = [IO.File]::ReadAllBytes($tmp)
          Write-Log ("FILEFIELD: SUCCESS - Downloaded {0} bytes from {1}" -f $bytes.Length,$ep.uri) 'INFO'
          return $bytes
        }
      }
    }
    catch{
      $statusCode = 0
      try{ $statusCode = $_.Exception.Response.StatusCode.value__ } catch {}
      Write-Log ("FILEFIELD: Endpoint {0} returned HTTP {1}" -f $ep.uri,$statusCode) 'DEBUG'
    }
    finally{
      try{ if(Test-Path $tmp){ Remove-Item $tmp -Force -ErrorAction SilentlyContinue } } catch {}
    }
  }
  
  # Method 3: Try POST to fields endpoint with comment (some APIs require this)
  try{
    $postUri = "{0}/secrets/{1}/fields/{2}" -f $apiBase.TrimEnd('/'),$secretId,$slug
    $postHeaders = @{
      Authorization = "Bearer $tok"
      Accept = "application/octet-stream"
      "Content-Type" = "application/json"
    }
    $postBody = @{ comment = "Migration export" } | ConvertTo-Json
    
    Write-Log ("FILEFIELD: Trying POST method to: {0}" -f $postUri) 'DEBUG'
    
    $response = Invoke-WebRequest -Method POST -Uri $postUri -Headers $postHeaders -Body $postBody -UseBasicParsing -OutFile $tmp -PassThru -ErrorAction Stop
    
    if(Test-Path $tmp){
      $fileInfo = Get-Item $tmp
      if($fileInfo.Length -gt 0){
        $bytes = [IO.File]::ReadAllBytes($tmp)
        Write-Log ("FILEFIELD: SUCCESS (POST) - Downloaded {0} bytes" -f $bytes.Length) 'INFO'
        return $bytes
      }
    }
  }
  catch{
    Write-Log ("FILEFIELD: POST method failed: {0}" -f $_.Exception.Message) 'DEBUG'
  }
  finally{
    try{ if(Test-Path $tmp){ Remove-Item $tmp -Force -ErrorAction SilentlyContinue } } catch {}
  }
  
  # Method 4: POST /restricted/fields/{slug} — Delinea endpoint for fields that are
  # checkout/comment protected or marked as sensitive. Returns raw file bytes.
  try{
    $restrictedUri = "{0}/secrets/{1}/restricted/fields/{2}" -f $apiBase.TrimEnd('/'),$secretId,$slug
    $restrictedBody = (@{
      checkIn         = $false
      comment         = 'Migration export'
      forceCheckIn    = $false
      includeInactive = $true
      noAutoCheckout  = $false
    } | ConvertTo-Json)
    $restrictedHeaders = @{
      Authorization  = "Bearer $tok"
      Accept         = 'application/octet-stream'
      'Content-Type' = 'application/json'
    }

    Write-Log ("FILEFIELD: Trying POST to restricted/fields endpoint: {0}" -f $restrictedUri) 'DEBUG'

    $response = Invoke-WebRequest -Method POST -Uri $restrictedUri -Headers $restrictedHeaders -Body $restrictedBody -UseBasicParsing -OutFile $tmp -PassThru -ErrorAction Stop
    if(Test-Path $tmp){
      $fileInfo = Get-Item $tmp
      if($fileInfo.Length -gt 0){
        $bytes = [IO.File]::ReadAllBytes($tmp)
        # Reject if it came back as the placeholder text
        $asText = [System.Text.Encoding]::UTF8.GetString($bytes)
        if($asText -notmatch '^\*{3}.*\*{3}$'){
          Write-Log ("FILEFIELD: SUCCESS (POST restricted) - Downloaded {0} bytes for secretId={1} slug='{2}'" -f $bytes.Length,$secretId,$slug) 'INFO'
          return $bytes
        }
      }
    }
  }
  catch{
    Write-Log ("FILEFIELD: POST restricted method failed for secretId={0} slug='{1}': {2}" -f $secretId,$slug,$_.Exception.Message) 'DEBUG'
  }
  finally{
    try{ if(Test-Path $tmp){ Remove-Item $tmp -Force -ErrorAction SilentlyContinue } } catch {}
  }

  # Method 5: POST /secrets/{id}/restricted — Delinea Cloud authoritative endpoint.
  # Retrieves the full secret (bypassing checkout/comment restrictions), then:
  #   (a) returns the field value as bytes if it is a plain-text/notes field, OR
  #   (b) retries the file-download endpoints now that the secret is checked out.
  $coUri    = "{0}/secrets/{1}/restricted" -f $apiBase.TrimEnd('/'),$secretId
  $coBody   = (@{ checkIn=$false; comment='Migration export'; forceCheckIn=$false; includeInactive=$true; noAutoCheckout=$false; ticketNumber=$null; ticketSystemId=$null } | ConvertTo-Json)
  $coHdrs   = @{ Authorization="Bearer $tok"; Accept='application/json'; 'Content-Type'='application/json' }
  $checkedOut = $false
  try{
    Write-Log ("FILEFIELD: Trying POST /restricted checkout for secretId={0} slug='{1}'" -f $secretId,$slug) 'DEBUG'
    $coSecret = Invoke-RestMethod -Method POST -Uri $coUri -Headers $coHdrs -Body $coBody -TimeoutSec 60 -ErrorAction Stop
    $checkedOut = $true

    # (a) Check whether the field value is now readable as plain text in the response
    $coItems = @()
    foreach($k in @('items','Items','fields','Fields')){ if($coSecret.PSObject.Properties.Name -contains $k){ $coItems = @($coSecret.$k); break } }
    foreach($coItem in $coItems){
      $coSlug = $null
      foreach($k in @('slug','Slug','fieldSlugName','FieldSlugName')){ if($coItem.PSObject.Properties.Name -contains $k){ $coSlug = [string]$coItem.$k; break } }
      if($coSlug -eq $slug){
        $coVal = $null
        foreach($k in @('value','Value','itemValue','ItemValue')){ if($coItem.PSObject.Properties.Name -contains $k){ $coVal = [string]$coItem.$k; break } }
        if(-not [string]::IsNullOrEmpty($coVal) -and $coVal -notmatch '^\*{3}.*\*{3}$'){
          $coBytes = [System.Text.Encoding]::UTF8.GetBytes($coVal)
          Write-Log ("FILEFIELD: SUCCESS (POST /restricted text) - {0} bytes for secretId={1} slug='{2}'" -f $coBytes.Length,$secretId,$slug) 'INFO'
          return $coBytes
        }
        break
      }
    }

    # (b) Secret is now checked out — retry the file-download endpoints
    foreach($ep in $downloadEndpoints){
      try{
        $rHdrs = @{ Authorization="Bearer $tok"; Accept=$ep.accept }
        $rResp = Invoke-WebRequest -Method GET -Uri $ep.uri -Headers $rHdrs -UseBasicParsing -OutFile $tmp -PassThru -ErrorAction Stop
        if(Test-Path $tmp){
          $rInfo = Get-Item $tmp
          if($rInfo.Length -gt 0){
            $rBytes = [IO.File]::ReadAllBytes($tmp)
            $rText  = [System.Text.Encoding]::UTF8.GetString($rBytes)
            if($rText -notmatch '^\*{3}.*\*{3}$'){
              Write-Log ("FILEFIELD: SUCCESS (POST /restricted + download) - {0} bytes for secretId={1} slug='{2}'" -f $rBytes.Length,$secretId,$slug) 'INFO'
              return $rBytes
            }
          }
        }
      }
      catch{ }
      finally{ try{ if(Test-Path $tmp){ Remove-Item $tmp -Force -ErrorAction SilentlyContinue } } catch {} }
    }
  }
  catch{
    $sc5 = 0; try{ $sc5 = $_.Exception.Response.StatusCode.value__ } catch {}
    Write-Log ("FILEFIELD: POST /restricted failed for secretId={0} slug='{1}' (HTTP {2}): {3}" -f $secretId,$slug,$sc5,$_.Exception.Message) 'DEBUG'
  }
  finally{
    # Always check the secret back in
    if($checkedOut){
      try{ Invoke-RestMethod -Method POST -Uri ("{0}/secrets/{1}/check-in" -f $apiBase.TrimEnd('/'),$secretId) -Headers @{Authorization="Bearer $tok"} -ContentType 'application/json' -Body '{}' -TimeoutSec 30 -ErrorAction SilentlyContinue } catch {}
    }
    try{ if(Test-Path $tmp){ Remove-Item $tmp -Force -ErrorAction SilentlyContinue } } catch {}
  }

  Write-Log ("FILEFIELD: All download methods failed for secretId={0} slug='{1}'" -f $secretId,$slug) 'WARN'
  return $null
}
# =================== HELPERS ===================}

function Get-Records($r){
  if($null -eq $r){ return @() }
  foreach($k in @('records','items','secrets','data')){
    if(Has-Prop $r $k){ return @($r.$k) }
  }
  return @($r)
}

function Add-IfValidInt([hashtable]$h,[string]$key,$value){
  if($null -eq $value){ return }
  try{
    $i=[int]$value
    if($i -ge 1){ $h[$key]=$i }
  }catch{}
}

function Parse-NullableInt([string]$text){
  if([string]::IsNullOrWhiteSpace($text)){ return $null }
  try{
    $val = [int]$text.Trim()
    return $val
  } catch {
    return $null
  }
}
function Normalize-ApiBase([string]$apiBase, [string]$tenantBase){
  # Normalize to https://<tenant>/api/v1
  if([string]::IsNullOrWhiteSpace($apiBase)){
    if([string]::IsNullOrWhiteSpace($tenantBase)){ return $null }
    return ($tenantBase.TrimEnd('/') + '/api/v1')
  }

  $b = $apiBase.Trim()

  if($b -match '^https://https://'){
    $b = $b -replace '^https://https://', 'https://'
  }

  # If user pasted tenant root (no /api/v1), append it
  if($b -notmatch '/api/v\d+$'){
    $b = $b.TrimEnd('/')
    $b = $b + '/api/v1'
  }

  return $b
}
function Validate-ApiBaseUrl([string]$apiBase){
  if([string]::IsNullOrWhiteSpace($apiBase)){
    return @{ Valid = $false; Message = "API Base URL is empty" }
  }
  
  # Check for common URL issues
  if($apiBase -notmatch '^https?://'){
    return @{ Valid = $false; Message = "API Base URL must start with https://" }
  }
  
  # Check for missing .com/.net/.org etc in secretservercloud URLs
  if($apiBase -match 'secretservercloud/' -and $apiBase -notmatch 'secretservercloud\.(com|net|org|eu|au)'){
    $suggested = $apiBase -replace '(secretservercloud)(/)', '$1.com$2'
    return @{ 
      Valid = $false
      Message = "API Base URL appears to be missing domain extension.`n`nCurrent: $apiBase`nDid you mean: $suggested" 
    }
  }
  
  # Check for double https://
  if($apiBase -match '^https://https://'){
    return @{ Valid = $false; Message = "API Base URL has duplicate https://" }
  }
  
  # Check URL ends with /api/v1 or /api/v2
  if($apiBase -notmatch '/api/v\d+$'){
    return @{ Valid = $false; Message = "API Base URL should end with /api/v1 (e.g., https://tenant.secretservercloud.com/api/v1)" }
  }
  
  return @{ Valid = $true; Message = "" }
}
# =================== EXPORT FUNCTIONS ===================
function Export-SettingsToXml {
  param(
    [Parameter(Mandatory)][string]$InputJsonPath,
    [Parameter(Mandatory)][string]$OutXmlPath
  )

  if(-not (Test-Path $InputJsonPath)){
    Write-Log "Settings XML: Input JSON not found: $InputJsonPath" 'WARN'
    return 0
  }

  $root = Read-LargeJsonAsPSObject $InputJsonPath
  $secrets = @($root.Secrets)
  
  $settingsCount = 0
  
  # Build XML
  $doc = New-Object System.Xml.XmlDocument
  $decl = $doc.CreateXmlDeclaration("1.0", "utf-8", $null)
  [void]$doc.AppendChild($decl)

  $rootNode = $doc.CreateElement("SecretSettings")
  [void]$doc.AppendChild($rootNode)

  foreach($sec in $secrets){
    $settings = Get-PropValue $sec @('SecretSettings','secretSettings') $null
    if($null -eq $settings){ continue }
    
    $secName = [string](Get-PropValue $sec @('Name','name') "Unknown")
    $secId = Get-PropValue $sec @('Id','id','SecretId','secretId') 0
    
    $secNode = $doc.CreateElement("Secret")
    [void]$secNode.SetAttribute("id", $secId)
    [void]$secNode.SetAttribute("name", $secName)
    
    # Add settings as child elements
    foreach($prop in $settings.PSObject.Properties){
      if($prop.MemberType -notin @('NoteProperty','Property')){ continue }
      
      $settingNode = $doc.CreateElement($prop.Name)
      $settingNode.InnerText = [string]$prop.Value
      [void]$secNode.AppendChild($settingNode)
    }
    
    [void]$rootNode.AppendChild($secNode)
    $settingsCount++
  }

  Ensure-Dir $OutXmlPath
  $doc.Save($OutXmlPath)
  
  Write-Log ("Settings XML: Exported settings for {0} secrets to {1}" -f $settingsCount,$OutXmlPath) 'INFO'
  return $settingsCount
}
function Get-SecretLookupPage {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Token,
    [int]$Page = 1,
    [int]$PageSize = 200,
    [string]$Search = '*',
    [Nullable[int]]$FolderId = $null
  )
  
  # Build query - use BOTH pagination styles for compatibility
  $q = @{
    'filter.searchText' = $Search
    'filter.page'       = $Page
    'filter.pageSize'   = $PageSize
    'take'              = $PageSize
    'skip'              = (($Page - 1) * $PageSize)
  }
  
  if($FolderId -ne $null -and $FolderId -gt 0){
    $q['filter.folderId'] = $FolderId
  }
  
  try{
    $resp = SS $ApiBase GET 'secrets/lookup' $Token $null $q
    $recs = @(Get-Records $resp)
    
    # Log actual count returned for debugging
    if($recs.Count -gt 0){
      Write-Log ("SecretLookup: folderId={0} page={1} returned={2}" -f $FolderId,$Page,$recs.Count) 'DEBUG'
    }
    
    return @{
      endpoint = 'secrets/lookup'
      records  = $recs
      hasMore  = ($recs.Count -ge $PageSize)
    }
  } 
  catch {
    Write-Log ("Secret lookup failed for folderId={0}: {1}" -f $FolderId,$_.Exception.Message) 'WARN'
    return @{
      endpoint = 'secrets/lookup'
      records  = @()
      hasMore  = $false
    }
  }
}
function Get-SecretsInFolder {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Token,
    [Parameter(Mandatory)][int]$FolderId
  )
  
  $allSecrets = New-Object 'System.Collections.Generic.List[object]'
  $seenIds = New-Object 'System.Collections.Generic.HashSet[int]'
  
  # Try multiple endpoints - some work better than others in different tenants
  $endpoints = @(
    # Pattern 1: /secrets with filter.folderId (most common)
    @{
      path = 'secrets'
      params = @{ 'filter.folderId'=$FolderId; 'filter.includeSubFolders'=$false; 'take'=500 }
    },
    # Pattern 2: /secrets/lookup with filter.folderId  
    @{
      path = 'secrets/lookup'
      params = @{ 'filter.folderId'=$FolderId; 'filter.searchText'='*'; 'take'=500 }
    },
    # Pattern 3: /folders/{id}/secrets
    @{
      path = "folders/$FolderId/secrets"
      params = @{ 'take'=500 }
    }
  )
  
  foreach($ep in $endpoints){
    $page = 1
    $foundInEndpoint = 0
    
    while($page -le 100){  # Safety limit
      try{
        $params = $ep.params.Clone()
        $params['filter.page'] = $page
        $params['filter.pageSize'] = 500
        $params['skip'] = (($page - 1) * 500)
        
        $resp = SS $ApiBase GET $ep.path $Token $null $params
        $recs = @(Get-Records $resp)
        
        foreach($rec in $recs){
          $sid = $null
          try{ $sid = [int](Get-PropValue $rec @('id','Id','secretId','SecretId') $null) } catch {}
          if($sid -ne $null -and $sid -gt 0 -and $seenIds.Add($sid)){
            $allSecrets.Add($rec) | Out-Null
            $foundInEndpoint++
          }
        }
        
        # If we got less than requested, we've reached the end
        if($recs.Count -lt 500){ break }
        $page++
      }
      catch{
        Write-Log ("Get-SecretsInFolder: endpoint '{0}' page {1} failed: {2}" -f $ep.path,$page,$_.Exception.Message) 'DEBUG'
        break
      }
    }
    
    if($foundInEndpoint -gt 0){
      Write-Log ("Get-SecretsInFolder: folderId={0} endpoint='{1}' found {2} secrets" -f $FolderId,$ep.path,$foundInEndpoint) 'DEBUG'
    }
  }
  
  return @($allSecrets.ToArray())
}
$script:FolderPathCache = @{}
function Get-FolderPath-Source([string]$srcApi,[string]$srcTok,[int]$srcFolderId){
  if($script:FolderPathCache.ContainsKey($srcFolderId)){
    return $script:FolderPathCache[$srcFolderId]
  }
  try{
    $folder = Get-FolderById -apiBase $srcApi -tok $srcTok -folderId $srcFolderId
    $path = [string](Get-PropValue $folder @('folderPath','FolderPath','path','Path') "\Folder$srcFolderId")
    $script:FolderPathCache[$srcFolderId] = $path
    return $path
  } catch {
    $script:FolderPathCache[$srcFolderId] = "\Folder$srcFolderId"
    return "\Folder$srcFolderId"
  }
}

function Get-FolderById([string]$apiBase,[string]$tok,[int]$folderId){
  return SS $apiBase GET ("folders/{0}" -f $folderId) $tok $null $null
}

function Get-FolderPermissions([string]$apiBase,[string]$tok,[int]$folderId){
  $perms = @()
  # Try standard filter endpoint first
  try{
    $page = 1
    while($true){
      $resp = SS $apiBase GET 'folder-permissions' $tok $null @{
        'filter.folderId' = $folderId
        'filter.page' = $page
        'filter.pageSize' = 200
      }
      $recs = @(Get-Records $resp)
      $perms += $recs
      if($recs.Count -lt 200){ break }
      $page++
    }
    if($perms.Count -gt 0){ return $perms }
  } catch {}

  # Fallback: try /folders/{id}/permissions endpoint
  try{
    $resp2 = SS $apiBase GET ("folders/{0}/permissions" -f $folderId) $tok $null @{'skip'=0;'take'=200}
    $recs2 = @(Get-Records $resp2)
    if($recs2.Count -gt 0){ return $recs2 }
  } catch {}

  # Fallback: try getting folder detail which may include permissions
  try{
    $folderDetail = SS $apiBase GET ("folders/{0}" -f $folderId) $tok $null $null
    $fp = Get-PropValue $folderDetail @('permissions','Permissions','folderPermissions','FolderPermissions') $null
    if($fp -and @($fp).Count -gt 0){ return @($fp) }
  } catch {}

  return $perms
}

function Get-SecretSettings([string]$apiBase,[string]$tok,[int]$secretId){
  try{
    return SS $apiBase GET ("secrets/{0}/settings" -f $secretId) $tok $null $null
  }
  catch{
    Write-Log ("Get-SecretSettings failed for secretId={0}: {1}" -f $secretId,$_) 'DEBUG'
    return $null
  }
}

function Get-SecretFieldHistory([string]$apiBase,[string]$tok,[int]$secretId,[string]$fieldSlug){
  # Get history for a specific field (e.g., password)
  # Tries multiple API strategies to retrieve password history under different permission models.

  # Strategy 1: Standard endpoint GET /secrets/{id}/fields/{slug}/history
  try{
    $r = SS $apiBase GET ("secrets/{0}/fields/{1}/history" -f $secretId,$fieldSlug) $tok $null @{'skip'=0;'take'=100}
    return $r
  }
  catch{
    $errMsg1 = $_.Exception.Message
    if($errMsg1 -notmatch '403|Forbidden|not authorized'){
      if($errMsg1 -match '404|Not Found'){
        Write-Log ("Get-SecretFieldHistory: No history found for secretId={0} field={1}" -f $secretId,$fieldSlug) 'DEBUG'
      } else {
        Write-Log ("Get-SecretFieldHistory failed for secretId={0} field={1}: {2}" -f $secretId,$fieldSlug,$errMsg1) 'WARN'
      }
      return $null
    }
  }

  Write-Log ("Get-SecretFieldHistory: Standard endpoint denied for secretId={0} field={1}. Trying fallback methods..." -f $secretId,$fieldSlug) 'DEBUG'

  # Strategy 2: Try GET /secrets/{id}/fields/{slug} with history query params (some SS versions)
  try{
    $r = SS $apiBase GET ("secrets/{0}/fields/{1}" -f $secretId,$fieldSlug) $tok $null @{'getHistory'='true';'includeHistory'='true'}
    if($r){ return $r }
  } catch {}

  # Strategy 3: Access secret via restricted endpoint (provides elevated access), then get history
  $checkedOut = $false
  try{
    $restrictedBody = @{
      comment      = "Migration export - password history retrieval"
      forceCheckIn = $true
    }
    $restricted = Invoke-RestMethod -Method POST `
      -Uri ("{0}/secrets/{1}/restricted" -f $apiBase.TrimEnd('/'),$secretId) `
      -Headers @{Authorization="Bearer $tok"} -ContentType 'application/json' `
      -Body ($restrictedBody | ConvertTo-Json -Depth 10) -TimeoutSec 30
    $checkedOut = $true
    # After restricted access, retry history
    $r = SS $apiBase GET ("secrets/{0}/fields/{1}/history" -f $secretId,$fieldSlug) $tok $null @{'skip'=0;'take'=100}
    return $r
  } catch {}
  finally{
    if($checkedOut){
      try{ 
        Invoke-RestMethod -Method POST -Uri ("{0}/secrets/{1}/check-in" -f $apiBase.TrimEnd('/'),$secretId) `
          -Headers @{Authorization="Bearer $tok"} -ContentType 'application/json' `
          -Body (@{comment="Auto check-in"} | ConvertTo-Json) -TimeoutSec 15 | Out-Null
      } catch {}
    }
  }

  # Strategy 4: Use the Secret Audit endpoint to get password change events
  # GET /secrets/{id}/audits returns audit trail including password rotations
  try{
    $audits = SS $apiBase GET ("secrets/{0}/audits" -f $secretId) $tok $null @{'skip'=0;'take'=200}
    $records = @(Get-Records $audits)
    # Filter for password-change related audit actions
    $pwdAudits = @($records | Where-Object {
      $action = Get-PropValue $_ @('action','Action','actionName','ActionName') ''
      $action -match 'password|rotate|change|check.?in|launched'
    })
    if($pwdAudits.Count -gt 0){
      Write-Log ("Get-SecretFieldHistory: Got {0} password-related audit entries for secretId={1} via audit trail" -f $pwdAudits.Count,$secretId) 'DEBUG'
      # Return audit entries as history (won't have actual password values but captures change events)
      $historyEntries = @()
      foreach($audit in $pwdAudits){
        $historyEntries += @{
          date     = Get-PropValue $audit @('dateRecorded','DateRecorded','date','Date') $null
          userId   = Get-PropValue $audit @('userId','UserId') $null
          userName = Get-PropValue $audit @('displayName','DisplayName','userName','UserName') $null
          action   = Get-PropValue $audit @('action','Action','actionName','ActionName') $null
          notes    = Get-PropValue $audit @('notes','Notes') $null
          _source  = 'audit-trail'
        }
      }
      return $historyEntries
    }
  } catch {}

  # Strategy 5: Use Secret Server report to get password history
  # Execute built-in report "Password History" filtered to this secret
  try{
    $reportBody = @{
      id         = $null
      categoryId = $null
      name       = $null
      parameters = @(
        @{ Name='SecretId'; Value=[string]$secretId }
      )
    }
    # Try common report endpoints
    $reportEndpoints = @(
      "reports/execute"
      "reports/secret-password-history"
    )
    foreach($ep in $reportEndpoints){
      try{
        $rpt = SS $apiBase POST $ep $tok $reportBody $null
        $rptRows = @(Get-Records $rpt)
        if($rptRows.Count -gt 0){
          Write-Log ("Get-SecretFieldHistory: Got {0} history entries via report for secretId={1}" -f $rptRows.Count,$secretId) 'DEBUG'
          $historyEntries = @()
          foreach($row in $rptRows){
            $historyEntries += @{
              date     = Get-PropValue $row @('date','Date','dateChanged','DateChanged','passwordChangedDate') $null
              password = Get-PropValue $row @('password','Password','oldPassword','OldPassword') $null
              userId   = Get-PropValue $row @('userId','UserId') $null
              userName = Get-PropValue $row @('userName','UserName','changedBy','ChangedBy') $null
              _source  = 'report'
            }
          }
          return $historyEntries
        }
      } catch { continue }
    }
  } catch {}

  # Strategy 6: Try fetching via v1/winauthwebservices or legacy SOAP-like endpoint
  try{
    # Some SS instances expose history at a different base path
    $altBase = $apiBase -replace '/api/v1$','/api/v2'
    $r = Invoke-RestMethod -Method GET `
      -Uri ("{0}/secrets/{1}/fields/{2}/history?skip=0&take=100" -f $altBase.TrimEnd('/'),$secretId,$fieldSlug) `
      -Headers @{Authorization="Bearer $tok"} -TimeoutSec 30
    if($r){ return $r }
  } catch {}

  # Strategy 7: Try getting secret with all fields expanded (some versions embed history)
  try{
    $fullSecret = SS $apiBase GET ("secrets/{0}" -f $secretId) $tok $null @{'includeInactive'='true';'includeFields'='true';'includePasswordHistory'='true'}
    $ph = Get-PropValue $fullSecret @('passwordHistory','PasswordHistory','fieldHistory','FieldHistory') $null
    if($ph){ return $ph }
  } catch {}

  # All strategies exhausted
  Write-Log ("Get-SecretFieldHistory: All methods failed for secretId={0} field={1}. Ensure the role has 'Unlimited Administrator' or 'View Password History' enabled at Admin > Roles > [YourRole] > Permissions." -f $secretId,$fieldSlug) 'WARN'
  return $null
}

function Get-SecretHistory([string]$apiBase,[string]$tok,[int]$secretId,[array]$items){
  # Get history for password fields in this secret
  $historyData = @()
  foreach($item in @($items)){
    $slug = Get-PropValue $item @('slug','Slug','fieldSlugName','FieldSlugName') $null
    $itemName = Get-PropValue $item @('name','Name','fieldName','FieldName') $null
    if([string]::IsNullOrWhiteSpace($slug)){ continue }
    
    # Identify password fields by slug or name containing 'password' or 'passphrase'
    # Also check for isPassword property if available
    $isPassword = Get-PropValue $item @('isPassword','IsPassword') $false
    $lowerSlug = [string]$slug.ToLower()
    $lowerName = [string]$itemName.ToLower()
    
    $isPasswordField = $isPassword -or 
                       $lowerSlug -match 'password|passphrase|pwd' -or 
                       $lowerName -match 'password|passphrase|pwd'
    
    # Only get history for password fields
    if($isPasswordField){
      Write-Log ("EXPORT: Attempting to get password history for secretId={0} field={1}" -f $secretId,$slug) 'DEBUG'
      $hist = Get-SecretFieldHistory -apiBase $apiBase -tok $tok -secretId $secretId -fieldSlug $slug
      if($hist -ne $null){
        $historyData += @{
          fieldSlug = $slug
          history = $hist
        }
        Write-Log ("EXPORT: Got password history for secretId={0} field={1}: {2} records" -f $secretId,$slug,@($hist).Count) 'INFO'
      }
      else{
        Write-Log ("EXPORT: No history available for secretId={0} field={1}" -f $secretId,$slug) 'DEBUG'
      }
    }
  }
  return $historyData
}

function Apply-PasswordHistory {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$SecretId,
    [Parameter(Mandatory)]$PasswordHistory,
    [Parameter(Mandatory)][string]$SecretName
  )
  
  # Apply password history to a target secret
  # Password history is an array of objects with fieldSlug and history properties
  # Each history object contains an array of historical password values
  
  if($PasswordHistory -eq $null -or @($PasswordHistory).Count -eq 0){
    Write-Log ("IMPORT: No password history to apply for secret '{0}'" -f $SecretName) 'DEBUG'
    return $false
  }
  
  $totalApplied = 0
  $totalFailed = 0
  
  foreach($fieldHist in @($PasswordHistory)){
    $fieldSlug = [string](Get-PropValue $fieldHist @('fieldSlug','FieldSlug') $null)
    if([string]::IsNullOrWhiteSpace($fieldSlug)){
      Write-Log ("IMPORT: Skipping password history entry - no fieldSlug" ) 'WARN'
      continue
    }
    
    $histRecords = @(Get-PropValue $fieldHist @('history','History') @())
    if($histRecords.Count -eq 0){
      Write-Log ("IMPORT: No history records for field '{0}' in secret '{1}'" -f $fieldSlug,$SecretName) 'DEBUG'
      continue
    }
    
    # Sort history by date (oldest first) to apply in chronological order
    # History records should have a property like 'dateRecorded', 'changedDate', or similar
    $sortedRecords = $histRecords | Sort-Object {
      $dt = $null
      foreach($prop in @('dateRecorded','DateRecorded','changedDate','ChangedDate','date','Date','created','Created')){
        if($_.PSObject.Properties.Name -contains $prop){
          try{
            $dt = [DateTime]$_.$prop
            break
          } catch {}
        }
      }
      if($dt -eq $null){ $dt = [DateTime]::MinValue }
      return $dt
    }
    
    Write-Log ("IMPORT: Applying {0} historical password values for field '{1}' in secret '{2}' (id={3})" -f $sortedRecords.Count,$fieldSlug,$SecretName,$SecretId) 'INFO'
    
    $appliedCount = 0
    $failedCount = 0
    
    # Apply each historical password value in order
    # Skip the most recent one since it should already be the current value
    $recordsToApply = @($sortedRecords | Select-Object -First ($sortedRecords.Count - 1))
    
    foreach($histRecord in $recordsToApply){
      # Get the password value from the history record
      $histValue = $null
      foreach($prop in @('value','Value','itemValue','ItemValue','password','Password')){
        if($histRecord.PSObject.Properties.Name -contains $prop){
          $histValue = [string]$histRecord.$prop
          if(-not [string]::IsNullOrWhiteSpace($histValue)){
            break
          }
        }
      }
      
      if([string]::IsNullOrWhiteSpace($histValue)){
        Write-Log ("IMPORT: Skipping history record with empty value for field '{0}'" -f $fieldSlug) 'DEBUG'
        continue
      }
      
      # Update the password field to recreate history entry
      try{
        $fieldBody = @{ value = $histValue }
        SS $TgtApiBase PUT ("secrets/{0}/fields/{1}" -f $SecretId,$fieldSlug) $TgtTok $fieldBody $null | Out-Null
        $appliedCount++
        
        # Small delay to ensure proper history ordering
        Start-Sleep -Milliseconds 100
      }
      catch{
        Write-Log ("IMPORT: Failed to apply password history entry for field '{0}': {1}" -f $fieldSlug,$_.Exception.Message) 'WARN'
        $failedCount++
      }
    }
    
    if($appliedCount -gt 0){
      Write-Log ("IMPORT: Applied {0} password history entries for field '{1}' in secret '{2}' ({3} failed)" -f $appliedCount,$fieldSlug,$SecretName,$failedCount) 'INFO'
      $totalApplied += $appliedCount
      $totalFailed += $failedCount
    }
  }
  
  if($totalApplied -gt 0){
    Write-Log ("IMPORT: Password history restore complete for secret '{0}' (id={1}): {2} entries applied, {3} failed" -f $SecretName,$SecretId,$totalApplied,$totalFailed) 'INFO'
    return $true
  }
  
  return $false
}

function Export-TemplateXml([string]$apiBase,[string]$tok,[int]$templateId){
  try{
    $r = SS $apiBase GET ("secret-templates/{0}/export" -f $templateId) $tok $null $null
    $xml = Get-PropValue $r @('exportFileText','ExportFileText') $null
    if([string]::IsNullOrWhiteSpace($xml)){ throw "Template export returned empty exportFileText for templateId=$templateId" }
    return [string]$xml
  } catch {
    Write-Log ("Template export failed for templateId={0}: {1}" -f $templateId,$_) 'WARN'
    return $null
  }
}

function Get-GroupNameById([string]$apiBase,[string]$tok,[int]$groupId){
  if($groupId -le 0){ return $null }
  
  try{
    $g = SS $apiBase GET ("groups/{0}" -f $groupId) $tok $null $null
    return [string](Get-PropValue $g @('name','groupName','Name','GroupName') $null)
  } 
  catch {
    # Silently return null - don't log ERROR for expected failures
    # Some group IDs may be invalid or the user may not have permission
    Write-Log ("Get-GroupNameById: groupId={0} not accessible (expected for some groups)" -f $groupId) 'DEBUG'
    return $null
  }
}
function Get-SecretNameIndexForFolder([string]$apiBase,[string]$tok,[int]$folderId){
  $index = @{}
  $page = 1
  $ps = 200

  Write-Log ("Get-SecretNameIndexForFolder: Building index for folderId={0} using /secrets endpoint" -f $folderId) 'DEBUG'

  # Use GET /secrets with filter.folderId - this returns ALL secrets the user can access
  # (unlike /secrets/lookup which has visibility limitations)
  while($true){
    $q = @{
      'filter.folderId'   = $folderId
      'filter.page'       = $page
      'filter.pageSize'   = $ps
    }

    try{
      $resp = SS $apiBase GET 'secrets' $tok $null $q
      $recs = @(Get-Records $resp)
      
      Write-Log ("Get-SecretNameIndexForFolder: folderId={0} page={1} returned {2} records" -f $folderId,$page,$recs.Count) 'DEBUG'

      foreach($x in $recs){
        # Get the secret ID
        $id = $null
        foreach($idKey in @('id','Id','secretId','SecretId')){
          if($x.PSObject.Properties.Name -contains $idKey){
            try{ 
              $id = [int]$x.$idKey 
              if($id -gt 0){ break }
            } catch {}
          }
        }
        
        if($id -eq $null -or $id -le 0){ continue }
        
        # GET /secrets returns 'name' field directly
        $n = $null
        foreach($nameKey in @('name','Name','secretName','SecretName')){
          if($x.PSObject.Properties.Name -contains $nameKey){
            $candidate = [string]$x.$nameKey
            if(-not [string]::IsNullOrWhiteSpace($candidate)){
              $n = $candidate
              break
            }
          }
        }
        
        if([string]::IsNullOrWhiteSpace($n)){
          Write-Log ("Get-SecretNameIndexForFolder: Could not extract name for secretId={0}" -f $id) 'DEBUG'
          continue
        }
        
        # Store BOTH trimmed and untrimmed versions for matching
        $key = $n.ToLowerInvariant()
        $keyTrimmed = $n.Trim().ToLowerInvariant()
        
        if(-not $index.ContainsKey($key)){
          $index[$key] = [int]$id
          Write-Log ("  Index: '{0}' -> id={1}" -f $n,$id) 'DEBUG'
        }
        if($keyTrimmed -ne $key -and -not $index.ContainsKey($keyTrimmed)){
          $index[$keyTrimmed] = [int]$id
        }
      }

      if($recs.Count -lt $ps){ break }
      $page++
      if($page -gt 100){
        Write-Log ("Get-SecretNameIndexForFolder: safety stop paging at page={0} folderId={1}" -f $page,$folderId) 'WARN'
        break
      }
    }
    catch{
      Write-Log ("Get-SecretNameIndexForFolder: Error on page {0}: {1}" -f $page,$_.Exception.Message) 'WARN'
      break
    }
  }

  Write-Log ("Get-SecretNameIndexForFolder: folderId={0} total indexed={1}" -f $folderId,$index.Count) 'DEBUG'
  return $index
}
function Get-TemplateNameIndex([string]$apiBase,[string]$tok){
  $index = @{}
  $page = 1
  do{
    $r = SS $apiBase GET 'secret-templates' $tok $null @{'filter.page'=$page;'filter.pageSize'=200}
    $recs = @(Get-Records $r)
    foreach($t in $recs){
      $name = Get-PropValue $t @('name','Name') $null
      $id = Get-PropValue $t @('id','Id') $null
      if($name -and $id){ $index[$name.ToLowerInvariant()] = [int]$id }
    }
    $page++
  }while($recs.Count -ge 200)
  return $index
}

function Get-AllSecretTemplatesDetailed([string]$apiBase,[string]$tok,[string[]]$detailIds=$null){
  <#
  .SYNOPSIS
    Retrieves all secret templates with their full details including fields and settings.
    If $detailIds is provided, only those template IDs get full detail fetches (fields);
    others are returned with basic list info for performance.
    Uses parallel HTTP calls for speed.
  #>
  $templates = @()
  $skip = 0
  $pageSize = 100
  $totalExpected = $null
  $detailSet = @{}
  if($detailIds){ foreach($d in $detailIds){ $detailSet[[string]$d] = $true } }
  
  Write-Log "Retrieving secret templates..." 'INFO'
  
  # Phase 1: Get the list of all templates (basic info, paged)
  $allBasic = @()
  do{
    try{
      $params = @{
        'take' = $pageSize
        'skip' = $skip
      }
      $r = SS $apiBase GET 'secret-templates' $tok $null $params
      
      if ($null -eq $totalExpected) {
        $totalExpected = Get-PropValue $r @('total','Total','totalCount','TotalCount') $null
        if ($totalExpected) {
          Write-Log "  API reports $totalExpected total templates" 'INFO'
        }
      }
      
      $recs = @(Get-Records $r)
      Write-Log "  Page at skip=$skip returned $($recs.Count) templates" 'DEBUG'
      
      if ($recs.Count -eq 0) { break }
      $allBasic += $recs
      
      $skip += $recs.Count
      if($recs.Count -lt $pageSize){ break }
      if ($totalExpected -and $skip -ge $totalExpected) { break }
    }
    catch{
      Write-Log ("Get-AllSecretTemplatesDetailed: Error at skip={0}: {1}" -f $skip,$_.Exception.Message) 'ERROR'
      break
    }
  }while($true)
  
  # Phase 2: Determine which IDs need detailed fetch
  $idsToFetch = @()
  $basicOnly = @()
  foreach($tmpl in $allBasic){
    $id = Get-PropValue $tmpl @('id','Id') $null
    $isActive = Get-PropValue $tmpl @('active','Active') $true
    if($id -ne $null -and $id -gt 0 -and $isActive){
      if($detailSet.Count -eq 0 -or $detailSet.ContainsKey([string]$id)){
        $idsToFetch += [int]$id
      } else {
        $basicOnly += $tmpl
      }
    }
  }
  
  Write-Log ("  Need detailed fetch for {0} templates, {1} basic-only" -f $idsToFetch.Count,$basicOnly.Count) 'DEBUG'
  
  # Phase 3: Fetch details in parallel using HttpClient
  $detailedTemplates = @()
  if($idsToFetch.Count -gt 0){
    $baseUri = $apiBase.TrimEnd('/')
    $batchSize = 10  # concurrent requests at a time
    
    try{
      $handler = New-Object System.Net.Http.HttpClientHandler
      $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
      $client = New-Object System.Net.Http.HttpClient($handler)
      $client.Timeout = [TimeSpan]::FromSeconds(60)
      $client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer',$tok)
      $client.DefaultRequestHeaders.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('application/json'))
      
      for($i = 0; $i -lt $idsToFetch.Count; $i += $batchSize){
        $batch = $idsToFetch[$i..([Math]::Min($i + $batchSize - 1, $idsToFetch.Count - 1))]
        $tasks = @()
        
        foreach($tid in $batch){
          $url = "$baseUri/secret-templates/$tid"
          $tasks += @{ Id = $tid; Task = $client.GetAsync($url) }
        }
        
        # Wait for all tasks in this batch
        try{
          [System.Threading.Tasks.Task]::WaitAll(($tasks | ForEach-Object { $_.Task }), 30000) | Out-Null
        } catch {}
        
        foreach($t in $tasks){
          try{
            $response = $t.Task.Result
            if($response.IsSuccessStatusCode){
              $json = $response.Content.ReadAsStringAsync().Result
              $detailed = $json | ConvertFrom-Json
              $detailedTemplates += $detailed
              Write-Log ("  Retrieved template: {0} (ID: {1})" -f (Get-PropValue $detailed @('name','Name') 'Unknown'),$t.Id) 'DEBUG'
            } else {
              Write-Log ("  Failed to get template ID {0}: HTTP {1}" -f $t.Id,$response.StatusCode) 'WARN'
            }
          }
          catch{
            Write-Log ("  Failed to get details for template ID {0}: {1}" -f $t.Id,$_.Exception.Message) 'WARN'
          }
        }
        
        Write-Log ("  Fetched batch {0}-{1} of {2}" -f ($i+1),[Math]::Min($i+$batchSize,$idsToFetch.Count),$idsToFetch.Count) 'DEBUG'
      }
    }
    catch{
      Write-Log ("Get-AllSecretTemplatesDetailed: HttpClient error: {0}. Falling back to sequential." -f $_.Exception.Message) 'WARN'
      # Fallback: sequential fetch for any remaining
      $fetchedIds = $detailedTemplates | ForEach-Object { Get-PropValue $_ @('id','Id') 0 }
      foreach($tid in $idsToFetch){
        if($tid -in $fetchedIds){ continue }
        try{
          $detailed = SS $apiBase GET ("secret-templates/{0}" -f $tid) $tok $null $null
          $detailedTemplates += $detailed
        } catch {
          Write-Log ("  Failed to get details for template ID {0}: {1}" -f $tid,$_.Exception.Message) 'WARN'
        }
      }
    }
    finally{
      if($client){ $client.Dispose() }
      if($handler){ $handler.Dispose() }
    }
  }
  
  $templates = $detailedTemplates + $basicOnly
  
  if ($totalExpected -and $templates.Count -lt $totalExpected) {
    Write-Log "API total: $totalExpected, Retrieved active: $($templates.Count) (inactive templates were skipped)" 'INFO'
  }
  
  Write-Log ("Retrieved {0} active secret templates" -f $templates.Count) 'INFO'
  return $templates
}

function Get-TemplatesFromJsonExport([string]$jsonPath){
  <#
  .SYNOPSIS
    Extracts template names from the JSON export file's TemplateExports section
  .DESCRIPTION
    Reads the secrets-export.json file and extracts template names from the 
    embedded XML in the TemplateExports section. Returns a list of template names
    found in the export, which may include templates that are no longer active.
  #>
  Write-Log "Reading templates from JSON export: $jsonPath" 'INFO'
  
  if(-not (Test-Path $jsonPath)){
    Write-Log "JSON export file not found: $jsonPath" 'ERROR'
    return @()
  }
  
  try{
    $json = Read-LargeJsonAsPSObject $jsonPath
    $templateNames = @()
    
    if($json.TemplateExports){
      foreach($tmplExport in $json.TemplateExports){
        try{
          $xml = [xml]$tmplExport.exportFileText
          $name = $xml.secrettype.name
          if($name){
            $templateNames += $name
            Write-Log ("  Found template in export: {0} (Template ID: {1})" -f $name,$tmplExport.templateId) 'DEBUG'
          }
        }
        catch{
          Write-Log ("  Failed to parse template export XML: {0}" -f $_.Exception.Message) 'WARN'
        }
      }
    }
    
    $uniqueNames = $templateNames | Sort-Object -Unique
    Write-Log ("Extracted {0} unique templates from JSON export" -f $uniqueNames.Count) 'INFO'
    return $uniqueNames
  }
  catch{
    Write-Log ("Failed to read JSON export file: {0}" -f $_.Exception.Message) 'ERROR'
    return @()
  }
}

function Update-JsonWithTemplateMapping{
  param(
    [Parameter(Mandatory)][string]$SourceJsonPath,
    [Parameter(Mandatory)][string]$OutputJsonPath,
    [Parameter(Mandatory)]$TemplateMapping
  )
  
  <#
  .SYNOPSIS
    Updates a secrets export JSON file with new template names and IDs based on mapping
  .DESCRIPTION
    Reads the source JSON export and replaces SecretTypeName and SecretTypeId fields
    for all secrets based on the provided template mapping. Useful when template names
    differ between source and target tenants.
  .PARAMETER TemplateMapping
    Array of mapping objects with properties: SourceName, SourceId, TargetName, TargetId
  #>
  
  Write-Log "Reading source JSON: $SourceJsonPath (using fast serializer)" 'INFO'
  
  if(-not (Test-Path $SourceJsonPath)){
    throw "Source JSON file not found: $SourceJsonPath"
  }
  
  try{
    # Ensure TemplateMapping is an array
    $mappings = @($TemplateMapping)
    
    # Read the JSON file using fast JavaScriptSerializer
    $json = Read-LargeJson -Path $SourceJsonPath
    
    # JavaScriptSerializer returns Dictionary<string,object> - find Secrets array
    $secretsKey = $null
    foreach ($k in @('Secrets','secrets')) {
      if ($json.ContainsKey($k)) { $secretsKey = $k; break }
    }
    if (-not $secretsKey) {
      throw "JSON file does not contain a 'Secrets' array"
    }
    $secretsList = $json[$secretsKey]
    
    # Build lookup dictionaries for fast mapping
    $nameMap = @{}  # SourceName -> TargetName
    $idMap = @{}    # SourceId -> TargetId
    
    foreach($mapping in $mappings){
      if($mapping.SourceName){ $nameMap[$mapping.SourceName] = $mapping.TargetName }
      if($mapping.SourceId -ne $null){ $idMap[[int]$mapping.SourceId] = [int]$mapping.TargetId }
    }
    
    Write-Log "Template mapping configured: $($nameMap.Count) name mappings, $($idMap.Count) ID mappings" 'INFO'
    
    # Update all secrets (working with Dictionary objects from JavaScriptSerializer)
    $updatedCount = 0
    $skippedCount = 0
    
    foreach($secret in $secretsList){
      if ($secret -isnot [System.Collections.Generic.Dictionary[string,object]]) { $skippedCount++; continue }
      
      # Get current template name and ID
      $currentName = $null
      $currentId = $null
      foreach ($k in @('SecretTypeName','secretTypeName')) {
        if ($secret.ContainsKey($k)) { $currentName = $secret[$k]; break }
      }
      foreach ($k in @('SecretTypeId','secretTypeId')) {
        if ($secret.ContainsKey($k)) { $currentId = $secret[$k]; break }
      }
      
      $updated = $false
      
      # Update template name if mapping exists
      if($currentName -and $nameMap.ContainsKey($currentName)){
        $newName = $nameMap[$currentName]
        foreach ($k in @('SecretTypeName','secretTypeName')) {
          if ($secret.ContainsKey($k)) { $secret[$k] = $newName; $updated = $true }
        }
        $secName = $null; foreach ($k in @('Name','name')) { if ($secret.ContainsKey($k)) { $secName = $secret[$k]; break } }
        Write-Log ("  Secret '{0}': Template name '{1}' -> '{2}'" -f $(if($secName){$secName}else{'Unknown'}),$currentName,$newName) 'DEBUG'
      }
      
      # Update template ID if mapping exists
      if($currentId -ne $null -and $idMap.ContainsKey([int]$currentId)){
        $newId = $idMap[[int]$currentId]
        foreach ($k in @('SecretTypeId','secretTypeId')) {
          if ($secret.ContainsKey($k)) { $secret[$k] = $newId; $updated = $true }
        }
        $secName = $null; foreach ($k in @('Name','name')) { if ($secret.ContainsKey($k)) { $secName = $secret[$k]; break } }
        Write-Log ("  Secret '{0}': Template ID {1} -> {2}" -f $(if($secName){$secName}else{'Unknown'}),$currentId,$newId) 'DEBUG'
      }
      
      if($updated){ $updatedCount++ } else { $skippedCount++ }
    }
    
    # Save the modified JSON using fast serializer
    Write-Log "Saving updated JSON to: $OutputJsonPath (using fast serializer)" 'INFO'
    Write-LargeJson -Object $json -Path $OutputJsonPath -Pretty
    
    Write-Log ("Template mapping complete: Updated {0} secrets, Skipped {1} secrets" -f $updatedCount,$skippedCount) 'INFO'
    
    return @{
      Success = $true
      SourcePath = $SourceJsonPath
      OutputPath = $OutputJsonPath
      TotalSecrets = $secretsList.Count
      UpdatedSecrets = $updatedCount
      SkippedSecrets = $skippedCount
      TemplateMappings = $mappings.Count
    }
  }
  catch{
    Write-Log ("Failed to update JSON with template mapping: {0}" -f $_.Exception.Message) 'ERROR'
    throw
  }
}

function Compare-SecretTemplates{
  param(
    [Parameter(Mandatory)]$SourceTemplates,
    [Parameter(Mandatory)]$TargetTemplates
  )
  
  <#
  .SYNOPSIS
    Compares source and target secret templates and returns a detailed comparison report
  #>
  
  $comparison = @{
    ComparisonDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Summary = @{
      SourceTemplateCount = $SourceTemplates.Count
      TargetTemplateCount = $TargetTemplates.Count
      MatchingByName = 0
      MissingInTarget = 0
      OnlyInTarget = 0
      DifferentSettings = 0
    }
    Details = @()
  }
  
  # Build target template lookup by name
  $targetByName = @{}
  foreach($t in $TargetTemplates){
    $name = Get-PropValue $t @('name','Name') $null
    if($name){ $targetByName[$name.Trim()] = $t }
  }
  
  # Compare each source template
  foreach($srcTmpl in $SourceTemplates){
    $srcName = (Get-PropValue $srcTmpl @('name','Name') 'Unknown').Trim()
    $srcId = Get-PropValue $srcTmpl @('id','Id') $null
    
    $detail = [ordered]@{
      TemplateName = $srcName
      SourceId = $srcId
      Status = ""
      Differences = @()
    }
    
    if($targetByName.ContainsKey($srcName)){
      $tgtTmpl = $targetByName[$srcName]
      $tgtId = Get-PropValue $tgtTmpl @('id','Id') $null
      $detail.TargetId = $tgtId
      $detail.Status = "Exists in both"
      $comparison.Summary.MatchingByName++
      
      # Compare fields
      $srcFields = @(Get-PropValue $srcTmpl @('fields','Fields') @())
      $tgtFields = @(Get-PropValue $tgtTmpl @('fields','Fields') @())
      
      $srcFieldNames = $srcFields | ForEach-Object { Get-PropValue $_ @('name','Name') '' } | Where-Object { $_ -ne '' }
      $tgtFieldNames = $tgtFields | ForEach-Object { Get-PropValue $_ @('name','Name') '' } | Where-Object { $_ -ne '' }
      
      # Fields only in source
      $missingFields = $srcFieldNames | Where-Object { $_ -notin $tgtFieldNames }
      if($missingFields){
        $detail.Differences += "Fields missing in target: $($missingFields -join ', ')"
      }
      
      # Fields only in target
      $extraFields = $tgtFieldNames | Where-Object { $_ -notin $srcFieldNames }
      if($extraFields){
        $detail.Differences += "Extra fields in target: $($extraFields -join ', ')"
      }
      
      # Compare field properties for matching fields
      foreach($srcField in $srcFields){
        $srcFldName = Get-PropValue $srcField @('name','Name') ''
        if([string]::IsNullOrWhiteSpace($srcFldName)){ continue }
        
        $tgtField = $tgtFields | Where-Object { (Get-PropValue $_ @('name','Name') '') -eq $srcFldName } | Select-Object -First 1
        if($tgtField){
          # Compare field types
          $srcType = Get-PropValue $srcField @('fieldTypeId','FieldTypeId','type','Type') $null
          $tgtType = Get-PropValue $tgtField @('fieldTypeId','FieldTypeId','type','Type') $null
          if($srcType -ne $tgtType){
            $detail.Differences += "Field '$srcFldName': Type differs (Source: $srcType, Target: $tgtType)"
          }
          
          # Compare required flag
          $srcReq = Get-PropValue $srcField @('isRequired','IsRequired','required','Required') $false
          $tgtReq = Get-PropValue $tgtField @('isRequired','IsRequired','required','Required') $false
          if($srcReq -ne $tgtReq){
            $detail.Differences += "Field '$srcFldName': Required flag differs (Source: $srcReq, Target: $tgtReq)"
          }
        }
      }
      
      # Compare other template settings
      $srcActive = Get-PropValue $srcTmpl @('active','Active') $true
      $tgtActive = Get-PropValue $tgtTmpl @('active','Active') $true
      if($srcActive -ne $tgtActive){
        $detail.Differences += "Active status differs (Source: $srcActive, Target: $tgtActive)"
      }
      
      # Compare checkOutEnabled
      $srcCheckout = Get-PropValue $srcTmpl @('checkOutEnabled','CheckOutEnabled') $null
      $tgtCheckout = Get-PropValue $tgtTmpl @('checkOutEnabled','CheckOutEnabled') $null
      if($srcCheckout -ne $null -and $tgtCheckout -ne $null -and $srcCheckout -ne $tgtCheckout){
        $detail.Differences += "Check Out Enabled differs (Source: $srcCheckout, Target: $tgtCheckout)"
      }
      
      # Compare sessionRecordingEnabled
      $srcSession = Get-PropValue $srcTmpl @('sessionRecordingEnabled','SessionRecordingEnabled') $null
      $tgtSession = Get-PropValue $tgtTmpl @('sessionRecordingEnabled','SessionRecordingEnabled') $null
      if($srcSession -ne $null -and $tgtSession -ne $null -and $srcSession -ne $tgtSession){
        $detail.Differences += "Session Recording Enabled differs (Source: $srcSession, Target: $tgtSession)"
      }
      
      # Compare requiresComment
      $srcComment = Get-PropValue $srcTmpl @('requiresComment','RequiresComment') $null
      $tgtComment = Get-PropValue $tgtTmpl @('requiresComment','RequiresComment') $null
      if($srcComment -ne $null -and $tgtComment -ne $null -and $srcComment -ne $tgtComment){
        $detail.Differences += "Requires Comment differs (Source: $srcComment, Target: $tgtComment)"
      }
      
      # Compare requiresApproval
      $srcApproval = Get-PropValue $srcTmpl @('requiresApproval','RequiresApproval') $null
      $tgtApproval = Get-PropValue $tgtTmpl @('requiresApproval','RequiresApproval') $null
      if($srcApproval -ne $null -and $tgtApproval -ne $null -and $srcApproval -ne $tgtApproval){
        $detail.Differences += "Requires Approval differs (Source: $srcApproval, Target: $tgtApproval)"
      }
      
      # Compare expirationDays
      $srcExpDays = Get-PropValue $srcTmpl @('expirationDays','ExpirationDays') $null
      $tgtExpDays = Get-PropValue $tgtTmpl @('expirationDays','ExpirationDays') $null
      if($srcExpDays -ne $null -and $tgtExpDays -ne $null -and $srcExpDays -ne $tgtExpDays){
        $detail.Differences += "Expiration Days differs (Source: $srcExpDays, Target: $tgtExpDays)"
      }
      
      # Compare oneTimePasswordEnabled
      $srcOTP = Get-PropValue $srcTmpl @('oneTimePasswordEnabled','OneTimePasswordEnabled') $null
      $tgtOTP = Get-PropValue $tgtTmpl @('oneTimePasswordEnabled','OneTimePasswordEnabled') $null
      if($srcOTP -ne $null -and $tgtOTP -ne $null -and $srcOTP -ne $tgtOTP){
        $detail.Differences += "One-Time Password Enabled differs (Source: $srcOTP, Target: $tgtOTP)"
      }
      
      # Compare allowMachineCredentialAccess
      $srcMachine = Get-PropValue $srcTmpl @('allowMachineCredentialAccess','AllowMachineCredentialAccess') $null
      $tgtMachine = Get-PropValue $tgtTmpl @('allowMachineCredentialAccess','AllowMachineCredentialAccess') $null
      if($srcMachine -ne $null -and $tgtMachine -ne $null -and $srcMachine -ne $tgtMachine){
        $detail.Differences += "Allow Machine Credential Access differs (Source: $srcMachine, Target: $tgtMachine)"
      }
      
      # Compare enableInheritPermissions
      $srcInherit = Get-PropValue $srcTmpl @('enableInheritPermissions','EnableInheritPermissions') $null
      $tgtInherit = Get-PropValue $tgtTmpl @('enableInheritPermissions','EnableInheritPermissions') $null
      if($srcInherit -ne $null -and $tgtInherit -ne $null -and $srcInherit -ne $tgtInherit){
        $detail.Differences += "Enable Inherit Permissions differs (Source: $srcInherit, Target: $tgtInherit)"
      }
      
      # Compare enableInheritSecretPolicy
      $srcPolicy = Get-PropValue $srcTmpl @('enableInheritSecretPolicy','EnableInheritSecretPolicy') $null
      $tgtPolicy = Get-PropValue $tgtTmpl @('enableInheritSecretPolicy','EnableInheritSecretPolicy') $null
      if($srcPolicy -ne $null -and $tgtPolicy -ne $null -and $srcPolicy -ne $tgtPolicy){
        $detail.Differences += "Enable Inherit Secret Policy differs (Source: $srcPolicy, Target: $tgtPolicy)"
      }
      
      # Compare validatePasswordRequirementsOnCreate
      $srcValidate = Get-PropValue $srcTmpl @('validatePasswordRequirementsOnCreate','ValidatePasswordRequirementsOnCreate') $null
      $tgtValidate = Get-PropValue $tgtTmpl @('validatePasswordRequirementsOnCreate','ValidatePasswordRequirementsOnCreate') $null
      if($srcValidate -ne $null -and $tgtValidate -ne $null -and $srcValidate -ne $tgtValidate){
        $detail.Differences += "Validate Password Requirements On Create differs (Source: $srcValidate, Target: $tgtValidate)"
      }
      
      # Compare validatePasswordRequirementsOnEdit
      $srcValidateEdit = Get-PropValue $srcTmpl @('validatePasswordRequirementsOnEdit','ValidatePasswordRequirementsOnEdit') $null
      $tgtValidateEdit = Get-PropValue $tgtTmpl @('validatePasswordRequirementsOnEdit','ValidatePasswordRequirementsOnEdit') $null
      if($srcValidateEdit -ne $null -and $tgtValidateEdit -ne $null -and $srcValidateEdit -ne $tgtValidateEdit){
        $detail.Differences += "Validate Password Requirements On Edit differs (Source: $srcValidateEdit, Target: $tgtValidateEdit)"
      }
      
      if($detail.Differences.Count -gt 0){
        $comparison.Summary.DifferentSettings++
      }
      
      # Remove from target lookup (for tracking target-only templates)
      $targetByName.Remove($srcName)
    }
    else{
      $detail.Status = "Missing in target"
      $detail.TargetId = $null
      $comparison.Summary.MissingInTarget++
      
      # Capture source template details for missing templates
      $srcFields = @(Get-PropValue $srcTmpl @('fields','Fields') @())
      if($srcFields.Count -gt 0){
        $fieldList = @()
        foreach($srcField in $srcFields){
          $fName = Get-PropValue $srcField @('name','Name') ''
          $fType = Get-PropValue $srcField @('fieldTypeId','FieldTypeId','type','Type') ''
          $fReq = Get-PropValue $srcField @('isRequired','IsRequired','required','Required') $false
          $reqText = if($fReq){" (Required)"}else{" (Optional)"}
          $fieldList += "$fName [Type: $fType]$reqText"
        }
        $detail.Differences += "Source template has $($srcFields.Count) fields: $($fieldList -join ', ')"
      }
      
      # Capture source template settings
      $srcActive = Get-PropValue $srcTmpl @('active','Active') $null
      if($srcActive -ne $null){ $detail.Differences += "Active: $srcActive" }
      
      $srcCheckout = Get-PropValue $srcTmpl @('checkOutEnabled','CheckOutEnabled') $null
      if($srcCheckout -ne $null){ $detail.Differences += "Check Out Enabled: $srcCheckout" }
      
      $srcSession = Get-PropValue $srcTmpl @('sessionRecordingEnabled','SessionRecordingEnabled') $null
      if($srcSession -ne $null){ $detail.Differences += "Session Recording Enabled: $srcSession" }
      
      $srcComment = Get-PropValue $srcTmpl @('requiresComment','RequiresComment') $null
      if($srcComment -ne $null){ $detail.Differences += "Requires Comment: $srcComment" }
      
      $srcApproval = Get-PropValue $srcTmpl @('requiresApproval','RequiresApproval') $null
      if($srcApproval -ne $null){ $detail.Differences += "Requires Approval: $srcApproval" }
      
      $srcExpDays = Get-PropValue $srcTmpl @('expirationDays','ExpirationDays') $null
      if($srcExpDays -ne $null){ $detail.Differences += "Expiration Days: $srcExpDays" }
      
      $srcOTP = Get-PropValue $srcTmpl @('oneTimePasswordEnabled','OneTimePasswordEnabled') $null
      if($srcOTP -ne $null){ $detail.Differences += "One-Time Password Enabled: $srcOTP" }
      
      $srcMachine = Get-PropValue $srcTmpl @('allowMachineCredentialAccess','AllowMachineCredentialAccess') $null
      if($srcMachine -ne $null){ $detail.Differences += "Allow Machine Credential Access: $srcMachine" }
      
      $srcInherit = Get-PropValue $srcTmpl @('enableInheritPermissions','EnableInheritPermissions') $null
      if($srcInherit -ne $null){ $detail.Differences += "Enable Inherit Permissions: $srcInherit" }
      
      $srcPolicy = Get-PropValue $srcTmpl @('enableInheritSecretPolicy','EnableInheritSecretPolicy') $null
      if($srcPolicy -ne $null){ $detail.Differences += "Enable Inherit Secret Policy: $srcPolicy" }
      
      $srcValidate = Get-PropValue $srcTmpl @('validatePasswordRequirementsOnCreate','ValidatePasswordRequirementsOnCreate') $null
      if($srcValidate -ne $null){ $detail.Differences += "Validate Password Requirements On Create: $srcValidate" }
      
      $srcValidateEdit = Get-PropValue $srcTmpl @('validatePasswordRequirementsOnEdit','ValidatePasswordRequirementsOnEdit') $null
      if($srcValidateEdit -ne $null){ $detail.Differences += "Validate Password Requirements On Edit: $srcValidateEdit" }
    }
    
    $comparison.Details += $detail
  }
  
  # Add templates that only exist in target
  foreach($tgtName in $targetByName.Keys){
    $tgtTmpl = $targetByName[$tgtName]
    $tgtId = Get-PropValue $tgtTmpl @('id','Id') $null
    
    $detail = [ordered]@{
      TemplateName = $tgtName
      SourceId = $null
      TargetId = $tgtId
      Status = "Only in target"
      Differences = @()
    }
    
    # Capture target template details for target-only templates
    $tgtFields = @(Get-PropValue $tgtTmpl @('fields','Fields') @())
    if($tgtFields.Count -gt 0){
      $fieldList = @()
      foreach($tgtField in $tgtFields){
        $fName = Get-PropValue $tgtField @('name','Name') ''
        $fType = Get-PropValue $tgtField @('fieldTypeId','FieldTypeId','type','Type') ''
        $fReq = Get-PropValue $tgtField @('isRequired','IsRequired','required','Required') $false
        $reqText = if($fReq){" (Required)"}else{" (Optional)"}
        $fieldList += "$fName [Type: $fType]$reqText"
      }
      $detail.Differences += "Target template has $($tgtFields.Count) fields: $($fieldList -join ', ')"
    }
    
    # Capture target template settings
    $tgtActive = Get-PropValue $tgtTmpl @('active','Active') $null
    if($tgtActive -ne $null){ $detail.Differences += "Active: $tgtActive" }
    
    $tgtCheckout = Get-PropValue $tgtTmpl @('checkOutEnabled','CheckOutEnabled') $null
    if($tgtCheckout -ne $null){ $detail.Differences += "Check Out Enabled: $tgtCheckout" }
    
    $tgtSession = Get-PropValue $tgtTmpl @('sessionRecordingEnabled','SessionRecordingEnabled') $null
    if($tgtSession -ne $null){ $detail.Differences += "Session Recording Enabled: $tgtSession" }
    
    $tgtComment = Get-PropValue $tgtTmpl @('requiresComment','RequiresComment') $null
    if($tgtComment -ne $null){ $detail.Differences += "Requires Comment: $tgtComment" }
    
    $tgtApproval = Get-PropValue $tgtTmpl @('requiresApproval','RequiresApproval') $null
    if($tgtApproval -ne $null){ $detail.Differences += "Requires Approval: $tgtApproval" }
    
    $tgtExpDays = Get-PropValue $tgtTmpl @('expirationDays','ExpirationDays') $null
    if($tgtExpDays -ne $null){ $detail.Differences += "Expiration Days: $tgtExpDays" }
    
    $tgtOTP = Get-PropValue $tgtTmpl @('oneTimePasswordEnabled','OneTimePasswordEnabled') $null
    if($tgtOTP -ne $null){ $detail.Differences += "One-Time Password Enabled: $tgtOTP" }
    
    $tgtMachine = Get-PropValue $tgtTmpl @('allowMachineCredentialAccess','AllowMachineCredentialAccess') $null
    if($tgtMachine -ne $null){ $detail.Differences += "Allow Machine Credential Access: $tgtMachine" }
    
    $tgtInherit = Get-PropValue $tgtTmpl @('enableInheritPermissions','EnableInheritPermissions') $null
    if($tgtInherit -ne $null){ $detail.Differences += "Enable Inherit Permissions: $tgtInherit" }
    
    $tgtPolicy = Get-PropValue $tgtTmpl @('enableInheritSecretPolicy','EnableInheritSecretPolicy') $null
    if($tgtPolicy -ne $null){ $detail.Differences += "Enable Inherit Secret Policy: $tgtPolicy" }
    
    $tgtValidate = Get-PropValue $tgtTmpl @('validatePasswordRequirementsOnCreate','ValidatePasswordRequirementsOnCreate') $null
    if($tgtValidate -ne $null){ $detail.Differences += "Validate Password Requirements On Create: $tgtValidate" }
    
    $tgtValidateEdit = Get-PropValue $tgtTmpl @('validatePasswordRequirementsOnEdit','ValidatePasswordRequirementsOnEdit') $null
    if($tgtValidateEdit -ne $null){ $detail.Differences += "Validate Password Requirements On Edit: $tgtValidateEdit" }
    
    $comparison.Details += $detail
    $comparison.Summary.OnlyInTarget++
  }
  
  return $comparison
}

function Export-SecretTemplateComparisonToCsv{
  param(
    [Parameter(Mandatory)]$ComparisonData,
    [Parameter(Mandatory)][string]$CsvPath
  )
  
  <#
  .SYNOPSIS
    Exports secret template comparison data to CSV format
  #>
  
  $csvRows = @()
  
  foreach($detail in $ComparisonData.Details){
    $row = [ordered]@{
      'Template Name' = $detail.TemplateName
      'Status' = $detail.Status
      'Source ID' = if($detail.SourceId) { $detail.SourceId } else { 'N/A' }
      'Target ID' = if($detail.TargetId) { $detail.TargetId } else { 'N/A' }
      'Differences Count' = $detail.Differences.Count
      'Differences' = if($detail.Differences.Count -gt 0) { $detail.Differences -join ' | ' } else { 'None' }
    }
    $csvRows += New-Object PSObject -Property $row
  }
  
  # Export to CSV
  $csvRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
  
  Write-Log "Template comparison exported to CSV: $CsvPath" 'INFO'
}

function Export-TemplateMappingsToCsv {
  param(
    [Parameter(Mandatory)]$FieldMappings,
    [Parameter(Mandatory)][string]$CsvPath
  )
  
  <#
  .SYNOPSIS
    Exports template mappings to CSV format compatible with Template Remapping Tool
    CSV Format: Source, Source ID, Target, Target ID
  #>
  
  $csvRows = @()
  $missingIds = @()
  
  foreach($mapping in $FieldMappings) {
    if (-not $mapping.Enabled) { continue }
    
    # Only populate target name if there's a target template ID
    $targetName = if (-not [string]::IsNullOrWhiteSpace($mapping.TargetTemplateId)) {
      if ($mapping.TargetTemplateName) { $mapping.TargetTemplateName } else { $mapping.TemplateName }
    } else {
      ''
    }
    
    # Check if target ID is missing
    if ([string]::IsNullOrWhiteSpace($mapping.TargetTemplateId)) {
      $missingIds += $mapping.TemplateName
    }
    
    $row = [PSCustomObject]@{
      'Source' = $mapping.TemplateName
      'Source ID' = $mapping.SourceTemplateId
      'Target' = $targetName
      'Target ID' = if ($mapping.TargetTemplateId) { $mapping.TargetTemplateId } else { '' }
    }
    $csvRows += $row
  }
  
  if ($csvRows.Count -eq 0) {
    Write-Log "No enabled template mappings to export" 'WARN'
    return @{
      Count = 0
      MissingIds = @()
    }
  }
  
  # Log warning for missing IDs
  if ($missingIds.Count -gt 0) {
    Write-Log "WARNING: $($missingIds.Count) template(s) missing Target ID: $($missingIds -join ', ')" 'WARN'
  }
  
  # Export to CSV
  $csvRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
  Write-Log "Template mappings exported to CSV: $CsvPath ($($csvRows.Count) mappings)" 'INFO'
  
  # Return info about the export
  return @{
    Count = $csvRows.Count
    MissingIds = $missingIds
  }
}

function Import-TemplateMappingsFromCsv {
  param(
    [Parameter(Mandatory)][string]$CsvPath
  )
  
  <#
  .SYNOPSIS
    Imports template mappings from CSV format
    Expected columns: Source, Source ID, Target, Target ID
  #>
  
  if (-not (Test-Path $CsvPath)) {
    Write-Log "Field mapping CSV not found: $CsvPath" 'WARN'
    return @()
  }
  
  try {
    $csvData = Import-Csv -Path $CsvPath
    
    if ($csvData.Count -eq 0) {
      Write-Log "CSV file is empty: $CsvPath" 'WARN'
      return @()
    }
    
    # Convert CSV to field mappings format
    $mappings = @()
    
    foreach ($row in $csvData) {
      $sourceName = if ($row.'Source') { $row.'Source' } else { $row.SourceName }
      $sourceId = if ($row.'Source ID') { $row.'Source ID' } else { $row.SourceId }
      $targetName = if ($row.'Target') { $row.'Target' } else { $row.TargetName }
      $targetId = if ($row.'Target ID') { $row.'Target ID' } else { $row.TargetId }
      
      $mappings += @{
        TemplateName = $sourceName
        SourceTemplateId = [int]$sourceId
        TargetTemplateName = $targetName
        TargetTemplateId = [int]$targetId
        Status = "Loaded from CSV"
        FieldMappings = @()
        Enabled = $true
      }
    }
    
    Write-Log "Template mappings loaded from CSV: $CsvPath ($($mappings.Count) mappings)" 'INFO'
    return $mappings
  } catch {
    Write-Log "Error loading template mappings from CSV: $($_.Exception.Message)" 'ERROR'
    return @()
  }
}

function Build-FieldMappingsFromComparison {
  param(
    [Parameter(Mandatory)]$ComparisonData,
    [Parameter(Mandatory)]$SourceTemplates,
    [Parameter(Mandatory)]$TargetTemplates,
    [Parameter(Mandatory=$false)][string]$TargetSuffix = ' TARGET'
  )
  
  <#
  .SYNOPSIS
    Builds field mapping data from template comparison for the mapping UI
  .PARAMETER TargetSuffix
    The suffix added to target template names (e.g., " TARGET", " XYZ", " Prod").
    Used for automatic template name matching.
  #>
  
  $mappings = @()
  
  # Build target lookup (normalize names with Trim)
  $targetByName = @{}
  $targetById = @{}
  foreach($t in $TargetTemplates){
    $name = Get-PropValue $t @('name','Name') $null
    $tid = Get-PropValue $t @('id','Id') $null
    if($name){ $targetByName[$name.Trim()] = $t }
    if($tid){ $targetById["$tid"] = $t }
  }
  
  # Build source lookup (normalize names with Trim)
  $sourceByName = @{}
  foreach($t in $SourceTemplates){
    $name = Get-PropValue $t @('name','Name') $null
    if($name){ $sourceByName[$name.Trim()] = $t }
  }
  
  foreach($detail in $ComparisonData.Details) {
    $templateName = if ($detail.TemplateName) { $detail.TemplateName.Trim() } else { $detail.TemplateName }
    
    # Process ALL templates (not just matched ones)
    # This allows users to see and manually configure mappings for templates with different names
    $srcTemplate = $sourceByName[$templateName]
    
    if ($null -eq $srcTemplate) { continue }
    
    # Try to find target template with multiple matching strategies
    $tgtTemplate = $null
    $matchConfidence = 0

    # Normalize the user-specified TargetSuffix once so callers can pass either
    # " ABCD" (leading space) or "ABCD"; we always want a single space joiner.
    $normSuffix = ''
    if (-not [string]::IsNullOrWhiteSpace($TargetSuffix)) {
        $normSuffix = ' ' + $TargetSuffix.Trim()
    }

    # Strategy 0a (highest priority when a suffix is given): exact "<source><suffix>"
    # match. Without this, a source like "Password" gets greedily matched to the
    # identically-named target "Password" (Strategy 1) before we ever try
    # "Password ABCD", and "Active Directory Account" gets fuzzy-matched to
    # "Active Directory Account Unix Servers ABCD" via substring containment.
    if ($null -eq $tgtTemplate -and $normSuffix) {
      $sought = "$templateName$normSuffix"
      if ($targetByName.ContainsKey($sought)) {
        $tgtTemplate = $targetByName[$sought]
        $matchConfidence = 100
        Write-Log "  Matched '$templateName' -> '$sought' (Strategy 0a: Source + Suffix exact)" 'INFO'
      } else {
        # Case-insensitive / whitespace-normalized fallback for the same exact pattern
        $soughtNorm = ($sought -replace '\s+',' ').Trim()
        foreach ($k in $targetByName.Keys) {
          $kNorm = ($k -replace '\s+',' ').Trim()
          if ($kNorm -ieq $soughtNorm) {
            $tgtTemplate = $targetByName[$k]
            $matchConfidence = 99
            Write-Log "  Matched '$templateName' -> '$k' (Strategy 0a: Source + Suffix exact, case/space-insensitive)" 'INFO'
            break
          }
        }
      }
    }

    # Strategy 0: Use TargetId from comparison detail (most reliable - already matched by Compare-SecretTemplates)
    if ($null -eq $tgtTemplate -and $detail.TargetId -and $targetById.ContainsKey("$($detail.TargetId)")) {
      $tgtTemplate = $targetById["$($detail.TargetId)"]
      $matchConfidence = 100
      Write-Log "  Matched '$templateName' via TargetId $($detail.TargetId) from comparison (Strategy 0: Detail TargetId)" 'INFO'
    }

    # Strategy 1: Exact name match (skipped when a TargetSuffix is configured and
    # we already searched for the suffixed form above - prevents same-name shadow
    # matches like Password->Password when Password ABCD exists).
    if ($null -eq $tgtTemplate -and -not $normSuffix -and $targetByName.ContainsKey($templateName)) {
      $tgtTemplate = $targetByName[$templateName]
      $matchConfidence = 100
      Write-Log "  Matched '$templateName' (Strategy 1: Exact match)" 'INFO'
    }
    
    # Strategy 2: Exact match + suffix
    if ($null -eq $tgtTemplate -and -not [string]::IsNullOrWhiteSpace($TargetSuffix)) {
      $possibleTargetName = "$templateName$TargetSuffix"
      Write-Log "  Strategy 2: Looking for '$possibleTargetName' (len=$($possibleTargetName.Length)) in targetByName (keys=$($targetByName.Count))" 'INFO'
      if ($targetByName.ContainsKey($possibleTargetName)) {
        $tgtTemplate = $targetByName[$possibleTargetName]
        $matchConfidence = 95
        Write-Log "  Matched '$templateName' -> '$possibleTargetName' (Strategy 2: Exact + Suffix)" 'INFO'
        
        # Verify we got a valid template object
        if ($null -eq $tgtTemplate) {
          Write-Log "  ERROR: Retrieved null template for key '$possibleTargetName'" 'ERROR'
        }
      } else {
        Write-Log "  Strategy 2: No match. Checking for similar keys..." 'INFO'
        foreach ($key in $targetByName.Keys) {
          if ($key -like "*$templateName*") {
            $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)
            $possBytes = [System.Text.Encoding]::UTF8.GetBytes($possibleTargetName)
            Write-Log "    Similar key: '$key' (len=$($key.Length), bytes=$($keyBytes.Count)) vs sought '$possibleTargetName' (len=$($possibleTargetName.Length), bytes=$($possBytes.Count))" 'INFO'
          }
        }
      }
    }
    
    # Strategy 2b: Case-insensitive match with suffix (hashtable keys can be case-sensitive)
    if ($null -eq $tgtTemplate -and -not [string]::IsNullOrWhiteSpace($TargetSuffix)) {
      $possibleTargetName = "$templateName$TargetSuffix"
      foreach ($key in $targetByName.Keys) {
        if ($key -ieq $possibleTargetName) {
          $tgtTemplate = $targetByName[$key]
          $matchConfidence = 94
          Write-Log "  Matched '$templateName' -> '$key' (Strategy 2b: Case-insensitive + Suffix)" 'INFO'
          break
        }
      }
    }
    
    # Strategy 2c: Trimmed whitespace comparison with suffix
    if ($null -eq $tgtTemplate -and -not [string]::IsNullOrWhiteSpace($TargetSuffix)) {
      $possibleNorm = ("$templateName$TargetSuffix" -replace '\s+', ' ').Trim()
      foreach ($key in $targetByName.Keys) {
        $keyNorm = ($key -replace '\s+', ' ').Trim()
        if ($keyNorm -ieq $possibleNorm) {
          $tgtTemplate = $targetByName[$key]
          $matchConfidence = 93
          Write-Log "  Matched '$templateName' -> '$key' (Strategy 2c: Normalized whitespace + Suffix)" 'INFO'
          break
        }
      }
    }
    
    # Strategy 3: Handle singular/plural with suffix (e.g., "Servers" vs "Server")
    # Only try this for templates ending in 's'
    if ($null -eq $tgtTemplate -and $templateName -match 's$' -and -not [string]::IsNullOrWhiteSpace($TargetSuffix)) {
      # Try singular version + suffix
      $singularName = $templateName -replace 's$', ''
      $possibleTargetName = "$singularName$TargetSuffix"
      if ($targetByName.ContainsKey($possibleTargetName)) {
        # Verify it's a meaningful match (not just any word ending in 's')
        $sourceWords = $templateName -split '\s+'
        $targetWords = $possibleTargetName -split '\s+'
        
        # Must have same number of words (excluding suffix) and similar structure
        if ($sourceWords.Count -eq ($targetWords.Count - 1)) {
          $tgtTemplate = $targetByName[$possibleTargetName]
          $matchConfidence = 90
        }
      }
    }
    
    # Strategy 4: Try plural version with suffix (for words not ending in 's')
    if ($null -eq $tgtTemplate -and $templateName -notmatch 's$' -and -not [string]::IsNullOrWhiteSpace($TargetSuffix)) {
      $pluralName = "$($templateName)s"
      $possibleTargetName = "$pluralName$TargetSuffix"
      if ($targetByName.ContainsKey($possibleTargetName)) {
        $sourceWords = $templateName -split '\s+'
        $targetWords = $possibleTargetName -split '\s+'
        
        if ($sourceWords.Count -eq ($targetWords.Count - 1)) {
          $tgtTemplate = $targetByName[$possibleTargetName]
          $matchConfidence = 90
        }
      }
    }
    
    # Strategy 5: Case-insensitive exact match (without TARGET suffix)
    if ($null -eq $tgtTemplate) {
      foreach ($targetName in $targetByName.Keys) {
        if ($targetName -eq $templateName -or $targetName -ieq $templateName) {
          $tgtTemplate = $targetByName[$targetName]
          $matchConfidence = 100
          break
        }
      }
    }
    
    # Strategy 6: Remove trailing 's' from last word and try with suffix
    # E.g., "Active Directory Account Unix Servers" -> "Active Directory Account Unix Server TARGET"
    if ($null -eq $tgtTemplate -and -not [string]::IsNullOrWhiteSpace($TargetSuffix)) {
      $words = $templateName -split '\s+'
      if ($words.Count -gt 1 -and $words[-1] -match 's$') {
        $words[-1] = $words[-1] -replace 's$', ''
        $modifiedName = $words -join ' '
        $possibleTargetName = "$modifiedName$TargetSuffix"
        
        if ($targetByName.ContainsKey($possibleTargetName)) {
          $tgtTemplate = $targetByName[$possibleTargetName]
          $matchConfidence = 85
          Write-Log "  Matched '$templateName' -> '$possibleTargetName' (Strategy 6: Last word singular + Suffix)" 'INFO'
        }
      }
    }
    
    # Strategy 7: Fuzzy match - source name is a substring of target name or vice versa (with suffix)
    if ($null -eq $tgtTemplate) {
      $srcNameNorm = $templateName.Trim().ToLower()

      # Normalize the user-specified TargetSuffix once (e.g., " ABCD" -> "abcd")
      $suffixTrimmed = if (-not [string]::IsNullOrWhiteSpace($TargetSuffix)) { $TargetSuffix.Trim().ToLower() } else { '' }

      # Build the list of well-known org suffixes so we can skip templates that end with
      # a DIFFERENT one (avoids matching "Foo TARGET" when the user specified suffix " ABCD")
      $knownOrgSuffixes = @('target', 'abcd', 'prod', 'dev', 'test', 'qa', 'staging')

      # Build the base-name strip pattern dynamically so the user's own suffix is also removed
      $stripTokens = [System.Collections.Generic.List[string]]@('target', 'copy', 'new', 'old', 'v2', 'v3')
      if (-not [string]::IsNullOrWhiteSpace($suffixTrimmed) -and $suffixTrimmed -notin $stripTokens) {
        $stripTokens.Add($suffixTrimmed)
      }
      $stripPattern7 = '\s*(' + (($stripTokens | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\s*$'

      # Pre-compute the source base name (source templates usually carry no org suffix)
      $srcBase7 = ($srcNameNorm -replace $stripPattern7, '').Trim()

      foreach ($targetName in $targetByName.Keys) {
        $tgtNameNorm = $targetName.Trim().ToLower()

        # If a TargetSuffix is set, skip any target template that ends with a DIFFERENT
        # known org suffix so we never accidentally match "Foo TARGET" while looking for "Foo ABCD"
        if (-not [string]::IsNullOrWhiteSpace($suffixTrimmed)) {
          $hasConflictingSuffix = $false
          foreach ($knownSuf in $knownOrgSuffixes) {
            if ($knownSuf -ne $suffixTrimmed -and $tgtNameNorm -match "\s+$([regex]::Escape($knownSuf))$") {
              $hasConflictingSuffix = $true
              break
            }
          }
          if ($hasConflictingSuffix) { continue }
        }

        # Strict substring match: only accept when one side is fully contained
        # in the other AND the lengths are within a small delta (catches typos
        # like "Foo" vs "Foo " but rejects "Active Directory Account" vs
        # "Active Directory Account Unix Servers ABCD"). The base-name path
        # below already handles legitimate suffix differences.
        $lenDelta = [Math]::Abs($tgtNameNorm.Length - $srcNameNorm.Length)
        if ($lenDelta -le 3 -and ($tgtNameNorm -like "*$srcNameNorm*" -or $srcNameNorm -like "*$tgtNameNorm*")) {
          $tgtTemplate = $targetByName[$targetName]
          $matchConfidence = 70
          Write-Log "  Matched '$templateName' -> '$targetName' (Strategy 7: Fuzzy substring match, len-delta=$lenDelta)" 'INFO'
          break
        }
        # Also try without common suffixes/prefixes (including the user's TargetSuffix)
        $tgtBase7 = ($tgtNameNorm -replace $stripPattern7, '').Trim()
        if ($srcBase7.Length -gt 3 -and $tgtBase7.Length -gt 3 -and ($srcBase7 -eq $tgtBase7)) {
          $tgtTemplate = $targetByName[$targetName]
          $matchConfidence = 75
          Write-Log "  Matched '$templateName' -> '$targetName' (Strategy 7: Base name match after suffix removal)" 'INFO'
          break
        }
      }
    }
    
    # Diagnostic: If still no match, log what was tried and list potential candidates
    if ($null -eq $tgtTemplate) {
      Write-Log "  *** NO MATCH for source template '$templateName' ***" 'WARN'
      Write-Log "    Suffix used: '$TargetSuffix'" 'WARN'
      Write-Log "    Tried exact: '$templateName'" 'WARN'
      if (-not [string]::IsNullOrWhiteSpace($TargetSuffix)) {
        Write-Log "    Tried with suffix: '$templateName$TargetSuffix'" 'WARN'
      }
      # Show closest target names for manual diagnosis
      $srcLower = $templateName.ToLower()
      $candidates = @()
      foreach ($tName in $targetByName.Keys) {
        $tLower = $tName.ToLower()
        # Check if any words overlap
        $srcWords = $srcLower -split '\s+'
        $tgtWords = $tLower -split '\s+'
        $commonWords = @($srcWords | Where-Object { $_ -in $tgtWords })
        if ($commonWords.Count -gt 0) {
          $candidates += "    Possible: '$tName' ($($commonWords.Count) common words: $($commonWords -join ', '))"
        }
      }
      if ($candidates.Count -gt 0) {
        Write-Log "    --- Possible target candidates ---" 'WARN'
        foreach ($c in $candidates) { Write-Log $c 'WARN' }
      } else {
        Write-Log "    No similar target templates found by word overlap." 'WARN'
      }
    }
    
    $srcFields = @(Get-PropValue $srcTemplate @('fields','Fields') @())
    $tgtFields = @()
    if ($tgtTemplate) {
      $tgtFields = @(Get-PropValue $tgtTemplate @('fields','Fields') @())
    }
    
    $perFieldMappings = @()
    
    foreach($srcField in $srcFields) {
      $srcFieldName = Get-PropValue $srcField @('name','Name') ''
      if([string]::IsNullOrWhiteSpace($srcFieldName)){ continue }
      
      $srcFieldId = Get-PropValue $srcField @('secretTemplateFieldId','fieldId','id','Id') $null
      $srcFieldType = Get-PropValue $srcField @('fieldTypeId','FieldTypeId','type','Type') $null
      
      # Try to find matching field in target
      $matchedTarget = $null
      $matchedTargetId = $null
      $matchedTargetType = $null
      
      if ($tgtFields -and $tgtFields.Count -gt 0) {
        $tgtField = $tgtFields | Where-Object { (Get-PropValue $_ @('name','Name') '') -eq $srcFieldName } | Select-Object -First 1
        if ($tgtField) {
          $matchedTarget = Get-PropValue $tgtField @('name','Name') ''
          $matchedTargetId = Get-PropValue $tgtField @('secretTemplateFieldId','fieldId','id','Id') $null
          $matchedTargetType = Get-PropValue $tgtField @('fieldTypeId','FieldTypeId','type','Type') $null
        }
      }
      
      $perFieldMappings += @{
        SourceFieldName = $srcFieldName
        SourceFieldId = $srcFieldId
        SourceFieldType = $srcFieldType
        TargetFieldName = $matchedTarget
        TargetFieldId = $matchedTargetId
        TargetFieldType = $matchedTargetType
        AutoMatched = ($null -ne $matchedTarget)
      }
    }
    
    # Always add template mapping, even if no fields (for template-level mapping)
    # Ensure FieldMappings is always an array
    # Enable templates that DON'T exist in target or have different names (need remapping)
    $hasTargetTemplate = ($null -ne $tgtTemplate)
    $targetTemplateName = if ($hasTargetTemplate) { (Get-PropValue $tgtTemplate @('name','Name') $null) } else { $null }
    
    # Log if no match found
    if (-not $hasTargetTemplate) {
      Write-Log "  No match found for source template '$templateName' - will need manual mapping" 'WARN'
    }
    
    # Try multiple property names for target template ID
    $targetTemplateId = $null
    if ($hasTargetTemplate) {
      # Try standard property names
      $targetTemplateId = Get-PropValue $tgtTemplate @('id','Id','secretTemplateId','SecretTemplateId','templateId','TemplateId') $null
      
      # If still null, try extracting from any property containing 'id' (case-insensitive)
      if ($null -eq $targetTemplateId -and $tgtTemplate.PSObject.Properties) {
        $idProps = $tgtTemplate.PSObject.Properties | Where-Object { $_.Name -imatch '\bid\b' -and ($_.Value -is [int] -or $_.Value -is [long]) }
        if ($idProps) {
          $targetTemplateId = $idProps[0].Value
          Write-Log "  Found target template ID using fuzzy match on property '$($idProps[0].Name)': $targetTemplateId" 'INFO'
        }
      }
      
      # Try dot notation access directly (in case it's a different object type)
      if ($null -eq $targetTemplateId) {
        try {
          if ($tgtTemplate.id) { $targetTemplateId = $tgtTemplate.id }
          elseif ($tgtTemplate.Id) { $targetTemplateId = $tgtTemplate.Id }
          elseif ($tgtTemplate.secretTemplateId) { $targetTemplateId = $tgtTemplate.secretTemplateId }
        } catch { }
      }
      
      # Debug: If still null, log available properties
      if ($null -eq $targetTemplateId) {
        $availableProps = if ($tgtTemplate.PSObject.Properties) { 
          ($tgtTemplate.PSObject.Properties | Select-Object -First 10 | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', '
        } elseif ($tgtTemplate -is [hashtable]) {
          ($tgtTemplate.Keys | Select-Object -First 10 | ForEach-Object { "$_=$($tgtTemplate[$_])" }) -join ', '
        } else { 
          "Object type: $($tgtTemplate.GetType().FullName)" 
        }
        Write-Log "  Warning: Could not find ID for target template '$targetTemplateName'. Sample properties: $availableProps" 'WARN'
      } else {
        Write-Log "  Target template '$targetTemplateName' has ID: $targetTemplateId" 'INFO'
      }
    }
    
    # Fallback to detail.TargetId if available (for exact name matches)
    if ($null -eq $targetTemplateId -and $detail.TargetId) {
      $targetTemplateId = $detail.TargetId
      Write-Log "  Using TargetId from comparison detail: $targetTemplateId" 'INFO'
    }
    
    # Enable mapping if: no target found, names differ, OR IDs differ (same name but different IDs still need remapping)
    $needsMapping = (-not $hasTargetTemplate) -or ($templateName -ne $targetTemplateName) -or ($detail.SourceId -ne $targetTemplateId)
    
    if ($needsMapping -and $hasTargetTemplate -and ($templateName -eq $targetTemplateName) -and ($detail.SourceId -ne $targetTemplateId)) {
      Write-Log "  Template '$templateName' has same name but different IDs (Source: $($detail.SourceId), Target: $targetTemplateId) - enabling mapping" 'INFO'
    }
    
    $mappings += @{
      TemplateName = $templateName
      SourceTemplateId = $detail.SourceId
      TargetTemplateId = $targetTemplateId
      TargetTemplateName = $targetTemplateName
      Status = $detail.Status
      FieldMappings = @($perFieldMappings)
      Enabled = $needsMapping
    }
  }
  
  return $mappings
}

function Load-GroupMapTranslations {
  <#
  .SYNOPSIS
    Populates script-scope translation tables from a groupsmap CSV so that
    import-time principal lookups (Get-TargetGroupIdByName /
    Get-TargetUserIdByName) can resolve source names to their mapped target
    names even when the JSON text-substitution missed a particular field.
  .OUTPUTS
    Total number of mapping rows loaded (0 if file missing or empty).
  #>
  param([Parameter(Mandatory)][string]$CsvPath)

  if(-not $script:GroupMapTranslations_Group){   $script:GroupMapTranslations_Group   = @{} }
  if(-not $script:GroupMapTranslations_User){    $script:GroupMapTranslations_User    = @{} }
  if(-not $script:GroupMapTranslations_KnownAs){ $script:GroupMapTranslations_KnownAs = @{} }

  if(-not (Test-Path $CsvPath)){
    Write-Log ("GROUPMAP-TRANSLATE: CSV not found: {0}" -f $CsvPath) 'WARN'
    return 0
  }
  $rows = @(Import-Csv -Path $CsvPath)
  if($rows.Count -le 0){ return 0 }
  foreach($r in $rows){
    try{
      $oG = if($r.OldGroupName){ $r.OldGroupName.Trim() } else { $null }
      $nG = if($r.NewGroupName){ $r.NewGroupName.Trim() } else { $null }
      if($oG -and $nG){ $script:GroupMapTranslations_Group[$oG.ToLowerInvariant()] = $nG }
      $oU = if($r.OldUserName){ $r.OldUserName.Trim() } else { $null }
      $nU = if($r.NewUserName){ $r.NewUserName.Trim() } else { $null }
      if($oU -and $nU){ $script:GroupMapTranslations_User[$oU.ToLowerInvariant()] = $nU }
      $oK = if($r.OldKnownAs){ $r.OldKnownAs.Trim() } else { $null }
      $nK = if($r.NewKnownAs){ $r.NewKnownAs.Trim() } else { $null }
      if($oK -and $nK){ $script:GroupMapTranslations_KnownAs[$oK.ToLowerInvariant()] = $nK }
    } catch {}
  }
  $script:GroupMapTranslations_LoadedFrom = $CsvPath
  Write-Log ("GROUPMAP-TRANSLATE: loaded {0} group / {1} user / {2} knownAs translations from {3}" -f $script:GroupMapTranslations_Group.Count,$script:GroupMapTranslations_User.Count,$script:GroupMapTranslations_KnownAs.Count,$CsvPath) 'INFO'
  return $rows.Count
}

function Load-TemplateMappingsCsv {
  <#
  .SYNOPSIS
    Populates script-scope template-mapping tables from a TemplateMappings.csv
    (columns: Source, Source ID, Target, Target ID) so that import-time template
    id resolution can use the CSV as an authoritative override before falling
    back to name-match / suffix-match / source-id heuristics. Uses the existing
    Import-TemplateMappingsFromCsv helper so the CSV format stays consistent
    with what the Template Check tab "Save Mappings" button writes.
  .OUTPUTS
    Total number of mapping rows loaded (0 if file missing or empty).
  #>
  param([Parameter(Mandatory)][string]$CsvPath)

  if(-not $script:TemplateMapBySrcId)  { $script:TemplateMapBySrcId  = @{} }
  if(-not $script:TemplateMapBySrcName){ $script:TemplateMapBySrcName= @{} }

  if(-not (Test-Path $CsvPath)){
    Write-Log ("TEMPLATEMAP: CSV not found: {0}" -f $CsvPath) 'WARN'
    return 0
  }
  $mappings = @(Import-TemplateMappingsFromCsv -CsvPath $CsvPath)
  if($mappings.Count -le 0){ return 0 }
  foreach($m in $mappings){
    try{
      $sid = 0; if($m.SourceTemplateId){ $sid = [int]$m.SourceTemplateId }
      $tid = 0; if($m.TargetTemplateId){ $tid = [int]$m.TargetTemplateId }
      $sName = if($m.TemplateName){ [string]$m.TemplateName } else { '' }
      $tName = if($m.TargetTemplateName){ [string]$m.TargetTemplateName } else { '' }
      if($sid -gt 0 -and $tid -gt 0){ $script:TemplateMapBySrcId[$sid] = @{ TargetId=$tid; TargetName=$tName; SourceName=$sName } }
      if($sName -and $tid -gt 0){ $script:TemplateMapBySrcName[$sName.Trim().ToLowerInvariant()] = @{ TargetId=$tid; TargetName=$tName; SourceId=$sid } }
    } catch {}
  }
  $script:TemplateMapLoadedFrom = $CsvPath
  Write-Log ("TEMPLATEMAP: loaded {0} template mappings ({1} by-id, {2} by-name) from {3}" -f $mappings.Count,$script:TemplateMapBySrcId.Count,$script:TemplateMapBySrcName.Count,$CsvPath) 'INFO'
  return $mappings.Count
}

function Apply-GroupMapCsvToJson {
  param(
    [Parameter(Mandatory)][string]$CsvPath,
    [Parameter(Mandatory)][string]$JsonPath,
    [switch]$InPlace,
    [string]$OutputPath
  )
  <#
  .SYNOPSIS
    Rewrites group/user principals in a permissions/export JSON file using a
    mapping CSV (same OldGroupName/OldKnownAs/OldUserName/OldDomainName ->
    NewGroupName/NewKnownAs/NewUserName/NewDomainName schema the Tools tab
    "Run Update" button uses). Logs via Write-Log so it shows in both the main
    log and any mirrored UI log box. Returns the total number of replacements.
  #>

  if(-not (Test-Path $CsvPath)){ Write-Log ("GROUPMAP: CSV not found: {0}" -f $CsvPath) 'WARN'; return 0 }
  if(-not (Test-Path $JsonPath)){ Write-Log ("GROUPMAP: JSON not found: {0}" -f $JsonPath) 'WARN'; return 0 }

  # Populate in-memory translation tables so import-time principal lookups
  # (Get-TargetGroupIdByName / Get-TargetUserIdByName) can fall back to the
  # CSV even when the JSON substring substitution did not match a particular
  # JSON shape (e.g. a permission entry that uses 'Name' instead of
  # 'groupName', or stores the source name in a nested 'principal' object).
  Load-GroupMapTranslations -CsvPath $CsvPath | Out-Null

  $csvRows = @(Import-Csv -Path $CsvPath)
  if($csvRows.Count -le 0){ Write-Log "GROUPMAP: CSV has 0 rows - skipping" 'WARN'; return 0 }
  Write-Log ("GROUPMAP: Loaded {0} mapping rows from {1}" -f $csvRows.Count,$CsvPath) 'INFO'

  $jsonText = [System.IO.File]::ReadAllText($JsonPath,[System.Text.Encoding]::UTF8)
  $orig = $jsonText

  # Identical search/replacement builders to the Tools tab Run Update handler.
  $buildSearchPattern = { param($s)
    $p = [regex]::Escape($s)
    $p = [regex]::Replace($p,'(\\\\)+','\\{1,2}')
    $p = $p -replace '&','(?:&|\\u0026)'
    $p
  }
  $buildReplacement = { param($s)
    $r = $s -replace '(?<!\\)\\(?!\\)','\\\\'
    $r = $r -replace '\$','$$'
    return $r
  }

  $totalChanges = 0
  $rowNum = 0
  foreach($row in $csvRows){
    $rowNum++
    $oldGN = if($row.OldGroupName){ $row.OldGroupName.Trim() } else { $null }
    $newGN = if($row.NewGroupName){ $row.NewGroupName.Trim() } else { $null }
    $oldKA = if($row.OldKnownAs){ $row.OldKnownAs.Trim() } else { $null }
    $newKA = if($row.NewKnownAs){ $row.NewKnownAs.Trim() } else { $null }
    $oldUN = if($row.OldUserName){ $row.OldUserName.Trim() } else { $null }
    $newUN = if($row.NewUserName){ $row.NewUserName.Trim() } else { $null }
    $oldDN = if($row.OldDomainName){ $row.OldDomainName.Trim() } else { $null }
    $newDN = if($row.NewDomainName){ $row.NewDomainName.Trim() } else { $null }

    $rowChanges = 0
    $tryReplace = {
      param($field,$oldVal,$newVal)
      $script:__gmHits = 0
      if([string]::IsNullOrWhiteSpace($oldVal) -or [string]::IsNullOrWhiteSpace($newVal)){ return }
      if($oldVal -eq $newVal){ return }
      $pat = ('("{0}"\s*:\s*")' -f $field) + (& $buildSearchPattern $oldVal) + '(")'
      $rep = '${1}' + (& $buildReplacement $newVal) + '${2}'
      $before = $jsonText
      $jsonText = [regex]::Replace($jsonText,$pat,$rep)
      if($jsonText -ne $before){
        $script:__gmHits = ([regex]::Matches($before,$pat)).Count
      }
    }
    & $tryReplace 'groupName'  $oldGN $newGN; $rowChanges += [int]$script:__gmHits
    & $tryReplace 'knownAs'    $oldKA $newKA; $rowChanges += [int]$script:__gmHits
    & $tryReplace 'userName'   $oldUN $newUN; $rowChanges += [int]$script:__gmHits
    & $tryReplace 'domainName' $oldDN $newDN; $rowChanges += [int]$script:__gmHits

    if($rowChanges -gt 0){
      $label = if($oldGN){$oldGN} elseif($oldKA){$oldKA} elseif($oldUN){$oldUN} else {'(domain only)'}
      $newLabel = if($newGN){$newGN} elseif($newKA){$newKA} elseif($newUN){$newUN} else {$newDN}
      Write-Log ("GROUPMAP: row {0}/{1}: '{2}' -> '{3}' ({4} replacements)" -f $rowNum,$csvRows.Count,$label,$newLabel,$rowChanges) 'INFO'
      $totalChanges += $rowChanges
    }
  }

  if($totalChanges -le 0){
    Write-Log ("GROUPMAP: 0 replacements (JSON did not contain any Old* values from CSV). File unchanged: {0}" -f $JsonPath) 'INFO'
    return 0
  }

  $outPath = $JsonPath
  if(-not $InPlace -and -not [string]::IsNullOrWhiteSpace($OutputPath)){ $outPath = $OutputPath }
  if($outPath -eq $JsonPath){
    $bak = "$JsonPath.before-groupmap.bak"
    try{ if(-not (Test-Path $bak)){ [System.IO.File]::Copy($JsonPath,$bak,$false) } } catch {}
    Write-Log ("GROUPMAP: backup of original JSON at {0}" -f $bak) 'INFO'
  }
  [System.IO.File]::WriteAllText($outPath,$jsonText,[System.Text.Encoding]::UTF8)
  Write-Log ("GROUPMAP: applied {0} total replacements; wrote {1}" -f $totalChanges,$outPath) 'INFO'
  return $totalChanges
}

function Apply-TemplateMappingsToJson {
  param(
    [Parameter(Mandatory)][string]$InputJsonPath,
    [Parameter(Mandatory)][string]$OutputJsonPath,
    [Parameter(Mandatory)]$FieldMappings
  )
  
  <#
  .SYNOPSIS
    Applies template and field mappings to a JSON export file
    Updates template names, IDs, and field IDs based on the mapping configuration
  #>
  
  if (-not (Test-Path $InputJsonPath)) {
    throw "Input JSON file not found: $InputJsonPath"
  }
  
  Write-Log "Loading JSON from: $InputJsonPath (using fast JavaScriptSerializer)" 'INFO'
  # Use fast JSON reader instead of ConvertFrom-Json (10-50x faster for large files)
  $jsonContent = Read-LargeJson -Path $InputJsonPath
  
  # Build quick lookup for template mappings
  $templateMap = @{}
  $fieldMapByTemplate = @{}
  
  foreach ($mapping in $FieldMappings) {
    if (-not $mapping.Enabled) { continue }
    
    $srcId = $mapping.SourceTemplateId
    $srcName = $mapping.TemplateName
    
    # Store template-level mapping
    if ($srcId -and $mapping.TargetTemplateId) {
      $templateMap[$srcId] = @{
        TargetId = $mapping.TargetTemplateId
        TargetName = if ($mapping.TargetTemplateName) { $mapping.TargetTemplateName } else { $srcName }
        SourceName = $srcName
      }
      
      # Build field mapping lookup for this template
      $fieldMap = @{}
      foreach ($fm in $mapping.FieldMappings) {
        if ($fm.SourceFieldId -and $fm.TargetFieldId) {
          $fieldMap[[int]$fm.SourceFieldId] = [int]$fm.TargetFieldId
        }
      }
      if ($fieldMap.Count -gt 0) {
        $fieldMapByTemplate[$srcId] = $fieldMap
      }
    }
  }
  
  if ($templateMap.Count -eq 0) {
    Write-Log "No enabled template mappings found" 'WARN'
    return 0
  }
  
  Write-Log "Applying $($templateMap.Count) template mappings..." 'INFO'
  
  $updatedCount = 0
  
  # JavaScriptSerializer returns Dictionary<string,object> and ArrayList
  # Handle both array root and object root with Secrets property
  $secrets = $null
  if ($jsonContent -is [System.Collections.ArrayList] -or $jsonContent -is [array]) {
    $secrets = $jsonContent
  } elseif ($jsonContent -is [System.Collections.Generic.Dictionary[string,object]] -or $jsonContent -is [hashtable]) {
    # Try common key names for the secrets array
    foreach ($key in @('Secrets','secrets')) {
      if ($jsonContent.ContainsKey($key)) { $secrets = $jsonContent[$key]; break }
    }
    if ($null -eq $secrets) { $secrets = @($jsonContent) }
  } else {
    $secrets = @($jsonContent)
  }
  
  # Helper to get first matching key from a dictionary
  function Get-DictValue($dict, [string[]]$keys, $default=$null) {
    if ($null -eq $dict) { return $default }
    foreach ($k in $keys) {
      if ($dict.ContainsKey($k)) { return $dict[$k] }
    }
    return $default
  }
  
  foreach ($secret in $secrets) {
    if ($secret -isnot [System.Collections.Generic.Dictionary[string,object]]) { continue }
    
    # Get current template ID
    $currentTemplateId = Get-DictValue $secret @('SecretTypeId','secretTypeId','templateId','TemplateId') $null
    
    if ($null -eq $currentTemplateId) { continue }
    
    # Check if we have a mapping for this template
    if ($templateMap.ContainsKey([int]$currentTemplateId)) {
      $tplMapping = $templateMap[[int]$currentTemplateId]
      
      # Update template ID - set on whichever key exists
      foreach ($k in @('SecretTypeId','secretTypeId','templateId','TemplateId')) {
        if ($secret.ContainsKey($k)) { $secret[$k] = $tplMapping.TargetId }
      }
      
      # Update template name if target name is different
      if ($tplMapping.TargetName -and $tplMapping.TargetName -ne $tplMapping.SourceName) {
        foreach ($k in @('SecretTypeName','secretTypeName','templateName','TemplateName')) {
          if ($secret.ContainsKey($k)) { $secret[$k] = $tplMapping.TargetName }
        }
      }
      
      # Update field IDs in items array if we have field mappings
      if ($fieldMapByTemplate.ContainsKey([int]$currentTemplateId)) {
        $fieldMap = $fieldMapByTemplate[[int]$currentTemplateId]
        
        $items = Get-DictValue $secret @('items','Items') $null
        if ($null -ne $items) {
          foreach ($item in $items) {
            if ($item -isnot [System.Collections.Generic.Dictionary[string,object]]) { continue }
            $currentFieldId = Get-DictValue $item @('fieldId','FieldId','secretTemplateFieldId','SecretTemplateFieldId') $null
            
            if ($null -ne $currentFieldId -and $fieldMap.ContainsKey([int]$currentFieldId)) {
              $newFieldId = $fieldMap[[int]$currentFieldId]
              foreach ($k in @('fieldId','FieldId','secretTemplateFieldId','SecretTemplateFieldId')) {
                if ($item.ContainsKey($k)) { $item[$k] = $newFieldId }
              }
            }
          }
        }
      }
      
      $updatedCount++
    }
  }
  
  # Save updated JSON
  Write-Log "Saving updated JSON to: $OutputJsonPath (using fast serializer)" 'INFO'
  
  # Create backup of input file if output is same as input
  if ($OutputJsonPath -eq $InputJsonPath) {
    $backupPath = $InputJsonPath -replace '\.json$', "_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    Copy-Item -Path $InputJsonPath -Destination $backupPath -Force
    Write-Log "Backup created: $backupPath" 'INFO'
  }
  
  Write-LargeJson -Object $jsonContent -Path $OutputJsonPath -Pretty
  
  Write-Log "Updated $updatedCount secrets with template mappings" 'INFO'
  return $updatedCount
}

function Resolve-TargetTemplateId([string]$tgtApiBase,[string]$tgtTok,$exportSecret,[bool]$MapByName){
  $srcId = Get-PropValue $exportSecret @('SecretTypeId','secretTypeId') $null
  $srcName = Get-PropValue $exportSecret @('SecretTypeName','secretTypeName') $null
  
  if($MapByName -and -not [string]::IsNullOrWhiteSpace($srcName)){
    $idx = Get-TemplateNameIndex -apiBase $tgtApiBase -tok $tgtTok
    if($idx.ContainsKey($srcName.ToLowerInvariant())){
      return [int]$idx[$srcName.ToLowerInvariant()]
    }
  }
  
  return $srcId
}

function Get-TemplateFieldIndex([string]$tgtApiBase,[string]$tgtTok,[int]$templateId){
  $script:TemplateFieldIndexCache = $script:TemplateFieldIndexCache -as [hashtable]
  if($script:TemplateFieldIndexCache.ContainsKey($templateId)){ return $script:TemplateFieldIndexCache[$templateId] }
  
  $idx=@{}
  $t = SS $tgtApiBase GET ("secret-templates/{0}" -f $templateId) $tgtTok $null $null
  $fields = @()
  if(Has-Prop $t 'fields'){ $fields = @($t.fields) }
  foreach($f in $fields){
    $fid = Get-PropValue $f @('secretTemplateFieldId','fieldId','id','Id') $null
    if($fid -eq $null){ continue }
    $name = Get-PropValue $f @('name','Name','displayName','DisplayName') $null
    $slug = Get-PropValue $f @('fieldSlugName','FieldSlugName','slug','Slug') $null
    if($name){ $idx[[string]$name.ToLowerInvariant()] = [int]$fid }
    if($slug){ $idx[[string]$slug.ToLowerInvariant()] = [int]$fid }
  }
  $script:TemplateFieldIndexCache[$templateId] = $idx
  return $idx
}

function New-SSItemObject([int]$fieldId,[string]$value){
  @{
    secretTemplateFieldId = $fieldId
    itemValue = $value
  }
}

# =================== IMPORT FUNCTIONS ===================

function Apply-SecretSettings {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$SecretId,
    [Parameter(Mandatory)]$Settings
  )
  
  if($null -eq $Settings){ return $false }
  
  # Build settings payload - only include supported settings
  $payload = @{}
  
  # Common settings that can be updated via API
  $settingsMap = @{
    'autoChangeEnabled' = @('autoChangeEnabled','AutoChangeEnabled')
    'autoChangeNextPassword' = @('autoChangeNextPassword','AutoChangeNextPassword')  
    'requiresApprovalForAccess' = @('requiresApprovalForAccess','RequiresApprovalForAccess')
    'requiresComment' = @('requiresComment','RequiresComment')
    'checkOutEnabled' = @('checkOutEnabled','CheckOutEnabled')
    'checkOutIntervalMinutes' = @('checkOutIntervalMinutes','CheckOutIntervalMinutes')
    'checkOutChangePasswordEnabled' = @('checkOutChangePasswordEnabled','CheckOutChangePasswordEnabled')
    'proxyEnabled' = @('proxyEnabled','ProxyEnabled')
    'sessionRecordingEnabled' = @('sessionRecordingEnabled','SessionRecordingEnabled')
    'restrictSshCommands' = @('restrictSshCommands','RestrictSshCommands')
    'allowOwnersUnrestrictedSshCommands' = @('allowOwnersUnrestrictedSshCommands','AllowOwnersUnrestrictedSshCommands')
    'enableInheritSecretPolicy' = @('enableInheritSecretPolicy','EnableInheritSecretPolicy')
    'siteId' = @('siteId','SiteId')
    'enableInheritPermissions' = @('enableInheritPermissions','EnableInheritPermissions')
    'isDoubleLockEnabled' = @('isDoubleLockEnabled','IsDoubleLockEnabled')
    'requiresDoubleLockPassword' = @('requiresDoubleLockPassword','RequiresDoubleLockPassword')
  }
  
  foreach($apiKey in $settingsMap.Keys){
    $propNames = $settingsMap[$apiKey]
    $val = Get-PropValue $Settings $propNames $null
    if($val -ne $null){
      $payload[$apiKey] = $val
    }
  }
  
  if($payload.Count -eq 0){
    Write-Log ("SETTINGS: No applicable settings to apply for secretId={0}" -f $SecretId) 'DEBUG'
    return $true
  }
  
  try{
    $null = SS $TgtApiBase PATCH ("secrets/{0}/settings" -f $SecretId) $TgtTok $payload $null
    Write-Log ("SETTINGS: Applied {0} settings to secretId={1}" -f $payload.Count,$SecretId) 'DEBUG'
    return $true
  }
  catch{
    Write-Log ("SETTINGS: Failed to apply settings to secretId={0}: {1}" -f $SecretId,$_.Exception.Message) 'WARN'
    return $false
  }
}
function Save-AttachmentToDisk(
  [string]$attachmentRoot,
  [int]$secretId,
  [string]$fieldSlug,
  [string]$fileName,
  [byte[]]$bytes
){
  if(-not $bytes -or $bytes.Length -le 0){ return $null }

  if([string]::IsNullOrWhiteSpace($fileName)){
    $fileName = "$fieldSlug.bin"
  }

  foreach($c in [IO.Path]::GetInvalidFileNameChars()){
    $fileName = $fileName.Replace($c, '_')
  }

  $dir = Join-Path $attachmentRoot (Join-Path $secretId $fieldSlug)
  Ensure-Dir $dir

  $path = Join-Path $dir $fileName
  [IO.File]::WriteAllBytes($path, $bytes)
  return $path
}

function Upload-SecretFieldFile-MultipartPS51(
  [string]$apiBase,
  [string]$tok,
  [int]$secretId,
  [string]$fieldSlug,
  [string]$filePath
){
  if([string]::IsNullOrWhiteSpace($fieldSlug)){ throw "Upload-SecretFieldFile-MultipartPS51: fieldSlug is blank." }
  if(-not (Test-Path $filePath)){ throw "Attachment file not found: $filePath" }

  $uri = $apiBase.TrimEnd('/') + "/secrets/$secretId/fields/$fieldSlug"
  $bytes = [IO.File]::ReadAllBytes($filePath)
  if($bytes.Length -le 0){ throw "Refusing to upload empty file: $filePath" }

  $boundary = "------------------------" + ([Guid]::NewGuid().ToString("N"))
  $fileName = [IO.Path]::GetFileName($filePath)
  
  # FIX: Ensure filename has an extension
  if(-not [IO.Path]::HasExtension($fileName)){
    Write-Log ("FILEFIELD: filename '{0}' has no extension; appending .txt" -f $fileName) 'WARN'
    $fileName = "$fileName.txt"
  }

  $pre = (
    "--$boundary`r`n" +
    "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"`r`n" +
    "Content-Type: application/octet-stream`r`n`r`n"
  )
  $post = "`r`n--$boundary--`r`n"

  $preBytes  = [Text.Encoding]::ASCII.GetBytes($pre)
  $postBytes = [Text.Encoding]::ASCII.GetBytes($post)

  $ms = New-Object System.IO.MemoryStream
  $ms.Write($preBytes, 0, $preBytes.Length)   | Out-Null
  $ms.Write($bytes,    0, $bytes.Length)      | Out-Null
  $ms.Write($postBytes,0, $postBytes.Length)  | Out-Null
  $bodyBytes = $ms.ToArray()
  $ms.Dispose()

  # Use HttpWebRequest for reliable raw binary upload in PS5.1
  # (Invoke-WebRequest can mishandle byte[] bodies in PS5.1)
  $request = [System.Net.HttpWebRequest]::Create($uri)
  $request.Method = "PUT"
  $request.ContentType = "multipart/form-data; boundary=$boundary"
  $request.Headers.Add("Authorization", "Bearer $tok")
  $request.Accept = "application/json"
  $request.ContentLength = $bodyBytes.Length
  $request.Timeout = 120000

  $reqStream = $request.GetRequestStream()
  $reqStream.Write($bodyBytes, 0, $bodyBytes.Length)
  $reqStream.Close()

  try {
    $response = [System.Net.HttpWebResponse]$request.GetResponse()
    $statusCode = [int]$response.StatusCode
    $respStream = $response.GetResponseStream()
    $respReader = New-Object System.IO.StreamReader($respStream)
    $respBody = $respReader.ReadToEnd()
    $respReader.Close()
    $response.Close()
    Write-Log ("FILEFIELD UPLOAD: secretId={0} slug='{1}' HTTP {2}" -f $secretId,$fieldSlug,$statusCode) 'DEBUG'
    if($statusCode -lt 200 -or $statusCode -ge 300){
      throw "Unexpected HTTP $statusCode response: $respBody"
    }
  }
  catch [System.Net.WebException] {
    $webEx = [System.Net.WebException]$_.Exception
    $errStatus = [int]$webEx.Response.StatusCode
    $errBody = ""
    try {
      $errStream = $webEx.Response.GetResponseStream()
      $errReader = New-Object System.IO.StreamReader($errStream)
      $errBody = $errReader.ReadToEnd()
      $errReader.Close()
    } catch {}
    throw "HTTP $errStatus uploading '$fieldSlug': $errBody"
  }
}

function Get-ExistingSecretPermissionIndex {
  param(
    [Parameter(Mandatory)][string]$apiBase,
    [Parameter(Mandatory)][string]$tok,
    [Parameter(Mandatory)][int]$secretId
  )

  $index = @{}
  $page = 1
  $ps = 200

  while($true){
    $resp = SS $apiBase GET 'secret-permissions' $tok $null @{
      'filter.secretId'  = [int]$secretId
      'filter.page'      = [int]$page
      'filter.pageSize'  = [int]$ps
    }

    $recs = @(Get-Records $resp)

    foreach($p in $recs){
      $uid = 0; $gid = 0
      try{ $uid = [int](Get-PropValue $p @('userId','UserId') 0) } catch {}
      try{ $gid = [int](Get-PropValue $p @('groupId','GroupId') 0) } catch {}

      $rid = $null
      try{ $rid = (Get-PropValue $p @('secretAccessRoleId','SecretAccessRoleId','roleId','RoleId') $null) } catch {}

      $rname = $null
      try{ $rname = [string](Get-PropValue $p @('secretAccessRoleName','SecretAccessRoleName','roleName','RoleName') $null) } catch {}

      # Store both roleId-based and roleName-based keys (roleName lowercased)
      if($uid -gt 0){
        if($rid -ne $null){
          $index["u:$uid|rid:$([int]$rid)"] = $true
        } elseif(-not [string]::IsNullOrWhiteSpace($rname)){
          $index["u:$uid|rnm:$($rname.ToLowerInvariant())"] = $true
        }
      }
      elseif($gid -gt 0){
        if($rid -ne $null){
          $index["g:$gid|rid:$([int]$rid)"] = $true
        } elseif(-not [string]::IsNullOrWhiteSpace($rname)){
          $index["g:$gid|rnm:$($rname.ToLowerInvariant())"] = $true
        }
      }
    }

    if($recs.Count -lt $ps){ break }
    $page++
    if($page -gt 2000){
      Write-Log ("Get-ExistingSecretPermissionIndex: safety stop paging secretId={0} at page={1}" -f $secretId,$page) 'WARN'
      break
    }
  }

  return $index
}

function Test-SecretPermissionAlreadyExists {
  param(
    [Parameter(Mandatory)]$index,
    [int]$userId = 0,
    [int]$groupId = 0,
    $roleId = $null,
    [string]$roleName = $null
  )

  if(-not $index){ return $false }

  $prefix = if($userId -gt 0){ "u:$userId" } elseif($groupId -gt 0){ "g:$groupId" } else { return $false }

  if($roleId -ne $null){
    try{
      $k = "$prefix|rid:$([int]$roleId)"
      return [bool]$index.ContainsKey($k)
    } catch {}
  }

  if(-not [string]::IsNullOrWhiteSpace($roleName)){
    $k2 = "$prefix|rnm:$($roleName.ToLowerInvariant())"
    return [bool]$index.ContainsKey($k2)
  }

  return $false
}

 function Test-UserCanCreateFolders([string]$apiBase,[string]$tok){
  try{
    # Test by attempting to get current user's roles
    $me = SS $apiBase GET 'users/current' $tok $null $null
    $roles = @()
    if(Has-Prop $me 'roles'){ $roles = @($me.roles) }
    
    $canCreate = $false
    foreach($r in $roles){
      $rname = [string](Get-PropValue $r @('name','Name') $null)
      if($rname -match 'Admin|Folder'){
        $canCreate = $true
        break
      }
    }
    
    if(-not $canCreate){
      Write-Log ("WARNING: Current user may lack folder creation permissions. Roles: {0}" -f (($roles | ForEach-Object { Get-PropValue $_ @('name','Name') 'Unknown' }) -join ', ')) 'WARN'
    }
    
    return $canCreate
  }
  catch{
    Write-Log ("Permission check failed (non-fatal): {0}" -f $_) 'WARN'
    return $true  # Allow to proceed
  }
}
#=============================================================================
$script:GroupNameCache = @{}
$script:UserNameCache = @{}

function Get-GroupNameById-Cached([string]$apiBase,[string]$tok,[int]$groupId){
  if($groupId -le 0){ return $null }
  
  $cacheKey = "{0}|{1}" -f $apiBase,$groupId
  if($script:GroupNameCache.ContainsKey($cacheKey)){
    return $script:GroupNameCache[$cacheKey]
  }
  
  try{
    $g = SS $apiBase GET ("groups/{0}" -f $groupId) $tok $null $null
    $name = [string](Get-PropValue $g @('name','groupName','Name','GroupName') $null)
    $script:GroupNameCache[$cacheKey] = $name
    return $name
  } 
  catch {
    # Cache the failure so we don't retry - this is expected for inaccessible groups
    $script:GroupNameCache[$cacheKey] = $null
    # Don't log - this is expected behavior for groups user can't access
    return $null
  }
}

function Get-UserNameById-Cached([string]$apiBase,[string]$tok,[int]$userId){
  if($userId -le 0){ return $null }
  
  $cacheKey = "{0}|{1}" -f $apiBase,$userId
  if($script:UserNameCache.ContainsKey($cacheKey)){
    return $script:UserNameCache[$cacheKey]
  }
  
  try{
    $u = SS $apiBase GET ("users/{0}" -f $userId) $tok $null $null
    $name = [string](Get-PropValue $u @('userName','UserName','username','name','Name') $null)
    $script:UserNameCache[$cacheKey] = $name
    return $name
  } 
  catch {
    # Cache the failure so we don't retry - this is expected for inaccessible users
    $script:UserNameCache[$cacheKey] = $null
    # Don't log - this is expected behavior for users we can't access
    return $null
  }
}


# Initialize tracking variables
$script:ImportedSecretIds = @()
$script:ImportedFolderIds = @()

function Reset-ImportTracking {
  $script:ImportRunCreatedSecretIds = New-Object 'System.Collections.Generic.List[int]'
  $script:ImportRunCreatedSecretsById = @{}
  $script:ImportRunCreatedFolderIds = New-Object 'System.Collections.Generic.List[int]'
  $script:ImportRunCreatedFoldersById = @{}
  $script:CreatedFolderCache = @{}
  
  # Permission tracking for rollback
  $script:ImportRunAppliedSecretPermissions = New-Object 'System.Collections.Generic.List[hashtable]'
  $script:ImportRunAppliedFolderPermissions = New-Object 'System.Collections.Generic.List[hashtable]'
  $script:ImportRunFoldersWithPermsApplied = New-Object 'System.Collections.Generic.HashSet[string]'
  # Track individual principals applied to parent folders (allows accumulation from multiple children)
  $script:ParentFolderPrincipalTracker = New-Object 'System.Collections.Generic.HashSet[string]'
  
  # Reset permission check cache for new import run
  $script:PermissionCheckCache = @{}
  $script:FolderPermAddedCache = @{}
  $script:FolderInheritanceBrokenCache = @{}
  
  Write-Log "IMPORT: Reset tracking for new import run" 'DEBUG'
}

function Track-CreatedSecret {
  param([int]$SecretId)
  if($SecretId -gt 0){
    $script:ImportedSecretIds += $SecretId
  }
}
function Remove-NullKeys {
  param([hashtable]$h)
  if(-not $h){ return $h }
  foreach($k in @($h.Keys)){
    if($null -eq $h[$k] -or [string]::IsNullOrWhiteSpace([string]$h[$k])){
      $h.Remove($k)
    }
  }
  return $h
}
function Track-CreatedFolder {
  param(
    [int]$id = 0,
    [int]$FolderId = 0,
    [string]$name = "",
    [string]$path = "",
    [int]$parentId = 0
  )
  
  # Use whichever ID parameter was provided
  $effectiveId = if($id -gt 0){ $id } else { $FolderId }
  
  if($effectiveId -gt 0){
    try{
      $script:ImportRunCreatedFolderIds.Add($effectiveId) | Out-Null
      $script:ImportRunCreatedFoldersById[[string]$effectiveId] = @{
        id = $effectiveId
        name = $name
        path = $path
        parentId = $parentId
      }
      Write-Log ("TRACK: Folder id={0} name='{1}'" -f $effectiveId,$name) 'DEBUG'
    }
    catch{
      Write-Log ("TRACK: Failed to track folder id={0}: {1}" -f $effectiveId,$_.Exception.Message) 'WARN'
    }
  }
}
# Cache for target tenant groups and users
$script:TgtGroupNameToIdCache = @{}
$script:TgtUserNameToIdCache = @{}
$script:TgtGroupCacheLoaded = $false
$script:TgtUserCacheLoaded = $false


# Add this function if it doesn't exist in your script:

function Find-FolderByNameUnderParent {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$ParentFolderId,
    [Parameter(Mandatory)][string]$FolderName
  )
  
  if([string]::IsNullOrWhiteSpace($FolderName)){ return 0 }
  
  $page = 1
  $ps = 200
  $targetNameLower = $FolderName.ToLowerInvariant()
  
  # Method 1: List all folders under parent and match by name
  while($page -le 20){
    try{
      $resp = SS $TgtApiBase GET 'folders' $TgtTok $null @{
        'filter.parentFolderId' = $ParentFolderId
        'filter.page' = $page
        'filter.pageSize' = $ps
      }
      
      $recs = @(Get-Records $resp)
      
      foreach($f in $recs){
        $fid = 0
        try{ $fid = [int](Get-PropValue $f @('id','folderId','Id','FolderId') 0) } catch {}
        $fname = [string](Get-PropValue $f @('folderName','FolderName','name','Name') $null)
        
        if($fid -gt 0 -and -not [string]::IsNullOrWhiteSpace($fname)){
          if($fname.ToLowerInvariant() -eq $targetNameLower){
            return $fid
          }
        }
      }
      
      if($recs.Count -lt $ps){ break }
      $page++
    }
    catch{
      Write-Log ("Find-FolderByNameUnderParent: Error listing under {0}: {1}" -f $ParentFolderId,$_.Exception.Message) 'DEBUG'
      break
    }
  }
  
  # Method 2: Use searchText filter (finds folders not returned by parent listing due to permissions)
  try{
    $resp2 = SS $TgtApiBase GET 'folders' $TgtTok $null @{
      'filter.searchText' = $FolderName
      'filter.parentFolderId' = $ParentFolderId
      'filter.page' = 1
      'filter.pageSize' = 50
    }
    $recs2 = @(Get-Records $resp2)
    foreach($f2 in $recs2){
      $fid2 = 0
      try{ $fid2 = [int](Get-PropValue $f2 @('id','folderId','Id','FolderId') 0) } catch {}
      $fname2 = [string](Get-PropValue $f2 @('folderName','FolderName','name','Name') $null)
      $fpid2 = Get-PropValue $f2 @('parentFolderId','ParentFolderId') $null
      
      if($fid2 -gt 0 -and -not [string]::IsNullOrWhiteSpace($fname2)){
        if($fname2.ToLowerInvariant() -eq $targetNameLower){
          # Verify parent matches (searchText may return from other parents)
          if($fpid2 -eq $null -or [int]$fpid2 -eq $ParentFolderId){
            Write-Log ("Find-FolderByNameUnderParent: Found '{0}' (id={1}) via searchText fallback" -f $FolderName,$fid2) 'DEBUG'
            return $fid2
          }
        }
      }
    }
  }
  catch{
    Write-Log ("Find-FolderByNameUnderParent: searchText fallback error for '{0}': {1}" -f $FolderName,$_.Exception.Message) 'DEBUG'
  }
  
  # Method 3: Try GET /folders/lookup with searchText (different endpoint, broader results)
  try{
    $resp3 = SS $TgtApiBase GET 'folders/lookup' $TgtTok $null @{
      'filter.searchText' = $FolderName
      'filter.parentFolderId' = $ParentFolderId
      'filter.page' = 1
      'filter.pageSize' = 50
    }
    $recs3 = @(Get-Records $resp3)
    foreach($f3 in $recs3){
      $fid3 = 0
      try{ $fid3 = [int](Get-PropValue $f3 @('id','folderId','Id','FolderId') 0) } catch {}
      $fname3 = [string](Get-PropValue $f3 @('folderName','FolderName','name','Name','value','Value') $null)
      
      if($fid3 -gt 0 -and -not [string]::IsNullOrWhiteSpace($fname3)){
        # lookup endpoint may return full path in value field - check if name matches
        $lastSeg = $fname3.Split([char[]]@('\','/'))[-1].Trim()
        if($lastSeg.ToLowerInvariant() -eq $targetNameLower){
          Write-Log ("Find-FolderByNameUnderParent: Found '{0}' (id={1}) via folders/lookup fallback" -f $FolderName,$fid3) 'DEBUG'
          return $fid3
        }
      }
    }
  }
  catch{
    # folders/lookup may not be available on all tenants - silently skip
  }
  
  return 0
}

function Load-TargetGroupCache {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok
  )
  
  if($script:TgtGroupCacheLoaded){ return }
  
  Write-Log "Loading target group cache..." 'DEBUG'
  $script:TgtGroupNameToIdCache = @{}
  
  $skip = 0
  $take = 100
  $totalLoaded = 0
  $maxIterations = 1000
  $iteration = 0
  
  # Try skip/take parameters instead of filter.page (Delinea API pagination issue)
  while($iteration -lt $maxIterations){
    try{
      $resp = SS $TgtApiBase GET 'groups' $TgtTok $null @{
        'skip' = $skip
        'take' = $take
      }
      
      $recs = @(Get-Records $resp)
      $pageCount = $recs.Count
      
      if($iteration -eq 0){
        Write-Log ("Load-TargetGroupCache: Using skip/take pagination (skip={0}, take={1})" -f $skip, $take) 'DEBUG'
      }
      
      $addedThisPage = 0
      foreach($g in $recs){
        $gid = 0
        try{ $gid = [int](Get-PropValue $g @('id','Id','groupId','GroupId') 0) } catch {}
        $gname = [string](Get-PropValue $g @('name','groupName','Name','GroupName') $null)
        $gDomain = [string](Get-PropValue $g @('domainName','DomainName','domain','Domain') $null)
        
        if($gid -gt 0 -and -not [string]::IsNullOrWhiteSpace($gname)){
          $key = $gname.ToLowerInvariant()
          if(-not $script:TgtGroupNameToIdCache.ContainsKey($key)){
            $script:TgtGroupNameToIdCache[$key] = $gid
            $totalLoaded++
            $addedThisPage++
          }
          # Also store with domain suffix format (name@domain) for cross-reference
          if(-not [string]::IsNullOrWhiteSpace($gDomain)){
            $domainKey = ("{0}@{1}" -f $gname, $gDomain).ToLowerInvariant()
            if(-not $script:TgtGroupNameToIdCache.ContainsKey($domainKey)){
              $script:TgtGroupNameToIdCache[$domainKey] = $gid
            }
            # Also store domain\name format
            $domainPrefixKey = ("{0}\{1}" -f $gDomain, $gname).ToLowerInvariant()
            if(-not $script:TgtGroupNameToIdCache.ContainsKey($domainPrefixKey)){
              $script:TgtGroupNameToIdCache[$domainPrefixKey] = $gid
            }
          }
          # If group name contains @, also store just the part before @
          if($gname -match '^(.+)@.+$'){
            $baseKey = $Matches[1].ToLowerInvariant()
            if(-not $script:TgtGroupNameToIdCache.ContainsKey($baseKey)){
              $script:TgtGroupNameToIdCache[$baseKey] = $gid
            }
          }
        }
      }
      
      # Log progress periodically
      if($iteration % 5 -eq 0 -or $addedThisPage -gt 0){
        Write-Log ("Load-TargetGroupCache: skip={0} returned {1} groups, added {2} new (total unique: {3})" -f $skip, $pageCount, $addedThisPage, $script:TgtGroupNameToIdCache.Count) 'DEBUG'
      }
      
      # Stop only if we got fewer records than requested (last page)
      if($recs.Count -lt $take){ 
        Write-Log ("Load-TargetGroupCache: Reached last page at skip={0} (got {1} < {2})" -f $skip,$recs.Count,$take) 'DEBUG'
        break 
      }
      
      $skip += $take
      $iteration++
    }
    catch{
      Write-Log ("Load-TargetGroupCache: skip={0} failed: {1}" -f $skip, $_.Exception.Message) 'WARN'
      break
    }
  }
  
  if($iteration -ge $maxIterations){
    Write-Log "Load-TargetGroupCache: WARNING - Reached max iterations. Some groups may not be loaded." 'WARN'
  }
  
  $script:TgtGroupCacheLoaded = $true
  Write-Log ("Target group cache loaded: {0} groups" -f $script:TgtGroupNameToIdCache.Count) 'DEBUG'
  # Log available groups for cross-tenant debugging
  if($script:TgtGroupNameToIdCache.Count -gt 0 -and $script:TgtGroupNameToIdCache.Count -le 50){
    $groupList = ($script:TgtGroupNameToIdCache.Keys | Sort-Object) -join ", "
    Write-Log ("Target groups available: {0}" -f $groupList) 'DEBUG'
  }
}

function Load-TargetUserCache {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok
  )
  
  if($script:TgtUserCacheLoaded){ return }
  
  Write-Log "Loading target user cache..." 'DEBUG'
  $script:TgtUserNameToIdCache = @{}  # <-- This is the correct variable name
  
  $skip = 0
  $take = 100
  $totalLoaded = 0
  $maxIterations = 1000
  $iteration = 0
  
  # Try skip/take parameters instead of filter.page (Delinea API pagination issue)
  while($iteration -lt $maxIterations){
    try{
      $resp = SS $TgtApiBase GET 'users' $TgtTok $null @{
        'skip' = $skip
        'take' = $take
      }
      
      $recs = @(Get-Records $resp)
      $pageCount = $recs.Count
      
      if($iteration -eq 0){
        Write-Log ("Load-TargetUserCache: Using skip/take pagination (skip={0}, take={1})" -f $skip, $take) 'DEBUG'
      }
      
      $addedThisPage = 0
      foreach($u in $recs){
        $uid = 0
        try{ $uid = [int](Get-PropValue $u @('id','Id','userId','UserId') 0) } catch {}
        $uname = [string](Get-PropValue $u @('userName','UserName','username','name','Name') $null)
        $uDisplayName = [string](Get-PropValue $u @('displayName','DisplayName') $null)
        $uDomain = [string](Get-PropValue $u @('domainName','DomainName','domain','Domain') $null)
        
        if($uid -gt 0 -and -not [string]::IsNullOrWhiteSpace($uname)){
          $key = $uname.ToLowerInvariant()
          if(-not $script:TgtUserNameToIdCache.ContainsKey($key)){
            $script:TgtUserNameToIdCache[$key] = $uid
            $totalLoaded++
            $addedThisPage++
          }
          # Also store with domain prefix (domain\username) for cross-reference
          if(-not [string]::IsNullOrWhiteSpace($uDomain)){
            $domainKey = ("{0}\{1}" -f $uDomain, $uname).ToLowerInvariant()
            if(-not $script:TgtUserNameToIdCache.ContainsKey($domainKey)){
              $script:TgtUserNameToIdCache[$domainKey] = $uid
            }
          }
          # If username contains @, also store just the part before @
          if($uname -match '^(.+)@.+$'){
            $baseKey = $Matches[1].ToLowerInvariant()
            if(-not $script:TgtUserNameToIdCache.ContainsKey($baseKey)){
              $script:TgtUserNameToIdCache[$baseKey] = $uid
            }
          }
          # Store displayName as additional key
          if(-not [string]::IsNullOrWhiteSpace($uDisplayName)){
            $dispKey = $uDisplayName.ToLowerInvariant()
            if(-not $script:TgtUserNameToIdCache.ContainsKey($dispKey)){
              $script:TgtUserNameToIdCache[$dispKey] = $uid
            }
            # Also store domain\displayName
            if(-not [string]::IsNullOrWhiteSpace($uDomain)){
              $domainDispKey = ("{0}\{1}" -f $uDomain, $uDisplayName).ToLowerInvariant()
              if(-not $script:TgtUserNameToIdCache.ContainsKey($domainDispKey)){
                $script:TgtUserNameToIdCache[$domainDispKey] = $uid
              }
            }
          }
        }
      }
      
      # Log progress periodically
      if($iteration % 5 -eq 0 -or $addedThisPage -gt 0){
        Write-Log ("Load-TargetUserCache: skip={0} returned {1} users, added {2} new (total unique: {3})" -f $skip, $pageCount, $addedThisPage, $script:TgtUserNameToIdCache.Count) 'DEBUG'
      }
      
      # Stop only if we got fewer records than requested (last page)
      if($recs.Count -lt $take){ 
        Write-Log ("Load-TargetUserCache: Reached last page at skip={0} (got {1} < {2})" -f $skip,$recs.Count,$take) 'DEBUG'
        break 
      }
      
      $skip += $take
      $iteration++
    }
    catch{
      Write-Log ("Load-TargetUserCache: skip={0} failed: {1}" -f $skip, $_.Exception.Message) 'WARN'
      break
    }
  }
  
  if($iteration -ge $maxIterations){
    Write-Log "Load-TargetUserCache: WARNING - Reached max iterations. Some users may not be loaded." 'WARN'
  }
  
  $script:TgtUserCacheLoaded = $true
  Write-Log ("Target user cache loaded: {0} users" -f $script:TgtUserNameToIdCache.Count) 'DEBUG'
  # Log available users for cross-tenant debugging
  if($script:TgtUserNameToIdCache.Count -gt 0 -and $script:TgtUserNameToIdCache.Count -le 50){
    $userList = ($script:TgtUserNameToIdCache.Keys | Sort-Object) -join ", "
    Write-Log ("Target users available: {0}" -f $userList) 'DEBUG'
  }
}
function Create-Folder-OnTarget {
  param(
    [Parameter(Mandatory)][string]$TgtApi,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$ParentId,
    [Parameter(Mandatory)][string]$FolderName
  )
  # folderTypeId=1 is required for Delinea API - it means "normal folder"
  $payload = @{
    folderName = $FolderName
    parentFolderId = $ParentFolderId
    folderTypeId = 1
    inheritPermissions = $true
    inheritSecretPolicy = $true
  }

  try{
    $result = SS $TgtApi POST 'folders' $TgtTok $payload $null
    $newId = [int](Get-PropValue $result @('id','Id','folderId','FolderId') 0)
    return $newId
  }
  catch{
    Write-Log ("Create-Folder-OnTarget: Failed to create '{0}' under parent {1}: {2}" -f $FolderName,$ParentId,$_.Exception.Message) 'ERROR'
    return 0
  }
}
function Get-TargetGroupIdByName {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][string]$GroupName,
    [string]$KnownAs = "",
    [string]$DomainName = ""
  )
  
  if([string]::IsNullOrWhiteSpace($GroupName)){ return $null }
  
  # Ensure cache is loaded
  Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
  
  # Strategy 1: Exact match on groupName
  $key = $GroupName.ToLowerInvariant()
  if($script:TgtGroupNameToIdCache.ContainsKey($key)){
    return $script:TgtGroupNameToIdCache[$key]
  }
  
  # Strategy 2: Try knownAs field
  if(-not [string]::IsNullOrWhiteSpace($KnownAs)){
    $key2 = $KnownAs.ToLowerInvariant()
    if($script:TgtGroupNameToIdCache.ContainsKey($key2)){
      Write-Log ("  Group resolved via knownAs: '{0}'" -f $KnownAs) 'DEBUG'
      return $script:TgtGroupNameToIdCache[$key2]
    }
  }
  
  # Strategy 3: Try groupName without domain suffix (strip @domain.com)
  if($GroupName -match '^(.+)@.+$'){
    $nameWithoutDomain = $Matches[1].ToLowerInvariant()
    if($script:TgtGroupNameToIdCache.ContainsKey($nameWithoutDomain)){
      Write-Log ("  Group resolved by stripping domain: '{0}' -> '{1}'" -f $GroupName, $nameWithoutDomain) 'DEBUG'
      return $script:TgtGroupNameToIdCache[$nameWithoutDomain]
    }
  }
  
  # Strategy 4: Try with domainName prefix (domain\groupName format)
  if(-not [string]::IsNullOrWhiteSpace($DomainName)){
    # Try domain\name format
    $domainPrefixed = ("{0}\{1}" -f $DomainName, $GroupName).ToLowerInvariant()
    if($script:TgtGroupNameToIdCache.ContainsKey($domainPrefixed)){
      Write-Log ("  Group resolved via domain prefix: '{0}'" -f $domainPrefixed) 'DEBUG'
      return $script:TgtGroupNameToIdCache[$domainPrefixed]
    }
    # Try domain\nameWithoutDomain
    if($GroupName -match '^(.+)@.+$'){
      $domainPrefixed2 = ("{0}\{1}" -f $DomainName, $Matches[1]).ToLowerInvariant()
      if($script:TgtGroupNameToIdCache.ContainsKey($domainPrefixed2)){
        Write-Log ("  Group resolved via domain\\name: '{0}'" -f $domainPrefixed2) 'DEBUG'
        return $script:TgtGroupNameToIdCache[$domainPrefixed2]
      }
    }
  }

  # Strategy 5: groupsmap.csv translation fallback. If the CSV was loaded via
  # Load-GroupMapTranslations / Apply-GroupMapCsvToJson, look up the source
  # name -> mapped target name and re-check the target cache. This catches
  # cases where the JSON text-substitution did not rewrite a specific field
  # (e.g. a nested principal object with a non-standard property name).
  if($script:GroupMapTranslations_Group -and $script:GroupMapTranslations_Group.Count -gt 0){
    $mapped = $null
    if($script:GroupMapTranslations_Group.ContainsKey($key)){ $mapped = [string]$script:GroupMapTranslations_Group[$key] }
    elseif(-not [string]::IsNullOrWhiteSpace($KnownAs) -and $script:GroupMapTranslations_KnownAs -and $script:GroupMapTranslations_KnownAs.ContainsKey($KnownAs.ToLowerInvariant())){
      $mapped = [string]$script:GroupMapTranslations_KnownAs[$KnownAs.ToLowerInvariant()]
    }
    if(-not [string]::IsNullOrWhiteSpace($mapped)){
      $mappedKey = $mapped.ToLowerInvariant()
      if($script:TgtGroupNameToIdCache.ContainsKey($mappedKey)){
        Write-Log ("  Group resolved via groupsmap.csv: '{0}' -> '{1}'" -f $GroupName,$mapped) 'INFO'
        return $script:TgtGroupNameToIdCache[$mappedKey]
      }
      # Try mapped value with domain stripped
      if($mapped -match '^(.+)@.+$'){
        $mb = $Matches[1].ToLowerInvariant()
        if($script:TgtGroupNameToIdCache.ContainsKey($mb)){
          Write-Log ("  Group resolved via groupsmap.csv (domain stripped): '{0}' -> '{1}' -> '{2}'" -f $GroupName,$mapped,$mb) 'INFO'
          return $script:TgtGroupNameToIdCache[$mb]
        }
      }
    }
  }
  
  # Strategy 5: Partial/substring match - check if any target group name contains the source name or vice versa
  $srcBase = if($GroupName -match '^(.+)@'){ $Matches[1].ToLowerInvariant() } else { $GroupName.ToLowerInvariant() }
  foreach($cachedKey in $script:TgtGroupNameToIdCache.Keys){
    $cachedBase = if($cachedKey -match '^(.+)@'){ $Matches[1] } else { $cachedKey }
    if($cachedBase -eq $srcBase){
      Write-Log ("  Group resolved via base name match: '{0}' -> cached '{1}'" -f $GroupName, $cachedKey) 'DEBUG'
      return $script:TgtGroupNameToIdCache[$cachedKey]
    }
  }
  
  # Strategy 5b: Strip common prefixes (e.g., "Folder/SecretOwners" -> "SecretOwners")
  $strippedName = $GroupName
  if($strippedName -match '^[^/]+/(.+)$'){
    $strippedName = $Matches[1]
    $strippedKey = $strippedName.ToLowerInvariant()
    if($script:TgtGroupNameToIdCache.ContainsKey($strippedKey)){
      Write-Log ("  Group resolved by stripping prefix: '{0}' -> '{1}'" -f $GroupName, $strippedName) 'DEBUG'
      return $script:TgtGroupNameToIdCache[$strippedKey]
    }
  }
  # Also try matching target groups that end with the source name (e.g., source "SecretOwners" matches target "Folder/SecretOwners")
  foreach($cachedKey in $script:TgtGroupNameToIdCache.Keys){
    if($cachedKey.EndsWith("/$($srcBase)") -or $cachedKey.EndsWith("\$($srcBase)")){
      Write-Log ("  Group resolved via suffix match: '{0}' -> cached '{1}'" -f $GroupName, $cachedKey) 'DEBUG'
      return $script:TgtGroupNameToIdCache[$cachedKey]
    }
  }
  
  # Strategy 6: Direct API search as last resort
  try{
    $searchName = if($GroupName -match '^(.+)@'){ $Matches[1] } else { $GroupName }
    $resp = SS $TgtApiBase GET 'groups' $TgtTok $null @{ 'filter.searchText' = $searchName; 'take' = 20 }
    $recs = @(Get-Records $resp)
    foreach($g in $recs){
      $gid = 0
      try{ $gid = [int](Get-PropValue $g @('id','Id','groupId','GroupId') 0) } catch {}
      $gname = [string](Get-PropValue $g @('name','groupName','Name','GroupName') $null)
      if($gid -gt 0 -and -not [string]::IsNullOrWhiteSpace($gname)){
        $gKey = $gname.ToLowerInvariant()
        $gBase = if($gname -match '^(.+)@'){ $Matches[1].ToLowerInvariant() } else { $gKey }
        if($gKey -eq $GroupName.ToLowerInvariant() -or $gBase -eq $srcBase){
          Write-Log ("  Group resolved via API search: '{0}' -> '{1}' (id={2})" -f $GroupName,$gname,$gid) 'DEBUG'
          $script:TgtGroupNameToIdCache[$gKey] = $gid
          $script:TgtGroupNameToIdCache[$GroupName.ToLowerInvariant()] = $gid
          return [int]$gid
        }
      }
    }
  } catch {
    Write-Log ("  Group API search failed for '{0}': {1}" -f $GroupName,$_.Exception.Message) 'DEBUG'
  }
  
  return $null
}
function Build-SecretCreateItems {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$TemplateId,
    [Parameter(Mandatory)][array]$ExportItems,  # Explicitly typed as array
    [string]$FallbackSecretName = ""
  )

  $template = SS $TgtApiBase GET ("secret-templates/{0}" -f $TemplateId) $TgtTok $null $null
  $templateFields = @(Get-PropValue $template @('fields','Fields') @())
  
  Write-Log ("BUILD ITEMS: Template {0} has {1} fields, export has {2} items" -f $TemplateId,$templateFields.Count,$ExportItems.Count) 'DEBUG'
  
  $items = @()
  $filledPlaceholders = @()

  foreach($tf in $templateFields){
    $tfSlug = [string](Get-PropValue $tf @('slug','Slug','fieldSlugName','FieldSlugName') $null)
    $tfName = [string](Get-PropValue $tf @('name','Name','displayName','DisplayName') $null)
    $tfId = [int](Get-PropValue $tf @('secretTemplateFieldId','SecretTemplateFieldId','fieldId','FieldId') 0)
    $isRequired = [bool](Get-PropValue $tf @('isRequired','IsRequired') $false)
    $isFile = [bool](Get-PropValue $tf @('isFile','IsFile') $false)

    # Find matching export item
    $matchedValue = $null
    $found = $false
    
    foreach($expItem in @($ExportItems)){
      $expSlug = [string](Get-PropValue $expItem @('slug','Slug') $null)
      $expName = [string](Get-PropValue $expItem @('name','Name','fieldName','FieldName') $null)
      
      if(($tfSlug -and $expSlug -and $tfSlug -eq $expSlug) -or 
         ($tfName -and $expName -and $tfName -eq $expName)){
        $matchedValue = Get-PropValue $expItem @('value','Value','itemValue','ItemValue') $null
        $found = $true
        Write-Log ("BUILD ITEMS: Matched field '{0}' (slug='{1}') with export value" -f $tfName,$tfSlug) 'DEBUG'
        break
      }
    }
    
    if(-not $found){
      Write-Log ("BUILD ITEMS: No match found for template field '{0}' (slug='{1}')" -f $tfName,$tfSlug) 'DEBUG'
    }

    $itemValue = ""
    if($found -and $matchedValue -ne $null){
      $itemValue = if($isFile){ "" } else { [string]$matchedValue }
    }

    # FORCE-CREATE FIX: Fill empty required fields with meaningful placeholders
    if($isRequired -and -not $isFile -and [string]::IsNullOrWhiteSpace($itemValue)){
      # Use field-specific placeholders
      if($tfSlug -match 'username|user' -or $tfName -match 'username|user'){
        if(-not [string]::IsNullOrWhiteSpace($FallbackSecretName)){
          $safeName = ($FallbackSecretName -replace '[^a-zA-Z0-9_\-]','_')
          if($safeName.Length -gt 30){ $safeName = $safeName.Substring(0,30) }
          $itemValue = "migrated_$safeName"
        } else {
          $itemValue = "migrated_user"
        }
      }
      elseif($tfSlug -match 'password|pass' -or $tfName -match 'password|pass'){
        $itemValue = "CHANGE_ME_" + [guid]::NewGuid().ToString("N").Substring(0,8)
      }
      elseif($tfSlug -match 'host|server|machine' -or $tfName -match 'host|server|machine'){
        $itemValue = "unknown.host"
      }
      else{
        $itemValue = "(not provided)"
      }
      
      $filledPlaceholders += "$tfName=$itemValue"
      Write-Log ("BUILD ITEMS: Required field '{0}' was empty - using placeholder: '{1}'" -f $tfName,$itemValue) 'WARN'
    }

    $items += [PSCustomObject]@{
      fieldId = $tfId
      itemValue = $itemValue
      IsFile = $isFile
    }
  }

  if($filledPlaceholders.Count -gt 0){
    Write-Log ("BUILD ITEMS: Template {0} - filled {1} required fields: {2}" -f $TemplateId,$filledPlaceholders.Count,($filledPlaceholders -join '; ')) 'WARN'
  }

  return @{
    Success = $true
    Items = $items
    MissingFields = @()
    FilledPlaceholders = $filledPlaceholders
  }
}
function Get-TargetUserIdByName {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][string]$UserName,
    [string]$KnownAs = "",
    [string]$DomainName = ""
  )
  
  if([string]::IsNullOrWhiteSpace($UserName)){ return $null }
  
  # Ensure cache is loaded
  Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
  
  # Strategy 1: Exact match on userName
  $key = $UserName.ToLowerInvariant()
  if($script:TgtUserNameToIdCache.ContainsKey($key)){
    return [int]$script:TgtUserNameToIdCache[$key]
  }
  
  # Strategy 2: Try knownAs field (e.g., "internal.abcd.com\John Doe" or just "John Doe"). This is useful for cases where the source system has a different username format than the target, but the knownAs field contains a more user-friendly name that may match the target's userName or displayName.
  if(-not [string]::IsNullOrWhiteSpace($KnownAs)){
    $key2 = $KnownAs.ToLowerInvariant()
    if($script:TgtUserNameToIdCache.ContainsKey($key2)){
      Write-Log ("  User resolved via knownAs: '{0}'" -f $KnownAs) 'DEBUG'
      return [int]$script:TgtUserNameToIdCache[$key2]
    }
    # Also try just the name part from knownAs (after the backslash)
    if($KnownAs -match '\\(.+)$'){
      $displayName = $Matches[1].ToLowerInvariant()
      if($script:TgtUserNameToIdCache.ContainsKey($displayName)){
        Write-Log ("  User resolved via knownAs display name: '{0}'" -f $displayName) 'DEBUG'
        return [int]$script:TgtUserNameToIdCache[$displayName]
      }
    }
  }
  
  # Strategy 3: Try userName without domain suffix (strip @domain.com)
  if($UserName -match '^(.+)@.+$'){
    $nameWithoutDomain = $Matches[1].ToLowerInvariant()
    if($script:TgtUserNameToIdCache.ContainsKey($nameWithoutDomain)){
      Write-Log ("  User resolved by stripping domain: '{0}' -> '{1}'" -f $UserName, $nameWithoutDomain) 'DEBUG'
      return [int]$script:TgtUserNameToIdCache[$nameWithoutDomain]
    }
  }
  
  # Strategy 4: Try with domainName prefix (domain\username format)
  if(-not [string]::IsNullOrWhiteSpace($DomainName)){
    $domainPrefixed = ("{0}\{1}" -f $DomainName, $UserName).ToLowerInvariant()
    if($script:TgtUserNameToIdCache.ContainsKey($domainPrefixed)){
      Write-Log ("  User resolved via domain prefix: '{0}'" -f $domainPrefixed) 'DEBUG'
      return [int]$script:TgtUserNameToIdCache[$domainPrefixed]
    }
    # Try domain\nameWithoutEmailDomain
    if($UserName -match '^(.+)@'){
      $domainPrefixed2 = ("{0}\{1}" -f $DomainName, $Matches[1]).ToLowerInvariant()
      if($script:TgtUserNameToIdCache.ContainsKey($domainPrefixed2)){
        Write-Log ("  User resolved via domain\\name: '{0}'" -f $domainPrefixed2) 'DEBUG'
        return [int]$script:TgtUserNameToIdCache[$domainPrefixed2]
      }
    }
  }

  # Strategy 4b: groupsmap.csv translation fallback (same idea as the group
  # lookup). If the CSV is loaded, try the mapped target name before falling
  # back to partial-match / API search.
  if($script:GroupMapTranslations_User -and $script:GroupMapTranslations_User.Count -gt 0){
    $mappedU = $null
    if($script:GroupMapTranslations_User.ContainsKey($key)){ $mappedU = [string]$script:GroupMapTranslations_User[$key] }
    elseif(-not [string]::IsNullOrWhiteSpace($KnownAs) -and $script:GroupMapTranslations_KnownAs -and $script:GroupMapTranslations_KnownAs.ContainsKey($KnownAs.ToLowerInvariant())){
      $mappedU = [string]$script:GroupMapTranslations_KnownAs[$KnownAs.ToLowerInvariant()]
    }
    if(-not [string]::IsNullOrWhiteSpace($mappedU)){
      $mappedUKey = $mappedU.ToLowerInvariant()
      if($script:TgtUserNameToIdCache.ContainsKey($mappedUKey)){
        Write-Log ("  User resolved via groupsmap.csv: '{0}' -> '{1}'" -f $UserName,$mappedU) 'INFO'
        return [int]$script:TgtUserNameToIdCache[$mappedUKey]
      }
      if($mappedU -match '^(.+)@'){
        $ub = $Matches[1].ToLowerInvariant()
        if($script:TgtUserNameToIdCache.ContainsKey($ub)){
          Write-Log ("  User resolved via groupsmap.csv (domain stripped): '{0}' -> '{1}' -> '{2}'" -f $UserName,$mappedU,$ub) 'INFO'
          return [int]$script:TgtUserNameToIdCache[$ub]
        }
      }
    }
  }
  
  # Strategy 5: Partial match - check if target has user with same base name
  $srcBase = if($UserName -match '^(.+)@'){ $Matches[1].ToLowerInvariant() } else { $UserName.ToLowerInvariant() }
  foreach($cachedKey in $script:TgtUserNameToIdCache.Keys){
    $cachedBase = if($cachedKey -match '^(.+)@'){ $Matches[1] } else { $cachedKey }
    if($cachedBase -eq $srcBase){
      Write-Log ("  User resolved via base name match: '{0}' -> cached '{1}'" -f $UserName, $cachedKey) 'DEBUG'
      return [int]$script:TgtUserNameToIdCache[$cachedKey]
    }
  }
  
  # Strategy 6: Direct API search as last resort
  try{
    $searchName = if($UserName -match '^(.+)@'){ $Matches[1] } else { $UserName }
    $resp = SS $TgtApiBase GET 'users' $TgtTok $null @{ 'filter.searchText' = $searchName; 'take' = 20 }
    $recs = @(Get-Records $resp)
    foreach($u in $recs){
      $uid = 0
      try{ $uid = [int](Get-PropValue $u @('id','Id','userId','UserId') 0) } catch {}
      $uname = [string](Get-PropValue $u @('userName','UserName','username','name','Name') $null)
      if($uid -gt 0 -and -not [string]::IsNullOrWhiteSpace($uname)){
        $uKey = $uname.ToLowerInvariant()
        # Check various matches
        $uBase = if($uname -match '^(.+)@'){ $Matches[1].ToLowerInvariant() } else { $uKey }
        if($uKey -eq $UserName.ToLowerInvariant() -or $uBase -eq $srcBase){
          Write-Log ("  User resolved via API search: '{0}' -> '{1}' (id={2})" -f $UserName,$uname,$uid) 'DEBUG'
          # Cache it
          $script:TgtUserNameToIdCache[$uKey] = $uid
          $script:TgtUserNameToIdCache[$UserName.ToLowerInvariant()] = $uid
          return [int]$uid
        }
      }
    }
  } catch {
    Write-Log ("  User API search failed for '{0}': {1}" -f $UserName,$_.Exception.Message) 'DEBUG'
  }
  
  # User not found in target
  return $null
}

function Export-JsonToXml {
  param(
    [Parameter(Mandatory)][string]$InputJsonPath,
    [Parameter(Mandatory)][string]$OutXmlPath
  )

  # Delegate to the full Delinea web portal compatible export function
  try {
    Export-SecretsJsonToDelineaImportXml -InputJsonPath $InputJsonPath -OutXmlPath $OutXmlPath -IncludeFolders -IncludePermissions
    $root = Read-LargeJsonAsPSObject $InputJsonPath
    return @($root.Secrets).Count
  }
  catch {
    Write-Log ("Export-JsonToXml failed: {0}" -f $_.Exception.Message) 'ERROR'
    return 0
  }
}
function Export-JsonToCsvBundle {
  param(
    [Parameter(Mandatory)][string]$InputJsonPath,
    [Parameter(Mandatory)][string]$OutDir
  )

  if(-not (Test-Path $InputJsonPath)){
    Write-Log "CSV BUNDLE: Input JSON not found: $InputJsonPath" 'WARN'
    return 0
  }

  $root = Read-LargeJsonAsPSObject $InputJsonPath
  $secrets = @($root.Secrets)
  
  Write-Log ("CSV BUNDLE: Starting from JSON: {0}" -f $InputJsonPath) 'INFO'
  Write-Log ("CSV BUNDLE: Processing {0} secrets..." -f $secrets.Count) 'INFO'

  # Ensure output directory exists
  if(-not (Test-Path $OutDir)){ New-Item -ItemType Directory -Path $OutDir | Out-Null }

  # Initialize CSV data collections (use List for O(1) append performance)
  $secretRows = [System.Collections.Generic.List[object]]::new()
  $itemRows = [System.Collections.Generic.List[object]]::new()
  $secretPermRows = [System.Collections.Generic.List[object]]::new()
  $folderPermRows = [System.Collections.Generic.List[object]]::new()
  $settingsRows = [System.Collections.Generic.List[object]]::new()
  $attachmentRows = [System.Collections.Generic.List[object]]::new()

  $idx = 0
  foreach($sec in $secrets){
    $idx++
    if($idx -eq 1 -or $idx % 100 -eq 0){
      Write-Log ("CSV BUNDLE: {0}/{1} secrets ({2:P0})" -f $idx,$secrets.Count,($idx/$secrets.Count)) 'INFO'
      [System.Windows.Forms.Application]::DoEvents()
    }
    
    $secId = Get-PropValue $sec @('Id','id') 0
    $secName = [string](Get-PropValue $sec @('Name','name') "")
    $tmplId = Get-PropValue $sec @('SecretTypeId','secretTypeId') 0
    $tmplName = [string](Get-PropValue $sec @('SecretTypeName','secretTypeName') "")
    $folderId = Get-PropValue $sec @('FolderId','folderId') $null
    $folderPath = [string](Get-PropValue $sec @('FolderPath','folderPath') "")
    $siteId = Get-PropValue $sec @('SiteId','siteId') $null
    
    # Secret row
    [void]$secretRows.Add([PSCustomObject]@{
      SecretId = $secId
      SecretName = $secName
      TemplateId = $tmplId
      TemplateName = $tmplName
      FolderId = $folderId
      FolderPath = $folderPath
      SiteId = $siteId
    })
    
    # Items
    $items = Get-PropValue $sec @('Items','items') @()
    foreach($it in @($items)){
      [void]$itemRows.Add([PSCustomObject]@{
        SecretId = $secId
        FieldName = [string](Get-PropValue $it @('name','Name') "")
        FieldSlug = [string](Get-PropValue $it @('slug','Slug') "")
        Value = [string](Get-PropValue $it @('value','Value') "")
        IsFile = [bool](Get-PropValue $it @('isFile','IsFile') $false)
        FileName = [string](Get-PropValue $it @('filename','fileName') "")
        FileExportPath = [string](Get-PropValue $it @('fileExportPath','FileExportPath') "")
        FileExportBytes = Get-PropValue $it @('fileExportBytes','FileExportBytes') 0
      })
      
      # Track attachments
      $exportPath = Get-PropValue $it @('fileExportPath','FileExportPath') $null
      if(-not [string]::IsNullOrWhiteSpace([string]$exportPath)){
        [void]$attachmentRows.Add([PSCustomObject]@{
          SecretId = $secId
          SecretName = $secName
          FieldSlug = [string](Get-PropValue $it @('slug','Slug') "")
          FileName = [string](Get-PropValue $it @('filename','fileName') "")
          FilePath = $exportPath
          FileBytes = Get-PropValue $it @('fileExportBytes','FileExportBytes') 0
        })
      }
    }
    
    # Secret permissions
    $secPerms = Get-PropValue $sec @('SecretPermissions','secretPermissions') @()
    foreach($p in @($secPerms)){
      [void]$secretPermRows.Add([PSCustomObject]@{
        SecretId = $secId
        SecretName = $secName
        UserId = Get-PropValue $p @('userId','UserId') $null
        UserName = [string](Get-PropValue $p @('userName','UserName') "")
        GroupId = Get-PropValue $p @('groupId','GroupId') $null
        GroupName = [string](Get-PropValue $p @('groupName','GroupName') "")
        RoleId = Get-PropValue $p @('secretAccessRoleId','SecretAccessRoleId') $null
        RoleName = [string](Get-PropValue $p @('secretAccessRoleName','SecretAccessRoleName') "")
      })
    }
    
    # Folder permissions
    $folderPerms = Get-PropValue $sec @('FolderPermissions','folderPermissions') @()
    foreach($p in @($folderPerms)){
      [void]$folderPermRows.Add([PSCustomObject]@{
        FolderId = $folderId
        FolderPath = $folderPath
        SecretId = $secId
        UserId = Get-PropValue $p @('userId','UserId') $null
        UserName = [string](Get-PropValue $p @('userName','UserName') "")
        GroupId = Get-PropValue $p @('groupId','GroupId') $null
        GroupName = [string](Get-PropValue $p @('groupName','GroupName') "")
        FolderAccessRoleId = Get-PropValue $p @('folderAccessRoleId','FolderAccessRoleId') $null
        FolderAccessRoleName = [string](Get-PropValue $p @('folderAccessRoleName','FolderAccessRoleName') "")
      })
    }
    
    # Settings
    $settings = Get-PropValue $sec @('SecretSettings','secretSettings') $null
    if($null -ne $settings){
      [void]$settingsRows.Add([PSCustomObject]@{
        SecretId = $secId
        SecretName = $secName
        AutoChangeEnabled = Get-PropValue $settings @('autoChangeEnabled','AutoChangeEnabled') $null
        RequiresComment = Get-PropValue $settings @('requiresComment','RequiresComment') $null
        CheckOutEnabled = Get-PropValue $settings @('checkOutEnabled','CheckOutEnabled') $null
        CheckOutIntervalMinutes = Get-PropValue $settings @('checkOutIntervalMinutes','CheckOutIntervalMinutes') $null
        ProxyEnabled = Get-PropValue $settings @('proxyEnabled','ProxyEnabled') $null
        SessionRecordingEnabled = Get-PropValue $settings @('sessionRecordingEnabled','SessionRecordingEnabled') $null
        SettingsJson = ($settings | ConvertTo-Json -Compress -Depth 10)
      })
    }
  }

  Write-Log "CSV BUNDLE: Finished processing {0} secrets. Writing CSV files..." -f $secrets.Count 'INFO'

  # Write CSV files
  if($secretRows.Count -gt 0){
    $secretRows | Export-Csv -Path (Join-Path $OutDir "secrets.csv") -NoTypeInformation -Encoding UTF8
  }
  if($itemRows.Count -gt 0){
    $itemRows | Export-Csv -Path (Join-Path $OutDir "secret-items.csv") -NoTypeInformation -Encoding UTF8
  }
  if($secretPermRows.Count -gt 0){
    $secretPermRows | Export-Csv -Path (Join-Path $OutDir "secret-permissions.csv") -NoTypeInformation -Encoding UTF8
  }
  if($folderPermRows.Count -gt 0){
    $folderPermRows | Export-Csv -Path (Join-Path $OutDir "folder-permissions.csv") -NoTypeInformation -Encoding UTF8
  }
  if($settingsRows.Count -gt 0){
    $settingsRows | Export-Csv -Path (Join-Path $OutDir "secret-settings.csv") -NoTypeInformation -Encoding UTF8
  }
  if($attachmentRows.Count -gt 0){
    $attachmentRows | Export-Csv -Path (Join-Path $OutDir "attachments.csv") -NoTypeInformation -Encoding UTF8
  }

  Write-Log ("[OK] CSV bundle complete: {0}" -f $OutDir) 'INFO'
  $c0=$secretRows.Count; $c1=$itemRows.Count; $c2=$secretPermRows.Count; $c3=$folderPermRows.Count; $c4=$settingsRows.Count; $c5=$attachmentRows.Count
  Write-Log "CSV counts: secrets=$c0, items=$c1, secretPerms=$c2, folderPerms=$c3, settings=$c4, attachments=$c5" 'INFO'

  return $secrets.Count
}
# =========================
# EXPORT FUNCTION (ASCII-SAFE)
# =========================
function Export-SS {
  param(
    [string]$ApiBase,
    [string]$Token,
    [string]$OutPath,
    [string]$Search = '*',
    [Nullable[int]]$FolderId = $null,
    [Nullable[int]]$MaxSecrets = $null,
    [bool]$IncludeHistory = $false,
    [bool]$ExportTemplates = $false,
    [bool]$CopyFolderAcls = $false,
    [bool]$CopySecretAcls = $false,
    [bool]$CopySecretSettings = $false,
    [bool]$CopyAttachments = $false,
    [bool]$Incremental = $false,
    [bool]$EncryptPasswords = $false,
    [int[]]$OnlySecretIds = $null
  )

  function Get-SrcTok { Token Src $tbSrcPwd }

  # Reset cancellation flag
  $script:ExportCancelled = $false

  # Log parameters
  Write-Log ("EXPORT: Parameters - MaxSecrets={0}, FolderId={1}, Search='{2}'" -f `
    $(if($MaxSecrets -ne $null -and $MaxSecrets -gt 0){"$MaxSecrets"}else{"(all)"}), `
    $(if($FolderId -ne $null -and $FolderId -gt 0){"$FolderId"}else{"(all)"}), `
    $Search) 'INFO'

  if($IncludeHistory){
    Write-Log "Include History enabled - will attempt to export password history for each secret." 'INFO'
  }

  if($CopyAttachments){
    Ensure-Dir $script:AttachmentRoot
    Write-Log ("Copy Attachments enabled. Exporting to: {0}" -f $script:AttachmentRoot) 'INFO'
  }

  # Incremental export: load existing secrets to skip
  $existingSecrets = New-Object 'System.Collections.Generic.List[object]'
  $existingSecretIds = New-Object 'System.Collections.Generic.HashSet[int]'
  $existingTemplates = @()
  
  # Auto-enable incremental if a partial (interrupted) export file exists
  if(-not $Incremental -and (Test-Path $OutPath)){
    try{
      $peekData = Get-Content $OutPath -Raw | ConvertFrom-Json
      if($peekData._ExportInProgress){
        Write-Log ("EXPORT: Detected interrupted export with {0} secrets on disk. Auto-enabling incremental/resume mode." -f @($peekData.Secrets).Count) 'WARN'
        $Incremental = $true
      }
    }catch{}
  }

  if($Incremental -and (Test-Path $OutPath)){
    Write-Log "EXPORT: Incremental mode - loading existing export file..." 'INFO'
    try{
      $existingData = Get-Content $OutPath -Raw | ConvertFrom-Json
      if($existingData._ExportInProgress){
        Write-Log ("EXPORT: Resuming interrupted export ({0} secrets already saved)" -f @($existingData.Secrets).Count) 'WARN'
      }
      if($existingData.Secrets){
        foreach($es in @($existingData.Secrets)){
          $esId = Get-PropValue $es @('Id','id','SecretId','secretId') $null
          if($esId -ne $null -and [int]$esId -gt 0){
            [void]$existingSecretIds.Add([int]$esId)
            $existingSecrets.Add($es)
          }
        }
      }
      if($existingData.TemplateExports){
        $existingTemplates = @($existingData.TemplateExports)
      }
      Write-Log ("EXPORT: Incremental - found {0} existing secrets to skip" -f $existingSecretIds.Count) 'INFO'
    }
    catch{
      Write-Log ("EXPORT: Could not load existing export file: {0}" -f $_.Exception.Message) 'WARN'
      $existingSecretIds.Clear()
      $existingSecrets.Clear()
    }
  }

  # Enumerate ALL secrets using tenant-wide /secrets endpoint
  Write-Log "EXPORT: Enumerating secrets using tenant-wide /secrets endpoint..." 'INFO'
  
  $apiCallCount = 0
  $allSecretIds = New-Object 'System.Collections.Generic.List[int]'
  $seenIds = New-Object 'System.Collections.Generic.HashSet[int]'
  $hasMaxLimit = ($MaxSecrets -ne $null -and $MaxSecrets -gt 0)

  # FAST PATH: caller supplied an explicit ID list (used by Reconcile Missing).
  # Skip enumeration entirely and use the provided IDs as the work list.
  if($OnlySecretIds -and $OnlySecretIds.Count -gt 0){
    Write-Log ("EXPORT: Targeted mode - {0} explicit secret IDs supplied; skipping enumeration" -f $OnlySecretIds.Count) 'INFO'
    foreach($oid in $OnlySecretIds){
      $oi = 0; try{ $oi = [int]$oid } catch {}
      if($oi -gt 0 -and $seenIds.Add($oi)){ [void]$allSecretIds.Add($oi) }
    }
    Write-Log ("EXPORT: Targeted mode work list = {0} IDs" -f $allSecretIds.Count) 'INFO'
  }
  else {
  $page = 1
  $pageSize = 500
  $lastLogTime = [DateTime]::MinValue
  
  # If folder filter requested, get descendant folder IDs
  $filterByFolder = ($FolderId -ne $null -and $FolderId -gt 0)
  $targetFolderIds = New-Object 'System.Collections.Generic.HashSet[int]'
  
  if($filterByFolder){
    Write-Log ("EXPORT: Folder filter specified (folderId={0})" -f $FolderId) 'INFO'
    try{
      $descendantIds = @(Get-DescendantFolderIds -ApiBase $ApiBase -Tok (Get-SrcTok) -RootFolderId ([int]$FolderId))
      foreach($did in $descendantIds){ [void]$targetFolderIds.Add($did) }
      Write-Log ("EXPORT: Will include secrets from {0} folders" -f $targetFolderIds.Count) 'INFO'
    }
    catch{
      [void]$targetFolderIds.Add([int]$FolderId)
    }
  }
  
  $stopEnumeration = $false
  
  while($page -le 500 -and -not $stopEnumeration){
    try{
      $params = @{
        'filter.searchText' = $Search
        'filter.page'       = $page
        'filter.pageSize'   = $pageSize
        'take'              = $pageSize
        'skip'              = (($page - 1) * $pageSize)
      }
      
      $resp = SS $ApiBase GET 'secrets' (Get-SrcTok) $null $params
      $apiCallCount++
      $recs = @(Get-Records $resp)
      
      foreach($rec in $recs){
        if($hasMaxLimit -and $allSecretIds.Count -ge $MaxSecrets){
          Write-Log ("EXPORT: Reached MaxSecrets limit ({0})" -f $MaxSecrets) 'INFO'
          $stopEnumeration = $true
          break
        }
        
        $sid = $null
        try{ $sid = [int](Get-PropValue $rec @('id','Id','secretId','SecretId') $null) } catch {}
        
        if($sid -ne $null -and $sid -gt 0 -and $seenIds.Add($sid)){
          # Skip already exported secrets in incremental mode
          if($Incremental -and $existingSecretIds.Contains($sid)){
            continue
          }
          if($filterByFolder){
            $recFolderId = $null
            try{ $recFolderId = [int](Get-PropValue $rec @('folderId','FolderId') $null) } catch {}
            if($recFolderId -ne $null -and $targetFolderIds.Contains($recFolderId)){
              $allSecretIds.Add($sid) | Out-Null
            }
          }
          else{
            $allSecretIds.Add($sid) | Out-Null
          }
        }
      }
      
      if($hasMaxLimit -and $allSecretIds.Count -ge $MaxSecrets){
        $stopEnumeration = $true
        break
      }
      
      $now = Get-Date
      if(($page % 5 -eq 0) -or (($now - $lastLogTime).TotalSeconds -ge 3)){
        Write-Log ("EXPORT: enumeration page {0}, collected {1} secrets..." -f $page,$allSecretIds.Count) 'INFO'
        $lastLogTime = $now
      }
      
      if($recs.Count -lt $pageSize){ break }
      $page++
    }
    catch{
      Write-Log ("EXPORT: enumeration failed on page {0}: {1}" -f $page,$_.Exception.Message) 'ERROR'
      break
    }
  }
  } # end else (non-targeted enumeration)
  
  # Trim to MaxSecrets if needed
  if($hasMaxLimit -and $allSecretIds.Count -gt $MaxSecrets){
    $trimmedList = New-Object 'System.Collections.Generic.List[int]'
    for($i = 0; $i -lt $MaxSecrets; $i++){
      $trimmedList.Add($allSecretIds[$i]) | Out-Null
    }
    $allSecretIds = $trimmedList
  }
  
  Write-Log ("EXPORT: Enumeration complete. {0} secrets to export." -f $allSecretIds.Count) 'INFO'

  # ============ BATCH-PARALLEL EXPORT USING HttpClient ============
  # Process secrets in batches, firing all API calls concurrently within each batch
  $batchSize = 20  # secrets per batch (each secret may have 1-4 API calls, so 20-80 concurrent requests)
  
  $list = New-Object 'System.Collections.Generic.List[object]'
  $templateIdSet = New-Object 'System.Collections.Generic.HashSet[int]'
  $secretCount = $allSecretIds.Count
  $secretIndex = 0
  $lastLogTime = [DateTime]::MinValue
  $exportStartTime = Get-Date
  $lastSaveIndex = 0
  $saveInterval = 100
  $script:FolderPermCache = @{}

  # Create a reusable HttpClient for the entire export
  $httpHandler = New-Object System.Net.Http.HttpClientHandler
  $httpHandler.MaxConnectionsPerServer = 50
  $httpClient = New-Object System.Net.Http.HttpClient($httpHandler)
  $httpClient.Timeout = [TimeSpan]::FromSeconds(120)
  $srcToken = Get-SrcTok
  $httpClient.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $srcToken)

  # Helper: fire a GET and return a Task
  function Start-AsyncGet([System.Net.Http.HttpClient]$client, [string]$url){
    return $client.GetAsync($url)
  }

  # Process in batches
  $allIds = @($allSecretIds)
  for($batchStart = 0; $batchStart -lt $allIds.Count; $batchStart += $batchSize){
    # Check cancellation
    if($script:ExportCancelled){
      Write-Log "EXPORT: Cancelled by user. Saving progress..." 'WARN'
      break
    }

    # Refresh token if needed (token cache handles expiry)
    try{
      $newTok = Get-SrcTok
      if($newTok -ne $srcToken){
        $srcToken = $newTok
        $httpClient.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $srcToken)
      }
    } catch {}

    $batchEnd = [Math]::Min($batchStart + $batchSize, $allIds.Count) - 1
    $batchIds = $allIds[$batchStart..$batchEnd]
    $apiBase = $ApiBase.TrimEnd('/')

    # --- Phase 1: Fire ALL API calls for this batch concurrently ---
    $tasks = @{}  # key = "type_secretId", value = Task<HttpResponseMessage>
    
    foreach($rid in $batchIds){
      # Secret detail (always needed)
      $tasks["detail_$rid"] = Start-AsyncGet $httpClient "$apiBase/secrets/$rid"
      
      # Secret settings (if enabled)
      if($CopySecretSettings){
        $tasks["settings_$rid"] = Start-AsyncGet $httpClient "$apiBase/secrets/$rid/settings"
      }
      
      # Secret permissions (if enabled)
      if($CopySecretAcls){
        $permUrl = "$apiBase/secret-permissions?filter.secretId=$rid&filter.page=1&filter.pageSize=200"
        $tasks["perms_$rid"] = Start-AsyncGet $httpClient $permUrl
      }
      
      # Password history (if enabled) - uses standard endpoint; fallback handled later for failures
      if($IncludeHistory){
        $tasks["history_$rid"] = Start-AsyncGet $httpClient "$apiBase/secrets/$rid/fields/password/history?skip=0&take=100"
      }
    }

    # --- Phase 2: Wait for all tasks in this batch ---
    try{
      $taskArray = [System.Threading.Tasks.Task[]]@($tasks.Values)
      [System.Threading.Tasks.Task]::WaitAll($taskArray)
    } catch {
      # Some tasks may have faulted; we handle individually below
    }

    # --- Phase 3: Parse responses and build export objects ---
    foreach($rid in $batchIds){
      $secretIndex++
      
      # Update progress
      $now = Get-Date
      $elapsed = ($now - $exportStartTime).TotalSeconds
      $rate = if($secretIndex -gt 1 -and $elapsed -gt 0){ $secretIndex / $elapsed } else { 0 }
      $remainingSec = if($rate -gt 0){ [int](($secretCount - $secretIndex) / $rate) } else { 0 }
      $etaText = if($remainingSec -ge 3600){ "{0}h {1}m" -f [int]($remainingSec/3600),[int](($remainingSec%3600)/60) } elseif($remainingSec -ge 60){ "{0}m {1}s" -f [int]($remainingSec/60),($remainingSec%60) } else { "{0}s" -f $remainingSec }
      $statusText = "{0}/{1} - ETA {2}" -f $secretIndex,$secretCount,$etaText
      try{ Update-ProgressBar -Current $secretIndex -Total $secretCount -StatusText $statusText }catch{}

      # Parse secret detail
      $s = $null
      $detailKey = "detail_$rid"
      if($tasks.ContainsKey($detailKey)){
        $resp = $tasks[$detailKey].Result
        if($resp.IsSuccessStatusCode){
          try{
            $json = $resp.Content.ReadAsStringAsync().Result
            $s = $json | ConvertFrom-Json
            $apiCallCount++
          } catch {}
        }
        $resp.Dispose()
      }
      if(-not $s){
        # Fallback: try via SS function
        try{
          $s = SS $ApiBase GET ("secrets/{0}" -f $rid) (Get-SrcTok) $null $null
          $apiCallCount++
        }
        catch{
          Write-Log ("EXPORT: Could not fetch secret id={0}: {1}" -f $rid,$_.Exception.Message) 'WARN'
          continue
        }
      }

      $sid   = [int](Get-PropValue $s @('id','Id','secretId','SecretId') $rid)
      $name  = [string](Get-PropValue $s @('name','Name','secretName','SecretName') ("secret_$sid"))
      $stypeId = Get-PropValue $s @('secretTypeId','SecretTypeId','secretTemplateId','SecretTemplateId') $null
      $stypeName = Get-PropValue $s @('secretTypeName','SecretTypeName','templateName','TemplateName') $null
      if($stypeId -ne $null){ [void]$templateIdSet.Add([int]$stypeId) }

      $folder = Get-PropValue $s @('folderId','FolderId') $null
      $site   = Get-PropValue $s @('siteId','SiteId') $null

      $rawItems = Get-PropValue $s @('items','Items','fields','Fields') @()
      $normItems = @()
     
        foreach($it in @($rawItems)){
      $n    = Get-PropValue $it @('name','Name','fieldName','FieldName') $null
      $slug = Get-PropValue $it @('slug','Slug','fieldSlugName','FieldSlugName') $null
      $val  = Get-PropValue $it @('value','Value','itemValue','ItemValue') $null

      # If the API returned a non-displayable placeholder (e.g. SSH private keys, restricted fields),
      # fetch the real value individually via GET /secrets/{id}/fields/{slug}
      if(-not [string]::IsNullOrWhiteSpace([string]$slug) -and
         ([string]$val -eq '*** Not Valid For Display ***' -or [string]$val -match '^\*{3}.*\*{3}$')){
        Write-Log ("EXPORT: Field '{0}' on secretId={1} is restricted ('{2}'); fetching via field endpoint" -f $slug,$sid,$val) 'DEBUG'
        $fetchedVal = SS-GetRestrictedFieldText -apiBase $ApiBase -tok (Get-SrcTok) -secretId $sid -slug ([string]$slug)
        if(-not [string]::IsNullOrEmpty($fetchedVal)){
          $val = $fetchedVal
          Write-Log ("EXPORT: Retrieved restricted field '{0}' for secretId={1} ({2} chars)" -f $slug,$sid,([string]$val).Length) 'INFO'
        } else {
          Write-Log ("EXPORT: Could not retrieve restricted field '{0}' for secretId={1} - value will remain as placeholder" -f $slug,$sid) 'WARN'
        }
      }

      # Encrypt password field value if encryption is enabled
      if($EncryptPasswords -and -not [string]::IsNullOrWhiteSpace([string]$val)){
        $slugLower = ([string]$slug).ToLowerInvariant()
        if($slugLower -match 'password|pass|pwd'){
          $originalVal = $val
          $val = Encrypt-PasswordValue -plainValue ([string]$val)
          if($val -ne $originalVal){
            Write-Log ("EXPORT: Encrypted password field for secret {0}, slug='{1}'" -f $sid,$slug) 'DEBUG'
          }
        }
      }

      $exportItem = [pscustomobject]@{
        name  = $n
        slug  = $slug
        value = $val
      }

      $isFile = $false
      try{ $isFile = [bool](Get-PropValue $it @('isFile','IsFile') $false) } catch {}
    # REPLACE the file field handling block in Export-SS function (inside the foreach($it in @($rawItems)) loop)
# Find the section that starts with: if($isFile -and -not [string]::IsNullOrWhiteSpace([string]$slug)){

    if($isFile -and -not [string]::IsNullOrWhiteSpace([string]$slug)){
        $exportItem | Add-Member -NotePropertyName isFile -NotePropertyValue $true -Force
        
        $fn = Get-PropValue $it @('filename','fileName','FileName') $null
        $exportItem | Add-Member -NotePropertyName filename -NotePropertyValue $fn -Force
        
        $fileAttachId = Get-PropValue $it @('fileAttachmentId','FileAttachmentId') $null
        $exportItem | Add-Member -NotePropertyName fileAttachmentId -NotePropertyValue $fileAttachId -Force

        if($CopyAttachments){
          # Attempt download - log only on DEBUG level for attempts
          Write-Log ("FILEFIELD: Checking secretId={0} slug='{1}'" -f $sid,$slug) 'DEBUG'
          
          $bytes = SS-GetFieldBytes -apiBase $ApiBase -tok (Get-SrcTok) -secretId $sid -slug ([string]$slug)
          
          if($bytes -and $bytes.Length -gt 0){
            # Determine filename
            if([string]::IsNullOrWhiteSpace([string]$fn)){ 
              $fn = "$slug.bin"
              if($slug -match 'private.*key|privatekey'){ $fn = "private-key.pem" }
              elseif($slug -match 'public.*key|publickey'){ $fn = "public-key.pem" }
              elseif($slug -match 'certificate|cert'){ $fn = "certificate.pem" }
            }
            
            $saved = Save-AttachmentToDisk -attachmentRoot $script:AttachmentRoot -secretId $sid -fieldSlug ([string]$slug) -fileName ([string]$fn) -bytes $bytes
            $exportItem | Add-Member -NotePropertyName fileExportPath -NotePropertyValue $saved -Force
            $exportItem | Add-Member -NotePropertyName fileExportBytes -NotePropertyValue $bytes.Length -Force
            # Only log SUCCESS at INFO level - this is important to know
            Write-Log ("ATTACHMENT: Saved {0} bytes for secret {1}" -f $bytes.Length,$sid) 'INFO'
          } 
          else {
            $exportItem | Add-Member -NotePropertyName fileExportPath -NotePropertyValue $null -Force
            $exportItem | Add-Member -NotePropertyName fileExportBytes -NotePropertyValue 0 -Force
            # Empty fields are DEBUG - not errors
            Write-Log ("FILEFIELD: Empty field secretId={0} slug='{1}'" -f $sid,$slug) 'DEBUG'
          }
        }
      }
        
      $normItems += $exportItem
    }

      $o = [pscustomobject]@{
      Id             = $sid
      Name           = $name
      SecretTypeId   = $stypeId
      SecretTypeName = $stypeName
      FolderId       = $folder
      SiteId         = $site
      Items          = $normItems
    }

    # Folder path
    try{
      if($folder -ne $null){
        $fp = Get-FolderPath-Source -srcApi $ApiBase -srcTok (Get-SrcTok) -srcFolderId ([int]$folder)
        if($fp){ Add-Member -InputObject $o -NotePropertyName FolderPath -NotePropertyValue $fp -Force }
      }
    } catch {}

    # Folder permissions
    if($CopyFolderAcls -and $folder -ne $null){
      try{
        $fldId = [int]$folder
        if($script:FolderPermCache -and $script:FolderPermCache.ContainsKey($fldId)){
          $perms = $script:FolderPermCache[$fldId]
        } else {
          $perms = Get-FolderPermissions -apiBase $ApiBase -tok (Get-SrcTok) -folderId $fldId
          $apiCallCount++
          if(-not $script:FolderPermCache){ $script:FolderPermCache = @{} }
          $script:FolderPermCache[$fldId] = $perms
          if($perms -and @($perms).Count -gt 0){
            Write-Log ("EXPORT: Got {0} folder permissions for folderId={1}" -f @($perms).Count,$fldId) 'DEBUG'
          }
        }
        if($perms -and @($perms).Count -gt 0){
          Add-Member -InputObject $o -NotePropertyName FolderPermissions -NotePropertyValue $perms -Force
        }
      } catch {
        Write-Log ("EXPORT: Folder permissions failed for folderId={0}: {1}" -f $folder,$_.Exception.Message) 'DEBUG'
      }
    }

    # Secret permissions - use batch-fetched result
    if($CopySecretAcls){
      $enriched = @()
      try{
        $permsKey = "perms_$rid"
        $recs = @()
        if($tasks.ContainsKey($permsKey)){
          $permsResp = $tasks[$permsKey].Result
          if($permsResp.IsSuccessStatusCode){
            $permsJson = $permsResp.Content.ReadAsStringAsync().Result
            $permsData = $permsJson | ConvertFrom-Json
            $recs = @(Get-Records $permsData)
            $apiCallCount++
          }
          $permsResp.Dispose()
        }
        if($recs.Count -eq 0){
          # Fallback to SS function
          $sp = SS $ApiBase GET 'secret-permissions' (Get-SrcTok) $null @{
            'filter.secretId' = [int]$sid
            'filter.page'     = 1
            'filter.pageSize' = 200
          }
          $apiCallCount++
          $recs = @(Get-Records $sp)
        }
        foreach($p in @($recs)){
            # Enrich group name if missing
            $gid = Get-PropValue $p @('groupId','GroupId') $null
            $gn  = Get-PropValue $p @('groupName','GroupName','name','Name') $null
            if(($gid -ne $null) -and ([int]$gid -gt 0) -and [string]::IsNullOrWhiteSpace([string]$gn)){
              $gn2 = Get-GroupNameById-Cached -apiBase $ApiBase -tok (Get-SrcTok) -groupId ([int]$gid)
              $apiCallCount++
              if($gn2){
                try{ $p | Add-Member -NotePropertyName groupName -NotePropertyValue $gn2 -Force } catch {}
              }
            }
            # Enrich user name if missing
            $uid = Get-PropValue $p @('userId','UserId') $null
            $un  = Get-PropValue $p @('userName','UserName','username') $null
            if(($uid -ne $null) -and ([int]$uid -gt 0) -and [string]::IsNullOrWhiteSpace([string]$un)){
              $un2 = Get-UserNameById-Cached -apiBase $ApiBase -tok (Get-SrcTok) -userId ([int]$uid)
              $apiCallCount++
              if($un2){
                try{ $p | Add-Member -NotePropertyName userName -NotePropertyValue $un2 -Force } catch {}
              }
            }
            $enriched += $p
          }
      }
      catch{}
      Add-Member -InputObject $o -NotePropertyName SecretPermissions -NotePropertyValue $enriched -Force
    }

    # Secret settings - use batch-fetched result
    if($CopySecretSettings){
      try{
        $settingsKey = "settings_$rid"
        $set = $null
        if($tasks.ContainsKey($settingsKey)){
          $settingsResp = $tasks[$settingsKey].Result
          if($settingsResp.IsSuccessStatusCode){
            $setJson = $settingsResp.Content.ReadAsStringAsync().Result
            $set = $setJson | ConvertFrom-Json
          }
          $settingsResp.Dispose()
          $apiCallCount++
        }
        if(-not $set){
          $set = Get-SecretSettings -apiBase $ApiBase -tok (Get-SrcTok) -secretId ([int]$sid)
          $apiCallCount++
        }
        if($null -ne $set){
          Add-Member -InputObject $o -NotePropertyName SecretSettings -NotePropertyValue $set -Force
        }
      } catch {
        Write-Log ("EXPORT: Could not get settings for secretId={0}: {1}" -f $sid,$_.Exception.Message) 'DEBUG'
      }
    }

    # Password history - use batch-fetched result first, fall back to Get-SecretHistory for retries
    if($IncludeHistory){
      try{
        $histKey = "history_$rid"
        $histData = $null
        if($tasks.ContainsKey($histKey)){
          $histResp = $tasks[$histKey].Result
          if($histResp.IsSuccessStatusCode){
            $histJson = $histResp.Content.ReadAsStringAsync().Result
            $histData = $histJson | ConvertFrom-Json
            $apiCallCount++
          }
          $histResp.Dispose()
        }
        if($histData){
          # Wrap in the expected format
          $hist = @(@{ fieldSlug='password'; history=$histData })
          Add-Member -InputObject $o -NotePropertyName PasswordHistory -NotePropertyValue $hist -Force
          Write-Log ("EXPORT: Got password history for secretId={0}" -f $sid) 'DEBUG'
        } else {
          # Fallback to full Get-SecretHistory with all retry strategies
          $items = Get-PropValue $o @('Items','items','fields','Fields') @()
          $hist = Get-SecretHistory -apiBase $ApiBase -tok (Get-SrcTok) -secretId ([int]$sid) -items $items
          if($hist -and $hist.Count -gt 0){
            Add-Member -InputObject $o -NotePropertyName PasswordHistory -NotePropertyValue $hist -Force
          }
          $apiCallCount++
        }
      } catch {
        Write-Log ("EXPORT: Could not get history for secretId={0}: {1}" -f $sid,$_.Exception.Message) 'WARN'
      }
    }

    $list.Add($o)

    # Periodic save - write progress to disk every N secrets for crash resilience
    if(($list.Count - $lastSaveIndex) -ge $saveInterval){
      $lastSaveIndex = $list.Count
      try{
        $progressSecrets = New-Object 'System.Collections.Generic.List[object]'
        if($existingSecrets.Count -gt 0){ foreach($es in $existingSecrets){ $progressSecrets.Add($es) } }
        foreach($ns in $list){ $progressSecrets.Add($ns) }
        $progressObj = [ordered]@{ Secrets = $progressSecrets; _ExportInProgress = $true; _ExportedCount = $progressSecrets.Count; _TotalExpected = $secretCount }
        Ensure-Dir $OutPath
        Write-LargeJson -Object $progressObj -Path $OutPath -Pretty
        Write-Log ("EXPORT: Progress saved - {0}/{1} secrets written to disk" -f $progressSecrets.Count,$secretCount) 'INFO'
      }
      catch{
        Write-Log ("EXPORT: Could not save progress: {0}" -f $_.Exception.Message) 'WARN'
      }
    }
    } # end foreach($rid in $batchIds)
  } # end for($batchStart...)

  # Dispose HttpClient
  try{ $httpClient.Dispose(); $httpHandler.Dispose() } catch {}

  # Merge with existing secrets for incremental export
  $finalSecrets = New-Object 'System.Collections.Generic.List[object]'
  if($Incremental -and $existingSecrets.Count -gt 0){
    Write-Log ("EXPORT: Merging {0} new secrets with {1} existing secrets" -f $list.Count,$existingSecrets.Count) 'INFO'
    foreach($es in $existingSecrets){ $finalSecrets.Add($es) }
  }
  foreach($ns in $list){ $finalSecrets.Add($ns) }

  # Build output
  $outObj = [ordered]@{ Secrets = $finalSecrets }

  # Mark as in-progress if cancelled (so auto-resume detects it on next run)
  if($script:ExportCancelled){
    $outObj._ExportInProgress = $true
    $outObj._ExportedCount = $finalSecrets.Count
    $outObj._TotalExpected = $secretCount
  }

  if($ExportTemplates -and $templateIdSet.Count -gt 0){
    $tmpl = @()
    # Preserve existing templates in incremental mode
    $existingTemplateIds = New-Object 'System.Collections.Generic.HashSet[int]'
    if($Incremental){
      foreach($et in $existingTemplates){
        $etId = Get-PropValue $et @('templateId','TemplateId') $null
        if($etId -ne $null){
          [void]$existingTemplateIds.Add([int]$etId)
          $tmpl += $et
        }
      }
    }
    foreach($tid in $templateIdSet){
      if($existingTemplateIds.Contains([int]$tid)){ continue }
      try{
        $xml = Export-TemplateXml -apiBase $ApiBase -tok (Get-SrcTok) -templateId ([int]$tid)
        if($xml){
          $tmpl += [pscustomobject]@{ templateId = [int]$tid; exportFileText = $xml }
        }
      } catch {}
    }
    $outObj.TemplateExports = $tmpl
  }

  Ensure-Dir $OutPath
  Write-LargeJson -Object $outObj -Path $OutPath -Pretty
  $newCount = $list.Count
  $totalCount = $finalSecrets.Count
  if($script:ExportCancelled){
    Write-Log ("EXPORT: Cancelled. Saved {0} secrets (of {1} total) to {2}. Use Incremental mode to resume." -f $totalCount,$secretCount,$OutPath) 'WARN'
  } elseif($Incremental){
    Write-Log ("EXPORT: Incremental complete - {0} new secrets, {1} total in {2}" -f $newCount,$totalCount,$OutPath) 'INFO'
  } else {
    Write-Log ("EXPORT: Exported {0} secrets to {1}" -f $totalCount,$OutPath) 'INFO'
  }

  $script:LastExportJsonPath = $OutPath
  return [int]$list.Count
}

# =========================
# IMPORT FUNCTION (ASCII-SAFE)
# =========================

$script:TgtUserNameCache = @{}
$script:TgtUserNameCacheLoaded = $false
function Load-SecretAccessRoleCache([string]$TgtApiBase, [string]$TgtTok) {
  if($script:SecretAccessRoleCacheLoaded){ return }
  
  Write-Log "PERM: Loading secret access roles..." 'INFO'
  $script:SecretAccessRoleCache = @{}
  
  try{
    # Try the roles endpoint
    $resp = SS $TgtApiBase GET 'roles' $TgtTok $null @{ 'filter.page'=1; 'filter.pageSize'=200 }
    $recs = @(Get-Records $resp)
    
    foreach($r in $recs){
      $rid = Get-PropValue $r @('id','Id','roleId','RoleId') $null
      $rname = [string](Get-PropValue $r @('name','Name','roleName','RoleName') $null)
      
      if($rid -ne $null -and -not [string]::IsNullOrWhiteSpace($rname)){
        $script:SecretAccessRoleCache[$rname.ToLowerInvariant()] = [int]$rid
      }
    }
  }
  catch{
    Write-Log ("PERM: Could not load roles: {0}" -f $_.Exception.Message) 'DEBUG'
  }
  
  # Add common default roles if not found
  $defaultRoles = @{
    'owner' = 1
    'edit' = 2
    'view' = 3
    'list' = 4
  }
  
  foreach($kv in $defaultRoles.GetEnumerator()){
    if(-not $script:SecretAccessRoleCache.ContainsKey($kv.Key)){
      $script:SecretAccessRoleCache[$kv.Key] = $kv.Value
    }
  }
  
  $script:SecretAccessRoleCacheLoaded = $true
  Write-Log ("PERM: Loaded {0} secret access roles" -f $script:SecretAccessRoleCache.Count) 'DEBUG'
}

# NOTE: Get-TargetUserIdByName defined earlier at ~line 2378

# Before creating the secret, log template field requirements
function Get-TemplateRequiredFields([string]$apiBase,[string]$tok,[int]$templateId){
  try{
    $template = SS $apiBase GET ("secret-templates/{0}" -f $templateId) $tok $null $null
    $fields = @(Get-PropValue $template @('fields','Fields') @())
    
    $required = @()
    foreach($f in $fields){
      $isRequired = [bool](Get-PropValue $f @('isRequired','IsRequired') $false)
      $name = [string](Get-PropValue $f @('name','Name','displayName') "Unknown")
      $fieldId = Get-PropValue $f @('secretTemplateFieldId','fieldId') 0
      
      if($isRequired){
        $required += [PSCustomObject]@{
          FieldId = $fieldId
          Name = $name
        }
      }
    }
    
    return $required
  }
  catch{
    return @()
  }
}
function Get-SecretAccessRoleId([string]$TgtApiBase, [string]$TgtTok, [string]$RoleName) {
  if([string]::IsNullOrWhiteSpace($RoleName)){ return $null }
  
  Load-SecretAccessRoleCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
  
  $key = $RoleName.ToLowerInvariant()
  if($script:SecretAccessRoleCache.ContainsKey($key)){
    return [int]$script:SecretAccessRoleCache[$key]
  }
  
  return $null
}
# Cache for secret access roles
$script:SecretAccessRoleCache = @{}
$script:SecretAccessRoleCacheLoaded = $false

# Script-level tracking variables (if not already defined)
if(-not (Get-Variable -Name 'ImportRunCreatedSecretIds' -Scope Script -ErrorAction SilentlyContinue)){
  $script:ImportRunCreatedSecretIds = New-Object 'System.Collections.Generic.List[int]'
}
if(-not (Get-Variable -Name 'ImportRunCreatedSecretsById' -Scope Script -ErrorAction SilentlyContinue)){
  $script:ImportRunCreatedSecretsById = @{}
}
if(-not (Get-Variable -Name 'ImportRunCreatedFolderIds' -Scope Script -ErrorAction SilentlyContinue)){
  $script:ImportRunCreatedFolderIds = New-Object 'System.Collections.Generic.List[int]'
}
if(-not (Get-Variable -Name 'ImportRunCreatedFoldersById' -Scope Script -ErrorAction SilentlyContinue)){
  $script:ImportRunCreatedFoldersById = @{}
}

$script:TgtRoleNameCache = @{}

function Load-TargetRoleCache([string]$TgtApiBase,[string]$TgtTok){
  $script:TgtRoleNameCache = @{}
  $page = 1
  $ps = 200
  
  while($page -le 20){
    try{
      $resp = SS $TgtApiBase GET 'roles' $TgtTok $null @{ 'filter.page'=$page; 'filter.pageSize'=$ps }
      $recs = @(Get-Records $resp)
      
      foreach($r in $recs){
        $rid = Get-PropValue $r @('id','Id') $null
        $rname = [string](Get-PropValue $r @('name','Name') $null)
        
        if($rid -ne $null -and -not [string]::IsNullOrWhiteSpace($rname)){
          $script:TgtRoleNameCache[$rname.ToLowerInvariant()] = [int]$rid
        }
      }
      
      if($recs.Count -lt $ps){ break }
      $page++
    }
    catch{ break }
  }
  
  Write-Log ("IMPORT: Loaded {0} roles from target tenant" -f $script:TgtRoleNameCache.Count) 'DEBUG'
}

function Find-ChildFolderIdByName([string]$tgtApi,[string]$tgtTok,[int]$parentId,[string]$childName){
  if([string]::IsNullOrWhiteSpace($childName)){ return $null }
  
  $page = 1
  $ps = 200
  
  while($page -le 10){
    try{
      $q = @{
        'filter.parentFolderId' = $parentId
        'filter.searchText' = $childName
        'filter.page' = $page
        'filter.pageSize' = $ps
      }
      
      $resp = SS $tgtApi GET 'folders' $tgtTok $null $q
      $recs = @(Get-Records $resp)
      
      foreach($f in $recs){
        $fid = Get-PropValue $f @('id','Id','folderId','FolderId') $null
        $fname = [string](Get-PropValue $f @('folderName','FolderName','name','Name') $null)
        $fpid = Get-PropValue $f @('parentFolderId','ParentFolderId') $null
        
        if($fid -ne $null -and $fname -and $fname.Equals($childName,[System.StringComparison]::OrdinalIgnoreCase)){
          if($fpid -eq $null -or [int]$fpid -eq $parentId){
            return [int]$fid
          }
        }
      }
      
      if($recs.Count -lt $ps){ break }
      $page++
    }
    catch{ break }
  }
  
  return $null
}

function Remove-SecretPermissionByMatch {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$SecretId,
    [int]$UserId = 0,
    [int]$GroupId = 0
  )
  
  # Fetch current permissions for the secret
  try{
    $perms = @()
    $page = 1
    while($true){
      $resp = SS $TgtApiBase GET 'secret-permissions' $TgtTok $null @{
        'filter.secretId' = $SecretId
        'filter.page' = $page
        'filter.pageSize' = 100
      }
      $recs = @(Get-Records $resp)
      $perms += $recs
      if($recs.Count -lt 100){ break }
      $page++
      if($page -gt 50){ break }
    }
    
    foreach($p in $perms){
      $permId = Get-PropValue $p @('id','Id','secretPermissionId','SecretPermissionId') $null
      $pUserId = Get-PropValue $p @('userId','UserId') $null
      $pGroupId = Get-PropValue $p @('groupId','GroupId') $null
      
      $match = $false
      if($UserId -gt 0 -and $pUserId -ne $null -and [int]$pUserId -eq $UserId){ $match = $true }
      if($GroupId -gt 0 -and $pGroupId -ne $null -and [int]$pGroupId -eq $GroupId){ $match = $true }
      
      if($match -and $permId -ne $null){
        SS $TgtApiBase DELETE ("secret-permissions/{0}" -f $permId) $TgtTok $null $null | Out-Null
        Write-Log ("PERM ROLLBACK: Removed secret permission id={0} from secretId={1}" -f $permId,$SecretId) 'INFO'
        return $true
      }
    }
    return $false
  }
  catch{
    Write-Log ("PERM ROLLBACK: Failed to remove permission from secretId={0}: {1}" -f $SecretId,$_) 'WARN'
    return $false
  }
}

function Remove-FolderPermissionByMatch {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$FolderId,
    [int]$UserId = 0,
    [int]$GroupId = 0
  )
  
  # Fetch current permissions for the folder
  try{
    $perms = @()
    $page = 1
    while($true){
      $resp = SS $TgtApiBase GET 'folder-permissions' $TgtTok $null @{
        'filter.folderId' = $FolderId
        'filter.page' = $page
        'filter.pageSize' = 100
      }
      $recs = @(Get-Records $resp)
      $perms += $recs
      if($recs.Count -lt 100){ break }
      $page++
      if($page -gt 50){ break }
    }
    
    foreach($p in $perms){
      $permId = Get-PropValue $p @('id','Id','folderPermissionId','FolderPermissionId') $null
      $pUserId = Get-PropValue $p @('userId','UserId') $null
      $pGroupId = Get-PropValue $p @('groupId','GroupId') $null
      
      $match = $false
      if($UserId -gt 0 -and $pUserId -ne $null -and [int]$pUserId -eq $UserId){ $match = $true }
      if($GroupId -gt 0 -and $pGroupId -ne $null -and [int]$pGroupId -eq $GroupId){ $match = $true }
      
      if($match -and $permId -ne $null){
        SS $TgtApiBase DELETE ("folder-permissions/{0}" -f $permId) $TgtTok $null $null | Out-Null
        Write-Log ("PERM ROLLBACK: Removed folder permission id={0} from folderId={1}" -f $permId,$FolderId) 'INFO'
        return $true
      }
    }
    return $false
  }
  catch{
    Write-Log ("PERM ROLLBACK: Failed to remove permission from folderId={0}: {1}" -f $FolderId,$_) 'WARN'
    return $false
  }
}

function Cleanup-LastImportRun {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok
  )
  
  Write-Log "CLEANUP: starting cleanup of last import run objects..." 'INFO'
  
  $secretsDeleted = 0
  $secretsFailed = 0
  $foldersDeleted = 0
  $foldersFailed = 0
  $secretPermsRemoved = 0
  $secretPermsFailed = 0
  $folderPermsRemoved = 0
  $folderPermsFailed = 0
  
  # Remove applied secret permissions first
  if($script:ImportRunAppliedSecretPermissions -and $script:ImportRunAppliedSecretPermissions.Count -gt 0){
    Write-Log ("CLEANUP: rolling back {0} applied secret permissions..." -f $script:ImportRunAppliedSecretPermissions.Count) 'INFO'
    
    foreach($sp in $script:ImportRunAppliedSecretPermissions){
      $sid = $sp.secretId
      $uid = if($sp.userId -ne $null){ [int]$sp.userId } else { 0 }
      $gid = if($sp.groupId -ne $null){ [int]$sp.groupId } else { 0 }
      
      if($sid -gt 0 -and ($uid -gt 0 -or $gid -gt 0)){
        $ok = Remove-SecretPermissionByMatch -TgtApiBase $TgtApiBase -TgtTok $TgtTok -SecretId $sid -UserId $uid -GroupId $gid
        if($ok){ $secretPermsRemoved++ } else { $secretPermsFailed++ }
      }
    }
  }
  
  # Remove applied folder permissions
  if($script:ImportRunAppliedFolderPermissions -and $script:ImportRunAppliedFolderPermissions.Count -gt 0){
    Write-Log ("CLEANUP: rolling back {0} applied folder permissions..." -f $script:ImportRunAppliedFolderPermissions.Count) 'INFO'
    
    foreach($fp in $script:ImportRunAppliedFolderPermissions){
      $fid = $fp.folderId
      $uid = if($fp.userId -ne $null){ [int]$fp.userId } else { 0 }
      $gid = if($fp.groupId -ne $null){ [int]$fp.groupId } else { 0 }
      
      if($fid -gt 0 -and ($uid -gt 0 -or $gid -gt 0)){
        $ok = Remove-FolderPermissionByMatch -TgtApiBase $TgtApiBase -TgtTok $TgtTok -FolderId $fid -UserId $uid -GroupId $gid
        if($ok){ $folderPermsRemoved++ } else { $folderPermsFailed++ }
      }
    }
  }
  
  # Delete secrets (reverse order)
  if($script:ImportRunCreatedSecretIds.Count -gt 0){
    Write-Log ("CLEANUP: deleting {0} created secrets..." -f $script:ImportRunCreatedSecretIds.Count) 'INFO'
    
    $secretIdsReversed = @($script:ImportRunCreatedSecretIds)
    [Array]::Reverse($secretIdsReversed)
    
    foreach($sid in $secretIdsReversed){
      $sname = ""
      if($script:ImportRunCreatedSecretsById.ContainsKey([string]$sid)){
        $sname = $script:ImportRunCreatedSecretsById[[string]$sid].name
      }
      
      try{
        SS $TgtApiBase DELETE ("secrets/{0}" -f $sid) $TgtTok $null $null | Out-Null
        Write-Log ("CLEANUP: deleted secret id={0} name='{1}'" -f $sid,$sname) 'INFO'
        $secretsDeleted++
      }
      catch{
        Write-Log ("CLEANUP: failed to delete secret id={0}: {1}" -f $sid,$_) 'WARN'
        $secretsFailed++
      }
    }
  }
  else{
    Write-Log "CLEANUP: no created secrets recorded for last import run." 'INFO'
  }
  
  # Delete folders (reverse order - children first)
  if($script:ImportRunCreatedFolderIds.Count -gt 0){
    Write-Log ("CLEANUP: deleting {0} created folders..." -f $script:ImportRunCreatedFolderIds.Count) 'INFO'
    
    $folderIdsReversed = @($script:ImportRunCreatedFolderIds)
    [Array]::Reverse($folderIdsReversed)
    
    foreach($fid in $folderIdsReversed){
      $fname = ""
      if($script:ImportRunCreatedFoldersById.ContainsKey([string]$fid)){
        $fname = $script:ImportRunCreatedFoldersById[[string]$fid].name
      }
      
      try{
        SS $TgtApiBase DELETE ("folders/{0}" -f $fid) $TgtTok $null $null | Out-Null
        Write-Log ("CLEANUP: deleted folder id={0} name='{1}'" -f $fid,$fname) 'INFO'
        $foldersDeleted++
      }
      catch{
        Write-Log ("CLEANUP: failed to delete folder id={0}: {1}" -f $fid,$_) 'WARN'
        $foldersFailed++
      }
    }
  }
  else{
    Write-Log "CLEANUP: no created folders recorded for last import run." 'INFO'
  }
  
  Write-Log ("CLEANUP: completed. Secrets: {0} deleted, {1} failed. Folders: {2} deleted, {3} failed. SecretPerms: {4} removed, {5} failed. FolderPerms: {6} removed, {7} failed." -f `
    $secretsDeleted,$secretsFailed,$foldersDeleted,$foldersFailed,$secretPermsRemoved,$secretPermsFailed,$folderPermsRemoved,$folderPermsFailed) 'INFO'
  
  # Reset tracking for next run
  Reset-ImportTracking
  
  return [pscustomobject]@{
    SecretsDeleted = $secretsDeleted
    SecretsFailed = $secretsFailed
    FoldersDeleted = $foldersDeleted
    FoldersFailed = $foldersFailed
    SecretPermsRemoved = $secretPermsRemoved
    SecretPermsFailed = $secretPermsFailed
    FolderPermsRemoved = $folderPermsRemoved
    FolderPermsFailed = $folderPermsFailed
  }
}
function Create-TargetFolder {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][string]$FolderName,
    [Parameter(Mandatory)][int]$ParentFolderId,
    [bool]$InheritPermissions = $true,
    [bool]$InheritSecretPolicy = $true
  )
  
  # Validate inputs
  if([string]::IsNullOrWhiteSpace($FolderName)){
    throw "FolderName cannot be empty"
  }
  if($ParentFolderId -le 0){
    throw "ParentFolderId must be greater than 0"
  }
  
  # Build the correct payload for Delinea API
  $payload = @{
    folderName = $FolderName
    parentFolderId = $ParentFolderId
    inheritPermissions = $InheritPermissions
    inheritSecretPolicy = $InheritSecretPolicy
  }
  
  Write-Log ("FOLDER: Creating '{0}' under parentId={1}" -f $FolderName,$ParentFolderId) 'DEBUG'
  
  try{
    $result = SS $TgtApiBase POST 'folders' $TgtTok $payload $null
    
    $newId = 0
    try{ $newId = [int](Get-PropValue $result @('id','folderId','Id','FolderId') 0) } catch {}
    
    if($newId -gt 0){
      Write-Log ("FOLDER: Created '{0}' with id={1}" -f $FolderName,$newId) 'INFO'
      Track-CreatedFolder -id $newId -name $FolderName -parentId $ParentFolderId
      return $newId
    }
    else{
      throw "Folder created but no ID returned"
    }
  }
  catch{
    Write-Log ("FOLDER: Failed to create '{0}' under {1}: {2}" -f $FolderName,$ParentFolderId,$_.Exception.Message) 'ERROR'
    throw $_
  }
}

function Ensure-TargetFolderForSourcePath {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$RootFolderId,
    [Parameter(Mandatory)][string]$SourceFolderPath,
    [bool]$DryRun = $false,
    [bool]$DisableInheritPermissions = $false
  )

  # Normalize path - remove leading/trailing backslashes and convert to segments
  $cleanPath = $SourceFolderPath.Trim().Trim('\').Trim('/')
  
  if([string]::IsNullOrWhiteSpace($cleanPath)){
    return $RootFolderId
  }

  # FIX: Use $cleanPath or $SourceFolderPath, NOT $path
  $segments = $cleanPath.Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
  
  Write-Log ("Ensure-TargetFolderForSourcePath: Path='{0}' -> {1} segments" -f $SourceFolderPath, $segments.Count) 'DEBUG'
  
  if($segments.Count -eq 0){
    return $RootFolderId
  }

  $currentParentId = $RootFolderId
  $pathSoFar = ""

  foreach($rawSegmentName in $segments){
    $segmentName = $rawSegmentName.Trim()
    if([string]::IsNullOrWhiteSpace($segmentName)){ continue }
    $pathSoFar = if($pathSoFar){ "$pathSoFar\$segmentName" } else { $segmentName }
    
    # Check cache first
    $cacheKey = "$currentParentId|$($segmentName.ToLowerInvariant())"
    if($script:CreatedFolderCache.ContainsKey($cacheKey)){
      $currentParentId = $script:CreatedFolderCache[$cacheKey]
      Write-Log ("FOLDER: Using cached folder '{0}' (ID: {1})" -f $segmentName, $currentParentId) 'DEBUG'
      continue
    }

    # Check if folder already exists
    $existingFolderId = Find-FolderByNameUnderParent -TgtApiBase $TgtApiBase -TgtTok $TgtTok -ParentFolderId $currentParentId -FolderName $segmentName
    
    if($existingFolderId -gt 0){
      $script:CreatedFolderCache[$cacheKey] = $existingFolderId
      $currentParentId = $existingFolderId
      Write-Log ("FOLDER: Found existing folder '{0}' (ID: {1})" -f $segmentName, $existingFolderId) 'DEBUG'
      continue
    }

    # Need to create the folder
    if($DryRun){
      Write-Log ("[DRY-RUN] Would CREATE folder '{0}' under parent {1}" -f $segmentName, $currentParentId) 'INFO'
      return $currentParentId
    }

    # SAFETY: Double-check folder doesn't exist (retry lookup to avoid duplicates from transient API issues)
    Start-Sleep -Milliseconds 200
    $retryFindId = Find-FolderByNameUnderParent -TgtApiBase $TgtApiBase -TgtTok $TgtTok -ParentFolderId $currentParentId -FolderName $segmentName
    if($retryFindId -gt 0){
      Write-Log ("FOLDER: Retry-find discovered existing '{0}' (ID: {1}) - avoiding duplicate creation" -f $segmentName, $retryFindId) 'WARN'
      $script:CreatedFolderCache[$cacheKey] = $retryFindId
      $currentParentId = $retryFindId
      continue
    }

    # Actually create the folder
    Write-Log ("FOLDER: Creating '{0}' under parentId={1}" -f $segmentName, $currentParentId) 'DEBUG'
    
    $shouldInherit = -not $DisableInheritPermissions
    $parentBeforeCreate = $currentParentId
    $body = @{
      folderName = $segmentName
      parentFolderId = $currentParentId
      folderTypeId = 1
      inheritPermissions = $shouldInherit
      inheritSecretPolicy = $true
    }

    try{
      $newFolder = SS $TgtApiBase POST 'folders' $TgtTok $body $null
      $newFolderId = [int](Get-PropValue $newFolder @('id','Id','folderId','FolderId') 0)
      
      if($newFolderId -gt 0){
        $script:CreatedFolderCache[$cacheKey] = $newFolderId
        $currentParentId = $newFolderId
        Write-Log ("FOLDER: Created '{0}' with ID {1}" -f $segmentName, $newFolderId) 'INFO'
        
        Track-CreatedFolder -FolderId $newFolderId -name $segmentName -parentId $parentBeforeCreate
      } else {
        throw "API returned folder without valid ID"
      }
    }
    catch{
      # On ANY error (especially 400), try to find the folder - it may exist but not be visible in normal listing
      $errStr = [string]$_.Exception.Message
      Write-Log ("FOLDER: Create failed for '{0}' under {1}: {2} - attempting recovery search" -f $segmentName, $currentParentId, $errStr) 'WARN'
      
      # Retry search with all methods (searchText, lookup, etc.)
      Start-Sleep -Milliseconds 300
      $findAfterErr = Find-FolderByNameUnderParent -TgtApiBase $TgtApiBase -TgtTok $TgtTok -ParentFolderId $currentParentId -FolderName $segmentName
      if($findAfterErr -gt 0){
        Write-Log ("FOLDER: Recovery found '{0}' (id={1}) after create error" -f $segmentName, $findAfterErr) 'INFO'
        $script:CreatedFolderCache[$cacheKey] = $findAfterErr
        $currentParentId = $findAfterErr
        continue
      }
      
      # Last resort: try to get folder by direct ID search across all folders
      try{
        $directSearch = SS $TgtApiBase GET 'folders' $TgtTok $null @{
          'filter.searchText' = $segmentName
          'filter.page' = 1
          'filter.pageSize' = 100
        }
        $directRecs = @(Get-Records $directSearch)
        foreach($df in $directRecs){
          $dfId = 0
          try{ $dfId = [int](Get-PropValue $df @('id','folderId','Id','FolderId') 0) } catch {}
          $dfName = [string](Get-PropValue $df @('folderName','FolderName','name','Name') $null)
          $dfParent = Get-PropValue $df @('parentFolderId','ParentFolderId') $null
          if($dfId -gt 0 -and $dfName.ToLowerInvariant() -eq $segmentName.ToLowerInvariant()){
            if($dfParent -ne $null -and [int]$dfParent -eq $currentParentId){
              Write-Log ("FOLDER: Last-resort search found '{0}' (id={1}) under parent {2}" -f $segmentName, $dfId, $currentParentId) 'INFO'
              $script:CreatedFolderCache[$cacheKey] = $dfId
              $currentParentId = $dfId
              break
            }
          }
        }
        # Check if we found it in the last-resort search
        if($script:CreatedFolderCache.ContainsKey($cacheKey)){
          continue
        }
      } catch {}
      
      Write-Log ("FOLDER: Failed to create or find '{0}' under {1}: {2}" -f $segmentName, $currentParentId, $errStr) 'ERROR'
      throw "Cannot resolve folder '$segmentName' under parent $currentParentId - folder may exist but is not accessible. Error: $errStr"
    }
  }

  return $currentParentId
}
function Get-RoleNameToIdMap([string]$TgtApiBase,[string]$TgtTok){
  Load-SecretAccessRoleCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
  # $script:SecretAccessRoleCache is already populated by Load-SecretAccessRoleCache
  return $script:SecretAccessRoleCache
}

# NOTE: Find-FolderByNameUnderParent defined earlier at ~line 2104 (with paging support)

# Replace the Normalize-PermissionObject function with this version
function Normalize-PermissionObject($perm){
  # Flatten to a case-insensitive dictionary; never dot-access unknown props (StrictMode-safe)
  if($null -eq $perm){ return @{} }

  # If it's an enumerable (array/list) but not a string/hashtable/psobject, take the first element
  if($perm -is [System.Collections.IEnumerable] -and
     -not ($perm -is [string]) -and
     -not ($perm -is [hashtable]) -and
     -not ($perm -is [psobject])){
    $perm = $perm | Select-Object -First 1
  }

  $dict = @{}

  if($perm -is [hashtable]){
    foreach($k in $perm.Keys){
      $dict[$k.ToString()] = $perm[$k]
    }
    return $dict
  }

  if($perm -is [psobject]){
    foreach($p in $perm.PSObject.Properties){
      $dict[$p.Name] = $p.Value
    }
    return $dict
  }

  # Scalar/placeholder (e.g., "...") -> return empty
  return @{}
}

function Add-SecretPermission-WithRemap {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$SecretId,
    [Parameter(Mandatory)]$Perm,
    [bool]$RemapPrincipals = $false
  )

  # Helper: case-insensitive lookup in dict
  function _permField($d,[string[]]$names){
    foreach($n in $names){
      foreach($k in $d.Keys){
        if($k -eq $n -or $k.ToLowerInvariant() -eq $n.ToLowerInvariant()){
          return $d[$k]
        }
      }
    }
    return $null
  }

  $p = Normalize-PermissionObject $Perm
  if($p.Count -eq 0){
    Write-Log "PERM SKIP: empty/placeholder permission object" 'WARN'
    return $false
  }

  $srcUserId    = 0
  $srcGroupId   = 0
  $srcGroupName = $null
  $srcUserName  = $null
  $srcKnownAs   = $null
  $srcDomainName = $null
  $roleId       = $null
  $roleName     = $null

  try{ $srcUserId    = [int](_permField $p @('userId','UserId')) } catch {}
  try{ $srcGroupId   = [int](_permField $p @('groupId','GroupId')) } catch {}
  try{ $srcGroupName = [string](_permField $p @('groupName','GroupName','name','Name')) } catch {}
  try{ $srcUserName  = [string](_permField $p @('userName','UserName','username')) } catch {}
  try{ $srcKnownAs   = [string](_permField $p @('knownAs','KnownAs')) } catch {}
  try{ $srcDomainName = [string](_permField $p @('domainName','DomainName')) } catch {}
  try{ $roleId       = _permField $p @('secretAccessRoleId','SecretAccessRoleId','roleId','RoleId') } catch {}
  try{ $roleName     = [string](_permField $p @('secretAccessRoleName','SecretAccessRoleName','roleName','RoleName')) } catch {}

  # Resolve role
  $resolvedRoleId = $null
  if(-not [string]::IsNullOrWhiteSpace($roleName)){
    $roleMap = Get-RoleNameToIdMap $TgtApiBase $TgtTok
    $rk = $roleName.ToLowerInvariant()
    if($roleMap.ContainsKey($rk)){ $resolvedRoleId = [int]$roleMap[$rk] }
  }
  if($resolvedRoleId -eq $null -and $roleId -ne $null){
    try{ $resolvedRoleId = [int]$roleId } catch {}
  }
  if($resolvedRoleId -eq $null){ $resolvedRoleId = 1 }

  # Resolve principal
  $targetUserId = 0; $targetGroupId = 0
  if($RemapPrincipals){
    # Cross-tenant: must remap by name - source IDs won't work in target tenant
    if($srcUserId -gt 0 -and -not [string]::IsNullOrWhiteSpace($srcUserName)){
      $targetUserId = Get-TargetUserIdByName -TgtApiBase $TgtApiBase -TgtTok $TgtTok -UserName $srcUserName -KnownAs $srcKnownAs -DomainName $srcDomainName
      if($targetUserId -le 0){
        Write-Log ("PERM SKIP: User '{0}' (srcId={1}) not found in target tenant for secretId={2}" -f $srcUserName, $srcUserId, $SecretId) 'WARN'
        return $false
      }
    } elseif($srcGroupId -gt 0 -and -not [string]::IsNullOrWhiteSpace($srcGroupName)){
      $targetGroupId = Get-TargetGroupIdByName -TgtApiBase $TgtApiBase -TgtTok $TgtTok -GroupName $srcGroupName -KnownAs $srcKnownAs -DomainName $srcDomainName
      if($targetGroupId -le 0){
        Write-Log ("PERM SKIP: Group '{0}' (srcId={1}) not found in target tenant for secretId={2}" -f $srcGroupName, $srcGroupId, $SecretId) 'WARN'
        return $false
      }
    } elseif($srcUserId -gt 0){
      # User has ID but no username - cannot remap
      Write-Log ("PERM SKIP: srcUserId={0} has no userName to remap for secretId={1}" -f $srcUserId, $SecretId) 'WARN'
      return $false
    } elseif($srcGroupId -gt 0){
      # Group has ID but no groupName - cannot remap
      Write-Log ("PERM SKIP: srcGroupId={0} has no groupName to remap for secretId={1}" -f $srcGroupId, $SecretId) 'WARN'
      return $false
    }
  } else {
    # DIRECT mode: Validate user/group exists in target tenant before attempting API call
    # This prevents 400 errors when source IDs don't exist in target
    Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
    Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
    
    if($srcUserId -gt 0){
      # Check if user ID exists in target
      $userExists = $false
      foreach($uid in $script:TgtUserNameToIdCache.Values){
        if([int]$uid -eq $srcUserId){ $userExists = $true; break }
      }
      if(-not $userExists){
        $dispName = if(-not [string]::IsNullOrWhiteSpace($srcUserName)){ "'{0}'" -f $srcUserName } else { "ID" }
        Write-Log ("PERM SKIP (DIRECT): User {0} (id={1}) does not exist in target tenant. Use 'Remap Principals' for cross-tenant migration. secretId={2}" -f $dispName, $srcUserId, $SecretId) 'WARN'
        return $false
      }
      $targetUserId = $srcUserId
    }
    elseif($srcGroupId -gt 0){
      # Check if group ID exists in target
      $groupExists = $false
      foreach($gid in $script:TgtGroupNameToIdCache.Values){
        if([int]$gid -eq $srcGroupId){ $groupExists = $true; break }
      }
      if(-not $groupExists){
        $dispName = if(-not [string]::IsNullOrWhiteSpace($srcGroupName)){ "'{0}'" -f $srcGroupName } else { "ID" }
        Write-Log ("PERM SKIP (DIRECT): Group {0} (id={1}) does not exist in target tenant. Use 'Remap Principals' for cross-tenant migration. secretId={2}" -f $dispName, $srcGroupId, $SecretId) 'WARN'
        return $false
      }
      $targetGroupId = $srcGroupId
    }
  }

  if($targetUserId -le 0 -and $targetGroupId -le 0){
     Write-Log ("PERM SKIP: No valid target user or group ID resolved for secretId={0}, srcUserId={1}, srcGroupId={2}, srcUserName='{3}', srcGroupName='{4}'" -f $SecretId, $srcUserId, $srcGroupId, $srcUserName, $srcGroupName) 'WARN'
     return $false
  }

  # Check if permission already exists on the secret using cache
  $cacheKey = "secret_$SecretId"
  if(-not $script:PermissionCheckCache){ $script:PermissionCheckCache = @{} }
  
  $existingRecs = @()
  if($script:PermissionCheckCache.ContainsKey($cacheKey)){
    $existingRecs = $script:PermissionCheckCache[$cacheKey]
    Write-Log ("SECRET PERM CHECK: Using cached permissions for secretId={0} (count={1})" -f $SecretId,$existingRecs.Count) 'DEBUG'
  } else {
    try{
      Write-Log ("SECRET PERM CHECK: Querying existing permissions for secretId={0}" -f $SecretId) 'DEBUG'
      
      # Try to query with filter first (more efficient)
      $allPerms = $null
      try{
        $allPerms = SS $TgtApiBase GET 'secret-permissions' $TgtTok $null @{
          'filter.secretId' = $SecretId
          'take' = 100
        }
        $allRecs = @(Get-Records $allPerms)
        Write-Log ("SECRET PERM CHECK: Retrieved {0} permissions using filter.secretId" -f $allRecs.Count) 'DEBUG'
        $existingRecs = $allRecs
      } catch {
        # Fallback: query all and filter client-side (slower)
        Write-Log ("SECRET PERM CHECK: filter.secretId not supported, querying all permissions" -f $null) 'DEBUG'
        $allPerms = SS $TgtApiBase GET 'secret-permissions' $TgtTok $null @{
          'skip' = 0
          'take' = 1000
        }
        $allRecs = @(Get-Records $allPerms)
        $existingRecs = @($allRecs | Where-Object { 
          $recSecretId = Get-PropValue $_ @('secretId','SecretId') 0
          [int]$recSecretId -eq [int]$SecretId
        })
        Write-Log ("SECRET PERM CHECK: Filtered to {0} permissions for secretId={1}" -f $existingRecs.Count,$SecretId) 'DEBUG'
      }
      
      # Cache the result
      $script:PermissionCheckCache[$cacheKey] = $existingRecs
    }
    catch{
      Write-Log ("SECRET PERM WARNING: Could not check existing permissions on secretId={0}: {1}" -f $SecretId,$_.Exception.Message) 'WARN'
    }
  }
  
  # Check if permission already exists (and update role if different)
  $modeStr = if($RemapPrincipals){"REMAP"}else{"DIRECT"}
  foreach($existingPerm in $existingRecs){
    $existingGroupId = Get-PropValue $existingPerm @('groupId','GroupId') 0
    $existingUserId = Get-PropValue $existingPerm @('userId','UserId') 0
    
    $principalMatch = $false
    if($targetGroupId -gt 0 -and [int]$existingGroupId -eq [int]$targetGroupId){ $principalMatch = $true }
    if($targetUserId -gt 0 -and [int]$existingUserId -eq [int]$targetUserId){ $principalMatch = $true }
    
    if($principalMatch){
      # Check if role needs updating
      $epRoleId = Get-PropValue $existingPerm @('secretAccessRoleId','SecretAccessRoleId') $null
      $epRoleName = [string](Get-PropValue $existingPerm @('secretAccessRoleName','SecretAccessRoleName') '')
      $epPermId = Get-PropValue $existingPerm @('id','Id','secretPermissionId','SecretPermissionId') $null
      
      $roleMatches = $true
      if($resolvedRoleId -ne $null -and $epRoleId -ne $null -and [int]$epRoleId -ne [int]$resolvedRoleId){
        $roleMatches = $false
      }
      elseif(-not [string]::IsNullOrWhiteSpace($roleName) -and -not [string]::IsNullOrWhiteSpace($epRoleName) -and $epRoleName -ne $roleName){
        $roleMatches = $false
      }
      
      if(-not $roleMatches -and $epPermId -ne $null -and [int]$epPermId -gt 0){
        # Role differs - update the existing permission
        Write-Log ("SECRET PERM UPDATE ({0}): Updating permId={1} on secretId={2} - Role '{3}'->'{4}'" -f `
          $modeStr,[int]$epPermId,$SecretId,$epRoleName,$roleName) 'INFO'
        try{
          $updatePayload = @{
            id                   = [int]$epPermId
            secretId             = $SecretId
            secretAccessRoleId   = [int]$resolvedRoleId
          }
          if(-not [string]::IsNullOrWhiteSpace($roleName)){ $updatePayload['secretAccessRoleName'] = $roleName }
          if($targetGroupId -gt 0){ $updatePayload['groupId'] = [int]$targetGroupId }
          elseif($targetUserId -gt 0){ $updatePayload['userId'] = [int]$targetUserId }
          
          SS $TgtApiBase PUT ("secret-permissions/{0}" -f [int]$epPermId) $TgtTok $updatePayload $null | Out-Null
          Write-Log ("SECRET PERM UPDATED ({0}): permId={1} on secretId={2} role updated successfully" -f $modeStr,[int]$epPermId,$SecretId) 'INFO'
          return $true
        }
        catch{
          Write-Log ("SECRET PERM UPDATE ERROR ({0}): Failed to update permId={1}: {2}" -f $modeStr,[int]$epPermId,$_.Exception.Message) 'WARN'
          return $false
        }
      }
      else{
        Write-Log ("SECRET PERM SKIP ({0}): Permission for groupId={1}/userId={2} already exists with same role on secretId={3}" -f $modeStr,$targetGroupId,$targetUserId,$SecretId) 'INFO'
        return $true
      }
    }
  }
  
  Write-Log ("SECRET PERM CHECK: Permission not found, will add groupId={0} userId={1} to secretId={2}" -f $targetGroupId,$targetUserId,$SecretId) 'DEBUG'

  $payload = @{ secretId = $SecretId }
  if($targetUserId  -gt 0){ $payload.userId  = $targetUserId }
  if($targetGroupId -gt 0){ $payload.groupId = $targetGroupId }
  if($resolvedRoleId -ne $null){ $payload.secretAccessRoleId = [int]$resolvedRoleId }
  if(-not [string]::IsNullOrWhiteSpace($roleName)){ $payload.secretAccessRoleName = $roleName }

  $modeStr = if($RemapPrincipals){"REMAP"}else{"DIRECT"}
  $logUserId = if($payload.ContainsKey('userId')){ $payload['userId'] } else { 0 }
  $logGroupId = if($payload.ContainsKey('groupId')){ $payload['groupId'] } else { 0 }
  $logRoleId = if($payload.ContainsKey('secretAccessRoleId')){ $payload['secretAccessRoleId'] } else { 0 }
  Write-Log ("PERM {0}: POST secret-permissions secretId={1} userId={2} groupId={3} roleId={4} roleName='{5}'" -f `
    $modeStr, $SecretId, $logUserId, $logGroupId, $logRoleId, $roleName) 'DEBUG'

  try{
    $null = SS $TgtApiBase POST 'secret-permissions' $TgtTok $payload $null
    Write-Log ("PERM {0}: Successfully applied permission to secretId={1}" -f $modeStr,$SecretId) 'DEBUG'
    
    # Track for rollback
    $script:ImportRunAppliedSecretPermissions.Add(@{
      secretId = $SecretId
      userId = $targetUserId
      groupId = $targetGroupId
    }) | Out-Null
    
    # Update cache after successful addition
    $cacheKey = "secret_$SecretId"
    if($script:PermissionCheckCache.ContainsKey($cacheKey)){
      # Add new permission to cache
      $newPerm = @{ secretId = $SecretId }
      if($targetUserId -gt 0){ $newPerm['userId'] = $targetUserId }
      if($targetGroupId -gt 0){ $newPerm['groupId'] = $targetGroupId }
      $script:PermissionCheckCache[$cacheKey] += @($newPerm)
    }
    
    return $true
  }
  catch{
    $errMsg = [string]$_
    # Provide more context for common errors
    if($errMsg -match '400|Invalid'){
      if($targetUserId -gt 0){
        $errMsg = "User ID {0} may already have permission or is invalid. {1}" -f $targetUserId,$errMsg
      } elseif($targetGroupId -gt 0){
        $errMsg = "Group ID {0} may already have permission or is invalid. {1}" -f $targetGroupId,$errMsg
      }
    }
    Write-Log ("PERM ERROR ({0}): Failed to add permission for secretId={1}: {2}" -f $modeStr,$SecretId,$errMsg) 'WARN'
    Write-Log ("PERM ERROR: Payload was: {0}" -f ($payload | ConvertTo-Json -Compress)) 'DEBUG'
    return $false
  }
}

# =========================
# Add-FolderPermission-WithRemap (parallel to Add-SecretPermission-WithRemap)
# =========================
function Add-FolderPermission-WithRemap {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$FolderId,
    [Parameter(Mandatory)]$Perm,
    [bool]$RemapPrincipals = $false
  )
  
  # Extract source IDs and names
  $srcGroupId   = Get-PropValue $Perm @('groupId','GroupId') $null
  $srcUserId    = Get-PropValue $Perm @('userId','UserId') $null
  $groupName    = [string](Get-PropValue $Perm @('groupName','GroupName') $null)
  $userName     = [string](Get-PropValue $Perm @('userName','UserName','knownAs','KnownAs') $null)
  $domainName   = [string](Get-PropValue $Perm @('domainName','DomainName') $null)
  $knownAs      = [string](Get-PropValue $Perm @('knownAs','KnownAs') $null)
  
  $folderAccessRoleName = [string](Get-PropValue $Perm @('folderAccessRoleName','FolderAccessRoleName') $null)
  $secretAccessRoleName = [string](Get-PropValue $Perm @('secretAccessRoleName','SecretAccessRoleName') $null)
  
  # Validate role names
  if([string]::IsNullOrWhiteSpace($folderAccessRoleName) -or [string]::IsNullOrWhiteSpace($secretAccessRoleName)){
    Write-Log ("FOLDER PERM SKIP: Missing folderAccessRoleName or secretAccessRoleName for folderId={0}" -f $FolderId) 'DEBUG'
    return $false
  }
  
  $targetGroupId = $null
  $targetUserId  = $null
  $modeStr = if($RemapPrincipals){'REMAP'}else{'DIRECT'}
  
  if($RemapPrincipals){
    # REMAP MODE: resolve by name using multi-strategy lookup
    if($srcGroupId -ne $null -and [int]$srcGroupId -gt 0 -and -not [string]::IsNullOrWhiteSpace($groupName)){
      Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
      $targetGroupId = Get-TargetGroupIdByName -TgtApiBase $TgtApiBase -TgtTok $TgtTok -GroupName $groupName -KnownAs $knownAs -DomainName $domainName
      if($targetGroupId -and $targetGroupId -gt 0){
        Write-Log ("FOLDER PERM (REMAP): Resolved group '{0}' to target groupId={1}" -f $groupName,$targetGroupId) 'DEBUG'
      } else {
        $availableCount = if($script:TgtGroupNameToIdCache){ $script:TgtGroupNameToIdCache.Count } else { 0 }
        Write-Log ("FOLDER PERM SKIP (REMAP): Group '{0}' not found in target. ({1} groups available in target)" -f $groupName,$availableCount) 'WARN'
        return $false
      }
    }
    elseif($srcUserId -ne $null -and [int]$srcUserId -gt 0){
      Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
      $targetUserId = Get-TargetUserIdByName -TgtApiBase $TgtApiBase -TgtTok $TgtTok -UserName $userName -KnownAs $knownAs -DomainName $domainName
      if($targetUserId -and $targetUserId -gt 0){
        Write-Log ("FOLDER PERM (REMAP): Resolved user '{0}' to target userId={1}" -f $userName,$targetUserId) 'DEBUG'
      } else {
        $availableCount = if($script:TgtUserNameToIdCache){ $script:TgtUserNameToIdCache.Count } else { 0 }
        Write-Log ("FOLDER PERM SKIP (REMAP): User '{0}' not found in target. ({1} users available in target)" -f $userName,$availableCount) 'WARN'
        return $false
      }
    }
    else{
      Write-Log ("FOLDER PERM SKIP: No valid group or user in source permission object") 'DEBUG'
      return $false
    }
  }
  else{
    # DIRECT MODE: use source IDs directly - validate they exist in target first
    # This only works for same-tenant scenarios - for cross-tenant, recommend Remap mode
    if($srcGroupId -ne $null -and [int]$srcGroupId -gt 0){
      # Validate group exists in target using cache
      $key = if(-not [string]::IsNullOrWhiteSpace($groupName)){ $groupName.Trim().ToLowerInvariant() } else { $null }
      if($key -and $script:TgtGroupNameToIdCache -and $script:TgtGroupNameToIdCache.ContainsKey($key)){
        $targetGroupId = $script:TgtGroupNameToIdCache[$key]
        Write-Log ("FOLDER PERM (DIRECT): Group '{0}' found in target with id={1}" -f $groupName,$targetGroupId) 'DEBUG'
      } else {
        Write-Log ("FOLDER PERM SKIP (DIRECT): Group '{0}' (id={1}) does not exist in target tenant. Use 'Remap Principals' for cross-tenant migration." -f $groupName,$srcGroupId) 'WARN'
        return $false
      }
    }
    elseif($srcUserId -ne $null -and [int]$srcUserId -gt 0){
      # Validate user exists in target using cache
      $key = if(-not [string]::IsNullOrWhiteSpace($userName)){ $userName.Trim().ToLowerInvariant() } else { $null }
      if($key -and $script:TgtUserNameToIdCache -and $script:TgtUserNameToIdCache.ContainsKey($key)){
        $targetUserId = $script:TgtUserNameToIdCache[$key]
        Write-Log ("FOLDER PERM (DIRECT): User '{0}' found in target with id={1}" -f $userName,$targetUserId) 'DEBUG'
      } else {
        Write-Log ("FOLDER PERM SKIP (DIRECT): User '{0}' (id={1}) does not exist in target tenant. Use 'Remap Principals' for cross-tenant migration." -f $userName,$srcUserId) 'WARN'
        return $false
      }
    }
    else{
      Write-Log ("FOLDER PERM SKIP: No groupId or userId in permission object") 'DEBUG'
      return $false
    }
  }
  
  # Check if we've already successfully added this permission (use tracking cache)
  $trackKey = "folder_${FolderId}_g${targetGroupId}_u${targetUserId}"
  if(-not $script:FolderPermAddedCache){ $script:FolderPermAddedCache = @{} }
  
  if($script:FolderPermAddedCache.ContainsKey($trackKey)){
    Write-Log ("FOLDER PERM SKIP ({0}): Already added permission groupId={1} userId={2} to folderId={3} in this run" -f $modeStr,$targetGroupId,$targetUserId,$FolderId) 'INFO'
    return $true
  }
  
  Write-Log ("FOLDER PERM: Will attempt to add groupId={0} userId={1} to folderId={2}" -f $targetGroupId,$targetUserId,$FolderId) 'DEBUG'
  
  # Track folders where we've broken inheritance
  if(-not $script:FolderInheritanceBrokenCache){ $script:FolderInheritanceBrokenCache = @{} }
  
  # NEVER break inheritance - folders are created with inheritPermissions=$true by design.
  # Adding permissions should ADD to inherited ones, not replace them.
  $shouldBreakInheritance = $false
  
  # Build payload
  # Note: Break inheritance only on first permission, then add remaining permissions without breaking again
  $payload = @{
    folderId             = $FolderId
    breakInheritance     = $shouldBreakInheritance
    folderAccessRoleName = $folderAccessRoleName
    secretAccessRoleName = $secretAccessRoleName
  }
  
  if($shouldBreakInheritance){
    Write-Log ("FOLDER PERM: Breaking inheritance for folderId={0} (first permission)" -f $FolderId) 'DEBUG'
  }
  
  if($targetGroupId -ne $null -and [int]$targetGroupId -gt 0){
    $payload['groupId'] = [int]$targetGroupId
  } elseif($targetUserId -ne $null -and [int]$targetUserId -gt 0){
    $payload['userId'] = [int]$targetUserId
  } else {
    Write-Log ("FOLDER PERM SKIP: No valid target principal resolved") 'DEBUG'
    return $false
  }
  
  Write-Log ("FOLDER PERM: Attempting to add permission - Folder={0}, Group={1}, User={2}, FolderRole='{3}', SecretRole='{4}'" -f $FolderId,$targetGroupId,$targetUserId,$folderAccessRoleName,$secretAccessRoleName) 'DEBUG'
  
  # Check if permission already exists on this folder (and update if roles differ)
  try{
    $existingPerms = @((SS $TgtApiBase GET "folder-permissions?filter.folderId=$FolderId" $TgtTok $null $null).records)
    foreach($ep in $existingPerms){
      $epGroupId = Get-PropValue $ep @('groupId','GroupId') $null
      $epUserId = Get-PropValue $ep @('userId','UserId') $null
      
      # Check if this permission matches what we're trying to add (same principal)
      if(($targetGroupId -and $epGroupId -and [int]$epGroupId -eq [int]$targetGroupId) -or 
         ($targetUserId -and $epUserId -and [int]$epUserId -eq [int]$targetUserId)){
        
        # Compare roles - if different, update the existing permission
        $epFolderRole = [string](Get-PropValue $ep @('folderAccessRoleName','FolderAccessRoleName') '')
        $epSecretRole = [string](Get-PropValue $ep @('secretAccessRoleName','SecretAccessRoleName') '')
        $epId = Get-PropValue $ep @('id','Id','folderPermissionId','FolderPermissionId') $null
        
        $rolesMatch = ($epFolderRole -eq $folderAccessRoleName) -and ($epSecretRole -eq $secretAccessRoleName)
        
        if(-not $rolesMatch -and $epId -ne $null -and [int]$epId -gt 0){
          # Roles differ - update the existing permission
          Write-Log ("FOLDER PERM UPDATE ({0}): Updating permId={1} on folderId={2} - FolderRole '{3}'->'{4}', SecretRole '{5}'->'{6}'" -f `
            $modeStr,[int]$epId,$FolderId,$epFolderRole,$folderAccessRoleName,$epSecretRole,$secretAccessRoleName) 'INFO'
          try{
            $updatePayload = @{
              id                   = [int]$epId
              folderId             = $FolderId
              folderAccessRoleName = $folderAccessRoleName
              secretAccessRoleName = $secretAccessRoleName
            }
            if($targetGroupId -gt 0){ $updatePayload['groupId'] = [int]$targetGroupId }
            elseif($targetUserId -gt 0){ $updatePayload['userId'] = [int]$targetUserId }
            
            SS $TgtApiBase PUT ("folder-permissions/{0}" -f [int]$epId) $TgtTok $updatePayload $null | Out-Null
            Write-Log ("FOLDER PERM UPDATED ({0}): permId={1} on folderId={2} roles updated successfully" -f $modeStr,[int]$epId,$FolderId) 'INFO'
            
            $trackKey = "folder_${FolderId}_g${targetGroupId}_u${targetUserId}"
            $script:FolderPermAddedCache[$trackKey] = $true
            return $true
          }
          catch{
            Write-Log ("FOLDER PERM UPDATE ERROR ({0}): Failed to update permId={1}: {2}" -f $modeStr,[int]$epId,$_.Exception.Message) 'WARN'
            # Fall through to try adding fresh
          }
        }
        else{
          Write-Log ("FOLDER PERM SKIP ({0}): Permission already exists with same roles - folderId={1}, groupId={2}, userId={3}" -f $modeStr,$FolderId,$epGroupId,$epUserId) 'INFO'
          
          # Track to avoid retrying
          $trackKey = "folder_${FolderId}_g${targetGroupId}_u${targetUserId}"
          $script:FolderPermAddedCache[$trackKey] = $true
          return $true
        }
      }
    }
  }
  catch{
    Write-Log ("FOLDER PERM: Could not check existing permissions for folder {0}: {1}" -f $FolderId,$_.Exception.Message) 'DEBUG'
    # Continue and attempt to add anyway
  }
  
  # Make API call
  try{
    SS $TgtApiBase POST 'folder-permissions' $TgtTok $payload $null | Out-Null
    if($targetGroupId -gt 0){
      Write-Log ("FOLDER PERM OK ({0}): Added groupId={1} to folderId={2} with FolderRole='{3}' SecretRole='{4}'" -f $modeStr,$targetGroupId,$FolderId,$folderAccessRoleName,$secretAccessRoleName) 'INFO'
    } else {
      Write-Log ("FOLDER PERM OK ({0}): Added userId={1} to folderId={2} with FolderRole='{3}' SecretRole='{4}'" -f $modeStr,$targetUserId,$FolderId,$folderAccessRoleName,$secretAccessRoleName) 'INFO'
    }
    
    # Track successful addition
    $trackKey = "folder_${FolderId}_g${targetGroupId}_u${targetUserId}"
    $script:FolderPermAddedCache[$trackKey] = $true
    
    return $true
  }
  catch{
    $errMsg = [string]$_
    $statusCode = 0
    try{ $statusCode = $_.Exception.Response.StatusCode.value__ } catch {}
    
    # Try to get more error details from response body
    $errorDetails = $null
    try{
      if($_.Exception.Response){
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $errorDetails = $reader.ReadToEnd()
        $reader.Close()
        if(-not [string]::IsNullOrWhiteSpace($errorDetails)){
          Write-Log ("FOLDER PERM ERROR: API Response body: {0}" -f $errorDetails) 'WARN'
        }
      }
    } catch {}
    
    # Log the full error details for debugging
    Write-Log ("FOLDER PERM ERROR ({0}): folderId={1}, groupId={2}, userId={3}, status={4}, error: {5}" -f $modeStr,$FolderId,$targetGroupId,$targetUserId,$statusCode,$errMsg) 'WARN'
    Write-Log ("FOLDER PERM ERROR: Payload sent: {0}" -f ($payload | ConvertTo-Json -Compress)) 'WARN'
    
    # If 400 error with "already" or "duplicate" in message, treat as success
    $isAlreadyExists = $false
    if($statusCode -eq 400){
      if($errMsg -match 'already|duplicate|exists' -or ($errorDetails -and $errorDetails -match 'already|duplicate|exists')){
        $isAlreadyExists = $true
      }
    }
    
    if($isAlreadyExists){
      if($targetUserId -gt 0){
        Write-Log ("FOLDER PERM SKIP ({0}): Permission for userId={1} already exists on folderId={2}" -f $modeStr,$targetUserId,$FolderId) 'INFO'
      } elseif($targetGroupId -gt 0){
        Write-Log ("FOLDER PERM SKIP ({0}): Permission for groupId={1} already exists on folderId={2}" -f $modeStr,$targetGroupId,$FolderId) 'INFO'
      }
      
      # Track to avoid retrying
      $trackKey = "folder_${FolderId}_g${targetGroupId}_u${targetUserId}"
      $script:FolderPermAddedCache[$trackKey] = $true
      
      return $true  # Treat as success
    }
    
    # Real error - log and fail
    Write-Log ("FOLDER PERM ERROR ({0}): Failed to add permission for folderId={1}: {2}" -f $modeStr,$FolderId,$errMsg) 'WARN'
    return $false
  }
}

# =========================
# Pre-Import Permission Check
# =========================
function Test-TargetAccountPermissions {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [int]$TargetFolderId = 0
  )
  
  $result = [pscustomobject]@{
    Success = $false
    CanCreateFolders = $false
    CanCreateSecrets = $false
    CurrentUser = $null
    CurrentUserRoles = @()
    FolderPermissions = @()
    ErrorMessage = $null
  }
  
  try{
    # Get current user info
    Write-Log "PERM CHECK: Verifying target account permissions..." 'INFO'
    $userInfo = SS $TgtApiBase GET 'users/current' $TgtTok $null $null
    $result.CurrentUser = Get-PropValue $userInfo @('userName','UserName','displayName') 'Unknown'
    $userId = Get-PropValue $userInfo @('id','Id','userId','UserId') 0
    Write-Log ("PERM CHECK: Current user: {0} (id={1})" -f $result.CurrentUser,$userId) 'INFO'
    
    # Get user's actual assigned roles (from user info, not all system roles)
    $isAdmin = $false
    try{
      $userRoles = Get-PropValue $userInfo @('roles','Roles') $null
      if($userRoles){
        foreach($role in $userRoles){
          $roleName = if($role -is [string]){ $role } else { Get-PropValue $role @('name','Name','roleName') '' }
          if(-not [string]::IsNullOrWhiteSpace($roleName)){
            $result.CurrentUserRoles += $roleName
            if($roleName -match 'Administrator|Admin'){
              $isAdmin = $true
            }
          }
        }
      }
      # Alternative: check isApplicationAccount or other admin indicators
      $isAppAccount = Get-PropValue $userInfo @('isApplicationAccount','IsApplicationAccount') $false
      if($isAppAccount){
        Write-Log "PERM CHECK: Account is an application account" 'DEBUG'
      }
    }
    catch{
      Write-Log ("PERM CHECK: Could not parse user roles: {0}" -f $_.Exception.Message) 'DEBUG'
    }
    
    # CRITICAL: Actually verify access to the target folder by trying to read it
    if($TargetFolderId -gt 0){
      Write-Log ("PERM CHECK: Verifying access to target folder ID {0}..." -f $TargetFolderId) 'INFO'
      try{
        $folderInfo = SS $TgtApiBase GET ("folders/{0}" -f $TargetFolderId) $TgtTok $null $null
        $folderName = Get-PropValue $folderInfo @('folderName','FolderName','name','Name') 'Unknown'
        Write-Log ("PERM CHECK: Successfully accessed target folder '{0}' (ID: {1})" -f $folderName,$TargetFolderId) 'INFO'
      }
      catch{
        $errMsg = $_.Exception.Message
        Write-Log ("PERM CHECK: FAILED to access target folder {0}: {1}" -f $TargetFolderId,$errMsg) 'ERROR'
        $result.ErrorMessage = "Cannot access target folder ID {0}. Error: {1}" -f $TargetFolderId,$errMsg
        $result.Success = $false
        return $result
      }
    }
    
    if($isAdmin){
      Write-Log ("PERM CHECK: User has admin role ({0}) - full access assumed" -f ($result.CurrentUserRoles -join ', ')) 'INFO'
      $result.CanCreateFolders = $true
      $result.CanCreateSecrets = $true
      $result.Success = $true
      return $result
    }
    
    # Check folder permissions if a target folder is specified
    if($TargetFolderId -gt 0){
      try{
        $folderPerms = @()
        $page = 1
        while($true){
          $resp = SS $TgtApiBase GET 'folder-permissions' $TgtTok $null @{
            'filter.folderId' = $TargetFolderId
            'filter.page' = $page
            'filter.pageSize' = 100
          }
          $recs = @(Get-Records $resp)
          $folderPerms += $recs
          if($recs.Count -lt 100){ break }
          $page++
          if($page -gt 10){ break }
        }
        
        $result.FolderPermissions = $folderPerms
        
        foreach($fp in $folderPerms){
          $fpUserId = Get-PropValue $fp @('userId','UserId') $null
          $fpUserName = Get-PropValue $fp @('userName','UserName') ''
          $folderRole = Get-PropValue $fp @('folderAccessRoleName','FolderAccessRoleName') ''
          $secretRole = Get-PropValue $fp @('secretAccessRoleName','SecretAccessRoleName') ''
          
          if($fpUserId -eq $userId -or $fpUserName -eq $result.CurrentUser){
            Write-Log ("PERM CHECK: Found permission for current user - FolderRole='{0}' SecretRole='{1}'" -f $folderRole,$secretRole) 'INFO'
            if($folderRole -match 'Owner|Edit|Add'){
              $result.CanCreateFolders = $true
            }
            if($secretRole -match 'Owner|Edit|View'){
              $result.CanCreateSecrets = $true
            }
          }
        }
        
        # List all permissions on the folder
        if($folderPerms.Count -gt 0){
          Write-Log ("PERM CHECK: Existing permissions on folder {0}:" -f $TargetFolderId) 'INFO'
          foreach($fp in $folderPerms){
            $fpUserName = Get-PropValue $fp @('userName','UserName') $null
            $fpGroupName = Get-PropValue $fp @('groupName','GroupName') $null
            $folderRole = Get-PropValue $fp @('folderAccessRoleName','FolderAccessRoleName') ''
            $secretRole = Get-PropValue $fp @('secretAccessRoleName','SecretAccessRoleName') ''
            $principal = if($fpUserName){ "User: $fpUserName" } elseif($fpGroupName){ "Group: $fpGroupName" } else { "Unknown" }
            Write-Log ("  - {0} | FolderRole={1} | SecretRole={2}" -f $principal,$folderRole,$secretRole) 'INFO'
          }
        }
        
        # MANDATORY: User MUST have Owner or Edit folder role to import
        if(-not $result.CanCreateFolders){
          $result.ErrorMessage = "Account '{0}' does not have Owner or Edit permission on folder {1}. Please grant folder permissions before importing." -f $result.CurrentUser,$TargetFolderId
          $result.Success = $false
          return $result
        }
      }
      catch{
        Write-Log ("PERM CHECK: Could not retrieve folder permissions: {0}" -f $_.Exception.Message) 'WARN'
      }
      
      # User has explicit folder permission - allow import
      $result.Success = $result.CanCreateFolders
      Write-Log ("PERM CHECK: Permission check passed. CanCreateFolders={0}, CanCreateSecrets={1}" -f $result.CanCreateFolders,$result.CanCreateSecrets) 'INFO'
      return $result
    }
    
    # No specific folder - verify API access only
    try{
      $testFolderResp = SS $TgtApiBase GET 'folders' $TgtTok $null @{'filter.page'=1;'filter.pageSize'=1}
      $result.CanCreateFolders = $true
      $result.CanCreateSecrets = $true
      $result.Success = $true
      Write-Log "PERM CHECK: API access verified - can list folders" 'INFO'
    }
    catch{
      $result.ErrorMessage = "Cannot access folders API: " + $_.Exception.Message
      Write-Log ("PERM CHECK: {0}" -f $result.ErrorMessage) 'ERROR'
      $result.Success = $false
    }
    
    return $result
  }
  catch{
    $result.ErrorMessage = "Permission check failed: " + $_.Exception.Message
    Write-Log ("PERM CHECK: {0}" -f $result.ErrorMessage) 'ERROR'
    return $result
  }
}

# =========================
# DRY-RUN PERMISSION COUNTING HELPERS
# =========================
function Count-SecretPermissionChanges {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$SecretId,
    [Parameter(Mandatory)]$PermissionsArray,
    [bool]$RemapPrincipals = $false
  )
  
  $addCount = 0
  $skipCount = 0
  $errorCount = 0
  
  # Get existing permissions for this secret - ALWAYS query fresh for accurate dry-run
  $existingPerms = @()
  try{
    $resp = SS $TgtApiBase GET 'secret-permissions' $TgtTok $null @{
      'filter.secretId' = $SecretId
      'take' = 100
    }
    $existingPerms = @(Get-Records $resp)
    Write-Log ("DRY-RUN PERM CHECK: Secret ID {0} currently has {1} ACLs on target system" -f $SecretId,$existingPerms.Count) 'INFO'
  } catch {
    Write-Log ("DRY-RUN PERM: Could not check existing secret permissions for secretId={0}: {1}" -f $SecretId,$_.Exception.Message) 'WARN'
  }
  
  # Load caches if not already loaded
  if($RemapPrincipals){
    Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
    Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
  } else {
    Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
    Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
  }
  
  foreach($perm in $PermissionsArray){
    try{
      $p = Normalize-PermissionObject $perm
      if($p.Count -eq 0){
        $skipCount++
        continue
      }
      
      # Extract source principal info
      $srcUserId = 0; $srcGroupId = 0
      $srcUserName = $null; $srcGroupName = $null
      $srcKnownAs = $null; $srcDomainName = $null
      
      # Use direct hashtable key lookup (Get-PropValue/Has-Prop don't work with hashtables)
      foreach($k in @($p.Keys)){
        $kl = $k.ToLowerInvariant()
        switch($kl){
          'userid'    { try{ if($p[$k] -ne $null){ $srcUserId = [int]$p[$k] } } catch {} }
          'groupid'   { try{ if($p[$k] -ne $null){ $srcGroupId = [int]$p[$k] } } catch {} }
          'username'  { if($p[$k] -ne $null){ $srcUserName = [string]$p[$k] } }
          'groupname' { if($p[$k] -ne $null){ $srcGroupName = [string]$p[$k] } }
          'knownas'   { if($p[$k] -ne $null){ $srcKnownAs = [string]$p[$k] } }
          'domainname' { if($p[$k] -ne $null){ $srcDomainName = [string]$p[$k] } }
        }
      }
      
      # Resolve target principal
      $targetUserId = 0; $targetGroupId = 0
      
      if($RemapPrincipals){
        # Remap by name
        if($srcUserId -gt 0 -and -not [string]::IsNullOrWhiteSpace($srcUserName)){
          $targetUserId = Get-TargetUserIdByName -TgtApiBase $TgtApiBase -TgtTok $TgtTok -UserName $srcUserName -KnownAs $srcKnownAs -DomainName $srcDomainName
          if($targetUserId -le 0){
            Write-Log ("DRY-RUN PERM: SecretId={0} - User '{1}' (src id={2}) NOT found in target - SKIPPING" -f $SecretId,$srcUserName,$srcUserId) 'INFO'
            $skipCount++
            continue
          }
          Write-Log ("DRY-RUN PERM: SecretId={0} - User '{1}' remapped from src id={2} to target id={3}" -f $SecretId,$srcUserName,$srcUserId,$targetUserId) 'INFO'
        } elseif($srcGroupId -gt 0 -and -not [string]::IsNullOrWhiteSpace($srcGroupName)){
          $targetGroupId = Get-TargetGroupIdByName -TgtApiBase $TgtApiBase -TgtTok $TgtTok -GroupName $srcGroupName -KnownAs $srcKnownAs -DomainName $srcDomainName
          if($targetGroupId -le 0){
            Write-Log ("DRY-RUN PERM: SecretId={0} - Group '{1}' (src id={2}) NOT found in target - SKIPPING" -f $SecretId,$srcGroupName,$srcGroupId) 'INFO'
            $skipCount++
            continue
          }
          Write-Log ("DRY-RUN PERM: SecretId={0} - Group '{1}' remapped from src id={2} to target id={3}" -f $SecretId,$srcGroupName,$srcGroupId,$targetGroupId) 'INFO'
        } else {
          Write-Log ("DRY-RUN PERM: SecretId={0} - Permission has no valid user/group - SKIPPING" -f $SecretId) 'INFO'
          $skipCount++
          continue
        }
      } else {
        # Direct mode - validate principal exists
        if($srcUserId -gt 0){
          $userExists = $false
          foreach($uid in $script:TgtUserNameToIdCache.Values){
            if([int]$uid -eq $srcUserId){ $userExists = $true; break }
          }
          if(-not $userExists){
            $skipCount++
            continue
          }
          $targetUserId = $srcUserId
        } elseif($srcGroupId -gt 0){
          $groupExists = $false
          foreach($gid in $script:TgtGroupNameToIdCache.Values){
            if([int]$gid -eq $srcGroupId){ $groupExists = $true; break }
          }
          if(-not $groupExists){
            $skipCount++
            continue
          }
          $targetGroupId = $srcGroupId
        } else {
          $skipCount++
          continue
        }
      }
      
      if($targetUserId -le 0 -and $targetGroupId -le 0){
        Write-Log ("DRY-RUN PERM: Could not resolve target principal - skipping") 'DEBUG'
        $skipCount++
        continue
      }
      
      $principalDesc = if($targetUserId -gt 0){ "User ID $targetUserId" } else { "Group ID $targetGroupId" }
      Write-Log ("DRY-RUN PERM: SecretId={0} checking {1}" -f $SecretId,$principalDesc) 'INFO'
      
      # Check if permission already exists
      $alreadyExists = $false
      
      foreach($ep in $existingPerms){
        $epGroupId = Get-PropValue $ep @('groupId','GroupId') 0
        $epUserId = Get-PropValue $ep @('userId','UserId') 0
        
        if($targetGroupId -gt 0 -and [int]$epGroupId -eq [int]$targetGroupId){
          Write-Log ("DRY-RUN PERM: SecretId={0} - {1} MATCH found with existing GroupId={2}" -f $SecretId,$principalDesc,$epGroupId) 'INFO'
          $alreadyExists = $true
          break
        }
        if($targetUserId -gt 0 -and [int]$epUserId -eq [int]$targetUserId){
          Write-Log ("DRY-RUN PERM: SecretId={0} - {1} MATCH found with existing UserId={2}" -f $SecretId,$principalDesc,$epUserId) 'INFO'
          $alreadyExists = $true
          break
        }
      }
      
      if($alreadyExists){
        $skipCount++
      } else {
        Write-Log ("DRY-RUN PERM CHECK: SecretId={0} - {1} would be ADDED (not found in {2} existing perms)" -f $SecretId,$principalDesc,$existingPerms.Count) 'INFO'
        $addCount++
      }
    } catch {
      $errorCount++
    }
  }
  
  return [pscustomobject]@{
    Add = $addCount
    Skip = $skipCount
    Error = $errorCount
  }
}

function Count-FolderPermissionChanges {
  param(
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$FolderId,
    [Parameter(Mandatory)]$PermissionsArray,
    [bool]$RemapPrincipals = $false,
    [bool]$AssumeNewFolder = $false
  )
  
  $addCount = 0
  $skipCount = 0
  $errorCount = 0
  
  # Get existing permissions for this folder (skip if new folder - it won't have any)
  $existingPerms = @()
  if(-not $AssumeNewFolder){
    try{
      Write-Log ("DRY-RUN PERM: Querying current permissions for folderId={0}" -f $FolderId) 'DEBUG'
      $resp = SS $TgtApiBase GET "folder-permissions?filter.folderId=$FolderId" $TgtTok $null $null
      $existingPerms = @(Get-Records $resp)
      Write-Log ("DRY-RUN PERM: Found {0} existing permissions on folderId={1}" -f $existingPerms.Count,$FolderId) 'DEBUG'
    } catch {
      Write-Log ("DRY-RUN PERM: Could not check existing folder permissions for folderId={0}: {1}" -f $FolderId,$_.Exception.Message) 'DEBUG'
    }
  } else {
    Write-Log ("DRY-RUN PERM: Folder would be newly created - assuming no existing permissions") 'DEBUG'
  }
  
  # Load caches
  if($RemapPrincipals){
    Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
    Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
  } else {
    Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
    Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok $TgtTok
  }
  
  foreach($perm in $PermissionsArray){
    try{
      $srcGroupId = Get-PropValue $perm @('groupId','GroupId') $null
      $srcUserId = Get-PropValue $perm @('userId','UserId') $null
      $groupName = [string](Get-PropValue $perm @('groupName','GroupName') $null)
      $userName = [string](Get-PropValue $perm @('userName','UserName','knownAs','KnownAs') $null)
      $srcKnownAs = [string](Get-PropValue $perm @('knownAs','KnownAs') $null)
      $srcDomainName = [string](Get-PropValue $perm @('domainName','DomainName') $null)
      
      $folderAccessRoleName = [string](Get-PropValue $perm @('folderAccessRoleName','FolderAccessRoleName') $null)
      $secretAccessRoleName = [string](Get-PropValue $perm @('secretAccessRoleName','SecretAccessRoleName') $null)
      
      # Skip if missing required role names
      if([string]::IsNullOrWhiteSpace($folderAccessRoleName) -or [string]::IsNullOrWhiteSpace($secretAccessRoleName)){
        $skipCount++
        continue
      }
      
      # Resolve target principal using multi-strategy lookup
      $targetGroupId = $null
      $targetUserId = $null
      
      if($RemapPrincipals){
        if($srcGroupId -ne $null -and [int]$srcGroupId -gt 0 -and -not [string]::IsNullOrWhiteSpace($groupName)){
          $targetGroupId = Get-TargetGroupIdByName -TgtApiBase $TgtApiBase -TgtTok $TgtTok -GroupName $groupName -KnownAs $srcKnownAs -DomainName $srcDomainName
          if($targetGroupId -le 0){ $targetGroupId = $null; $skipCount++; continue }
        } elseif($srcUserId -ne $null -and [int]$srcUserId -gt 0 -and -not [string]::IsNullOrWhiteSpace($userName)){
          $targetUserId = Get-TargetUserIdByName -TgtApiBase $TgtApiBase -TgtTok $TgtTok -UserName $userName -KnownAs $srcKnownAs -DomainName $srcDomainName
          if($targetUserId -le 0){ $targetUserId = $null; $skipCount++; continue }
        } else {
          $skipCount++
          continue
        }
      } else {
        if($srcGroupId -ne $null -and [int]$srcGroupId -gt 0 -and -not [string]::IsNullOrWhiteSpace($groupName)){
          $targetGroupId = Get-TargetGroupIdByName -TgtApiBase $TgtApiBase -TgtTok $TgtTok -GroupName $groupName -KnownAs $srcKnownAs -DomainName $srcDomainName
          if($targetGroupId -le 0){ $targetGroupId = $null; $skipCount++; continue }
        } elseif($srcUserId -ne $null -and [int]$srcUserId -gt 0 -and -not [string]::IsNullOrWhiteSpace($userName)){
          $targetUserId = Get-TargetUserIdByName -TgtApiBase $TgtApiBase -TgtTok $TgtTok -UserName $userName -KnownAs $srcKnownAs -DomainName $srcDomainName
          if($targetUserId -le 0){ $targetUserId = $null; $skipCount++; continue }
        } else {
          $skipCount++
          continue
        }
      }
      
      if($targetGroupId -eq $null -and $targetUserId -eq $null){
        $skipCount++
        continue
      }
      
      # Check if permission already exists (and if roles differ = would update)
      $alreadyExists = $false
      $wouldUpdate = $false
      $srcFolderRole = [string](Get-PropValue $perm @('folderAccessRoleName','FolderAccessRoleName') '')
      $srcSecretRole = [string](Get-PropValue $perm @('secretAccessRoleName','SecretAccessRoleName') '')
      
      foreach($ep in $existingPerms){
        $epGroupId = Get-PropValue $ep @('groupId','GroupId') $null
        $epUserId = Get-PropValue $ep @('userId','UserId') $null
        
        $principalMatch = $false
        if($targetGroupId -ne $null -and $epGroupId -ne $null -and [int]$epGroupId -eq [int]$targetGroupId){ $principalMatch = $true }
        if($targetUserId -ne $null -and $epUserId -ne $null -and [int]$epUserId -eq [int]$targetUserId){ $principalMatch = $true }
        
        if($principalMatch){
          $alreadyExists = $true
          # Check if roles differ
          $epFolderRole = [string](Get-PropValue $ep @('folderAccessRoleName','FolderAccessRoleName') '')
          $epSecretRole = [string](Get-PropValue $ep @('secretAccessRoleName','SecretAccessRoleName') '')
          if((-not [string]::IsNullOrWhiteSpace($srcFolderRole) -and $epFolderRole -ne $srcFolderRole) -or
             (-not [string]::IsNullOrWhiteSpace($srcSecretRole) -and $epSecretRole -ne $srcSecretRole)){
            $wouldUpdate = $true
          }
          break
        }
      }
      
      if($alreadyExists -and $wouldUpdate){
        $addCount++  # counts as a change (update)
      } elseif($alreadyExists){
        $skipCount++
      } else {
        $addCount++
      }
    } catch {
      $errorCount++
    }
  }
  
  return [pscustomobject]@{
    Add = $addCount
    Skip = $skipCount
    Error = $errorCount
  }
}

# =========================
# IMPORT-Folders and Secrets 
# =========================
function Add-SuffixToTemplateXml([string]$templateXml,[string]$suffix){
  if([string]::IsNullOrWhiteSpace($templateXml) -or [string]::IsNullOrWhiteSpace($suffix)){ return $templateXml }
  try{
    [xml]$x = $templateXml
    $nameNode = $x.SelectSingleNode('//secrettype/name')
    if(-not $nameNode){ $nameNode = $x.SelectSingleNode('//SecretType/Name') }
    if(-not $nameNode){ $nameNode = $x.SelectSingleNode('//secretType/name') }
    if($nameNode){
      $originalName = $nameNode.InnerText
      $nameNode.InnerText = "$originalName $suffix"
      return $x.OuterXml
    }
    if($templateXml -match '<name>([^<]+)</name>'){
      $originalName = $Matches[1]
      $newName = "$originalName $suffix"
      return $templateXml -replace "<name>$([regex]::Escape($originalName))</name>", "<name>$newName</name>"
    }
    return $templateXml
  } catch {
    Write-Log ("Add-SuffixToTemplateXml: Failed to modify XML - {0}" -f $_.Exception.Message) 'WARN'
    return $templateXml
  }
}

function Sync-TemplateFieldsFromSource {
  param(
    [Parameter(Mandatory)][string]$SrcApiBase,
    [Parameter(Mandatory)][string]$SrcTok,
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)]$ExportData,
    [string]$MappingCsvPath = ''
  )
  Write-Log "SYNC-TEMPLATE-FIELDS: Starting field synchronization from source to target templates" 'INFO'
  try {
    # Collect template IDs used by exported secrets
    $usedTemplateIds = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach($s in @($ExportData.Secrets)){
      $tid = Get-PropValue $s @('SecretTypeId','secretTypeId','templateId','TemplateId') $null
      if($tid){ [void]$usedTemplateIds.Add([string]$tid) }
    }
    Write-Log ("SYNC-TEMPLATE-FIELDS: Found {0} distinct template IDs used by source secrets" -f $usedTemplateIds.Count) 'INFO'
    if($usedTemplateIds.Count -eq 0){
      Write-Log "SYNC-TEMPLATE-FIELDS: No template IDs found in source data - nothing to sync" 'WARN'
      return
    }

    $srcTemplates = Get-AllSecretTemplatesDetailed -apiBase $SrcApiBase -tok $SrcTok -detailIds ($usedTemplateIds | ForEach-Object { $_ })
    $tgtTemplates = Get-AllSecretTemplatesDetailed -apiBase $TgtApiBase -tok $TgtTok
    if(-not $srcTemplates -or -not $tgtTemplates){
      Write-Log "SYNC-TEMPLATE-FIELDS: Could not retrieve templates - aborting field sync" 'WARN'
      return
    }

    # Strip trailing ' Source' / ' MIGRATED' from target template names to enable matching against source
    foreach($t in @($tgtTemplates)){
      $name = [string](Get-PropValue $t @('name','Name') '')
      if($name -match '\s+(ABCD|MIGRATED)\s*$'){
        $clean = $name -replace '\s+(ABCD|MIGRATED)\s*$',''
        try { $t.name = $clean } catch {
          try { $t | Add-Member -NotePropertyName name -NotePropertyValue $clean -Force } catch {}
        }
      }
    }

    $comparison = Compare-SecretTemplates -SourceTemplates $srcTemplates -TargetTemplates $tgtTemplates
    if(-not $comparison){
      Write-Log "SYNC-TEMPLATE-FIELDS: Template comparison returned no result" 'WARN'
      return
    }

    $matched = @(Get-PropValue $comparison @('Matched','matched') @())
    Write-Log ("SYNC-TEMPLATE-FIELDS: {0} matched template pairs to evaluate" -f $matched.Count) 'INFO'

    $addedTotal = 0
    $demotedTotal = 0
    $errorsTotal = 0
    foreach($pair in $matched){
      $srcId = [int](Get-PropValue $pair @('SourceId','sourceId') 0)
      $tgtId = [int](Get-PropValue $pair @('TargetId','targetId') 0)
      $name  = [string](Get-PropValue $pair @('Name','name') '')
      if($tgtId -le 0){ continue }

      $srcFields = @(Get-PropValue $pair @('SourceFields','sourceFields') @())
      $tgtFields = @(Get-PropValue $pair @('TargetFields','targetFields') @())

      # Index by slug
      $srcBySlug = @{}
      foreach($f in $srcFields){
        $slug = [string](Get-PropValue $f @('slug','Slug','fieldSlug','FieldSlug') '')
        if($slug){ $srcBySlug[$slug.ToLowerInvariant()] = $f }
      }
      $tgtBySlug = @{}
      foreach($f in $tgtFields){
        $slug = [string](Get-PropValue $f @('slug','Slug','fieldSlug','FieldSlug') '')
        if($slug){ $tgtBySlug[$slug.ToLowerInvariant()] = $f }
      }

      # Demote target-only required fields to optional (so import won't fail on missing values)
      foreach($key in $tgtBySlug.Keys){
        if(-not $srcBySlug.ContainsKey($key)){
          $tf = $tgtBySlug[$key]
          $req = [bool](Get-PropValue $tf @('isRequired','IsRequired','required','Required') $false)
          if($req){
            try {
              $body = @{ isRequired = $false }
              SS $TgtApiBase PUT ("secret-templates/{0}/fields/{1}" -f $tgtId,$key) $TgtTok $body $null | Out-Null
              Write-Log ("SYNC-TEMPLATE-FIELDS: [{0}] Demoted target-only required field '{1}' to optional" -f $name,$key) 'INFO'
              $demotedTotal++
            } catch {
              Write-Log ("SYNC-TEMPLATE-FIELDS: [{0}] Failed to demote '{1}': {2}" -f $name,$key,$_.Exception.Message) 'WARN'
              $errorsTotal++
            }
          }
        }
      }

      # Add fields that exist in source but missing on target
      foreach($key in $srcBySlug.Keys){
        if(-not $tgtBySlug.ContainsKey($key)){
          $sf = $srcBySlug[$key]
          $body = @{
            slug         = $key
            displayName  = (Get-PropValue $sf @('displayName','DisplayName','name','Name') $key)
            description  = (Get-PropValue $sf @('description','Description') '')
            isPassword   = [bool](Get-PropValue $sf @('isPassword','IsPassword') $false)
            isUrl        = [bool](Get-PropValue $sf @('isUrl','IsUrl') $false)
            isNotes      = [bool](Get-PropValue $sf @('isNotes','IsNotes') $false)
            isFile       = [bool](Get-PropValue $sf @('isFile','IsFile') $false)
            isList       = [bool](Get-PropValue $sf @('isList','IsList') $false)
            isRequired   = $false  # add as optional to avoid breaking import
            editRequires = [string](Get-PropValue $sf @('editRequires','EditRequires') 'Edit')
            historyLength= [int](Get-PropValue $sf @('historyLength','HistoryLength') 0)
          }
          try {
            SS $TgtApiBase POST ("secret-templates/{0}/fields" -f $tgtId) $TgtTok $body $null | Out-Null
            Write-Log ("SYNC-TEMPLATE-FIELDS: [{0}] Added missing field '{1}'" -f $name,$key) 'INFO'
            $addedTotal++
          } catch {
            Write-Log ("SYNC-TEMPLATE-FIELDS: [{0}] Failed to add field '{1}': {2}" -f $name,$key,$_.Exception.Message) 'WARN'
            $errorsTotal++
          }
        }
      }
    }
    Write-Log ("SYNC-TEMPLATE-FIELDS: Complete. Added={0}, Demoted={1}, Errors={2}" -f $addedTotal,$demotedTotal,$errorsTotal) 'INFO'
  } catch {
    Write-Log ("SYNC-TEMPLATE-FIELDS: Unexpected error: {0}" -f $_.Exception.Message) 'ERROR'
  }
}

function Import-SS {
  param(
    [Parameter(Mandatory)][string]$SrcApiBase,
    [Parameter(Mandatory)][string]$SrcToken,
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtToken,
    [Parameter(Mandatory)][string]$InputPath,
    [int]$TargetFolderId = 0,
    [bool]$UseFolderTree = $false,
    [int]$TargetRootFolderId = 1,
    [bool]$OverwriteIfExists = $true,
    [bool]$SecretTypeMapByName = $false,
    [bool]$ImportTemplates = $false,
    [string]$TemplateSuffix = '',
    [bool]$SyncTemplateFields = $false,
    [bool]$SkipPasswordValidation = $false,
    [bool]$StopOnError = $false,
    [bool]$CopyFolderAcls = $false,
    [bool]$CopySecretAcls = $false,
    [bool]$CopySecretSettings = $false,
    [bool]$CopyAttachments = $false,
    [bool]$RemapPrincipals = $false,
    [bool]$DryRun = $false,
    [bool]$DecryptPasswords = $false,
    [bool]$DisableInheritPermissions = $false
  )

  # Make new options available at script scope so deep helpers (Build-Items / payload builders) can read them
  $script:Opt_SkipPasswordValidation = [bool]$SkipPasswordValidation
  $script:Opt_TemplateSuffix         = [string]$TemplateSuffix
  $script:Opt_StopOnError            = [bool]$StopOnError
  $script:LastImportError            = $null
  $script:LastErrorSecret            = $null

  # Centralized error handler. Returns $true if caller should break out of the loop.
  function Handle-ImportError {
    param([string]$Context,[string]$SecretName,$ErrorRecord)
    $script:LastImportError = $ErrorRecord
    $script:LastErrorSecret = $SecretName
    Write-Log ("IMPORT-ERROR [{0}] secret='{1}': {2}" -f $Context,$SecretName,$ErrorRecord.Exception.Message) 'ERROR'
    if($script:Opt_StopOnError){
      Write-Log ("IMPORT: StopOnError is enabled - aborting import after error on '{0}'" -f $SecretName) 'ERROR'
      $script:ImportCancelled = $true
      return $true
    }
    return $false
  }

  # Always re-acquire tokens via Token() so that the global TokenCache (and any
  # auto-refresh performed inside SS on a 401) is honored. Returning the captured
  # $SrcToken/$TgtToken parameters would hand out a stale token after expiration,
  # causing every subsequent API call to fail with "Authentication failed".
  function Get-TgtTok {
    $tb = $null
    try { $tb = Get-Variable -Name 'tbTgtPwd' -Scope Script -ValueOnly -ErrorAction SilentlyContinue } catch {}
    return (Token Tgt $tb)
  }
  function Get-SrcTok {
    $tb = $null
    try { $tb = Get-Variable -Name 'tbSrcPwd' -Scope Script -ValueOnly -ErrorAction SilentlyContinue } catch {}
    return (Token Src $tb)
  }

  # Reset cancellation flag
  $script:ImportCancelled = $false

  # Reset tracking at start of import
  Reset-ImportTracking
  $script:CreatedFolderCache = @{}
  
  # Pre-import permission check
  $effectiveTargetFolder = if($TargetFolderId -gt 0){ $TargetFolderId } else { $TargetRootFolderId }
  $permCheck = Test-TargetAccountPermissions -TgtApiBase $TgtApiBase -TgtTok $TgtToken -TargetFolderId $effectiveTargetFolder
  if(-not $permCheck.Success){
    # Single clean error message - no throw (return instead to avoid catch block noise)
    Write-Log ("IMPORT: {0}" -f $permCheck.ErrorMessage) 'ERROR'
    Write-Log ("IMPORT: To fix this, add '{0}' with FolderRole=Owner or Edit on folder {1}" -f $permCheck.CurrentUser,$effectiveTargetFolder) 'INFO'
    return [pscustomobject]@{ Created = 0; Updated = 0; Skipped = 0; SecretACLs = 0; FolderACLs = 0; Error = $permCheck.ErrorMessage }
  }

  if(-not (Test-Path $InputPath)){
    throw "IMPORT: input JSON not found: $InputPath"
  }

  # Use fast JSON parser for large files (ConvertFrom-Json chokes on 100MB+)
  $fileSizeMB = [math]::Round((Get-Item $InputPath).Length / 1MB, 1)
  Write-Log ("IMPORT: Loading JSON file: {0} ({1} MB)" -f $InputPath, $fileSizeMB) 'INFO'
  if($fileSizeMB -gt 50){
    Write-Log "IMPORT: Large file detected - using fast JavaScriptSerializer parser (please wait ~15s)..." 'INFO'
  }
  [System.Windows.Forms.Application]::DoEvents()
  # Read as Dictionary (6 seconds) then convert to PSObject (7 seconds) = ~14s total for 326MB
  $in = Read-LargeJsonAsPSObject $InputPath
  [System.Windows.Forms.Application]::DoEvents()
  Write-Log "IMPORT: JSON loaded successfully" 'INFO'
  $secrets = @($in.Secrets)
  
  if(@($secrets).Count -eq 0){
    Write-Log "IMPORT: no secrets found in JSON" 'WARN'
    return [pscustomobject]@{ Created = 0; Updated = 0; Skipped = 0; SecretACLs = 0; FolderACLs = 0 }
  }

  Write-Log ("IMPORT: Processing {0} secrets from {1}" -f $secrets.Count,$InputPath) 'INFO'
  Write-Log ("IMPORT: Options - UseFolderTree={0}, RemapPrincipals={1}, CopySecretAcls={2}, DryRun={3}, ImportTemplates={4}" -f $UseFolderTree,$RemapPrincipals,$CopySecretAcls,$DryRun,$ImportTemplates) 'INFO'

  # Import progress tracking file for resume capability
  $importProgressFile = $InputPath -replace '\.json$', '-import-progress.json'
  $importedSecretIds = New-Object 'System.Collections.Generic.HashSet[int]'
  # Index-based resume: the array index at which the next run should start.
  # This is robust against `continue` statements scattered through the loop body
  # (each iteration advances this counter BEFORE processing the next secret).
  $resumeFromIndex = 0
  # Load previously saved progress if resuming
  if(Test-Path $importProgressFile){
    try{
      $progressData = Get-Content $importProgressFile -Raw | ConvertFrom-Json
      $progressProps = @($progressData.PSObject.Properties.Name)
      # Preferred: explicit next-index pointer (new format)
      if($progressProps -contains 'ResumeFromIndex' -and $progressData.ResumeFromIndex -ne $null){
        $resumeFromIndex = [int]$progressData.ResumeFromIndex
        if($resumeFromIndex -lt 0){ $resumeFromIndex = 0 }
        Write-Log ("IMPORT: Resuming - previous run stopped at array index {0}" -f $resumeFromIndex) 'WARN'
      }
      # Backwards compat: legacy id-set format
      if($progressData.ImportedSecretIds){
        foreach($pid in @($progressData.ImportedSecretIds)){ [void]$importedSecretIds.Add([int]$pid) }
      }
      # Backwards compat: legacy LastIndex field (set every save in old code = number of
      # secrets processed by the loop). Use it as the resume start index when no
      # explicit ResumeFromIndex is present. This is more reliable than scanning the
      # incomplete id-set, because the old tracker missed most success paths.
      if($resumeFromIndex -le 0 -and $progressProps -contains 'LastIndex' -and $progressData.LastIndex -ne $null){
        $resumeFromIndex = [int]$progressData.LastIndex
        if($resumeFromIndex -lt 0){ $resumeFromIndex = 0 }
        Write-Log ("IMPORT: Resuming - legacy progress file detected, starting at index {0} (LastIndex)" -f $resumeFromIndex) 'WARN'
      } elseif($importedSecretIds.Count -gt 0 -and $resumeFromIndex -le 0){
        Write-Log ("IMPORT: Resuming - {0} secrets already imported from previous run (legacy id-set format)" -f $importedSecretIds.Count) 'WARN'
      }
      # Log additional context if available
      if($progressProps -contains 'StoppedOnSecret' -and $progressData.StoppedOnSecret){
        Write-Log ("IMPORT: Previous run stopped on secret '{0}'" -f $progressData.StoppedOnSecret) 'WARN'
      }
      if($progressProps -contains 'Total' -and $progressData.Total){
        Write-Log ("IMPORT: Previous run progress: {0} of {1} secrets" -f $resumeFromIndex,$progressData.Total) 'INFO'
      }
    }catch{
      Write-Log ("IMPORT: Failed to read progress file '{0}': {1}" -f $importProgressFile,$_.Exception.Message) 'WARN'
    }
  } else {
    Write-Log ("IMPORT: No progress file found at '{0}' - starting fresh import" -f $importProgressFile) 'INFO'
  }

  # Get duplicate action from config
  $dupAction = [string]$Global:Config.Tgt.DuplicateSecretAction
  if([string]::IsNullOrWhiteSpace($dupAction)){ $dupAction = "Skip" }
  Write-Log ("IMPORT: DuplicateSecretAction = '{0}'" -f $dupAction) 'INFO'

  # =====================================================
  # IMPORT TEMPLATES (if requested)
  # =====================================================
  if($ImportTemplates -and -not $DryRun){
    if($in.PSObject.Properties.Name -contains 'TemplateExports'){
      $templateExports = @($in.TemplateExports)
      if($templateExports.Count -gt 0){
        $suffixInfo = if([string]::IsNullOrWhiteSpace($TemplateSuffix)){''}else{" with suffix '$TemplateSuffix'"}
        Write-Log ("IMPORT: Found {0} template exports in JSON. Attempting to import{1}..." -f $templateExports.Count,$suffixInfo) 'INFO'
        $templatesImported = 0
        $templatesSkipped = 0
        $templatesFailed = 0
        
        foreach($tExp in $templateExports){
          $tid = Get-PropValue $tExp @('templateId','TemplateId') $null
          $xmlText = Get-PropValue $tExp @('exportFileText','ExportFileText') $null
          
          if(-not $xmlText){
            Write-Log ("IMPORT TEMPLATE: Skipping templateId={0} - no XML" -f $tid) 'WARN'
            $templatesSkipped++
            continue
          }
          
          # Parse template name from XML for better logging
          $templateName = Get-TemplateNameFromXml -templateXml $xmlText
          if(-not $templateName){ $templateName = "Template_$tid" }

          # Apply suffix if requested
          $targetName = $templateName
          $modifiedXml = $xmlText
          if(-not [string]::IsNullOrWhiteSpace($TemplateSuffix)){
            $targetName = "$templateName $TemplateSuffix"
            $modifiedXml = Add-SuffixToTemplateXml -templateXml $xmlText -suffix $TemplateSuffix
          }

          # Check if template already exists on target (by target name including suffix)
          $templateExists = Test-TargetTemplateExistsByName -tgtApiBase $TgtApiBase -tgtTok (Get-TgtTok) -templateName $targetName

          if($templateExists){
            Write-Log ("IMPORT TEMPLATE: '{0}' already exists on target - skipping" -f $targetName) 'INFO'
            $templatesSkipped++
            continue
          }

          # Import template
          try{
            Import-TemplateXml -apiBase $TgtApiBase -tok (Get-TgtTok) -templateXml $modifiedXml
            Write-Log ("IMPORT TEMPLATE: Successfully imported '{0}' (templateId={1})" -f $targetName,$tid) 'INFO'
            $templatesImported++
          }
          catch{
            Write-Log ("IMPORT TEMPLATE: Failed to import '{0}': {1}" -f $targetName,$_.Exception.Message) 'WARN'
            $templatesFailed++
          }
        }
        
        Write-Log ("IMPORT TEMPLATES: Complete - Imported={0}, Skipped={1}, Failed={2}" -f $templatesImported,$templatesSkipped,$templatesFailed) 'INFO'
      }
      else{
        Write-Log "IMPORT: No template exports found in JSON (TemplateExports array is empty)" 'INFO'
      }
    }
    else{
      Write-Log "IMPORT: No TemplateExports section in JSON - skipping template import" 'INFO'
    }
  }
  elseif($ImportTemplates -and $DryRun){
    Write-Log "[DRY-RUN] Would import templates from TemplateExports section if present" 'INFO'
  }

  # =====================================================
  # SYNC TEMPLATE FIELDS (if requested) - additive to existing target templates
  # =====================================================
  if($SyncTemplateFields -and -not $DryRun){
    Write-Log "IMPORT: Syncing template fields from source to target before secret import..." 'INFO'
    $mappingCsv = [string](Get-PropValue $Global:Config @('MappingCsvPath') '')
    Sync-TemplateFieldsFromSource `
      -SrcApiBase $SrcApiBase `
      -SrcTok (Get-SrcTok) `
      -TgtApiBase $TgtApiBase `
      -TgtTok (Get-TgtTok) `
      -ExportData $in `
      -MappingCsvPath $mappingCsv
  } elseif($SyncTemplateFields -and $DryRun){
    Write-Log "[DRY-RUN] Would sync template fields from source to target before import" 'INFO'
  }

  $created = 0
  $updated = 0
  $skipped = 0
  $secretIndex = 0
  $totalSecretPermsApplied = 0
  $totalFolderPermsApplied = 0
  
  # Pre-load caches if copying ACLs (needed for both Remap mode and DIRECT mode validation)
  if(($CopySecretAcls -or $CopyFolderAcls) -and -not $DryRun){
    Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
    Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
  }
  
  # Cache for template name -> ID mapping. Use Get-AllSecretTemplatesDetailed
  # (skip/take pagination) instead of Get-TemplateNameIndex (filter.page) -
  # the latter truncates to 10 entries on this tenant, causing suffixed
  # templates (e.g. 'Windows Account ABCD') to miss the cache and fall
  # through to source-id-fallback.
  $tgtTemplateNameIndex = $null
  if($SecretTypeMapByName){
    $tgtTemplateNameIndex = @{}
    try{
      $__tgtAll = @(Get-AllSecretTemplatesDetailed -apiBase $TgtApiBase -tok (Get-TgtTok))
      foreach($__t in $__tgtAll){
        $__n = Get-PropValue $__t @('name','Name') $null
        $__i = Get-PropValue $__t @('id','Id') $null
        if($__n -and $__i){ $tgtTemplateNameIndex[([string]$__n).Trim().ToLowerInvariant()] = [int]$__i }
      }
      Write-Log ("IMPORT: Built target template name->id index with {0} entries (via Get-AllSecretTemplatesDetailed)." -f $tgtTemplateNameIndex.Count) 'INFO'
    } catch {
      Write-Log ("IMPORT: Detailed target template list failed: {0}. Falling back to Get-TemplateNameIndex." -f $_.Exception.Message) 'WARN'
      try{ $tgtTemplateNameIndex = Get-TemplateNameIndex -apiBase $TgtApiBase -tok (Get-TgtTok) } catch {}
    }
  }

  # Cache for folder secret indexes (to avoid re-fetching)
  $folderSecretIndexCache = @{}

  $lastProgressSave = 0
  $importSaveInterval = 25  # Save progress every N secrets

  # Determine the array index to start from. Prefer the new index-based pointer.
  # If only the legacy id-set is present, derive the start index by scanning for
  # the first secret whose source Id isn't already in the imported set.
  $resumeStartIndex = $resumeFromIndex
  if($resumeStartIndex -le 0 -and $importedSecretIds.Count -gt 0){
    for($i = 0; $i -lt $secrets.Count; $i++){
      $sid = Get-PropValue $secrets[$i] @('Id','id','SecretId','secretId') $null
      if($sid -eq $null -or [int]$sid -le 0 -or -not $importedSecretIds.Contains([int]$sid)){
        $resumeStartIndex = $i
        break
      }
      if($i -eq $secrets.Count - 1){ $resumeStartIndex = $secrets.Count }
    }
  }
  if($resumeStartIndex -gt $secrets.Count){ $resumeStartIndex = $secrets.Count }

  if($resumeStartIndex -gt 0){
    if($resumeStartIndex -lt $secrets.Count){
      $firstPendingName = [string](Get-PropValue $secrets[$resumeStartIndex] @('name','Name','secretName','SecretName') '')
      Write-Log ("IMPORT: Resume detected - skipping {0:N0} already-processed secrets, starting at #{1:N0}/{2:N0}: '{3}'" -f $resumeStartIndex,($resumeStartIndex+1),$secrets.Count,$firstPendingName) 'INFO'
      # Account for the secrets we are seeking past in the skipped counter so final totals add up
      $skipped += $resumeStartIndex
      $secretIndex = $resumeStartIndex
      try{
        $resumeStatusText = "Resuming at {0}/{1} ({2}%) - {3}" -f ($resumeStartIndex+1),$secrets.Count,[int](($resumeStartIndex/$secrets.Count)*100),$firstPendingName
        Update-ProgressBar -Current ($resumeStartIndex+1) -Total $secrets.Count -StatusText $resumeStatusText
      }catch{}
    } else {
      Write-Log ("IMPORT: Resume detected - all {0:N0} secrets already processed in previous run. Nothing to do." -f $secrets.Count) 'INFO'
      $skipped += $secrets.Count
    }
  }

  # Index of the next secret to process if the run is interrupted. We advance this
  # at the TOP of each iteration BEFORE handling the current secret, so every
  # `continue` / success / skip / duplicate / update / error-skip path automatically
  # counts as "done". On StopOnError / Cancel we break out before bumping, so resume
  # restarts at the current (failed) secret.
  $script:ImportResumeNextIndex = $resumeStartIndex

  for($__idx = $resumeStartIndex; $__idx -lt $secrets.Count; $__idx++){
    $sec = $secrets[$__idx]
    # Check for cancellation (do this BEFORE advancing the resume pointer so we
    # restart at the current secret on next run)
    if($script:ImportCancelled){
      $script:ImportResumeNextIndex = $__idx
      Write-Log "IMPORT: Cancelled by user. Progress saved." 'WARN'
      break
    }

    # The PREVIOUS iteration is now fully complete (whether it succeeded, skipped,
    # was a duplicate, updated, or recorded a non-stopping error). Advance the
    # resume pointer so a crash/cancel from this point forward restarts at the
    # current index, not earlier.
    $script:ImportResumeNextIndex = $__idx

    $secretIndex++

    # Allow GUI to process events (cancel button clicks)
    if($secretIndex % 3 -eq 0){
      [System.Windows.Forms.Application]::DoEvents()
    }
    
    $secName = [string](Get-PropValue $sec @('Name','name') $null)
    if([string]::IsNullOrWhiteSpace($secName)){
      Write-Log ("IMPORT: Skipping secret {0} - no name" -f $secretIndex) 'WARN'
      $skipped++
      continue
    }

    # Skip already-imported secrets (resume support)
    $secId = Get-PropValue $sec @('Id','id','SecretId','secretId') $null
    if($secId -ne $null -and [int]$secId -gt 0 -and $importedSecretIds.Contains([int]$secId)){
      Write-Log ("IMPORT: Skipping secret {0}/{1}: '{2}' (already imported in previous run)" -f $secretIndex,$secrets.Count,$secName) 'DEBUG'
      $skipped++
      continue
    }
    
    Write-Log ("IMPORT: Processing secret {0}/{1}: '{2}'" -f $secretIndex,$secrets.Count,$secName) 'INFO'
    # Update progress bar
    try{
      $importStatusText = "{0}/{1} ({2}%) - {3}" -f $secretIndex,$secrets.Count,[int](($secretIndex/$secrets.Count)*100),$secName
      Update-ProgressBar -Current $secretIndex -Total $secrets.Count -StatusText $importStatusText
    }catch{}
    
    # =====================================================
    # DETERMINE TARGET FOLDER
    # =====================================================
    $targetFolderIdForSecret = $TargetFolderId
    if($targetFolderIdForSecret -le 0){ $targetFolderIdForSecret = $TargetRootFolderId }
    
    if($UseFolderTree){
      $srcFolderPath = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
      
      if(-not [string]::IsNullOrWhiteSpace($srcFolderPath)){
        try{
          $targetFolderIdForSecret = Ensure-TargetFolderForSourcePath `
            -TgtApiBase $TgtApiBase `
            -TgtTok (Get-TgtTok) `
            -RootFolderId $TargetRootFolderId `
            -SourceFolderPath $srcFolderPath `
            -DryRun $DryRun `
            -DisableInheritPermissions ([bool]$DisableInheritPermissions)
        }
        catch{
          Write-Log ("IMPORT: Could not create folder tree for '{0}': {1}. SKIPPING secret (will not place in wrong folder)." -f $secName,$_.Exception.Message) 'ERROR'
          $skipped++
          continue
        }
      }
    }
    
    if($targetFolderIdForSecret -le 0){
      Write-Log ("IMPORT: No valid target folder for '{0}'. Skipping." -f $secName) 'WARN'
      $skipped++
      continue
    }
    
    # =====================================================
    # RESOLVE TEMPLATE ID
    # =====================================================
    $srcTemplateId = Get-PropValue $sec @('SecretTypeId','secretTypeId','SecretTemplateId','secretTemplateId') $null
    $srcTemplateName = [string](Get-PropValue $sec @('SecretTypeName','secretTypeName','templateName','TemplateName') $null)
    $tgtTemplateId = $null
    
    if($SecretTypeMapByName -and $tgtTemplateNameIndex -and -not [string]::IsNullOrWhiteSpace($srcTemplateName)){
      $key = $srcTemplateName.ToLowerInvariant()
      if($tgtTemplateNameIndex.ContainsKey($key)){
        $tgtTemplateId = [int]$tgtTemplateNameIndex[$key]
      }
    }
    
    if($tgtTemplateId -eq $null -and $srcTemplateId -ne $null){
      $tgtTemplateId = [int]$srcTemplateId
    }
    
    if($tgtTemplateId -eq $null -or $tgtTemplateId -le 0){
      Write-Log ("IMPORT: No valid template for '{0}'. Skipping." -f $secName) 'WARN'
      $skipped++
      continue
    }

    # =====================================================
    # DEFINE FOLDER CACHE KEY (MUST BE BEFORE DUPLICATE CHECK)
    # =====================================================
    $folderCacheKey = [string]$targetFolderIdForSecret

        # =====================================================
    # CHECK FOR EXISTING SECRET (DUPLICATE CHECK)
    # =====================================================
    $existingSecretId = 0
    $skipThisSecret = $false
    $skipPermsForSkippedSecret = $false
    $isUpdateMode = $false
    
    # Get or build the folder's secret index (cached)
    $folderCacheKey = [string]$targetFolderIdForSecret
    if(-not $folderSecretIndexCache.ContainsKey($folderCacheKey)){
      $folderSecretIndexCache[$folderCacheKey] = Get-SecretNameIndexForFolder `
        -apiBase $TgtApiBase `
        -tok (Get-TgtTok) `
        -folderId $targetFolderIdForSecret
    }
    $secretNameIndex = $folderSecretIndexCache[$folderCacheKey]
    
    # Check for existing secret - try multiple name formats
    # The secret name might have leading/trailing spaces
    $namesToTry = @(
      $secName.Trim().ToLowerInvariant(),           # Trimmed lowercase
      $secName.ToLowerInvariant(),                   # Original lowercase (preserves spaces)
      $secName.Trim(),                               # Trimmed original case
      $secName                                       # Original
    ) | Select-Object -Unique
    
    foreach($nameVariant in $namesToTry){
      $lookupKey = $nameVariant.ToLowerInvariant()
      if($secretNameIndex.ContainsKey($lookupKey)){
        $existingSecretId = [int]$secretNameIndex[$lookupKey]
        Write-Log ("DUPLICATE CHECK: Found match using key '{0}'" -f $lookupKey) 'DEBUG'
        break
      }
    }
    
    # FALLBACK: If not found in cached index, do a targeted search by name in the folder.
    # The bulk /secrets listing may not return all secrets due to API visibility limits,
    # so this fallback is the safety net that prevents accidental duplicate CREATE attempts.
    if($existingSecretId -le 0){
      try{
        $searchQ = @{
          'filter.folderId'    = $targetFolderIdForSecret
          'filter.searchText'  = $secName.Trim()
          'filter.pageSize'    = 50
        }
        $searchResp = SS $TgtApiBase GET 'secrets' (Get-TgtTok) $null $searchQ
        $searchRecs = @(Get-Records $searchResp)
        foreach($sr in $searchRecs){
          $srName = $null
          foreach($nk in @('name','Name','secretName','SecretName')){
            if($sr.PSObject.Properties.Name -contains $nk){
              $c = [string]$sr.$nk
              if(-not [string]::IsNullOrWhiteSpace($c)){ $srName = $c; break }
            }
          }
          if($srName -and $srName.Trim().ToLowerInvariant() -eq $secName.Trim().ToLowerInvariant()){
            $srId = $null
            foreach($ik in @('id','Id','secretId','SecretId')){
              if($sr.PSObject.Properties.Name -contains $ik){
                try{ $srId = [int]$sr.$ik; if($srId -gt 0){ break } } catch {}
              }
            }
            if($srId -gt 0){
              $existingSecretId = $srId
              # Add to cache so future lookups within this run don't miss it
              $secretNameIndex[$secName.Trim().ToLowerInvariant()] = $srId
              Write-Log ("DUPLICATE CHECK FALLBACK: Found '{0}' via searchText (id={1})" -f $secName,$srId) 'INFO'
              break
            }
          }
        }
      } catch {
        Write-Log ("DUPLICATE CHECK FALLBACK: searchText query failed for '{0}': {1}" -f $secName,$_.Exception.Message) 'WARN'
      }
    }
    
    Write-Log ("DUPLICATE CHECK: Secret '{0}' in folder {1} -> existingId={2}, indexCount={3}" -f $secName,$targetFolderIdForSecret,$existingSecretId,$secretNameIndex.Count) 'DEBUG'
    # =====================================================
    # HANDLE DUPLICATES BASED ON CONFIG
    # =====================================================
    if($existingSecretId -gt 0){
      Write-Log ("IMPORT: Secret '{0}' already exists in folder {1} (existing id={2}). Action: {3}" -f $secName,$targetFolderIdForSecret,$existingSecretId,$dupAction) 'INFO'
      
      switch($dupAction.Trim().ToLowerInvariant()){
        "skip" {
          Write-Log ("[SKIP] Secret '{0}' already exists (id={1}) - skipping (no permission/ACL changes)" -f $secName,$existingSecretId) 'INFO'
          $skipped++
          $skipThisSecret = $true
          $skipPermsForSkippedSecret = $true
        }
        "update" {
          Write-Log ("[UPDATE MODE] Secret '{0}' exists (id={1}) - will update if different" -f $secName,$existingSecretId) 'INFO'
          $isUpdateMode = $true
        }
        "createnew" {
          Write-Log ("[CREATE-NEW] Secret '{0}' exists (id={1}) - creating duplicate as configured" -f $secName,$existingSecretId) 'INFO'
          $isUpdateMode = $false
        }
        default {
          Write-Log ("[SKIP] Secret '{0}' already exists (id={1}) - skipping (no permission/ACL changes)" -f $secName,$existingSecretId) 'INFO'
          $skipped++
          $skipThisSecret = $true
          $skipPermsForSkippedSecret = $true
        }
      }
    }
    
    # If skipping secret creation/update, jump to permission application
    # (unless Skip mode requested a true skip with no ACL processing)
    if($skipThisSecret){
      if($skipPermsForSkippedSecret){
        # True skip: no permission/ACL processing at all - advance to next secret
        continue
      }
      # Handle dry-run for skip mode
      if($DryRun){
        Write-Log "[DRY-RUN] Would SKIP secret modification but apply permissions to existing secret id=$existingSecretId" 'INFO'
        if($CopySecretAcls){
          $secPerms = @(Get-PropValue $sec @('SecretPermissions','secretPermissions') @())
          if($secPerms.Count -gt 0){
            $permChanges = Count-SecretPermissionChanges -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -SecretId $existingSecretId -PermissionsArray $secPerms -RemapPrincipals $RemapPrincipals
            
            $totalCount = $permChanges.Add + $permChanges.Skip + $permChanges.Error
            Write-Log ("[DRY-RUN]   - Secret ACLs: {0} total ({1} would add, {2} already exist, {3} skip/error)" -f `
              $totalCount, $permChanges.Add, $permChanges.Skip, $permChanges.Error) 'INFO'
            $totalSecretPermsApplied += $totalCount
          }
        }
        if($CopyFolderAcls -and $targetFolderIdForSecret -gt 0){
          $folderPerms = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
          $srcFolderPathForAcl = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
          # In dry-run with folder tree, subfolder won't exist yet so treat as new folder
          $isNewFolder = ($UseFolderTree -and -not [string]::IsNullOrWhiteSpace($srcFolderPathForAcl))
          $folderAclKey = if($isNewFolder){ "new|$($srcFolderPathForAcl.ToLowerInvariant())" } else { "existing|$targetFolderIdForSecret" }
          if($folderPerms.Count -gt 0 -and -not $script:ImportRunFoldersWithPermsApplied.Contains($folderAclKey)){
            $folderPermChanges = Count-FolderPermissionChanges -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -FolderId $targetFolderIdForSecret -PermissionsArray $folderPerms -RemapPrincipals $RemapPrincipals `
              -AssumeNewFolder $isNewFolder
            
            $folderTotalCount = $folderPermChanges.Add + $folderPermChanges.Skip + $folderPermChanges.Error
            $folderLabel = if($isNewFolder){ "new folder '$srcFolderPathForAcl'" } else { "folder $targetFolderIdForSecret" }
            Write-Log ("[DRY-RUN]   - Folder ACLs for {0}: {1} total ({2} would add, {3} already exist, {4} skip/error)" -f `
              $folderLabel, $folderTotalCount, $folderPermChanges.Add, $folderPermChanges.Skip, $folderPermChanges.Error) 'INFO'
            
            [void]$script:ImportRunFoldersWithPermsApplied.Add($folderAclKey)
            $totalFolderPermsApplied += $folderPermChanges.Add
          }
          # Also report parent folder permissions in dry-run (per-principal tracking)
          if($UseFolderTree -and -not [string]::IsNullOrWhiteSpace($srcFolderPathForAcl)){
            $parentSegmentsDR = $srcFolderPathForAcl.TrimStart('\','/').Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
            if($parentSegmentsDR.Count -gt 1){
              for($pi = 0; $pi -lt ($parentSegmentsDR.Count - 1); $pi++){
                $pSegDR = $parentSegmentsDR[$pi]
                if($folderPerms.Count -gt 0){
                  $newCount = 0
                  foreach($fpDR in $folderPerms){
                    $pGrpN = [string](Get-PropValue $fpDR @('groupName','GroupName') '')
                    $pUsrN = [string](Get-PropValue $fpDR @('userName','UserName','knownAs','KnownAs') '')
                    $drKey = "dr|$pSegDR|g:$($pGrpN.ToLowerInvariant())|u:$($pUsrN.ToLowerInvariant())"
                    if(-not $script:ParentFolderPrincipalTracker.Contains($drKey)){
                      $newCount++
                      [void]$script:ParentFolderPrincipalTracker.Add($drKey)
                    }
                  }
                  if($newCount -gt 0){
                    Write-Log ("[DRY-RUN]   - Parent Folder ACLs for '{0}': {1} would add" -f $pSegDR,$newCount) 'INFO'
                    $totalFolderPermsApplied += $newCount
                  }
                }
              }
            }
          }
        }
        continue
      }
      
      # Still apply permissions for the existing secret
      if($CopySecretAcls -and $existingSecretId -gt 0){
        $secPerms = @(Get-PropValue $sec @('SecretPermissions','secretPermissions') @())
        if($secPerms.Count -gt 0){
          $permSuccess = 0; $permFailed = 0
          foreach($perm in $secPerms){
            try{
              $permObj = Normalize-PermissionObject $perm
              $ok = Add-SecretPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                    -SecretId $existingSecretId -Perm $permObj -RemapPrincipals $RemapPrincipals
              if($ok){ $permSuccess++ } else { $permFailed++ }
            } catch {
              Write-Log ("PERM ERROR: exception while applying ACL to secretId={0}: {1}" -f $existingSecretId,$_.Exception.Message) 'WARN'
              $permFailed++
            }
          }
          if($permFailed -gt 0){
            Write-Log ("IMPORT: ACLs for '{0}': {1} applied, {2} failed" -f $secName,$permSuccess,$permFailed) 'WARN'
          }
          $totalSecretPermsApplied += $permSuccess
        }
      }
      
      # Apply folder permissions if requested (only once per folder)
      if($CopyFolderAcls -and $targetFolderIdForSecret -gt 0){
        $folderPermKey = "existing|$targetFolderIdForSecret"
        if(-not $script:ImportRunFoldersWithPermsApplied.Contains($folderPermKey)){
          $folderPerms = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
          if($folderPerms.Count -gt 0){
            $fpSuccess = 0; $fpFailed = 0
            foreach($fp in $folderPerms){
              try{
                $ok = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                      -FolderId $targetFolderIdForSecret -Perm $fp -RemapPrincipals $RemapPrincipals
                if($ok){ $fpSuccess++ } else { $fpFailed++ }
              } catch {
                Write-Log ("FOLDER PERM ERROR: exception while applying to folderId={0}: {1}" -f $targetFolderIdForSecret,$_.Exception.Message) 'WARN'
                $fpFailed++
              }
            }
            [void]$script:ImportRunFoldersWithPermsApplied.Add($folderPermKey)
            if($fpSuccess -gt 0 -or $fpFailed -gt 0){
              Write-Log ("IMPORT: Folder ACLs for folderId={0}: {1} applied, {2} failed" -f $targetFolderIdForSecret,$fpSuccess,$fpFailed) 'INFO'
            }
            $totalFolderPermsApplied += $fpSuccess
          }
        }
        # Also apply folder permissions to parent folders in the path (e.g., CA_Secrets)
        # Uses per-principal tracking to accumulate permissions from ALL child folders
        if($UseFolderTree){
          $srcFolderPathForParents = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
          if(-not [string]::IsNullOrWhiteSpace($srcFolderPathForParents)){
            $parentSegments = $srcFolderPathForParents.TrimStart('\','/').Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
            if($parentSegments.Count -gt 1){
              $parentId = $TargetRootFolderId
              for($pi = 0; $pi -lt ($parentSegments.Count - 1); $pi++){
                $pSeg = $parentSegments[$pi]
                $pCacheKey = "$parentId|$($pSeg.ToLowerInvariant())"
                if($script:CreatedFolderCache.ContainsKey($pCacheKey)){
                  $parentFolderId = $script:CreatedFolderCache[$pCacheKey]
                  $folderPerms2 = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
                  if($folderPerms2.Count -gt 0){
                    $pfpSuccess = 0; $pfpFailed = 0; $pfpSkipped = 0
                    foreach($fp2 in $folderPerms2){
                      # Build principal key to track what's already been applied to this parent
                      $pGrpName = [string](Get-PropValue $fp2 @('groupName','GroupName') '')
                      $pUsrName = [string](Get-PropValue $fp2 @('userName','UserName','knownAs','KnownAs') '')
                      $principalKey = "$parentFolderId|g:$($pGrpName.ToLowerInvariant())|u:$($pUsrName.ToLowerInvariant())"
                      if($script:ParentFolderPrincipalTracker.Contains($principalKey)){
                        $pfpSkipped++; continue
                      }
                      try{
                        $ok2 = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                              -FolderId $parentFolderId -Perm $fp2 -RemapPrincipals $RemapPrincipals
                        if($ok2){ $pfpSuccess++ } else { $pfpFailed++ }
                      } catch { $pfpFailed++ }
                      [void]$script:ParentFolderPrincipalTracker.Add($principalKey)
                    }
                    if($pfpSuccess -gt 0 -or $pfpFailed -gt 0){
                      Write-Log ("IMPORT: Parent Folder ACLs for '{0}' (folderId={1}): {2} applied, {3} failed, {4} already tracked" -f $pSeg,$parentFolderId,$pfpSuccess,$pfpFailed,$pfpSkipped) 'INFO'
                    }
                    $totalFolderPermsApplied += $pfpSuccess
                  }
                  $parentId = $parentFolderId
                } else { break }
              }
            }
          }
        }
      }
      
      # Done with this skipped secret - move to next
      continue
    }
    
    # =====================================================
    # BUILD ITEMS ARRAY
    # =====================================================
    $exportItems = @(Get-PropValue $sec @('Items','items','fields','Fields') @())
    
    # Decrypt password fields if requested
    if($DecryptPasswords){
      foreach($item in $exportItems){
        $slug = [string](Get-PropValue $item @('slug','Slug') $null)
        $val = Get-PropValue $item @('value','Value','itemValue','ItemValue') $null
        
        if(-not [string]::IsNullOrWhiteSpace($slug) -and -not [string]::IsNullOrWhiteSpace([string]$val)){
          $slugLower = $slug.ToLowerInvariant()
          if($slugLower -match 'password|pass|pwd'){
            $decryptedVal = Decrypt-PasswordValue -encryptedValue ([string]$val)
            if($decryptedVal -ne $val){
              $item | Add-Member -NotePropertyName value -NotePropertyValue $decryptedVal -Force
              Write-Log ("IMPORT: Decrypted password field for secret '{0}', slug='{1}'" -f $secName,$slug) 'DEBUG'
            }
          }
        }
      }
    }
    else {
      # Auto-detect DPAPI-encrypted password fields even when DecryptPasswords is not checked
      foreach($item in $exportItems){
        $slug = [string](Get-PropValue $item @('slug','Slug') $null)
        $val = [string](Get-PropValue $item @('value','Value','itemValue','ItemValue') $null)
        
        if(-not [string]::IsNullOrWhiteSpace($slug) -and -not [string]::IsNullOrWhiteSpace($val)){
          $slugLower = $slug.ToLowerInvariant()
          if(($slugLower -match 'password|pass|pwd') -and $val -match '^01000000d08c9ddf'){
            Write-Log ("IMPORT: Auto-detected DPAPI-encrypted password for secret '{0}', slug='{1}' - attempting decrypt" -f $secName,$slug) 'WARN'
            $decryptedVal = Decrypt-PasswordValue -encryptedValue $val
            if($decryptedVal -ne $val){
              $item | Add-Member -NotePropertyName value -NotePropertyValue $decryptedVal -Force
              Write-Log ("IMPORT: Auto-decrypted password field for secret '{0}', slug='{1}'" -f $secName,$slug) 'INFO'
            } else {
              Write-Log ("IMPORT: DPAPI decryption failed for secret '{0}', slug='{1}' - password was encrypted on a different machine. Check 'Decrypt passwords on import' or re-export from the original machine." -f $secName,$slug) 'ERROR'
            }
          }
        }
      }
    }
    
    $builtItems = $null
    
    try{
      $builtResult = Build-SecretCreateItems `
        -TgtApiBase $TgtApiBase `
        -TgtTok (Get-TgtTok) `
        -TemplateId $tgtTemplateId `
        -ExportItems @($exportItems) `
        -FallbackSecretName $secName
      
      if($builtResult.Success){
        $builtItems = $builtResult.Items
        
        # DIAGNOSTIC: Log items count
        $builtItemsCount = if($builtItems){ @($builtItems).Count } else { 0 }
        Write-Log ("IMPORT: Built {0} items for secret '{1}' from {2} export items" -f $builtItemsCount,$secName,@($exportItems).Count) 'DEBUG'
        
        if($builtResult.FilledPlaceholders -and $builtResult.FilledPlaceholders.Count -gt 0){
          Write-Log ("IMPORT: Secret '{0}' has {1} placeholder fields that need review" -f $secName,$builtResult.FilledPlaceholders.Count) 'WARN'
        }
      } else {
        Write-Log ("[ERROR] Cannot build items for '{0}': Missing fields: {1}" -f $secName,($builtResult.MissingFields -join ', ')) 'ERROR'
        $skipped++
        continue
      }
    }
    catch{
      Write-Log ("[ERROR] Cannot build items for '{0}': {1}" -f $secName,$_.Exception.Message) 'ERROR'
      $skipped++
      continue
    }
        
    # =====================================================
    # DRY RUN MODE
    # =====================================================
    if($DryRun){
      $folderDisplay = "folder id=$targetFolderIdForSecret"
      
      if($isUpdateMode){
        Write-Log ("[DRY-RUN] Would UPDATE secret '{0}' (existing id={1}) in {2}" -f $secName,$existingSecretId,$folderDisplay) 'INFO'
        Write-Log ("[DRY-RUN]   - Would update {0} fields" -f @($builtItems).Count) 'INFO'
        $updated++
      } 
      else {
        Write-Log ("[DRY-RUN] Would CREATE secret '{0}' in {1} using template {2}" -f $secName,$folderDisplay,$tgtTemplateId) 'INFO'
        Write-Log ("[DRY-RUN]   - Would create with {0} fields" -f @($builtItems).Count) 'INFO'
        $created++
      }
      
      if($CopySecretAcls){
        $secPerms = @(Get-PropValue $sec @('SecretPermissions','secretPermissions') @())
        if($secPerms.Count -gt 0){
          # Use the secret ID that would receive permissions (existing or would-be-created)
          $targetSecretIdForPermCheck = if($isUpdateMode){ $existingSecretId } else { 0 }
          
          if($targetSecretIdForPermCheck -gt 0){
            # For existing secrets, we can check current permissions
            $permChanges = Count-SecretPermissionChanges -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -SecretId $targetSecretIdForPermCheck -PermissionsArray $secPerms -RemapPrincipals $RemapPrincipals
            
            $totalCount = $permChanges.Add + $permChanges.Skip + $permChanges.Error
            Write-Log ("[DRY-RUN]   - Secret ACLs: {0} total ({1} would add, {2} already exist, {3} skip/error)" -f `
              $totalCount, $permChanges.Add, $permChanges.Skip, $permChanges.Error) 'INFO'
            $totalSecretPermsApplied += $totalCount
          } else {
            # For new secrets, count valid permissions that would be added
            # (can't check existing since secret doesn't exist yet, but can validate principals)
            $validCount = 0
            $skipCount = 0
            
            # Load caches for validation
            if($RemapPrincipals){
              Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
              Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
            } else {
              Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
              Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
            }
            
            foreach($perm in $secPerms){
              try{
                $p = Normalize-PermissionObject $perm
                if($p.Count -eq 0){ $skipCount++; continue }
                
                $srcUserId = 0; $srcGroupId = 0
                $srcUserName = $null; $srcGroupName = $null
                $srcKnownAs = $null; $srcDomainName = $null
                
                # Use direct hashtable key lookup (Get-PropValue/Has-Prop don't work with hashtables)
                foreach($k in @($p.Keys)){
                  $kl = $k.ToLowerInvariant()
                  switch($kl){
                    'userid'    { try{ if($p[$k] -ne $null){ $srcUserId = [int]$p[$k] } } catch {} }
                    'groupid'   { try{ if($p[$k] -ne $null){ $srcGroupId = [int]$p[$k] } } catch {} }
                    'username'  { if($p[$k] -ne $null){ $srcUserName = [string]$p[$k] } }
                    'groupname' { if($p[$k] -ne $null){ $srcGroupName = [string]$p[$k] } }
                    'knownas'   { if($p[$k] -ne $null){ $srcKnownAs = [string]$p[$k] } }
                    'domainname' { if($p[$k] -ne $null){ $srcDomainName = [string]$p[$k] } }
                  }
                }
                
                $canResolve = $false
                
                if($RemapPrincipals){
                  if($srcUserId -gt 0 -and -not [string]::IsNullOrWhiteSpace($srcUserName)){
                    $tid = Get-TargetUserIdByName -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -UserName $srcUserName -KnownAs $srcKnownAs -DomainName $srcDomainName
                    if($tid -gt 0){ $canResolve = $true }
                  } elseif($srcGroupId -gt 0 -and -not [string]::IsNullOrWhiteSpace($srcGroupName)){
                    $tgid = Get-TargetGroupIdByName -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -GroupName $srcGroupName -KnownAs $srcKnownAs -DomainName $srcDomainName
                    if($tgid -gt 0){ $canResolve = $true }
                  }
                } else {
                  # Direct mode
                  if($srcUserId -gt 0){
                    $userExists = $false
                    foreach($uid in $script:TgtUserNameToIdCache.Values){
                      if([int]$uid -eq $srcUserId){ $userExists = $true; break }
                    }
                    $canResolve = $userExists
                  } elseif($srcGroupId -gt 0){
                    $groupExists = $false
                    foreach($gid in $script:TgtGroupNameToIdCache.Values){
                      if([int]$gid -eq $srcGroupId){ $groupExists = $true; break }
                    }
                    $canResolve = $groupExists
                  }
                }
                
                if($canResolve){ $validCount++ } else { $skipCount++ }
              } catch {
                $skipCount++
              }
            }
            
            Write-Log ("[DRY-RUN]   - Secret ACLs: {0} total ({1} would add to new secret, {2} skip/error)" -f `
              $secPerms.Count, $validCount, $skipCount) 'INFO'
            $totalSecretPermsApplied += $validCount
          }
        }
      }
      
      if($CopyFolderAcls -and $targetFolderIdForSecret -gt 0){
        $srcFolderPathForAcl2 = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
        $isNewFolder2 = ($UseFolderTree -and -not [string]::IsNullOrWhiteSpace($srcFolderPathForAcl2))
        $folderAclKey2 = if($isNewFolder2){ "new|$($srcFolderPathForAcl2.ToLowerInvariant())" } else { "existing|$targetFolderIdForSecret" }
        if(-not $script:ImportRunFoldersWithPermsApplied.Contains($folderAclKey2)){
          $folderPerms = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
          if($folderPerms.Count -gt 0){
            $folderPermChanges = Count-FolderPermissionChanges -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -FolderId $targetFolderIdForSecret -PermissionsArray $folderPerms -RemapPrincipals $RemapPrincipals `
              -AssumeNewFolder $isNewFolder2
            
            $folderTotalCount = $folderPermChanges.Add + $folderPermChanges.Skip + $folderPermChanges.Error
            $folderLabel2 = if($isNewFolder2){ "new folder '$srcFolderPathForAcl2'" } else { "folder $targetFolderIdForSecret" }
            Write-Log ("[DRY-RUN]   - Folder ACLs for {0}: {1} total ({2} would add, {3} already exist, {4} skip/error)" -f `
              $folderLabel2, $folderTotalCount, $folderPermChanges.Add, $folderPermChanges.Skip, $folderPermChanges.Error) 'INFO'
            
            [void]$script:ImportRunFoldersWithPermsApplied.Add($folderAclKey2)
            $totalFolderPermsApplied += $folderPermChanges.Add
          }
        }
        # Also report parent folder permissions in dry-run (per-principal tracking)
        if($isNewFolder2 -and -not [string]::IsNullOrWhiteSpace($srcFolderPathForAcl2)){
          $parentSegmentsDR2 = $srcFolderPathForAcl2.TrimStart('\','/').Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
          if($parentSegmentsDR2.Count -gt 1){
            $folderPermsForParent = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
            for($pi = 0; $pi -lt ($parentSegmentsDR2.Count - 1); $pi++){
              $pSegDR2 = $parentSegmentsDR2[$pi]
              if($folderPermsForParent.Count -gt 0){
                $newCount2 = 0
                foreach($fpDR2 in $folderPermsForParent){
                  $pGrpN2 = [string](Get-PropValue $fpDR2 @('groupName','GroupName') '')
                  $pUsrN2 = [string](Get-PropValue $fpDR2 @('userName','UserName','knownAs','KnownAs') '')
                  $drKey2 = "dr|$pSegDR2|g:$($pGrpN2.ToLowerInvariant())|u:$($pUsrN2.ToLowerInvariant())"
                  if(-not $script:ParentFolderPrincipalTracker.Contains($drKey2)){
                    $newCount2++
                    [void]$script:ParentFolderPrincipalTracker.Add($drKey2)
                  }
                }
                if($newCount2 -gt 0){
                  Write-Log ("[DRY-RUN]   - Parent Folder ACLs for '{0}': {1} would add" -f $pSegDR2,$newCount2) 'INFO'
                  $totalFolderPermsApplied += $newCount2
                }
              }
            }
          }
        }
      }
      
      if($CopyAttachments){
        $attachCount = 0
        foreach($item in @($exportItems)){
          $isFile = $false
          try{ $isFile = [bool](Get-PropValue $item @('isFile','IsFile') $false) } catch {}
          if($isFile){
            $filePath = Get-PropValue $item @('fileExportPath','FileExportPath') $null
            if(-not [string]::IsNullOrWhiteSpace([string]$filePath) -and (Test-Path $filePath)){
              $attachCount++
            }
          }
        }
        if($attachCount -gt 0){
          Write-Log ("[DRY-RUN]   - Would upload {0} attachments" -f $attachCount) 'INFO'
        }
      }
      
      continue
    }
    
    # =====================================================
    # UPDATE EXISTING SECRET
    # =====================================================
    if($isUpdateMode -and $existingSecretId -gt 0){
      try{
        Write-Log ("IMPORT: Updating existing secret '{0}' (id={1})..." -f $secName,$existingSecretId) 'INFO'
        
        # Get current secret to compare
        $currentSecret = $null
        try{
          $currentSecret = SS $TgtApiBase GET ("secrets/{0}" -f $existingSecretId) (Get-TgtTok) $null $null
        }
        catch{
          Write-Log ("IMPORT: Could not fetch existing secret {0} for comparison: {1}" -f $existingSecretId,$_.Exception.Message) 'WARN'
        }
        
        # Build fieldId -> slug mapping from template
        $fieldIdToSlug = @{}
        try{
          $templateFields = @(Get-PropValue (SS $TgtApiBase GET ("secret-templates/{0}" -f $tgtTemplateId) (Get-TgtTok) $null $null) @('fields','Fields') @())
          foreach($tf in $templateFields){
            $tfId = Get-PropValue $tf @('secretTemplateFieldId','SecretTemplateFieldId','fieldId','FieldId') $null
            $tfSlug = [string](Get-PropValue $tf @('slug','Slug','fieldSlugName','FieldSlugName') '')
            if($tfId -ne $null -and -not [string]::IsNullOrWhiteSpace($tfSlug)){
              $fieldIdToSlug[[int]$tfId] = $tfSlug
            }
          }
        }
        catch{
          Write-Log ("IMPORT: Could not load template {0} for field mapping: {1}" -f $tgtTemplateId,$_.Exception.Message) 'WARN'
        }
        
        # Compare and update fields
        $fieldUpdateCount = 0
        $fieldSkippedCount = 0
        $fieldNoIdCount = 0
        
        Write-Log ("IMPORT: Comparing {0} built items for secret '{1}' (id={2})" -f @($builtItems).Count,$secName,$existingSecretId) 'DEBUG'
        
        foreach($item in @($builtItems)){
          $fieldId = Get-PropValue $item @('fieldId','secretTemplateFieldId') $null
          $newValue = [string](Get-PropValue $item @('itemValue','value') "")
          
          # SKIP file fields - they cannot be updated via JSON PUT; handled separately by the attachment upload block
          if([bool](Get-PropValue $item @('IsFile','isFile') $false)){
            $fieldSkippedCount++
            Write-Log ("IMPORT: Skipping file field id={0} (will be handled by attachment upload)" -f $fieldId) 'DEBUG'
            continue
          }

          if($fieldId -eq $null -or [int]$fieldId -le 0){ 
            $fieldNoIdCount++
            Write-Log "IMPORT: Skipping item with invalid fieldId (null or <= 0)" 'DEBUG'
            continue 
          }
          
          # Get the field slug from our mapping
          $fieldSlug = $null
          if($fieldIdToSlug.ContainsKey([int]$fieldId)){
            $fieldSlug = $fieldIdToSlug[[int]$fieldId]
          }
          
          if([string]::IsNullOrWhiteSpace($fieldSlug)){
            Write-Log ("IMPORT: Skipping field {0} - no slug mapping found" -f $fieldId) 'DEBUG'
            $fieldSkippedCount++
            continue
          }
          
          # Check if value is different from current
          $currentValue = ""
          if($currentSecret -ne $null){
            $currentItems = @(Get-PropValue $currentSecret @('items','Items','fields','Fields') @())
            foreach($ci in $currentItems){
              $ciFieldId = Get-PropValue $ci @('fieldId','secretTemplateFieldId') $null
              if($ciFieldId -ne $null -and [int]$ciFieldId -eq [int]$fieldId){
                $currentValue = [string](Get-PropValue $ci @('itemValue','value','Value') "")
                break
              }
            }
          }
          
          # Skip if values are the same
          if($newValue -eq $currentValue){
            $fieldSkippedCount++
            continue
          }
          
          # Update the field using slug and proper body format
          try{
            $fieldBody = @{ value = $newValue }
            SS $TgtApiBase PUT ("secrets/{0}/fields/{1}" -f $existingSecretId,$fieldSlug) (Get-TgtTok) $fieldBody $null | Out-Null
            $fieldUpdateCount++
            Write-Log ("IMPORT: Updated field '{0}' (id={1}) for secret '{2}'" -f $fieldSlug,$fieldId,$secName) 'DEBUG'
          }
          catch{
            Write-Log ("IMPORT: Failed to update field '{0}' (id={1}): {2}" -f $fieldSlug,$fieldId,$_.Exception.Message) 'WARN'
          }
        }
        
        if($fieldUpdateCount -gt 0){
          Write-Log ("[OK] UPDATED secret '{0}' (id={1}) - {2} fields changed, {3} unchanged" -f $secName,$existingSecretId,$fieldUpdateCount,$fieldSkippedCount) 'INFO'
          $updated++
          
          # Track for potential cleanup
          try{
            $script:ImportRunCreatedSecretIds.Add($existingSecretId) | Out-Null
            $script:ImportRunCreatedSecretsById[[string]$existingSecretId] = @{ id=$existingSecretId; name=$secName; folderId=$targetFolderIdForSecret }
          } catch {}
        }
        else{
          Write-Log ("[NO CHANGES] Secret '{0}' (id={1}) - {2} fields unchanged, {3} had no fieldId" -f $secName,$existingSecretId,$fieldSkippedCount,$fieldNoIdCount) 'INFO'
          $skipped++
        }
        # Apply permissions if requested
      if($CopySecretAcls){
    $secPerms = @(Get-PropValue $sec @('SecretPermissions','secretPermissions') @())
    if($secPerms.Count -gt 0){
    $permSuccess = 0; $permFailed  = 0
    foreach($perm in $secPerms){
      try{
        $permObj = Normalize-PermissionObject $perm
        $ok = Add-SecretPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -SecretId $existingSecretId -Perm $permObj -RemapPrincipals $RemapPrincipals
        if($ok){ $permSuccess++ } else { $permFailed++ }
      } catch {
        Write-Log ("PERM ERROR: exception while applying ACL to secretId={0}: {1}" -f $existingSecretId,$_.Exception.Message) 'WARN'
        $permFailed++
      }
    }
    if($permFailed -gt 0){
      Write-Log ("IMPORT: ACLs for '{0}': {1} applied, {2} failed" -f $secName,$permSuccess,$permFailed) 'WARN'
    }
    $totalSecretPermsApplied += $permSuccess
  }
}

        # Apply folder permissions if requested (only once per folder)
        if($CopyFolderAcls -and $targetFolderIdForSecret -gt 0){
          $folderPermKey = "existing|$targetFolderIdForSecret"
          if(-not $script:ImportRunFoldersWithPermsApplied.Contains($folderPermKey)){
            $folderPerms = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
            if($folderPerms.Count -gt 0){
              $fpSuccess = 0; $fpFailed = 0
              foreach($fp in $folderPerms){
                try{
                  $ok = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                        -FolderId $targetFolderIdForSecret -Perm $fp -RemapPrincipals $RemapPrincipals
                  if($ok){ $fpSuccess++ } else { $fpFailed++ }
                } catch {
                  Write-Log ("FOLDER PERM ERROR: exception while applying to folderId={0}: {1}" -f $targetFolderIdForSecret,$_.Exception.Message) 'WARN'
                  $fpFailed++
                }
              }
              [void]$script:ImportRunFoldersWithPermsApplied.Add($folderPermKey)
              if($fpSuccess -gt 0 -or $fpFailed -gt 0){
                Write-Log ("IMPORT: Folder ACLs for folderId={0}: {1} applied, {2} failed" -f $targetFolderIdForSecret,$fpSuccess,$fpFailed) 'INFO'
              }
              $totalFolderPermsApplied += $fpSuccess
            }
          }
          # Also apply folder permissions to parent folders in the path
          # Uses per-principal tracking to accumulate permissions from ALL child folders
          if($UseFolderTree){
            $srcFolderPathForParents = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
            if(-not [string]::IsNullOrWhiteSpace($srcFolderPathForParents)){
              $parentSegments = $srcFolderPathForParents.TrimStart('\','/').Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
              if($parentSegments.Count -gt 1){
                $parentId = $TargetRootFolderId
                for($pi = 0; $pi -lt ($parentSegments.Count - 1); $pi++){
                  $pSeg = $parentSegments[$pi]
                  $pCacheKey = "$parentId|$($pSeg.ToLowerInvariant())"
                  if($script:CreatedFolderCache.ContainsKey($pCacheKey)){
                    $parentFolderId = $script:CreatedFolderCache[$pCacheKey]
                    $folderPerms2 = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
                    if($folderPerms2.Count -gt 0){
                      $pfpSuccess = 0; $pfpFailed = 0; $pfpSkipped = 0
                      foreach($fp2 in $folderPerms2){
                        $pGrpName = [string](Get-PropValue $fp2 @('groupName','GroupName') '')
                        $pUsrName = [string](Get-PropValue $fp2 @('userName','UserName','knownAs','KnownAs') '')
                        $principalKey = "$parentFolderId|g:$($pGrpName.ToLowerInvariant())|u:$($pUsrName.ToLowerInvariant())"
                        if($script:ParentFolderPrincipalTracker.Contains($principalKey)){
                          $pfpSkipped++; continue
                        }
                        try{
                          $ok2 = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                                -FolderId $parentFolderId -Perm $fp2 -RemapPrincipals $RemapPrincipals
                          if($ok2){ $pfpSuccess++ } else { $pfpFailed++ }
                        } catch { $pfpFailed++ }
                        [void]$script:ParentFolderPrincipalTracker.Add($principalKey)
                      }
                      if($pfpSuccess -gt 0 -or $pfpFailed -gt 0){
                        Write-Log ("IMPORT: Parent Folder ACLs for '{0}' (folderId={1}): {2} applied, {3} failed, {4} already tracked" -f $pSeg,$parentFolderId,$pfpSuccess,$pfpFailed,$pfpSkipped) 'INFO'
                      }
                      $totalFolderPermsApplied += $pfpSuccess
                    }
                    $parentId = $parentFolderId
                  } else { break }
                }
              }
            }
          }
        }

        
# Upload attachments if requested
        if($CopyAttachments){
          foreach($item in @($exportItems)){
            $isFile = $false
            try{ $isFile = [bool](Get-PropValue $item @('isFile','IsFile') $false) } catch {}
            if($isFile){
              $filePath = Get-PropValue $item @('fileExportPath','FileExportPath') $null
              $slug = [string](Get-PropValue $item @('slug','Slug','fieldSlugName','FieldSlugName') $null)
              if([string]::IsNullOrWhiteSpace([string]$filePath)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' field '{1}' - fileExportPath is null/empty in export data" -f $secName,$slug) 'WARN'
              } elseif(-not (Test-Path $filePath)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' field '{1}' - file not found on disk: {2}" -f $secName,$slug,$filePath) 'WARN'
              } elseif([string]::IsNullOrWhiteSpace($slug)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' - slug is blank for file field" -f $secName) 'WARN'
              } else {
                try{
                  Upload-SecretFieldFile-MultipartPS51 -apiBase $TgtApiBase -tok (Get-TgtTok) -secretId $existingSecretId -fieldSlug $slug -filePath $filePath
                  Write-Log ("IMPORT: Uploaded attachment for secret '{0}' field '{1}' (secretId={2}, file={3})" -f $secName,$slug,$existingSecretId,[IO.Path]::GetFileName($filePath)) 'INFO'
                }
                catch{
                  Write-Log ("IMPORT: Failed to upload attachment for '{0}' field '{1}': {2}" -f $secName,$slug,$_.Exception.Message) 'WARN'
                }
              }
            }
          }
        }
        
        # Apply settings if requested
        if($CopySecretSettings){
          $secSettings = Get-PropValue $sec @('SecretSettings','secretSettings') $null
          if($secSettings -ne $null){
            $settingsOk = Apply-SecretSettings -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -SecretId $existingSecretId -Settings $secSettings
            if($settingsOk){ Write-Log ("IMPORT: Settings applied to '{0}'" -f $secName) 'DEBUG' }
          }
        }
        
        # Apply password history if available
        $applyHist = $true
        try { $applyHist = [bool](Get-Variable -Name 'cbApplyPwdHistory' -Scope Script -ValueOnly -ErrorAction SilentlyContinue).Checked } catch { $applyHist = $true }
        $pwdHistory = Get-PropValue $sec @('PasswordHistory','passwordHistory') $null
        if($applyHist -and $pwdHistory -ne $null -and @($pwdHistory).Count -gt 0){
          try{
            $historyOk = Apply-PasswordHistory -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -SecretId $existingSecretId -PasswordHistory $pwdHistory -SecretName $secName
            if($historyOk){ Write-Log ("IMPORT: Password history applied to '{0}'" -f $secName) 'INFO' }
          }
          catch{
            Write-Log ("IMPORT: Failed to apply password history for '{0}': {1}" -f $secName,$_.Exception.Message) 'WARN'
          }
        } elseif(-not $applyHist -and $pwdHistory -ne $null -and @($pwdHistory).Count -gt 0){
          Write-Log ("IMPORT: Password history present for '{0}' but Apply Password History is disabled - skipping" -f $secName) 'DEBUG'
        }
      }
      catch{
        if(Handle-ImportError -Context 'UPDATE' -SecretName $secName -ErrorRecord $_){ $skipped++; break }
        $skipped++
      }
      
      # CRITICAL: Move to next secret after update attempt
      continue
    }
    
    # =====================================================
    # CREATE NEW SECRET
    # =====================================================
    $payload = @{
      name = $secName
      folderId = [int]$targetFolderIdForSecret
      secretTemplateId = [int]$tgtTemplateId
      items = @($builtItems)
    }
    
    $siteId = Get-PropValue $sec @('SiteId','siteId') $null
    if($siteId -ne $null -and [int]$siteId -gt 0){
      $payload.siteId = [int]$siteId
    }

    # SkipPasswordValidation: Delinea API expects this as a BODY field, not a query param.
    # (Passing it on the query string causes Invalid request (400) on every CREATE.)
    if($SkipPasswordValidation){
      $payload.validatePasswordRequirements = $false
    }
    
    if($secretIndex -le 3){
      Write-Log ("IMPORT DEBUG: Payload for '{0}': {1}" -f $secName,($payload | ConvertTo-Json -Depth 10 -Compress)) 'DEBUG'
    }
    
    try{
      $result = SS $TgtApiBase POST 'secrets' (Get-TgtTok) $payload $null
      $newId = [int](Get-PropValue $result @('id','Id','secretId','SecretId') 0)
      
      if($newId -gt 0){
        # Track for cleanup
        try{
          $script:ImportRunCreatedSecretIds.Add($newId) | Out-Null
          $script:ImportRunCreatedSecretsById[[string]$newId] = @{ id=$newId; name=$secName; folderId=$targetFolderIdForSecret }
        } catch {}
        
        # Update the folder cache with the new secret
        if($folderSecretIndexCache.ContainsKey($folderCacheKey)){
          $folderSecretIndexCache[$folderCacheKey][$secName.Trim().ToLowerInvariant()] = $newId
          $folderSecretIndexCache[$folderCacheKey][$secName.ToLowerInvariant()] = $newId
        }
        
        Write-Log ("[OK] CREATED secret '{0}' (id={1}) in folder {2}" -f $secName,$newId,$targetFolderIdForSecret) 'INFO'
        $created++
        
        # Apply permissions
      if($CopySecretAcls){
      $secPerms = @(Get-PropValue $sec @('SecretPermissions','secretPermissions') @())
      if($secPerms.Count -gt 0){
      $permSuccess = 0; $permFailed  = 0
    foreach($perm in $secPerms){
      try{
        $permObj = Normalize-PermissionObject $perm
        $ok = Add-SecretPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -SecretId $newId -Perm $permObj -RemapPrincipals $RemapPrincipals
        if($ok){ $permSuccess++ } else { $permFailed++ }
      } catch {
        Write-Log ("PERM ERROR: exception while applying ACL to secretId={0}: {1}" -f $newId,$_.Exception.Message) 'WARN'
        $permFailed++
      }
    }
    if($permFailed -gt 0){
      Write-Log ("IMPORT: ACLs for '{0}': {1} applied, {2} failed" -f $secName,$permSuccess,$permFailed) 'WARN'
    }
    $totalSecretPermsApplied += $permSuccess
  }
}
        
        # Apply folder permissions if requested (only once per folder)
        if($CopyFolderAcls -and $targetFolderIdForSecret -gt 0){
          $folderPermKey = "existing|$targetFolderIdForSecret"
          if(-not $script:ImportRunFoldersWithPermsApplied.Contains($folderPermKey)){
            $folderPerms = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
            if($folderPerms.Count -gt 0){
              $fpSuccess = 0; $fpFailed = 0
              foreach($fp in $folderPerms){
                try{
                  $ok = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                        -FolderId $targetFolderIdForSecret -Perm $fp -RemapPrincipals $RemapPrincipals
                  if($ok){ $fpSuccess++ } else { $fpFailed++ }
                } catch {
                  Write-Log ("FOLDER PERM ERROR: exception while applying to folderId={0}: {1}" -f $targetFolderIdForSecret,$_.Exception.Message) 'WARN'
                  $fpFailed++
                }
              }
              [void]$script:ImportRunFoldersWithPermsApplied.Add($folderPermKey)
              if($fpSuccess -gt 0 -or $fpFailed -gt 0){
                Write-Log ("IMPORT: Folder ACLs for folderId={0}: {1} applied, {2} failed" -f $targetFolderIdForSecret,$fpSuccess,$fpFailed) 'INFO'
              }
              $totalFolderPermsApplied += $fpSuccess
            }
          }
          # Also apply folder permissions to parent folders in the path
          # Uses per-principal tracking to accumulate permissions from ALL child folders
          if($UseFolderTree){
            $srcFolderPathForParents = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
            if(-not [string]::IsNullOrWhiteSpace($srcFolderPathForParents)){
              $parentSegments = $srcFolderPathForParents.TrimStart('\','/').Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
              if($parentSegments.Count -gt 1){
                $parentId = $TargetRootFolderId
                for($pi = 0; $pi -lt ($parentSegments.Count - 1); $pi++){
                  $pSeg = $parentSegments[$pi]
                  $pCacheKey = "$parentId|$($pSeg.ToLowerInvariant())"
                  if($script:CreatedFolderCache.ContainsKey($pCacheKey)){
                    $parentFolderId = $script:CreatedFolderCache[$pCacheKey]
                    $folderPerms2 = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
                    if($folderPerms2.Count -gt 0){
                      $pfpSuccess = 0; $pfpFailed = 0; $pfpSkipped = 0
                      foreach($fp2 in $folderPerms2){
                        $pGrpName = [string](Get-PropValue $fp2 @('groupName','GroupName') '')
                        $pUsrName = [string](Get-PropValue $fp2 @('userName','UserName','knownAs','KnownAs') '')
                        $principalKey = "$parentFolderId|g:$($pGrpName.ToLowerInvariant())|u:$($pUsrName.ToLowerInvariant())"
                        if($script:ParentFolderPrincipalTracker.Contains($principalKey)){
                          $pfpSkipped++; continue
                        }
                        try{
                          $ok2 = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                                -FolderId $parentFolderId -Perm $fp2 -RemapPrincipals $RemapPrincipals
                          if($ok2){ $pfpSuccess++ } else { $pfpFailed++ }
                        } catch { $pfpFailed++ }
                        [void]$script:ParentFolderPrincipalTracker.Add($principalKey)
                      }
                      if($pfpSuccess -gt 0 -or $pfpFailed -gt 0){
                        Write-Log ("IMPORT: Parent Folder ACLs for '{0}' (folderId={1}): {2} applied, {3} failed, {4} already tracked" -f $pSeg,$parentFolderId,$pfpSuccess,$pfpFailed,$pfpSkipped) 'INFO'
                      }
                      $totalFolderPermsApplied += $pfpSuccess
                    }
                    $parentId = $parentFolderId
                  } else { break }
                }
              }
            }
          }
        }

        # Upload attachments
        if($CopyAttachments){
          foreach($item in @($exportItems)){
            $isFile = $false
            try{ $isFile = [bool](Get-PropValue $item @('isFile','IsFile') $false) } catch {}
            if($isFile){
              $filePath = Get-PropValue $item @('fileExportPath','FileExportPath') $null
              $slug = [string](Get-PropValue $item @('slug','Slug','fieldSlugName','FieldSlugName') $null)
              if([string]::IsNullOrWhiteSpace([string]$filePath)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' field '{1}' - fileExportPath is null/empty in export data" -f $secName,$slug) 'WARN'
              } elseif(-not (Test-Path $filePath)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' field '{1}' - file not found on disk: {2}" -f $secName,$slug,$filePath) 'WARN'
              } elseif([string]::IsNullOrWhiteSpace($slug)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' - slug is blank for file field" -f $secName) 'WARN'
              } else {
                try{
                  Upload-SecretFieldFile-MultipartPS51 -apiBase $TgtApiBase -tok (Get-TgtTok) -secretId $newId -fieldSlug $slug -filePath $filePath
                  Write-Log ("IMPORT: Uploaded attachment for secret '{0}' field '{1}' (secretId={2}, file={3})" -f $secName,$slug,$newId,[IO.Path]::GetFileName($filePath)) 'INFO'
                }
                catch{
                  Write-Log ("IMPORT: Failed to upload attachment for '{0}' field '{1}': {2}" -f $secName,$slug,$_.Exception.Message) 'WARN'
                }
              }
            }
          }
        }
        
        # Apply settings
        if($CopySecretSettings){
          $secSettings = Get-PropValue $sec @('SecretSettings','secretSettings') $null
          if($secSettings -ne $null){
            $settingsOk = Apply-SecretSettings -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -SecretId $newId -Settings $secSettings
            if($settingsOk){ Write-Log ("IMPORT: Settings applied to '{0}'" -f $secName) 'DEBUG' }
          }
        }
        
        # Apply password history if available
        $applyHist2 = $true
        try { $applyHist2 = [bool](Get-Variable -Name 'cbApplyPwdHistory' -Scope Script -ValueOnly -ErrorAction SilentlyContinue).Checked } catch { $applyHist2 = $true }
        $pwdHistory = Get-PropValue $sec @('PasswordHistory','passwordHistory') $null
        if($applyHist2 -and $pwdHistory -ne $null -and @($pwdHistory).Count -gt 0){
          try{
            $historyOk = Apply-PasswordHistory -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -SecretId $newId -PasswordHistory $pwdHistory -SecretName $secName
            if($historyOk){ Write-Log ("IMPORT: Password history applied to '{0}'" -f $secName) 'INFO' }
          }
          catch{
            Write-Log ("IMPORT: Failed to apply password history for '{0}': {1}" -f $secName,$_.Exception.Message) 'WARN'
          }
        } elseif(-not $applyHist2 -and $pwdHistory -ne $null -and @($pwdHistory).Count -gt 0){
          Write-Log ("IMPORT: Password history present for '{0}' but Apply Password History is disabled - skipping" -f $secName) 'DEBUG'
        }
      }
      else{
        Write-Log ("[WARN] Secret created but no ID returned for '{0}'" -f $secName) 'WARN'
        $created++
      }
    }
    catch{
      Write-Log ("[ERROR] CREATE FAILED '{0}': {1}" -f $secName,$_.Exception.Message) 'ERROR'
      Write-Log ("[ERROR] CREATE FAILED '{0}' details: templateId={1}, folderId={2}, itemCount={3}, siteId={4}" -f $secName,$tgtTemplateId,$targetFolderIdForSecret,@($builtItems).Count,(Get-PropValue $sec @('SiteId','siteId') 'n/a')) 'ERROR'

      # Dump the actual HTTP response body so the rejection reason from Delinea
      # (modelState, missing required field, invalid siteId, etc.) is visible.
      try{
        $__resp = $_.Exception.Response
        if($__resp){
          $__sr = New-Object IO.StreamReader($__resp.GetResponseStream())
          $__bodyTxt = $__sr.ReadToEnd()
          $__sr.Close()
          if(-not [string]::IsNullOrWhiteSpace($__bodyTxt)){
            $__bodyShort = if($__bodyTxt.Length -gt 2000){ $__bodyTxt.Substring(0,2000) + '...[truncated]' } else { $__bodyTxt }
            Write-Log ("[ERROR] CREATE FAILED '{0}' RESPONSE BODY: {1}" -f $secName,$__bodyShort) 'ERROR'
          }
        }
      } catch {}

      # Also dump the request payload (first few only, to avoid log spam) so the user
      # can correlate the rejection with the exact body that was sent.
      try{
        if($secretIndex -le 5){
          $__pj = $payload | ConvertTo-Json -Depth 10 -Compress
          if($__pj.Length -gt 1500){ $__pj = $__pj.Substring(0,1500) + '...[truncated]' }
          Write-Log ("[ERROR] CREATE FAILED '{0}' REQUEST PAYLOAD: {1}" -f $secName,$__pj) 'ERROR'
        }
      } catch {}

      # HINT: 400 Invalid Request while SkipPasswordValidation is on often means the target
      # tenant/template rejects the validatePasswordRequirements body flag. Tell the user.
      $__sc400 = 0
      try{ $__sc400 = [int]$_.Exception.Response.StatusCode.value__ } catch {}
      $__msg400 = [string]$_.Exception.Message
      if($SkipPasswordValidation -and ($__sc400 -eq 400 -or $__msg400 -match '(?i)invalid request|\(400\)|bad request')){
        Write-Log ("[HINT] '{0}' returned 400 with SkipPasswordValidation=True. This option is not supported by the target tenant - UNCHECK 'Skip Password Validation' in the Options panel and re-run." -f $secName) 'WARN'
      }

      $skipped++
      if(Handle-ImportError -Context 'CREATE' -SecretName $secName -ErrorRecord $_){ break }
    }

    # Track successfully imported secret for resume
    if($secId -ne $null -and [int]$secId -gt 0){
      [void]$importedSecretIds.Add([int]$secId)
    }

    # Periodic progress save. We write the index of the NEXT secret to process
    # ($__idx + 1) since the current iteration completed without breaking.
    if(($secretIndex - $lastProgressSave) -ge $importSaveInterval){
      $lastProgressSave = $secretIndex
      try{
        $progressObj = @{
          ResumeFromIndex   = ($__idx + 1)
          ImportedSecretIds = @($importedSecretIds)
          LastIndex         = $secretIndex
          Total             = $secrets.Count
          Timestamp         = (Get-Date -Format 'o')
        }
        ($progressObj | ConvertTo-Json -Depth 5) | Set-Content -Path $importProgressFile -Encoding UTF8
        Write-Log ("IMPORT: Progress saved - {0}/{1} secrets processed (next resume index={2})" -f $secretIndex,$secrets.Count,($__idx + 1)) 'INFO'
      }catch{}
    }
  }

  # Save final progress
  try{
    if($script:ImportCancelled){
      # $script:ImportResumeNextIndex points at the secret that should be retried
      # on the next run (the one that failed / was being cancelled).
      $nextIdx = if($script:ImportResumeNextIndex -ne $null){ [int]$script:ImportResumeNextIndex } else { 0 }
      $progressObj = @{
        ResumeFromIndex   = $nextIdx
        ImportedSecretIds = @($importedSecretIds)
        LastIndex         = $secretIndex
        Total             = $secrets.Count
        Timestamp         = (Get-Date -Format 'o')
        Cancelled         = $true
      }
      ($progressObj | ConvertTo-Json -Depth 5) | Set-Content -Path $importProgressFile -Encoding UTF8
      Write-Log ("IMPORT: Final progress saved - resume will start at index {0}/{1}" -f $nextIdx,$secrets.Count) 'INFO'
    } else {
      # Import completed - remove progress file
      if(Test-Path $importProgressFile){ Remove-Item $importProgressFile -Force }
    }
  }catch{}

  if($script:ImportCancelled){
    Write-Log ("IMPORT: Cancelled. Processed {0}/{1} secrets (Created={2}, Updated={3}, Skipped={4}). Re-run to resume." -f $secretIndex,$secrets.Count,$created,$updated,$skipped) 'WARN'
  } else {
    Write-Log ("IMPORT: Complete. Created={0}, Updated={1}, Skipped={2}" -f $created,$updated,$skipped) 'INFO'
  }
  if($totalSecretPermsApplied -gt 0 -or $totalFolderPermsApplied -gt 0){
    Write-Log ("IMPORT: Permissions Applied - Secret ACLs: {0}, Folder ACLs: {1}" -f $totalSecretPermsApplied,$totalFolderPermsApplied) 'INFO'
  }
  Write-Log ("IMPORT: Tracked {0} folders and {1} secrets for cleanup" -f $script:ImportRunCreatedFolderIds.Count,$script:ImportRunCreatedSecretIds.Count) 'INFO'
  
  return [pscustomobject]@{
    Created = $created
    Updated = $updated
    Skipped = $skipped
    SecretACLs = $totalSecretPermsApplied
    FolderACLs = $totalFolderPermsApplied
  }
}

# =========================
# RECON-CREATE-MISSING-SECRETS: V13 Import-SS lifted verbatim (renamed) for use by Reconcile Missing Secrets
# =========================

function Import-SS-Recon {
  param(
    [Parameter(Mandatory)][string]$SrcApiBase,
    [Parameter(Mandatory)][string]$SrcToken,
    [Parameter(Mandatory)][string]$TgtApiBase,
    [Parameter(Mandatory)][string]$TgtToken,
    [Parameter(Mandatory)][string]$InputPath,
    [int]$TargetFolderId = 0,
    [bool]$UseFolderTree = $false,
    [int]$TargetRootFolderId = 1,
    [bool]$OverwriteIfExists = $true,
    [bool]$SecretTypeMapByName = $false,
    [bool]$ImportTemplates = $false,
    [bool]$CopyFolderAcls = $false,
    [bool]$CopySecretAcls = $false,
    [bool]$CopySecretSettings = $false,
    [bool]$CopyAttachments = $false,
    [bool]$RemapPrincipals = $false,
    [bool]$DryRun = $false,
    [bool]$DecryptPasswords = $false,
    [bool]$DisableInheritPermissions = $false,
    [string]$TemplateSuffix = '',
    [bool]$SkipPasswordValidation = $false
  )

  # Always re-acquire tokens via Token() so that the global TokenCache (and any
  # auto-refresh performed inside SS on a 401) is honored. Returning the captured
  # $SrcToken/$TgtToken parameters would hand out a stale token after expiration,
  # causing every subsequent API call to fail with "Authentication failed".
  function Get-TgtTok {
    $tb = $null
    try { $tb = Get-Variable -Name 'tbTgtPwd' -Scope Script -ValueOnly -ErrorAction SilentlyContinue } catch {}
    return (Token Tgt $tb)
  }
  function Get-SrcTok {
    $tb = $null
    try { $tb = Get-Variable -Name 'tbSrcPwd' -Scope Script -ValueOnly -ErrorAction SilentlyContinue } catch {}
    return (Token Src $tb)
  }

  # Reset cancellation flag
  $script:ImportCancelled = $false

  # Reset tracking at start of import
  Reset-ImportTracking
  $script:CreatedFolderCache = @{}
  
  # Pre-import permission check
  $effectiveTargetFolder = if($TargetFolderId -gt 0){ $TargetFolderId } else { $TargetRootFolderId }
  $permCheck = Test-TargetAccountPermissions -TgtApiBase $TgtApiBase -TgtTok $TgtToken -TargetFolderId $effectiveTargetFolder
  if(-not $permCheck.Success){
    # Single clean error message - no throw (return instead to avoid catch block noise)
    Write-Log ("IMPORT: {0}" -f $permCheck.ErrorMessage) 'ERROR'
    Write-Log ("IMPORT: To fix this, add '{0}' with FolderRole=Owner or Edit on folder {1}" -f $permCheck.CurrentUser,$effectiveTargetFolder) 'INFO'
    return [pscustomobject]@{ Created = 0; Updated = 0; Skipped = 0; SecretACLs = 0; FolderACLs = 0; Error = $permCheck.ErrorMessage }
  }

  if(-not (Test-Path $InputPath)){
    throw "IMPORT: input JSON not found: $InputPath"
  }

  # Use fast JSON parser for large files (ConvertFrom-Json chokes on 100MB+)
  $fileSizeMB = [math]::Round((Get-Item $InputPath).Length / 1MB, 1)
  Write-Log ("IMPORT: Loading JSON file: {0} ({1} MB)" -f $InputPath, $fileSizeMB) 'INFO'
  if($fileSizeMB -gt 50){
    Write-Log "IMPORT: Large file detected - using fast JavaScriptSerializer parser (please wait ~15s)..." 'INFO'
  }
  [System.Windows.Forms.Application]::DoEvents()
  # Read as Dictionary (6 seconds) then convert to PSObject (7 seconds) = ~14s total for 326MB
  $in = Read-LargeJsonAsPSObject $InputPath
  [System.Windows.Forms.Application]::DoEvents()
  Write-Log "IMPORT: JSON loaded successfully" 'INFO'
  $secrets = @($in.Secrets)
  
  if(@($secrets).Count -eq 0){
    Write-Log "IMPORT: no secrets found in JSON" 'WARN'
    return [pscustomobject]@{ Created = 0; Updated = 0; Skipped = 0; SecretACLs = 0; FolderACLs = 0 }
  }

  Write-Log ("IMPORT: Processing {0} secrets from {1}" -f $secrets.Count,$InputPath) 'INFO'
  Write-Log ("IMPORT: Options - UseFolderTree={0}, RemapPrincipals={1}, CopySecretAcls={2}, DryRun={3}, ImportTemplates={4}" -f $UseFolderTree,$RemapPrincipals,$CopySecretAcls,$DryRun,$ImportTemplates) 'INFO'

  # Import progress tracking file for resume capability
  $importProgressFile = $InputPath -replace '\.json$', '-import-progress.json'
  $importedSecretIds = New-Object 'System.Collections.Generic.HashSet[int]'
  # Index-based resume: the array index at which the next run should start.
  # This is robust against `continue` statements scattered through the loop body
  # (each iteration advances this counter BEFORE processing the next secret).
  $resumeFromIndex = 0
  # Load previously saved progress if resuming
  if(Test-Path $importProgressFile){
    try{
      $progressData = Get-Content $importProgressFile -Raw | ConvertFrom-Json
      $progressProps = @($progressData.PSObject.Properties.Name)
      # Preferred: explicit next-index pointer (new format)
      if($progressProps -contains 'ResumeFromIndex' -and $progressData.ResumeFromIndex -ne $null){
        $resumeFromIndex = [int]$progressData.ResumeFromIndex
        if($resumeFromIndex -lt 0){ $resumeFromIndex = 0 }
        Write-Log ("IMPORT: Resuming - previous run stopped at array index {0}" -f $resumeFromIndex) 'WARN'
      }
      # Backwards compat: legacy id-set format
      if($progressData.ImportedSecretIds){
        foreach($pid in @($progressData.ImportedSecretIds)){ [void]$importedSecretIds.Add([int]$pid) }
      }
      # Backwards compat: legacy LastIndex field (set every save in old code = number of
      # secrets processed by the loop). Use it as the resume start index when no
      # explicit ResumeFromIndex is present. This is more reliable than scanning the
      # incomplete id-set, because the old tracker missed most success paths.
      if($resumeFromIndex -le 0 -and $progressProps -contains 'LastIndex' -and $progressData.LastIndex -ne $null){
        $resumeFromIndex = [int]$progressData.LastIndex
        if($resumeFromIndex -lt 0){ $resumeFromIndex = 0 }
        Write-Log ("IMPORT: Resuming - legacy progress file detected, starting at index {0} (LastIndex)" -f $resumeFromIndex) 'WARN'
      } elseif($importedSecretIds.Count -gt 0 -and $resumeFromIndex -le 0){
        Write-Log ("IMPORT: Resuming - {0} secrets already imported from previous run (legacy id-set format)" -f $importedSecretIds.Count) 'WARN'
      }
      # Log additional context if available
      if($progressProps -contains 'StoppedOnSecret' -and $progressData.StoppedOnSecret){
        Write-Log ("IMPORT: Previous run stopped on secret '{0}'" -f $progressData.StoppedOnSecret) 'WARN'
      }
      if($progressProps -contains 'Total' -and $progressData.Total){
        Write-Log ("IMPORT: Previous run progress: {0} of {1} secrets" -f $resumeFromIndex,$progressData.Total) 'INFO'
      }
    }catch{
      Write-Log ("IMPORT: Failed to read progress file '{0}': {1}" -f $importProgressFile,$_.Exception.Message) 'WARN'
    }
  } else {
    Write-Log ("IMPORT: No progress file found at '{0}' - starting fresh import" -f $importProgressFile) 'INFO'
  }

  # Get duplicate action from config
  $dupAction = [string]$Global:Config.Tgt.DuplicateSecretAction
  if([string]::IsNullOrWhiteSpace($dupAction)){ $dupAction = "Skip" }
  Write-Log ("IMPORT: DuplicateSecretAction = '{0}'" -f $dupAction) 'INFO'

  # =====================================================
  # IMPORT TEMPLATES (if requested)
  # =====================================================
  if($ImportTemplates -and -not $DryRun){
    if($in.PSObject.Properties.Name -contains 'TemplateExports'){
      $templateExports = @($in.TemplateExports)
      if($templateExports.Count -gt 0){
        Write-Log ("IMPORT: Found {0} template exports in JSON. Attempting to import..." -f $templateExports.Count) 'INFO'
        $templatesImported = 0
        $templatesSkipped = 0
        $templatesFailed = 0
        
        foreach($tExp in $templateExports){
          $tid = Get-PropValue $tExp @('templateId','TemplateId') $null
          $xmlText = Get-PropValue $tExp @('exportFileText','ExportFileText') $null
          
          if(-not $xmlText){
            Write-Log ("IMPORT TEMPLATE: Skipping templateId={0} - no XML" -f $tid) 'WARN'
            $templatesSkipped++
            continue
          }
          
          # Parse template name from XML for better logging
          $templateName = Get-TemplateNameFromXml -templateXml $xmlText
          if(-not $templateName){ $templateName = "Template_$tid" }
          
          # Check if template already exists on target
          $templateExists = Test-TargetTemplateExistsByName -tgtApiBase $TgtApiBase -tgtTok (Get-TgtTok) -templateName $templateName
          
          if($templateExists){
            Write-Log ("IMPORT TEMPLATE: '{0}' already exists on target - skipping" -f $templateName) 'INFO'
            $templatesSkipped++
            continue
          }
          
          # Import template
          try{
            Import-TemplateXml -apiBase $TgtApiBase -tok (Get-TgtTok) -templateXml $xmlText
            Write-Log ("IMPORT TEMPLATE: Successfully imported '{0}' (templateId={1})" -f $templateName,$tid) 'INFO'
            $templatesImported++
          }
          catch{
            Write-Log ("IMPORT TEMPLATE: Failed to import '{0}': {1}" -f $templateName,$_.Exception.Message) 'WARN'
            $templatesFailed++
          }
        }
        
        Write-Log ("IMPORT TEMPLATES: Complete - Imported={0}, Skipped={1}, Failed={2}" -f $templatesImported,$templatesSkipped,$templatesFailed) 'INFO'
      }
      else{
        Write-Log "IMPORT: No template exports found in JSON (TemplateExports array is empty)" 'INFO'
      }
    }
    else{
      Write-Log "IMPORT: No TemplateExports section in JSON - skipping template import" 'INFO'
    }
  }
  elseif($ImportTemplates -and $DryRun){
    Write-Log "[DRY-RUN] Would import templates from TemplateExports section if present" 'INFO'
  }

  $created = 0
  $updated = 0
  $skipped = 0
  $secretIndex = 0
  $totalSecretPermsApplied = 0
  $totalFolderPermsApplied = 0
  
  # Pre-load caches if copying ACLs (needed for both Remap mode and DIRECT mode validation)
  if(($CopySecretAcls -or $CopyFolderAcls) -and -not $DryRun){
    Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
    Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
  }
  
  # Cache for template name -> ID mapping. Use Get-AllSecretTemplatesDetailed
  # (skip/take pagination) instead of Get-TemplateNameIndex (filter.page) -
  # the latter truncates to 10 entries on this tenant, causing suffixed
  # templates (e.g. 'Windows Account ABCD') to miss the cache and fall
  # through to source-id-fallback.
  $tgtTemplateNameIndex = $null
  if($SecretTypeMapByName){
    $tgtTemplateNameIndex = @{}
    try{
      $__tgtAll = @(Get-AllSecretTemplatesDetailed -apiBase $TgtApiBase -tok (Get-TgtTok))
      foreach($__t in $__tgtAll){
        $__n = Get-PropValue $__t @('name','Name') $null
        $__i = Get-PropValue $__t @('id','Id') $null
        if($__n -and $__i){ $tgtTemplateNameIndex[([string]$__n).Trim().ToLowerInvariant()] = [int]$__i }
      }
      Write-Log ("IMPORT: Built target template name->id index with {0} entries (via Get-AllSecretTemplatesDetailed)." -f $tgtTemplateNameIndex.Count) 'INFO'
    } catch {
      Write-Log ("IMPORT: Detailed target template list failed: {0}. Falling back to Get-TemplateNameIndex." -f $_.Exception.Message) 'WARN'
      try{ $tgtTemplateNameIndex = Get-TemplateNameIndex -apiBase $TgtApiBase -tok (Get-TgtTok) } catch {}
    }
  }

  # Load TemplateMappings.csv from the Reconciliation folder (written by the
  # btnReconMissing handler via Compare Templates + Save Mappings) as an
  # authoritative override for source-template-id -> target-template-id.
  # Fall back to BaseDir\TemplateMappings.csv if the Reconciliation copy is
  # missing. The override is consulted FIRST in the resolution block below
  # so templates whose only difference is a target-side suffix (e.g. source
  # 'Password' id=2 -> target 'Password ABCD' id=6175) map correctly.
  $script:TemplateMapBySrcId   = @{}
  $script:TemplateMapBySrcName = @{}
  try{
    $__tmBase = if($script:BaseDir){ [string]$script:BaseDir } else { [System.IO.Path]::GetTempPath() }
    $__tmPath = Join-Path (Join-Path $__tmBase 'Reconciliation') 'TemplateMappings.csv'
    if(-not (Test-Path $__tmPath)){
      $__tmFallback = Join-Path $__tmBase 'TemplateMappings.csv'
      if(Test-Path $__tmFallback){ $__tmPath = $__tmFallback }
    }
    if(Test-Path $__tmPath){ Load-TemplateMappingsCsv -CsvPath $__tmPath | Out-Null }
    else { Write-Log ("IMPORT: No TemplateMappings.csv found at {0} - will use name/suffix matching only." -f $__tmPath) 'WARN' }
  } catch {
    Write-Log ("IMPORT: Failed to load TemplateMappings.csv: {0}" -f $_.Exception.Message) 'WARN'
  }

  # Cache for source template ID -> name. Used when the exported secret object
  # lacks SecretTypeName/templateName so we can still resolve by name on target.
  # We use Get-AllSecretTemplatesDetailed (skip/take pagination) - the same helper
  # the Template Check / Preview Differences flow uses - because it is known to
  # return the complete template list on this tenant (filter.page/pageSize was
  # capping at 10 entries).
  $srcTemplateIdToName = @{}
  if($SecretTypeMapByName){
    try{
      $__srcAll = @(Get-AllSecretTemplatesDetailed -apiBase $SrcApiBase -tok (Get-SrcTok))
      foreach($__t in $__srcAll){
        $__n = Get-PropValue $__t @('name','Name') $null
        $__i = Get-PropValue $__t @('id','Id') $null
        if($__n -and $__i){ $srcTemplateIdToName[[int]$__i] = [string]$__n }
      }
      Write-Log ("IMPORT: Built source template id->name index with {0} entries (via Get-AllSecretTemplatesDetailed)." -f $srcTemplateIdToName.Count) 'INFO'
    } catch {
      Write-Log ("IMPORT: Failed to build source template id->name index: {0}" -f $_.Exception.Message) 'WARN'
    }
  }

  # Cache for folder secret indexes (to avoid re-fetching)
  $folderSecretIndexCache = @{}

  $lastProgressSave = 0
  $importSaveInterval = 25  # Save progress every N secrets

  # Determine the array index to start from. Prefer the new index-based pointer.
  # If only the legacy id-set is present, derive the start index by scanning for
  # the first secret whose source Id isn't already in the imported set.
  $resumeStartIndex = $resumeFromIndex
  if($resumeStartIndex -le 0 -and $importedSecretIds.Count -gt 0){
    for($i = 0; $i -lt $secrets.Count; $i++){
      $sid = Get-PropValue $secrets[$i] @('Id','id','SecretId','secretId') $null
      if($sid -eq $null -or [int]$sid -le 0 -or -not $importedSecretIds.Contains([int]$sid)){
        $resumeStartIndex = $i
        break
      }
      if($i -eq $secrets.Count - 1){ $resumeStartIndex = $secrets.Count }
    }
  }
  if($resumeStartIndex -gt $secrets.Count){ $resumeStartIndex = $secrets.Count }

  if($resumeStartIndex -gt 0){
    if($resumeStartIndex -lt $secrets.Count){
      $firstPendingName = [string](Get-PropValue $secrets[$resumeStartIndex] @('name','Name','secretName','SecretName') '')
      Write-Log ("IMPORT: Resume detected - skipping {0:N0} already-processed secrets, starting at #{1:N0}/{2:N0}: '{3}'" -f $resumeStartIndex,($resumeStartIndex+1),$secrets.Count,$firstPendingName) 'INFO'
      # Account for the secrets we are seeking past in the skipped counter so final totals add up
      $skipped += $resumeStartIndex
      $secretIndex = $resumeStartIndex
      try{
        $resumeStatusText = "Resuming at {0}/{1} ({2}%) - {3}" -f ($resumeStartIndex+1),$secrets.Count,[int](($resumeStartIndex/$secrets.Count)*100),$firstPendingName
        Update-ProgressBar -Current ($resumeStartIndex+1) -Total $secrets.Count -StatusText $resumeStatusText
      }catch{}
    } else {
      Write-Log ("IMPORT: Resume detected - all {0:N0} secrets already processed in previous run. Nothing to do." -f $secrets.Count) 'INFO'
      $skipped += $secrets.Count
    }
  }

  # Index of the next secret to process if the run is interrupted. We advance this
  # at the TOP of each iteration BEFORE handling the current secret, so every
  # `continue` / success / skip / duplicate / update / error-skip path automatically
  # counts as "done". On StopOnError / Cancel we break out before bumping, so resume
  # restarts at the current (failed) secret.
  $script:ImportResumeNextIndex = $resumeStartIndex

  for($__idx = $resumeStartIndex; $__idx -lt $secrets.Count; $__idx++){
    $sec = $secrets[$__idx]
    # Check for cancellation (do this BEFORE advancing the resume pointer so we
    # restart at the current secret on next run)
    if($script:ImportCancelled){
      $script:ImportResumeNextIndex = $__idx
      Write-Log "IMPORT: Cancelled by user. Progress saved." 'WARN'
      break
    }

    # The PREVIOUS iteration is now fully complete (whether it succeeded, skipped,
    # was a duplicate, updated, or recorded a non-stopping error). Advance the
    # resume pointer so a crash/cancel from this point forward restarts at the
    # current index, not earlier.
    $script:ImportResumeNextIndex = $__idx

    $secretIndex++

    # Allow GUI to process events (cancel button clicks)
    if($secretIndex % 3 -eq 0){
      [System.Windows.Forms.Application]::DoEvents()
    }
    
    $secName = [string](Get-PropValue $sec @('Name','name') $null)
    if([string]::IsNullOrWhiteSpace($secName)){
      Write-Log ("IMPORT: Skipping secret {0} - no name" -f $secretIndex) 'WARN'
      $skipped++
      continue
    }

    # Skip already-imported secrets (resume support)
    $secId = Get-PropValue $sec @('Id','id','SecretId','secretId') $null
    if($secId -ne $null -and [int]$secId -gt 0 -and $importedSecretIds.Contains([int]$secId)){
      Write-Log ("IMPORT: Skipping secret {0}/{1}: '{2}' (already imported in previous run)" -f $secretIndex,$secrets.Count,$secName) 'DEBUG'
      $skipped++
      continue
    }
    
    Write-Log ("IMPORT: Processing secret {0}/{1}: '{2}'" -f $secretIndex,$secrets.Count,$secName) 'INFO'
    # Update progress bar
    try{
      $importStatusText = "{0}/{1} ({2}%) - {3}" -f $secretIndex,$secrets.Count,[int](($secretIndex/$secrets.Count)*100),$secName
      Update-ProgressBar -Current $secretIndex -Total $secrets.Count -StatusText $importStatusText
    }catch{}
    
    # =====================================================
    # DETERMINE TARGET FOLDER
    # =====================================================
    $targetFolderIdForSecret = $TargetFolderId
    if($targetFolderIdForSecret -le 0){ $targetFolderIdForSecret = $TargetRootFolderId }
    
    if($UseFolderTree){
      $srcFolderPath = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
      
      if(-not [string]::IsNullOrWhiteSpace($srcFolderPath)){
        try{
          $targetFolderIdForSecret = Ensure-TargetFolderForSourcePath `
            -TgtApiBase $TgtApiBase `
            -TgtTok (Get-TgtTok) `
            -RootFolderId $TargetRootFolderId `
            -SourceFolderPath $srcFolderPath `
            -DryRun $DryRun `
            -DisableInheritPermissions ([bool]$DisableInheritPermissions)
        }
        catch{
          Write-Log ("IMPORT: Could not create folder tree for '{0}': {1}. SKIPPING secret (will not place in wrong folder)." -f $secName,$_.Exception.Message) 'ERROR'
          $skipped++
          continue
        }
      }
    }
    
    if($targetFolderIdForSecret -le 0){
      Write-Log ("IMPORT: No valid target folder for '{0}'. Skipping." -f $secName) 'WARN'
      $skipped++
      continue
    }
    
    # =====================================================
    # RESOLVE TEMPLATE ID
    # =====================================================
    $srcTemplateId = Get-PropValue $sec @('SecretTypeId','secretTypeId','SecretTemplateId','secretTemplateId') $null
    $srcTemplateName = [string](Get-PropValue $sec @('SecretTypeName','secretTypeName','templateName','TemplateName') $null)
    # If the exported secret didn't include a template name, look it up from the
    # source-side id->name index we built up front.
    if([string]::IsNullOrWhiteSpace($srcTemplateName) -and $srcTemplateId -ne $null -and $srcTemplateIdToName -and $srcTemplateIdToName.ContainsKey([int]$srcTemplateId)){
      $srcTemplateName = [string]$srcTemplateIdToName[[int]$srcTemplateId]
    }
    # Last-resort: direct GET /secret-templates/{id} on source to resolve a name
    # we still don't have. The bulk listing endpoint can be flaky/paginated on
    # some tenants, so fall back to the single-id endpoint and cache the result.
    if([string]::IsNullOrWhiteSpace($srcTemplateName) -and $srcTemplateId -ne $null -and [int]$srcTemplateId -gt 0){
      try{
        $__t1 = SS $SrcApiBase GET ("secret-templates/{0}" -f [int]$srcTemplateId) (Get-SrcTok) $null $null
        $__n1 = Get-PropValue $__t1 @('name','Name') $null
        if($__n1){
          $srcTemplateName = [string]$__n1
          if($srcTemplateIdToName){ $srcTemplateIdToName[[int]$srcTemplateId] = $srcTemplateName }
        }
      } catch {
        # Silent: will fall through to source-id-fallback below
      }
    }
    $tgtTemplateId = $null
    $__tplResolveVia = 'none'

    # Authoritative override: TemplateMappings.csv (Reconciliation folder).
    # Consulted FIRST so a curated source-id -> target-id mapping always wins
    # over the name/suffix heuristics below.
    if($script:TemplateMapBySrcId -and $script:TemplateMapBySrcId.Count -gt 0 -and $srcTemplateId -ne $null){
      $__sidKey = 0; try{ $__sidKey = [int]$srcTemplateId } catch {}
      if($__sidKey -gt 0 -and $script:TemplateMapBySrcId.ContainsKey($__sidKey)){
        $tgtTemplateId = [int]$script:TemplateMapBySrcId[$__sidKey].TargetId
        $__tplResolveVia = 'csv-by-srcid'
      }
    }
    if($tgtTemplateId -eq $null -and $script:TemplateMapBySrcName -and $script:TemplateMapBySrcName.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($srcTemplateName)){
      $__snKey = $srcTemplateName.Trim().ToLowerInvariant()
      if($script:TemplateMapBySrcName.ContainsKey($__snKey)){
        $tgtTemplateId = [int]$script:TemplateMapBySrcName[$__snKey].TargetId
        $__tplResolveVia = 'csv-by-srcname'
      }
    }

    if($tgtTemplateId -eq $null -and $SecretTypeMapByName -and $tgtTemplateNameIndex -and -not [string]::IsNullOrWhiteSpace($srcTemplateName)){
      $key = $srcTemplateName.Trim().ToLowerInvariant()
      if($tgtTemplateNameIndex.ContainsKey($key)){
        $tgtTemplateId = [int]$tgtTemplateNameIndex[$key]
        $__tplResolveVia = 'name-match'
      }
      # Try with target suffix (e.g. source 'Windows Account' -> target 'Windows Account ABCD')
      if($tgtTemplateId -eq $null -and -not [string]::IsNullOrWhiteSpace($TemplateSuffix)){
        $__suffix = $TemplateSuffix.Trim()
        $nameWithSfx = ("{0} {1}" -f $srcTemplateName.Trim(),$__suffix)
        $keyWithSfx = $nameWithSfx.ToLowerInvariant()
        if($tgtTemplateNameIndex.ContainsKey($keyWithSfx)){
          $tgtTemplateId = [int]$tgtTemplateNameIndex[$keyWithSfx]
          $__tplResolveVia = ("name-match-suffix:'{0}'" -f $__suffix)
        }
      }
      # Secondary API lookup if bulk index missed it
      if($tgtTemplateId -eq $null){
        try{
          $__chk = Test-TargetTemplateExistsByName -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -TemplateName $srcTemplateName
          if($__chk -and $__chk.Found -and [int]$__chk.Id -gt 0){
            $tgtTemplateId = [int]$__chk.Id
            $tgtTemplateNameIndex[$key] = $tgtTemplateId
            $__tplResolveVia = 'name-match-api'
          }
        } catch {}
      }
      if($tgtTemplateId -eq $null -and -not [string]::IsNullOrWhiteSpace($TemplateSuffix)){
        try{
          $__nameWithSfx2 = ("{0} {1}" -f $srcTemplateName.Trim(),$TemplateSuffix.Trim())
          $__chk2 = Test-TargetTemplateExistsByName -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -TemplateName $__nameWithSfx2
          if($__chk2 -and $__chk2.Found -and [int]$__chk2.Id -gt 0){
            $tgtTemplateId = [int]$__chk2.Id
            $tgtTemplateNameIndex[$__nameWithSfx2.ToLowerInvariant()] = $tgtTemplateId
            $__tplResolveVia = ("name-match-api-suffix:'{0}'" -f $TemplateSuffix.Trim())
          }
        } catch {}
      }
    }

    if($tgtTemplateId -eq $null -and $srcTemplateId -ne $null){
      $tgtTemplateId = [int]$srcTemplateId
      $__tplResolveVia = 'source-id-fallback'
    }

    # Log every resolution for the first few secrets, and any non-name-match result,
    # so a 400 'Provided Secret Template is invalid' is debuggable.
    if($secretIndex -le 5 -or $__tplResolveVia -notlike 'name-match*'){
      Write-Log ("IMPORT TEMPLATE RESOLVE: secret='{0}' srcTemplateName='{1}' srcTemplateId={2} -> tgtTemplateId={3} via={4} (suffix='{5}')" -f $secName,$srcTemplateName,$srcTemplateId,$tgtTemplateId,$__tplResolveVia,$TemplateSuffix) 'INFO'
    }

    if($tgtTemplateId -eq $null -or $tgtTemplateId -le 0){
      Write-Log ("IMPORT: No valid template for '{0}' (srcTemplateName='{1}', srcTemplateId={2}). Skipping." -f $secName,$srcTemplateName,$srcTemplateId) 'WARN'
      $skipped++
      continue
    }

    # =====================================================
    # DEFINE FOLDER CACHE KEY (MUST BE BEFORE DUPLICATE CHECK)
    # =====================================================
    $folderCacheKey = [string]$targetFolderIdForSecret

        # =====================================================
    # CHECK FOR EXISTING SECRET (DUPLICATE CHECK)
    # =====================================================
    $existingSecretId = 0
    $skipThisSecret = $false
    $isUpdateMode = $false
    
    # Get or build the folder's secret index (cached)
    $folderCacheKey = [string]$targetFolderIdForSecret
    if(-not $folderSecretIndexCache.ContainsKey($folderCacheKey)){
      $folderSecretIndexCache[$folderCacheKey] = Get-SecretNameIndexForFolder `
        -apiBase $TgtApiBase `
        -tok (Get-TgtTok) `
        -folderId $targetFolderIdForSecret
    }
    $secretNameIndex = $folderSecretIndexCache[$folderCacheKey]
    
    # Check for existing secret - try multiple name formats
    # The secret name might have leading/trailing spaces
    $namesToTry = @(
      $secName.Trim().ToLowerInvariant(),           # Trimmed lowercase
      $secName.ToLowerInvariant(),                   # Original lowercase (preserves spaces)
      $secName.Trim(),                               # Trimmed original case
      $secName                                       # Original
    ) | Select-Object -Unique
    
    foreach($nameVariant in $namesToTry){
      $lookupKey = $nameVariant.ToLowerInvariant()
      if($secretNameIndex.ContainsKey($lookupKey)){
        $existingSecretId = [int]$secretNameIndex[$lookupKey]
        Write-Log ("DUPLICATE CHECK: Found match using key '{0}'" -f $lookupKey) 'DEBUG'
        break
      }
    }
    
    # FALLBACK: If not found in cached index, do a targeted search by name in the folder.
    # The bulk /secrets listing may not return all secrets due to API visibility limits.
    if($existingSecretId -le 0){
      try{
        $searchQ = @{
          'filter.folderId'    = $targetFolderIdForSecret
          'filter.searchText'  = $secName.Trim()
          'filter.pageSize'    = 50
        }
        $searchResp = SS $TgtApiBase GET 'secrets' (Get-TgtTok) $null $searchQ
        $searchRecs = @(Get-Records $searchResp)
        foreach($sr in $searchRecs){
          $srName = $null
          foreach($nk in @('name','Name','secretName','SecretName')){
            if($sr.PSObject.Properties.Name -contains $nk){
              $c = [string]$sr.$nk
              if(-not [string]::IsNullOrWhiteSpace($c)){ $srName = $c; break }
            }
          }
          if($srName -and $srName.Trim().ToLowerInvariant() -eq $secName.Trim().ToLowerInvariant()){
            $srId = $null
            foreach($ik in @('id','Id','secretId','SecretId')){
              if($sr.PSObject.Properties.Name -contains $ik){
                try{ $srId = [int]$sr.$ik; if($srId -gt 0){ break } } catch {}
              }
            }
            if($srId -gt 0){
              $existingSecretId = $srId
              # Add to cache so future lookups within this run don't miss it
              $secretNameIndex[$secName.Trim().ToLowerInvariant()] = $srId
              Write-Log ("DUPLICATE CHECK FALLBACK: Found '{0}' via searchText (id={1})" -f $secName,$srId) 'INFO'
              break
            }
          }
        }
      } catch {
        Write-Log ("DUPLICATE CHECK FALLBACK: searchText query failed for '{0}': {1}" -f $secName,$_.Exception.Message) 'WARN'
      }
    }
    
    Write-Log ("DUPLICATE CHECK: Secret '{0}' in folder {1} -> existingId={2}, indexCount={3}" -f $secName,$targetFolderIdForSecret,$existingSecretId,$secretNameIndex.Count) 'DEBUG'
    # =====================================================
    # HANDLE DUPLICATES BASED ON CONFIG
    # =====================================================
    if($existingSecretId -gt 0){
      Write-Log ("IMPORT: Secret '{0}' already exists in folder {1} (existing id={2}). Action: {3}" -f $secName,$targetFolderIdForSecret,$existingSecretId,$dupAction) 'INFO'
      
      switch($dupAction.Trim().ToLowerInvariant()){
        "skip" {
          Write-Log ("[SKIP] Secret '{0}' already exists (id={1}) - will apply permissions only" -f $secName,$existingSecretId) 'INFO'
          $skipped++
          $skipThisSecret = $true
        }
        "update" {
          Write-Log ("[UPDATE MODE] Secret '{0}' exists (id={1}) - will update if different" -f $secName,$existingSecretId) 'INFO'
          $isUpdateMode = $true
        }
        "createnew" {
          Write-Log ("[CREATE-NEW] Secret '{0}' exists (id={1}) - creating duplicate as configured" -f $secName,$existingSecretId) 'INFO'
          $isUpdateMode = $false
        }
        default {
          Write-Log ("[SKIP] Secret '{0}' already exists (id={1}) - will apply permissions only" -f $secName,$existingSecretId) 'INFO'
          $skipped++
          $skipThisSecret = $true
        }
      }
    }
    
    # If skipping secret creation/update, jump to permission application
    if($skipThisSecret){
      # Handle dry-run for skip mode
      if($DryRun){
        Write-Log "[DRY-RUN] Would SKIP secret modification but apply permissions to existing secret id=$existingSecretId" 'INFO'
        if($CopySecretAcls){
          $secPerms = @(Get-PropValue $sec @('SecretPermissions','secretPermissions') @())
          if($secPerms.Count -gt 0){
            $permChanges = Count-SecretPermissionChanges -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -SecretId $existingSecretId -PermissionsArray $secPerms -RemapPrincipals $RemapPrincipals
            
            $totalCount = $permChanges.Add + $permChanges.Skip + $permChanges.Error
            Write-Log ("[DRY-RUN]   - Secret ACLs: {0} total ({1} would add, {2} already exist, {3} skip/error)" -f `
              $totalCount, $permChanges.Add, $permChanges.Skip, $permChanges.Error) 'INFO'
            $totalSecretPermsApplied += $totalCount
          }
        }
        if($CopyFolderAcls -and $targetFolderIdForSecret -gt 0){
          $folderPerms = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
          $srcFolderPathForAcl = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
          # In dry-run with folder tree, subfolder won't exist yet so treat as new folder
          $isNewFolder = ($UseFolderTree -and -not [string]::IsNullOrWhiteSpace($srcFolderPathForAcl))
          $folderAclKey = if($isNewFolder){ "new|$($srcFolderPathForAcl.ToLowerInvariant())" } else { "existing|$targetFolderIdForSecret" }
          if($folderPerms.Count -gt 0 -and -not $script:ImportRunFoldersWithPermsApplied.Contains($folderAclKey)){
            $folderPermChanges = Count-FolderPermissionChanges -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -FolderId $targetFolderIdForSecret -PermissionsArray $folderPerms -RemapPrincipals $RemapPrincipals `
              -AssumeNewFolder $isNewFolder
            
            $folderTotalCount = $folderPermChanges.Add + $folderPermChanges.Skip + $folderPermChanges.Error
            $folderLabel = if($isNewFolder){ "new folder '$srcFolderPathForAcl'" } else { "folder $targetFolderIdForSecret" }
            Write-Log ("[DRY-RUN]   - Folder ACLs for {0}: {1} total ({2} would add, {3} already exist, {4} skip/error)" -f `
              $folderLabel, $folderTotalCount, $folderPermChanges.Add, $folderPermChanges.Skip, $folderPermChanges.Error) 'INFO'
            
            [void]$script:ImportRunFoldersWithPermsApplied.Add($folderAclKey)
            $totalFolderPermsApplied += $folderPermChanges.Add
          }
          # Also report parent folder permissions in dry-run (per-principal tracking)
          if($UseFolderTree -and -not [string]::IsNullOrWhiteSpace($srcFolderPathForAcl)){
            $parentSegmentsDR = $srcFolderPathForAcl.TrimStart('\','/').Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
            if($parentSegmentsDR.Count -gt 1){
              for($pi = 0; $pi -lt ($parentSegmentsDR.Count - 1); $pi++){
                $pSegDR = $parentSegmentsDR[$pi]
                if($folderPerms.Count -gt 0){
                  $newCount = 0
                  foreach($fpDR in $folderPerms){
                    $pGrpN = [string](Get-PropValue $fpDR @('groupName','GroupName') '')
                    $pUsrN = [string](Get-PropValue $fpDR @('userName','UserName','knownAs','KnownAs') '')
                    $drKey = "dr|$pSegDR|g:$($pGrpN.ToLowerInvariant())|u:$($pUsrN.ToLowerInvariant())"
                    if(-not $script:ParentFolderPrincipalTracker.Contains($drKey)){
                      $newCount++
                      [void]$script:ParentFolderPrincipalTracker.Add($drKey)
                    }
                  }
                  if($newCount -gt 0){
                    Write-Log ("[DRY-RUN]   - Parent Folder ACLs for '{0}': {1} would add" -f $pSegDR,$newCount) 'INFO'
                    $totalFolderPermsApplied += $newCount
                  }
                }
              }
            }
          }
        }
        continue
      }
      
      # Still apply permissions for the existing secret
      if($CopySecretAcls -and $existingSecretId -gt 0){
        $secPerms = @(Get-PropValue $sec @('SecretPermissions','secretPermissions') @())
        if($secPerms.Count -gt 0){
          $permSuccess = 0; $permFailed = 0
          foreach($perm in $secPerms){
            try{
              $permObj = Normalize-PermissionObject $perm
              $ok = Add-SecretPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                    -SecretId $existingSecretId -Perm $permObj -RemapPrincipals $RemapPrincipals
              if($ok){ $permSuccess++ } else { $permFailed++ }
            } catch {
              Write-Log ("PERM ERROR: exception while applying ACL to secretId={0}: {1}" -f $existingSecretId,$_.Exception.Message) 'WARN'
              $permFailed++
            }
          }
          if($permFailed -gt 0){
            Write-Log ("IMPORT: ACLs for '{0}': {1} applied, {2} failed" -f $secName,$permSuccess,$permFailed) 'WARN'
          }
          $totalSecretPermsApplied += $permSuccess
        }
      }
      
      # Apply folder permissions if requested (only once per folder)
      if($CopyFolderAcls -and $targetFolderIdForSecret -gt 0){
        $folderPermKey = "existing|$targetFolderIdForSecret"
        if(-not $script:ImportRunFoldersWithPermsApplied.Contains($folderPermKey)){
          $folderPerms = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
          if($folderPerms.Count -gt 0){
            $fpSuccess = 0; $fpFailed = 0
            foreach($fp in $folderPerms){
              try{
                $ok = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                      -FolderId $targetFolderIdForSecret -Perm $fp -RemapPrincipals $RemapPrincipals
                if($ok){ $fpSuccess++ } else { $fpFailed++ }
              } catch {
                Write-Log ("FOLDER PERM ERROR: exception while applying to folderId={0}: {1}" -f $targetFolderIdForSecret,$_.Exception.Message) 'WARN'
                $fpFailed++
              }
            }
            [void]$script:ImportRunFoldersWithPermsApplied.Add($folderPermKey)
            if($fpSuccess -gt 0 -or $fpFailed -gt 0){
              Write-Log ("IMPORT: Folder ACLs for folderId={0}: {1} applied, {2} failed" -f $targetFolderIdForSecret,$fpSuccess,$fpFailed) 'INFO'
            }
            $totalFolderPermsApplied += $fpSuccess
          }
        }
        # Also apply folder permissions to parent folders in the path (e.g., CA_Secrets)
        # Uses per-principal tracking to accumulate permissions from ALL child folders
        if($UseFolderTree){
          $srcFolderPathForParents = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
          if(-not [string]::IsNullOrWhiteSpace($srcFolderPathForParents)){
            $parentSegments = $srcFolderPathForParents.TrimStart('\','/').Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
            if($parentSegments.Count -gt 1){
              $parentId = $TargetRootFolderId
              for($pi = 0; $pi -lt ($parentSegments.Count - 1); $pi++){
                $pSeg = $parentSegments[$pi]
                $pCacheKey = "$parentId|$($pSeg.ToLowerInvariant())"
                if($script:CreatedFolderCache.ContainsKey($pCacheKey)){
                  $parentFolderId = $script:CreatedFolderCache[$pCacheKey]
                  $folderPerms2 = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
                  if($folderPerms2.Count -gt 0){
                    $pfpSuccess = 0; $pfpFailed = 0; $pfpSkipped = 0
                    foreach($fp2 in $folderPerms2){
                      # Build principal key to track what's already been applied to this parent
                      $pGrpName = [string](Get-PropValue $fp2 @('groupName','GroupName') '')
                      $pUsrName = [string](Get-PropValue $fp2 @('userName','UserName','knownAs','KnownAs') '')
                      $principalKey = "$parentFolderId|g:$($pGrpName.ToLowerInvariant())|u:$($pUsrName.ToLowerInvariant())"
                      if($script:ParentFolderPrincipalTracker.Contains($principalKey)){
                        $pfpSkipped++; continue
                      }
                      try{
                        $ok2 = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                              -FolderId $parentFolderId -Perm $fp2 -RemapPrincipals $RemapPrincipals
                        if($ok2){ $pfpSuccess++ } else { $pfpFailed++ }
                      } catch { $pfpFailed++ }
                      [void]$script:ParentFolderPrincipalTracker.Add($principalKey)
                    }
                    if($pfpSuccess -gt 0 -or $pfpFailed -gt 0){
                      Write-Log ("IMPORT: Parent Folder ACLs for '{0}' (folderId={1}): {2} applied, {3} failed, {4} already tracked" -f $pSeg,$parentFolderId,$pfpSuccess,$pfpFailed,$pfpSkipped) 'INFO'
                    }
                    $totalFolderPermsApplied += $pfpSuccess
                  }
                  $parentId = $parentFolderId
                } else { break }
              }
            }
          }
        }
      }
      
      # Done with this skipped secret - move to next
      continue
    }
    
    # =====================================================
    # BUILD ITEMS ARRAY
    # =====================================================
    $exportItems = @(Get-PropValue $sec @('Items','items','fields','Fields') @())
    
    # Decrypt password fields if requested
    if($DecryptPasswords){
      foreach($item in $exportItems){
        $slug = [string](Get-PropValue $item @('slug','Slug') $null)
        $val = Get-PropValue $item @('value','Value','itemValue','ItemValue') $null
        
        if(-not [string]::IsNullOrWhiteSpace($slug) -and -not [string]::IsNullOrWhiteSpace([string]$val)){
          $slugLower = $slug.ToLowerInvariant()
          if($slugLower -match 'password|pass|pwd'){
            $decryptedVal = Decrypt-PasswordValue -encryptedValue ([string]$val)
            if($decryptedVal -ne $val){
              $item | Add-Member -NotePropertyName value -NotePropertyValue $decryptedVal -Force
              Write-Log ("IMPORT: Decrypted password field for secret '{0}', slug='{1}'" -f $secName,$slug) 'DEBUG'
            }
          }
        }
      }
    }
    else {
      # Auto-detect DPAPI-encrypted password fields even when DecryptPasswords is not checked
      foreach($item in $exportItems){
        $slug = [string](Get-PropValue $item @('slug','Slug') $null)
        $val = [string](Get-PropValue $item @('value','Value','itemValue','ItemValue') $null)
        
        if(-not [string]::IsNullOrWhiteSpace($slug) -and -not [string]::IsNullOrWhiteSpace($val)){
          $slugLower = $slug.ToLowerInvariant()
          if(($slugLower -match 'password|pass|pwd') -and $val -match '^01000000d08c9ddf'){
            Write-Log ("IMPORT: Auto-detected DPAPI-encrypted password for secret '{0}', slug='{1}' - attempting decrypt" -f $secName,$slug) 'WARN'
            $decryptedVal = Decrypt-PasswordValue -encryptedValue $val
            if($decryptedVal -ne $val){
              $item | Add-Member -NotePropertyName value -NotePropertyValue $decryptedVal -Force
              Write-Log ("IMPORT: Auto-decrypted password field for secret '{0}', slug='{1}'" -f $secName,$slug) 'INFO'
            } else {
              Write-Log ("IMPORT: DPAPI decryption failed for secret '{0}', slug='{1}' - password was encrypted on a different machine. Check 'Decrypt passwords on import' or re-export from the original machine." -f $secName,$slug) 'ERROR'
            }
          }
        }
      }
    }
    
    $builtItems = $null
    
    try{
      $builtResult = Build-SecretCreateItems `
        -TgtApiBase $TgtApiBase `
        -TgtTok (Get-TgtTok) `
        -TemplateId $tgtTemplateId `
        -ExportItems @($exportItems) `
        -FallbackSecretName $secName
      
      if($builtResult.Success){
        $builtItems = $builtResult.Items
        
        # DIAGNOSTIC: Log items count
        $builtItemsCount = if($builtItems){ @($builtItems).Count } else { 0 }
        Write-Log ("IMPORT: Built {0} items for secret '{1}' from {2} export items" -f $builtItemsCount,$secName,@($exportItems).Count) 'DEBUG'
        
        if($builtResult.FilledPlaceholders -and $builtResult.FilledPlaceholders.Count -gt 0){
          Write-Log ("IMPORT: Secret '{0}' has {1} placeholder fields that need review" -f $secName,$builtResult.FilledPlaceholders.Count) 'WARN'
        }
      } else {
        Write-Log ("[ERROR] Cannot build items for '{0}': Missing fields: {1}" -f $secName,($builtResult.MissingFields -join ', ')) 'ERROR'
        $skipped++
        continue
      }
    }
    catch{
      Write-Log ("[ERROR] Cannot build items for '{0}': {1}" -f $secName,$_.Exception.Message) 'ERROR'
      $skipped++
      continue
    }
        
    # =====================================================
    # DRY RUN MODE
    # =====================================================
    if($DryRun){
      $folderDisplay = "folder id=$targetFolderIdForSecret"
      
      if($isUpdateMode){
        Write-Log ("[DRY-RUN] Would UPDATE secret '{0}' (existing id={1}) in {2}" -f $secName,$existingSecretId,$folderDisplay) 'INFO'
        Write-Log ("[DRY-RUN]   - Would update {0} fields" -f @($builtItems).Count) 'INFO'
        $updated++
      } 
      else {
        Write-Log ("[DRY-RUN] Would CREATE secret '{0}' in {1} using template {2}" -f $secName,$folderDisplay,$tgtTemplateId) 'INFO'
        Write-Log ("[DRY-RUN]   - Would create with {0} fields" -f @($builtItems).Count) 'INFO'
        $created++
      }
      
      if($CopySecretAcls){
        $secPerms = @(Get-PropValue $sec @('SecretPermissions','secretPermissions') @())
        if($secPerms.Count -gt 0){
          # Use the secret ID that would receive permissions (existing or would-be-created)
          $targetSecretIdForPermCheck = if($isUpdateMode){ $existingSecretId } else { 0 }
          
          if($targetSecretIdForPermCheck -gt 0){
            # For existing secrets, we can check current permissions
            $permChanges = Count-SecretPermissionChanges -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -SecretId $targetSecretIdForPermCheck -PermissionsArray $secPerms -RemapPrincipals $RemapPrincipals
            
            $totalCount = $permChanges.Add + $permChanges.Skip + $permChanges.Error
            Write-Log ("[DRY-RUN]   - Secret ACLs: {0} total ({1} would add, {2} already exist, {3} skip/error)" -f `
              $totalCount, $permChanges.Add, $permChanges.Skip, $permChanges.Error) 'INFO'
            $totalSecretPermsApplied += $totalCount
          } else {
            # For new secrets, count valid permissions that would be added
            # (can't check existing since secret doesn't exist yet, but can validate principals)
            $validCount = 0
            $skipCount = 0
            
            # Load caches for validation
            if($RemapPrincipals){
              Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
              Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
            } else {
              Load-TargetUserCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
              Load-TargetGroupCache -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok)
            }
            
            foreach($perm in $secPerms){
              try{
                $p = Normalize-PermissionObject $perm
                if($p.Count -eq 0){ $skipCount++; continue }
                
                $srcUserId = 0; $srcGroupId = 0
                $srcUserName = $null; $srcGroupName = $null
                $srcKnownAs = $null; $srcDomainName = $null
                
                # Use direct hashtable key lookup (Get-PropValue/Has-Prop don't work with hashtables)
                foreach($k in @($p.Keys)){
                  $kl = $k.ToLowerInvariant()
                  switch($kl){
                    'userid'    { try{ if($p[$k] -ne $null){ $srcUserId = [int]$p[$k] } } catch {} }
                    'groupid'   { try{ if($p[$k] -ne $null){ $srcGroupId = [int]$p[$k] } } catch {} }
                    'username'  { if($p[$k] -ne $null){ $srcUserName = [string]$p[$k] } }
                    'groupname' { if($p[$k] -ne $null){ $srcGroupName = [string]$p[$k] } }
                    'knownas'   { if($p[$k] -ne $null){ $srcKnownAs = [string]$p[$k] } }
                    'domainname' { if($p[$k] -ne $null){ $srcDomainName = [string]$p[$k] } }
                  }
                }
                
                $canResolve = $false
                
                if($RemapPrincipals){
                  if($srcUserId -gt 0 -and -not [string]::IsNullOrWhiteSpace($srcUserName)){
                    $tid = Get-TargetUserIdByName -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -UserName $srcUserName -KnownAs $srcKnownAs -DomainName $srcDomainName
                    if($tid -gt 0){ $canResolve = $true }
                  } elseif($srcGroupId -gt 0 -and -not [string]::IsNullOrWhiteSpace($srcGroupName)){
                    $tgid = Get-TargetGroupIdByName -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -GroupName $srcGroupName -KnownAs $srcKnownAs -DomainName $srcDomainName
                    if($tgid -gt 0){ $canResolve = $true }
                  }
                } else {
                  # Direct mode
                  if($srcUserId -gt 0){
                    $userExists = $false
                    foreach($uid in $script:TgtUserNameToIdCache.Values){
                      if([int]$uid -eq $srcUserId){ $userExists = $true; break }
                    }
                    $canResolve = $userExists
                  } elseif($srcGroupId -gt 0){
                    $groupExists = $false
                    foreach($gid in $script:TgtGroupNameToIdCache.Values){
                      if([int]$gid -eq $srcGroupId){ $groupExists = $true; break }
                    }
                    $canResolve = $groupExists
                  }
                }
                
                if($canResolve){ $validCount++ } else { $skipCount++ }
              } catch {
                $skipCount++
              }
            }
            
            Write-Log ("[DRY-RUN]   - Secret ACLs: {0} total ({1} would add to new secret, {2} skip/error)" -f `
              $secPerms.Count, $validCount, $skipCount) 'INFO'
            $totalSecretPermsApplied += $validCount
          }
        }
      }
      
      if($CopyFolderAcls -and $targetFolderIdForSecret -gt 0){
        $srcFolderPathForAcl2 = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
        $isNewFolder2 = ($UseFolderTree -and -not [string]::IsNullOrWhiteSpace($srcFolderPathForAcl2))
        $folderAclKey2 = if($isNewFolder2){ "new|$($srcFolderPathForAcl2.ToLowerInvariant())" } else { "existing|$targetFolderIdForSecret" }
        if(-not $script:ImportRunFoldersWithPermsApplied.Contains($folderAclKey2)){
          $folderPerms = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
          if($folderPerms.Count -gt 0){
            $folderPermChanges = Count-FolderPermissionChanges -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -FolderId $targetFolderIdForSecret -PermissionsArray $folderPerms -RemapPrincipals $RemapPrincipals `
              -AssumeNewFolder $isNewFolder2
            
            $folderTotalCount = $folderPermChanges.Add + $folderPermChanges.Skip + $folderPermChanges.Error
            $folderLabel2 = if($isNewFolder2){ "new folder '$srcFolderPathForAcl2'" } else { "folder $targetFolderIdForSecret" }
            Write-Log ("[DRY-RUN]   - Folder ACLs for {0}: {1} total ({2} would add, {3} already exist, {4} skip/error)" -f `
              $folderLabel2, $folderTotalCount, $folderPermChanges.Add, $folderPermChanges.Skip, $folderPermChanges.Error) 'INFO'
            
            [void]$script:ImportRunFoldersWithPermsApplied.Add($folderAclKey2)
            $totalFolderPermsApplied += $folderPermChanges.Add
          }
        }
        # Also report parent folder permissions in dry-run (per-principal tracking)
        if($isNewFolder2 -and -not [string]::IsNullOrWhiteSpace($srcFolderPathForAcl2)){
          $parentSegmentsDR2 = $srcFolderPathForAcl2.TrimStart('\','/').Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
          if($parentSegmentsDR2.Count -gt 1){
            $folderPermsForParent = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
            for($pi = 0; $pi -lt ($parentSegmentsDR2.Count - 1); $pi++){
              $pSegDR2 = $parentSegmentsDR2[$pi]
              if($folderPermsForParent.Count -gt 0){
                $newCount2 = 0
                foreach($fpDR2 in $folderPermsForParent){
                  $pGrpN2 = [string](Get-PropValue $fpDR2 @('groupName','GroupName') '')
                  $pUsrN2 = [string](Get-PropValue $fpDR2 @('userName','UserName','knownAs','KnownAs') '')
                  $drKey2 = "dr|$pSegDR2|g:$($pGrpN2.ToLowerInvariant())|u:$($pUsrN2.ToLowerInvariant())"
                  if(-not $script:ParentFolderPrincipalTracker.Contains($drKey2)){
                    $newCount2++
                    [void]$script:ParentFolderPrincipalTracker.Add($drKey2)
                  }
                }
                if($newCount2 -gt 0){
                  Write-Log ("[DRY-RUN]   - Parent Folder ACLs for '{0}': {1} would add" -f $pSegDR2,$newCount2) 'INFO'
                  $totalFolderPermsApplied += $newCount2
                }
              }
            }
          }
        }
      }
      
      if($CopyAttachments){
        $attachCount = 0
        foreach($item in @($exportItems)){
          $isFile = $false
          try{ $isFile = [bool](Get-PropValue $item @('isFile','IsFile') $false) } catch {}
          if($isFile){
            $filePath = Get-PropValue $item @('fileExportPath','FileExportPath') $null
            if(-not [string]::IsNullOrWhiteSpace([string]$filePath) -and (Test-Path $filePath)){
              $attachCount++
            }
          }
        }
        if($attachCount -gt 0){
          Write-Log ("[DRY-RUN]   - Would upload {0} attachments" -f $attachCount) 'INFO'
        }
      }
      
      continue
    }
    
    # =====================================================
    # UPDATE EXISTING SECRET
    # =====================================================
    if($isUpdateMode -and $existingSecretId -gt 0){
      try{
        Write-Log ("IMPORT: Updating existing secret '{0}' (id={1})..." -f $secName,$existingSecretId) 'INFO'
        
        # Get current secret to compare
        $currentSecret = $null
        try{
          $currentSecret = SS $TgtApiBase GET ("secrets/{0}" -f $existingSecretId) (Get-TgtTok) $null $null
        }
        catch{
          Write-Log ("IMPORT: Could not fetch existing secret {0} for comparison: {1}" -f $existingSecretId,$_.Exception.Message) 'WARN'
        }
        
        # Build fieldId -> slug mapping from template
        $fieldIdToSlug = @{}
        try{
          $templateFields = @(Get-PropValue (SS $TgtApiBase GET ("secret-templates/{0}" -f $tgtTemplateId) (Get-TgtTok) $null $null) @('fields','Fields') @())
          foreach($tf in $templateFields){
            $tfId = Get-PropValue $tf @('secretTemplateFieldId','SecretTemplateFieldId','fieldId','FieldId') $null
            $tfSlug = [string](Get-PropValue $tf @('slug','Slug','fieldSlugName','FieldSlugName') '')
            if($tfId -ne $null -and -not [string]::IsNullOrWhiteSpace($tfSlug)){
              $fieldIdToSlug[[int]$tfId] = $tfSlug
            }
          }
        }
        catch{
          Write-Log ("IMPORT: Could not load template {0} for field mapping: {1}" -f $tgtTemplateId,$_.Exception.Message) 'WARN'
        }
        
        # Compare and update fields
        $fieldUpdateCount = 0
        $fieldSkippedCount = 0
        $fieldNoIdCount = 0
        
        Write-Log ("IMPORT: Comparing {0} built items for secret '{1}' (id={2})" -f @($builtItems).Count,$secName,$existingSecretId) 'DEBUG'
        
        foreach($item in @($builtItems)){
          $fieldId = Get-PropValue $item @('fieldId','secretTemplateFieldId') $null
          $newValue = [string](Get-PropValue $item @('itemValue','value') "")
          
          # SKIP file fields - they cannot be updated via JSON PUT; handled separately by the attachment upload block
          if([bool](Get-PropValue $item @('IsFile','isFile') $false)){
            $fieldSkippedCount++
            Write-Log ("IMPORT: Skipping file field id={0} (will be handled by attachment upload)" -f $fieldId) 'DEBUG'
            continue
          }

          if($fieldId -eq $null -or [int]$fieldId -le 0){ 
            $fieldNoIdCount++
            Write-Log "IMPORT: Skipping item with invalid fieldId (null or <= 0)" 'DEBUG'
            continue 
          }
          
          # Get the field slug from our mapping
          $fieldSlug = $null
          if($fieldIdToSlug.ContainsKey([int]$fieldId)){
            $fieldSlug = $fieldIdToSlug[[int]$fieldId]
          }
          
          if([string]::IsNullOrWhiteSpace($fieldSlug)){
            Write-Log ("IMPORT: Skipping field {0} - no slug mapping found" -f $fieldId) 'DEBUG'
            $fieldSkippedCount++
            continue
          }
          
          # Check if value is different from current
          $currentValue = ""
          if($currentSecret -ne $null){
            $currentItems = @(Get-PropValue $currentSecret @('items','Items','fields','Fields') @())
            foreach($ci in $currentItems){
              $ciFieldId = Get-PropValue $ci @('fieldId','secretTemplateFieldId') $null
              if($ciFieldId -ne $null -and [int]$ciFieldId -eq [int]$fieldId){
                $currentValue = [string](Get-PropValue $ci @('itemValue','value','Value') "")
                break
              }
            }
          }
          
          # Skip if values are the same
          if($newValue -eq $currentValue){
            $fieldSkippedCount++
            continue
          }
          
          # Update the field using slug and proper body format
          try{
            $fieldBody = @{ value = $newValue }
            SS $TgtApiBase PUT ("secrets/{0}/fields/{1}" -f $existingSecretId,$fieldSlug) (Get-TgtTok) $fieldBody $null | Out-Null
            $fieldUpdateCount++
            Write-Log ("IMPORT: Updated field '{0}' (id={1}) for secret '{2}'" -f $fieldSlug,$fieldId,$secName) 'DEBUG'
          }
          catch{
            Write-Log ("IMPORT: Failed to update field '{0}' (id={1}): {2}" -f $fieldSlug,$fieldId,$_.Exception.Message) 'WARN'
          }
        }
        
        if($fieldUpdateCount -gt 0){
          Write-Log ("[OK] UPDATED secret '{0}' (id={1}) - {2} fields changed, {3} unchanged" -f $secName,$existingSecretId,$fieldUpdateCount,$fieldSkippedCount) 'INFO'
          $updated++
          
          # Track for potential cleanup
          try{
            $script:ImportRunCreatedSecretIds.Add($existingSecretId) | Out-Null
            $script:ImportRunCreatedSecretsById[[string]$existingSecretId] = @{ id=$existingSecretId; name=$secName; folderId=$targetFolderIdForSecret }
          } catch {}
        }
        else{
          Write-Log ("[NO CHANGES] Secret '{0}' (id={1}) - {2} fields unchanged, {3} had no fieldId" -f $secName,$existingSecretId,$fieldSkippedCount,$fieldNoIdCount) 'INFO'
          $skipped++
        }
        # Apply permissions if requested
      if($CopySecretAcls){
    $secPerms = @(Get-PropValue $sec @('SecretPermissions','secretPermissions') @())
    if($secPerms.Count -gt 0){
    $permSuccess = 0; $permFailed  = 0
    foreach($perm in $secPerms){
      try{
        $permObj = Normalize-PermissionObject $perm
        $ok = Add-SecretPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -SecretId $existingSecretId -Perm $permObj -RemapPrincipals $RemapPrincipals
        if($ok){ $permSuccess++ } else { $permFailed++ }
      } catch {
        Write-Log ("PERM ERROR: exception while applying ACL to secretId={0}: {1}" -f $existingSecretId,$_.Exception.Message) 'WARN'
        $permFailed++
      }
    }
    if($permFailed -gt 0){
      Write-Log ("IMPORT: ACLs for '{0}': {1} applied, {2} failed" -f $secName,$permSuccess,$permFailed) 'WARN'
    }
    $totalSecretPermsApplied += $permSuccess
  }
}

        # Apply folder permissions if requested (only once per folder)
        if($CopyFolderAcls -and $targetFolderIdForSecret -gt 0){
          $folderPermKey = "existing|$targetFolderIdForSecret"
          if(-not $script:ImportRunFoldersWithPermsApplied.Contains($folderPermKey)){
            $folderPerms = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
            if($folderPerms.Count -gt 0){
              $fpSuccess = 0; $fpFailed = 0
              foreach($fp in $folderPerms){
                try{
                  $ok = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                        -FolderId $targetFolderIdForSecret -Perm $fp -RemapPrincipals $RemapPrincipals
                  if($ok){ $fpSuccess++ } else { $fpFailed++ }
                } catch {
                  Write-Log ("FOLDER PERM ERROR: exception while applying to folderId={0}: {1}" -f $targetFolderIdForSecret,$_.Exception.Message) 'WARN'
                  $fpFailed++
                }
              }
              [void]$script:ImportRunFoldersWithPermsApplied.Add($folderPermKey)
              if($fpSuccess -gt 0 -or $fpFailed -gt 0){
                Write-Log ("IMPORT: Folder ACLs for folderId={0}: {1} applied, {2} failed" -f $targetFolderIdForSecret,$fpSuccess,$fpFailed) 'INFO'
              }
              $totalFolderPermsApplied += $fpSuccess
            }
          }
          # Also apply folder permissions to parent folders in the path
          # Uses per-principal tracking to accumulate permissions from ALL child folders
          if($UseFolderTree){
            $srcFolderPathForParents = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
            if(-not [string]::IsNullOrWhiteSpace($srcFolderPathForParents)){
              $parentSegments = $srcFolderPathForParents.TrimStart('\','/').Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
              if($parentSegments.Count -gt 1){
                $parentId = $TargetRootFolderId
                for($pi = 0; $pi -lt ($parentSegments.Count - 1); $pi++){
                  $pSeg = $parentSegments[$pi]
                  $pCacheKey = "$parentId|$($pSeg.ToLowerInvariant())"
                  if($script:CreatedFolderCache.ContainsKey($pCacheKey)){
                    $parentFolderId = $script:CreatedFolderCache[$pCacheKey]
                    $folderPerms2 = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
                    if($folderPerms2.Count -gt 0){
                      $pfpSuccess = 0; $pfpFailed = 0; $pfpSkipped = 0
                      foreach($fp2 in $folderPerms2){
                        $pGrpName = [string](Get-PropValue $fp2 @('groupName','GroupName') '')
                        $pUsrName = [string](Get-PropValue $fp2 @('userName','UserName','knownAs','KnownAs') '')
                        $principalKey = "$parentFolderId|g:$($pGrpName.ToLowerInvariant())|u:$($pUsrName.ToLowerInvariant())"
                        if($script:ParentFolderPrincipalTracker.Contains($principalKey)){
                          $pfpSkipped++; continue
                        }
                        try{
                          $ok2 = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                                -FolderId $parentFolderId -Perm $fp2 -RemapPrincipals $RemapPrincipals
                          if($ok2){ $pfpSuccess++ } else { $pfpFailed++ }
                        } catch { $pfpFailed++ }
                        [void]$script:ParentFolderPrincipalTracker.Add($principalKey)
                      }
                      if($pfpSuccess -gt 0 -or $pfpFailed -gt 0){
                        Write-Log ("IMPORT: Parent Folder ACLs for '{0}' (folderId={1}): {2} applied, {3} failed, {4} already tracked" -f $pSeg,$parentFolderId,$pfpSuccess,$pfpFailed,$pfpSkipped) 'INFO'
                      }
                      $totalFolderPermsApplied += $pfpSuccess
                    }
                    $parentId = $parentFolderId
                  } else { break }
                }
              }
            }
          }
        }

        
# Upload attachments if requested
        if($CopyAttachments){
          foreach($item in @($exportItems)){
            $isFile = $false
            try{ $isFile = [bool](Get-PropValue $item @('isFile','IsFile') $false) } catch {}
            if($isFile){
              $filePath = Get-PropValue $item @('fileExportPath','FileExportPath') $null
              $slug = [string](Get-PropValue $item @('slug','Slug','fieldSlugName','FieldSlugName') $null)
              if([string]::IsNullOrWhiteSpace([string]$filePath)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' field '{1}' - fileExportPath is null/empty in export data" -f $secName,$slug) 'WARN'
              } elseif(-not (Test-Path $filePath)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' field '{1}' - file not found on disk: {2}" -f $secName,$slug,$filePath) 'WARN'
              } elseif([string]::IsNullOrWhiteSpace($slug)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' - slug is blank for file field" -f $secName) 'WARN'
              } else {
                try{
                  Upload-SecretFieldFile-MultipartPS51 -apiBase $TgtApiBase -tok (Get-TgtTok) -secretId $existingSecretId -fieldSlug $slug -filePath $filePath
                  Write-Log ("IMPORT: Uploaded attachment for secret '{0}' field '{1}' (secretId={2}, file={3})" -f $secName,$slug,$existingSecretId,[IO.Path]::GetFileName($filePath)) 'INFO'
                }
                catch{
                  Write-Log ("IMPORT: Failed to upload attachment for '{0}' field '{1}': {2}" -f $secName,$slug,$_.Exception.Message) 'WARN'
                }
              }
            }
          }
        }
        
        # Apply settings if requested
        if($CopySecretSettings){
          $secSettings = Get-PropValue $sec @('SecretSettings','secretSettings') $null
          if($secSettings -ne $null){
            $settingsOk = Apply-SecretSettings -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -SecretId $existingSecretId -Settings $secSettings
            if($settingsOk){ Write-Log ("IMPORT: Settings applied to '{0}'" -f $secName) 'DEBUG' }
          }
        }
        
        # Apply password history if available
        $pwdHistory = Get-PropValue $sec @('PasswordHistory','passwordHistory') $null
        if($pwdHistory -ne $null -and @($pwdHistory).Count -gt 0){
          try{
            $historyOk = Apply-PasswordHistory -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -SecretId $existingSecretId -PasswordHistory $pwdHistory -SecretName $secName
            if($historyOk){ Write-Log ("IMPORT: Password history applied to '{0}'" -f $secName) 'INFO' }
          }
          catch{
            Write-Log ("IMPORT: Failed to apply password history for '{0}': {1}" -f $secName,$_.Exception.Message) 'WARN'
          }
        }
      }
      catch{
        Write-Log ("[ERROR] UPDATE FAILED '{0}': {1}" -f $secName,$_.Exception.Message) 'ERROR'
        $skipped++
      }
      
      # CRITICAL: Move to next secret after update attempt
      continue
    }
    
    # =====================================================
    # CREATE NEW SECRET
    # =====================================================
    $payload = @{
      name = $secName
      folderId = [int]$targetFolderIdForSecret
      secretTemplateId = [int]$tgtTemplateId
      items = @($builtItems)
    }
    
    $siteId = Get-PropValue $sec @('SiteId','siteId') $null
    if($siteId -ne $null -and [int]$siteId -gt 0){
      $payload.siteId = [int]$siteId
    }

    # SkipPasswordValidation: temporarily disable password complexity at the
    # TEMPLATE level on the target (per-template, lazy, once). Delinea SS Cloud
    # enforces complexity via the template's validatePasswordRequirementsOnCreate
    # /-OnEdit flags; the body-level 'validatePasswordRequirements' field is
    # silently ignored. We PUT the template with those flags cleared the first
    # time we encounter it, and the Reconcile handler restores the originals in
    # its finally block (via $script:__reconPwdPolicyOriginals).
    if($SkipPasswordValidation -and [int]$tgtTemplateId -gt 0){
      if(-not (Test-Path variable:script:__reconPwdPolicyOriginals) -or $null -eq $script:__reconPwdPolicyOriginals){
        $script:__reconPwdPolicyOriginals = @{}
      }
      if(-not $script:__reconPwdPolicyOriginals.ContainsKey([int]$tgtTemplateId)){
        try{
          $__tmpl = SS $TgtApiBase GET ("secret-templates/{0}" -f [int]$tgtTemplateId) (Get-TgtTok) $null $null
          # NOTE: GET /secret-templates/{id} on this SS Cloud tenant does NOT
          # return the validatePasswordRequirementsOnCreate/OnEdit properties
          # at all. Default to $false (assume the operator has them off) so we
          # don't print a misleading "currently True" message when the UI
          # actually shows the checkbox unchecked. The PWDPOLICY reminder
          # below is gated on the values we actually read - if the API didn't
          # tell us, we stay quiet rather than crying wolf.
          $__origCreate = [bool](Get-PropValue $__tmpl @('validatePasswordRequirementsOnCreate','ValidatePasswordRequirementsOnCreate') $false)
          $__origEdit   = [bool](Get-PropValue $__tmpl @('validatePasswordRequirementsOnEdit','ValidatePasswordRequirementsOnEdit') $false)
          $__tname      = [string](Get-PropValue $__tmpl @('name','Name') ("id=$tgtTemplateId"))
          # Record both originals AND the API base so the Reconcile handler can
          # restore using the right tenant context.
          $script:__reconPwdPolicyOriginals[[int]$tgtTemplateId] = @{
            name=$__tname; create=$__origCreate; edit=$__origEdit; apiBase=$TgtApiBase
          }
          if($__origCreate -or $__origEdit){
            # NOTE: SS Cloud (this tenant) does not expose a working REST
            # endpoint to toggle template-level password validation. PUT
            # /secret-templates/{id} rejects with 'Invalid (SecretTemplateFieldId)'
            # and PATCH /general returns 404. The only reliable way to bypass
            # complexity checks for an import is to flip these flags manually
            # in the SS UI BEFORE the import, then flip them back AFTER.
            # The SkipPasswordValidation checkbox now just records the intent
            # and prints a clear reminder; the actual flag toggle is on you.
            Write-Log ("PWDPOLICY: target template id={0} name='{1}' currently has Validate-on-Create={2} / Validate-on-Edit={3}. SET BOTH TO 'No' IN THE SS UI BEFORE PROCEEDING and remember to set them back to 'Yes' after the import completes." -f $tgtTemplateId,$__tname,$__origCreate,$__origEdit) 'WARN'
          } else {
            Write-Log ("PWDPOLICY: target template id={0} name='{1}' - API did not report Validate-on-Create/Edit (or both off). No reminder needed." -f $tgtTemplateId,$__tname) 'DEBUG'
          }
        } catch {
          Write-Log ("PWDPOLICY: failed to disable password validation on template id={0}: {1}" -f $tgtTemplateId,$_.Exception.Message) 'WARN'
        }
      }
    }

    if($secretIndex -le 3){
      Write-Log ("IMPORT DEBUG: Payload for '{0}': {1}" -f $secName,($payload | ConvertTo-Json -Depth 10 -Compress)) 'DEBUG'
    }
    
    try{
      $result = $null
      try{
        $result = SS $TgtApiBase POST 'secrets' (Get-TgtTok) $payload $null
      }
      catch{
        # V13-compatible fallback: when the curated target template (CSV-mapped
        # or name+suffix-mapped) rejects the secret (typically 400 "An error
        # has occurred" with empty body from SS Cloud field validators that
        # cannot be programmatically inspected), retry ONCE using the source
        # template id directly. V13 Import-SS had no suffix-match and no CSV
        # override, so it fell back to source-id and wrote secrets against
        # the target's built-in default template (same id as source) which
        # has no custom validators. Only triggers when the source id differs
        # from the resolved target id.
        $__firstErr = $_
        $__sc = 0; try{ $__sc = [int]$_.Exception.Response.StatusCode.value__ } catch {}
        $__canRetry = ($srcTemplateId -ne $null) -and ([int]$srcTemplateId -gt 0) -and ([int]$payload.secretTemplateId -ne [int]$srcTemplateId)
        if($__canRetry){
          Write-Log ("[RETRY] '{0}' CREATE failed against tgtTemplateId={1} (resolveVia={2}, status={3}). Retrying with srcTemplateId={4} (V13-compatible fallback to target's built-in template)." -f $secName,$payload.secretTemplateId,$__tplResolveVia,$__sc,[int]$srcTemplateId) 'WARN'
          try{
            # CRITICAL: items[].fieldId values are template-specific. The current
            # payload has fieldIds belonging to the curated (csv-mapped) target
            # template; submitting them against srcTemplateId would fail with
            # 'secretCreateArgs: An error has occurred'. We must REBUILD items
            # against the source template id (which on this target equals the
            # built-in default template with the same id, e.g. 'Password' id=2).
            $__retryBuilt = Build-SecretCreateItems `
              -TgtApiBase $TgtApiBase `
              -TgtTok (Get-TgtTok) `
              -TemplateId ([int]$srcTemplateId) `
              -ExportItems @($exportItems) `
              -FallbackSecretName $secName
            if(-not $__retryBuilt.Success){
              Write-Log ("[RETRY] '{0}' could not rebuild items for srcTemplateId={1}: {2}" -f $secName,[int]$srcTemplateId,(($__retryBuilt.MissingFields) -join ', ')) 'WARN'
              throw $__firstErr
            }
            $__retryItems = @($__retryBuilt.Items)
            Write-Log ("[RETRY] '{0}' rebuilt {1} items for srcTemplateId={2}" -f $secName,$__retryItems.Count,[int]$srcTemplateId) 'DEBUG'
            $payload.secretTemplateId = [int]$srcTemplateId
            $payload.items            = $__retryItems
            $result = SS $TgtApiBase POST 'secrets' (Get-TgtTok) $payload $null
            $__tplResolveVia = ("{0}+retry-srcid" -f $__tplResolveVia)
            $tgtTemplateId = [int]$srcTemplateId
            $builtItems    = $__retryItems
            Write-Log ("[RETRY] '{0}' CREATE succeeded using srcTemplateId={1}" -f $secName,[int]$srcTemplateId) 'INFO'
          }
          catch{
            # Both attempts failed - surface the ORIGINAL (curated-target) error
            # so the user sees the validator that is actually rejecting them.
            throw $__firstErr
          }
        }
        else { throw }
      }
      $newId = [int](Get-PropValue $result @('id','Id','secretId','SecretId') 0)
      
      if($newId -gt 0){
        # Track for cleanup
        try{
          $script:ImportRunCreatedSecretIds.Add($newId) | Out-Null
          $script:ImportRunCreatedSecretsById[[string]$newId] = @{ id=$newId; name=$secName; folderId=$targetFolderIdForSecret }
        } catch {}
        
        # Update the folder cache with the new secret
        if($folderSecretIndexCache.ContainsKey($folderCacheKey)){
          $folderSecretIndexCache[$folderCacheKey][$secName.Trim().ToLowerInvariant()] = $newId
          $folderSecretIndexCache[$folderCacheKey][$secName.ToLowerInvariant()] = $newId
        }
        
        Write-Log ("[OK] CREATED secret '{0}' (id={1}) in folder {2}" -f $secName,$newId,$targetFolderIdForSecret) 'INFO'
        $created++
        
        # Apply permissions
      if($CopySecretAcls){
      $secPerms = @(Get-PropValue $sec @('SecretPermissions','secretPermissions') @())
      if($secPerms.Count -gt 0){
      $permSuccess = 0; $permFailed  = 0
    foreach($perm in $secPerms){
      try{
        $permObj = Normalize-PermissionObject $perm
        $ok = Add-SecretPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
              -SecretId $newId -Perm $permObj -RemapPrincipals $RemapPrincipals
        if($ok){ $permSuccess++ } else { $permFailed++ }
      } catch {
        Write-Log ("PERM ERROR: exception while applying ACL to secretId={0}: {1}" -f $newId,$_.Exception.Message) 'WARN'
        $permFailed++
      }
    }
    if($permFailed -gt 0){
      Write-Log ("IMPORT: ACLs for '{0}': {1} applied, {2} failed" -f $secName,$permSuccess,$permFailed) 'WARN'
    }
    $totalSecretPermsApplied += $permSuccess
  }
}
        
        # Apply folder permissions if requested (only once per folder)
        if($CopyFolderAcls -and $targetFolderIdForSecret -gt 0){
          $folderPermKey = "existing|$targetFolderIdForSecret"
          if(-not $script:ImportRunFoldersWithPermsApplied.Contains($folderPermKey)){
            $folderPerms = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
            if($folderPerms.Count -gt 0){
              $fpSuccess = 0; $fpFailed = 0
              foreach($fp in $folderPerms){
                try{
                  $ok = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                        -FolderId $targetFolderIdForSecret -Perm $fp -RemapPrincipals $RemapPrincipals
                  if($ok){ $fpSuccess++ } else { $fpFailed++ }
                } catch {
                  Write-Log ("FOLDER PERM ERROR: exception while applying to folderId={0}: {1}" -f $targetFolderIdForSecret,$_.Exception.Message) 'WARN'
                  $fpFailed++
                }
              }
              [void]$script:ImportRunFoldersWithPermsApplied.Add($folderPermKey)
              if($fpSuccess -gt 0 -or $fpFailed -gt 0){
                Write-Log ("IMPORT: Folder ACLs for folderId={0}: {1} applied, {2} failed" -f $targetFolderIdForSecret,$fpSuccess,$fpFailed) 'INFO'
              }
              $totalFolderPermsApplied += $fpSuccess
            }
          }
          # Also apply folder permissions to parent folders in the path
          # Uses per-principal tracking to accumulate permissions from ALL child folders
          if($UseFolderTree){
            $srcFolderPathForParents = [string](Get-PropValue $sec @('FolderPath','folderPath') $null)
            if(-not [string]::IsNullOrWhiteSpace($srcFolderPathForParents)){
              $parentSegments = $srcFolderPathForParents.TrimStart('\','/').Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
              if($parentSegments.Count -gt 1){
                $parentId = $TargetRootFolderId
                for($pi = 0; $pi -lt ($parentSegments.Count - 1); $pi++){
                  $pSeg = $parentSegments[$pi]
                  $pCacheKey = "$parentId|$($pSeg.ToLowerInvariant())"
                  if($script:CreatedFolderCache.ContainsKey($pCacheKey)){
                    $parentFolderId = $script:CreatedFolderCache[$pCacheKey]
                    $folderPerms2 = @(Get-PropValue $sec @('FolderPermissions','folderPermissions') @())
                    if($folderPerms2.Count -gt 0){
                      $pfpSuccess = 0; $pfpFailed = 0; $pfpSkipped = 0
                      foreach($fp2 in $folderPerms2){
                        $pGrpName = [string](Get-PropValue $fp2 @('groupName','GroupName') '')
                        $pUsrName = [string](Get-PropValue $fp2 @('userName','UserName','knownAs','KnownAs') '')
                        $principalKey = "$parentFolderId|g:$($pGrpName.ToLowerInvariant())|u:$($pUsrName.ToLowerInvariant())"
                        if($script:ParentFolderPrincipalTracker.Contains($principalKey)){
                          $pfpSkipped++; continue
                        }
                        try{
                          $ok2 = Add-FolderPermission-WithRemap -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) `
                                -FolderId $parentFolderId -Perm $fp2 -RemapPrincipals $RemapPrincipals
                          if($ok2){ $pfpSuccess++ } else { $pfpFailed++ }
                        } catch { $pfpFailed++ }
                        [void]$script:ParentFolderPrincipalTracker.Add($principalKey)
                      }
                      if($pfpSuccess -gt 0 -or $pfpFailed -gt 0){
                        Write-Log ("IMPORT: Parent Folder ACLs for '{0}' (folderId={1}): {2} applied, {3} failed, {4} already tracked" -f $pSeg,$parentFolderId,$pfpSuccess,$pfpFailed,$pfpSkipped) 'INFO'
                      }
                      $totalFolderPermsApplied += $pfpSuccess
                    }
                    $parentId = $parentFolderId
                  } else { break }
                }
              }
            }
          }
        }

        # Upload attachments
        if($CopyAttachments){
          foreach($item in @($exportItems)){
            $isFile = $false
            try{ $isFile = [bool](Get-PropValue $item @('isFile','IsFile') $false) } catch {}
            if($isFile){
              $filePath = Get-PropValue $item @('fileExportPath','FileExportPath') $null
              $slug = [string](Get-PropValue $item @('slug','Slug','fieldSlugName','FieldSlugName') $null)
              if([string]::IsNullOrWhiteSpace([string]$filePath)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' field '{1}' - fileExportPath is null/empty in export data" -f $secName,$slug) 'WARN'
              } elseif(-not (Test-Path $filePath)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' field '{1}' - file not found on disk: {2}" -f $secName,$slug,$filePath) 'WARN'
              } elseif([string]::IsNullOrWhiteSpace($slug)){
                Write-Log ("IMPORT: ATTACH SKIP '{0}' - slug is blank for file field" -f $secName) 'WARN'
              } else {
                try{
                  Upload-SecretFieldFile-MultipartPS51 -apiBase $TgtApiBase -tok (Get-TgtTok) -secretId $newId -fieldSlug $slug -filePath $filePath
                  Write-Log ("IMPORT: Uploaded attachment for secret '{0}' field '{1}' (secretId={2}, file={3})" -f $secName,$slug,$newId,[IO.Path]::GetFileName($filePath)) 'INFO'
                }
                catch{
                  Write-Log ("IMPORT: Failed to upload attachment for '{0}' field '{1}': {2}" -f $secName,$slug,$_.Exception.Message) 'WARN'
                }
              }
            }
          }
        }
        
        # Apply settings
        if($CopySecretSettings){
          $secSettings = Get-PropValue $sec @('SecretSettings','secretSettings') $null
          if($secSettings -ne $null){
            $settingsOk = Apply-SecretSettings -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -SecretId $newId -Settings $secSettings
            if($settingsOk){ Write-Log ("IMPORT: Settings applied to '{0}'" -f $secName) 'DEBUG' }
          }
        }
        
        # Apply password history if available
        $pwdHistory = Get-PropValue $sec @('PasswordHistory','passwordHistory') $null
        if($pwdHistory -ne $null -and @($pwdHistory).Count -gt 0){
          try{
            $historyOk = Apply-PasswordHistory -TgtApiBase $TgtApiBase -TgtTok (Get-TgtTok) -SecretId $newId -PasswordHistory $pwdHistory -SecretName $secName
            if($historyOk){ Write-Log ("IMPORT: Password history applied to '{0}'" -f $secName) 'INFO' }
          }
          catch{
            Write-Log ("IMPORT: Failed to apply password history for '{0}': {1}" -f $secName,$_.Exception.Message) 'WARN'
          }
        }
      }
      else{
        Write-Log ("[WARN] Secret created but no ID returned for '{0}'" -f $secName) 'WARN'
        $created++
      }
    }
    catch{
      Write-Log ("[ERROR] CREATE FAILED '{0}': {1}" -f $secName,$_.Exception.Message) 'ERROR'
      Write-Log ("[ERROR] CREATE FAILED '{0}' details: srcTemplateName='{1}' resolveVia={2} tgtTemplateId={3}, folderId={4}, itemCount={5}, siteId={6}" -f $secName,$srcTemplateName,$__tplResolveVia,$tgtTemplateId,$targetFolderIdForSecret,@($builtItems).Count,(Get-PropValue $sec @('SiteId','siteId') 'n/a')) 'ERROR'
      # PS 5.1 surfaces the 4xx response body on $_.ErrorDetails.Message; older
      # stream-based read can silently fail if the stream was already consumed.
      try{
        $__payloadJson = $payload | ConvertTo-Json -Depth 10 -Compress
        Write-Log ("[ERROR] CREATE FAILED '{0}' request payload: {1}" -f $secName,$__payloadJson) 'ERROR'
      } catch {}
      $__respBody = $null
      try{ if($_.ErrorDetails -and $_.ErrorDetails.Message){ $__respBody = [string]$_.ErrorDetails.Message } } catch {}
      if([string]::IsNullOrWhiteSpace($__respBody)){
        try{
          $__resp = $_.Exception.Response
          if($__resp){
            $__reader = New-Object IO.StreamReader($__resp.GetResponseStream())
            $__respBody = $__reader.ReadToEnd()
            $__reader.Close()
          }
        } catch {}
      }
      if(-not [string]::IsNullOrWhiteSpace($__respBody)){
        Write-Log ("[ERROR] CREATE FAILED '{0}' server response: {1}" -f $secName,$__respBody) 'ERROR'
      } else {
        Write-Log ("[ERROR] CREATE FAILED '{0}' server response: <empty body>" -f $secName) 'ERROR'
      }
      # Show first few item slugs/types so we can spot template/field mismatch quickly.
      try{
        $__itemSummary = @()
        foreach($__it in @($builtItems)){
          $__slug = Get-PropValue $__it @('slug','Slug','fieldSlugName','FieldSlugName') $null
          $__fieldId = Get-PropValue $__it @('fieldId','FieldId','secretTemplateFieldId') $null
          $__hasVal = $false
          try{ $__hasVal = -not [string]::IsNullOrEmpty([string](Get-PropValue $__it @('itemValue','ItemValue') $null)) } catch {}
          $__itemSummary += ("slug={0} fieldId={1} hasValue={2}" -f $__slug,$__fieldId,$__hasVal)
        }
        Write-Log ("[ERROR] CREATE FAILED '{0}' items: [{1}]" -f $secName,($__itemSummary -join ' ; ')) 'ERROR'
      } catch {}
      $skipped++
    }

    # Track successfully imported secret for resume
    if($secId -ne $null -and [int]$secId -gt 0){
      [void]$importedSecretIds.Add([int]$secId)
    }

    # Periodic progress save. We write the index of the NEXT secret to process
    # ($__idx + 1) since the current iteration completed without breaking.
    if(($secretIndex - $lastProgressSave) -ge $importSaveInterval){
      $lastProgressSave = $secretIndex
      try{
        $progressObj = @{
          ResumeFromIndex   = ($__idx + 1)
          ImportedSecretIds = @($importedSecretIds)
          LastIndex         = $secretIndex
          Total             = $secrets.Count
          Timestamp         = (Get-Date -Format 'o')
        }
        ($progressObj | ConvertTo-Json -Depth 5) | Set-Content -Path $importProgressFile -Encoding UTF8
        Write-Log ("IMPORT: Progress saved - {0}/{1} secrets processed (next resume index={2})" -f $secretIndex,$secrets.Count,($__idx + 1)) 'INFO'
      }catch{}
    }
  }

  # Save final progress
  try{
    if($script:ImportCancelled){
      # $script:ImportResumeNextIndex points at the secret that should be retried
      # on the next run (the one that failed / was being cancelled).
      $nextIdx = if($script:ImportResumeNextIndex -ne $null){ [int]$script:ImportResumeNextIndex } else { 0 }
      $progressObj = @{
        ResumeFromIndex   = $nextIdx
        ImportedSecretIds = @($importedSecretIds)
        LastIndex         = $secretIndex
        Total             = $secrets.Count
        Timestamp         = (Get-Date -Format 'o')
        Cancelled         = $true
      }
      ($progressObj | ConvertTo-Json -Depth 5) | Set-Content -Path $importProgressFile -Encoding UTF8
      Write-Log ("IMPORT: Final progress saved - resume will start at index {0}/{1}" -f $nextIdx,$secrets.Count) 'INFO'
    } else {
      # Import completed - remove progress file
      if(Test-Path $importProgressFile){ Remove-Item $importProgressFile -Force }
    }
  }catch{}

  if($script:ImportCancelled){
    Write-Log ("IMPORT: Cancelled. Processed {0}/{1} secrets (Created={2}, Updated={3}, Skipped={4}). Re-run to resume." -f $secretIndex,$secrets.Count,$created,$updated,$skipped) 'WARN'
  } else {
    Write-Log ("IMPORT: Complete. Created={0}, Updated={1}, Skipped={2}" -f $created,$updated,$skipped) 'INFO'
  }
  if($totalSecretPermsApplied -gt 0 -or $totalFolderPermsApplied -gt 0){
    Write-Log ("IMPORT: Permissions Applied - Secret ACLs: {0}, Folder ACLs: {1}" -f $totalSecretPermsApplied,$totalFolderPermsApplied) 'INFO'
  }
  Write-Log ("IMPORT: Tracked {0} folders and {1} secrets for cleanup" -f $script:ImportRunCreatedFolderIds.Count,$script:ImportRunCreatedSecretIds.Count) 'INFO'
  
  return [pscustomobject]@{
    Created = $created
    Updated = $updated
    Skipped = $skipped
    SecretACLs = $totalSecretPermsApplied
    FolderACLs = $totalFolderPermsApplied
  }
}
# =========================
# EXPORT-ZIPBUNDLE 
# =========================


# =========================
# EXPORT-ZIPBUNDLE 
# =========================

function Export-ZipBundle {
    param(
        [Parameter(Mandatory)][string]$SourceDir,
        [Parameter(Mandatory)][string]$OutZipPath
    )

    if (-not (Test-Path $SourceDir)) {
        Write-Log "[WARN] ZIP: source directory not found: $SourceDir" 'WARN'
        return $null
    }

    $parentDir = Split-Path -Parent $OutZipPath
    if (-not (Test-Path $parentDir)) { New-Item -ItemType Directory -Path $parentDir | Out-Null }

    try {
        if (Test-Path $OutZipPath) { Remove-Item $OutZipPath -Force }
        Compress-Archive -Path (Join-Path $SourceDir '*') -DestinationPath $OutZipPath -CompressionLevel Optimal -Force
        $zipSize = (Get-Item $OutZipPath).Length
        Write-Log ("[OK] ZIP bundle created: {0} ({1} bytes)" -f $OutZipPath, $zipSize) 'INFO'
        return $OutZipPath
    } catch {
        Write-Log ("[ERROR] ZIP bundle failed: {0}" -f $_) 'ERROR'
        return $null
    }
}

function Export-SS-DirectToXml {
  param(
    [string]$ApiBase,
    [string]$Token,
    [string]$OutXmlPath,
    [string]$Search = '*',
    [Nullable[int]]$FolderId = $null,
    [Nullable[int]]$MaxSecrets = $null,
    [bool]$IncludeFolders = $true,
    [bool]$IncludePermissions = $false,
    [bool]$IncludeAttachments = $false,
    [bool]$IncludeHistory = $false,
    [int[]]$OnlySecretIds = $null
  )

  function Get-SrcTok { Token Src $tbSrcPwd }

  Write-Log "Direct API export: enumerating secrets from source..." 'INFO'
  
  # CRITICAL FIX: Add the missing secret enumeration logic
  $page = 1
  $ps = 200
  $all = @()
  
  if($OnlySecretIds -and $OnlySecretIds.Count -gt 0){
    # Targeted export: build pseudo-records from the explicit ID list and
    # skip the broken folder-scoped pagination entirely.
    Write-Log ("Direct API export: targeted mode for {0} explicit secret IDs" -f $OnlySecretIds.Count) 'INFO'
    foreach($oid in $OnlySecretIds){
      $all += [pscustomobject]@{ id = [int]$oid }
    }
  } else {
    do {
      $pg = Get-SecretLookupPage -ApiBase $ApiBase -Token (Get-SrcTok) -Page $page -PageSize $ps -Search $Search -FolderId $FolderId
      $recs = @($pg.records)
      $all += $recs
      $page++
      if ($MaxSecrets -and @($all).Count -ge $MaxSecrets) {
        $all = @($all) | Select-Object -First $MaxSecrets
        break
      }
    } while (@($recs).Count -ge $ps)
  }
  
  Write-Log ("Found {0} secrets. Fetching details for XML generation..." -f @($all).Count) 'INFO'

  # Build XML document
  $doc = New-Object System.Xml.XmlDocument
  $decl = $doc.CreateXmlDeclaration("1.0", "utf-16", $null)
  [void]$doc.AppendChild($decl)

  $importFile = $doc.CreateElement("ImportFile")
  [void]$importFile.SetAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
  [void]$importFile.SetAttribute("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
  [void]$doc.AppendChild($importFile)

  # Folders section
  $folderSet = New-Object 'System.Collections.Generic.HashSet[string]'
  
  if ($IncludeFolders) {
    $foldersNode = $doc.CreateElement("Folders")
    [void]$importFile.AppendChild($foldersNode)
  }

  # Templates section (placeholder)
  $tmplNode = $doc.CreateElement("SecretTemplates")
  [void]$importFile.AppendChild($tmplNode)

  # Secrets section
  $secretsNode = $doc.CreateElement("Secrets")
  [void]$importFile.AppendChild($secretsNode)

  foreach ($rec in @($all)) {
    $rid = Get-PropValue $rec @('id', 'Id', 'secretId', 'SecretId') $null
    if ($rid -eq $null) { continue }

    # Fetch full secret detail
    $s = SS $ApiBase GET ("secrets/{0}" -f $rid) (Get-SrcTok) $null $null

    $sid = [int](Get-PropValue $s @('id', 'Id', 'secretId', 'SecretId') $rid)
    $name = [string](Get-PropValue $s @('name', 'Name', 'secretName', 'SecretName') ("secret_$sid"))
    $stypeName = Get-PropValue $s @('secretTypeName', 'SecretTypeName', 'templateName', 'TemplateName') $null
    $folderId = Get-PropValue $s @('folderId', 'FolderId') $null

    # Get folder path
    $folderPath = ""
    if ($folderId -ne $null -and $IncludeFolders) {
      try {
        $fp = Get-FolderPath-Source -srcApi $ApiBase -srcTok (Get-SrcTok) -srcFolderId ([int]$folderId)
        if ($fp) {
          $folderPath = $fp.TrimStart('\')
          
          # Add folder hierarchy to set
          $parts = @($folderPath.Split('\') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
          $cur = ""
          foreach ($part in $parts) {
            $cur = if ($cur) { "$cur\$part" } else { $part }
            [void]$folderSet.Add($cur)
          }
        }
      }
      catch {}
    }

    # Create Secret XML node
    $secNode = $doc.CreateElement("Secret")
    [void]$secretsNode.AppendChild($secNode)

    $secNameNode = $doc.CreateElement("SecretName")
    $secNameNode.InnerText = $name
    [void]$secNode.AppendChild($secNameNode)

    $tmplNameNode = $doc.CreateElement("SecretTemplateName")
    $tmplNameNode.InnerText = if ($stypeName) { [string]$stypeName } else { "Unknown Template" }
    [void]$secNode.AppendChild($tmplNameNode)

    $fpNode = $doc.CreateElement("FolderPath")
    $fpNode.InnerText = $folderPath
    [void]$secNode.AppendChild($fpNode)

    # Permissions (placeholder for now)
    $permsNode = $doc.CreateElement("Permissions")
    [void]$secNode.AppendChild($permsNode)

    # Secret items
    $itemsNode = $doc.CreateElement("SecretItems")
    [void]$secNode.AppendChild($itemsNode)

    $rawItems = Get-PropValue $s @('items', 'Items', 'fields', 'Fields') @()
    foreach ($it in @($rawItems)) {
      $fieldName = [string](Get-PropValue $it @('name', 'Name', 'FieldName', 'fieldName') $null)
      if ([string]::IsNullOrWhiteSpace($fieldName)) { continue }

      $val = Get-PropValue $it @('value', 'Value', 'itemValue', 'ItemValue') ""
      $isFile = $false
      try { $isFile = [bool](Get-PropValue $it @('isFile', 'IsFile') $false) } catch {}

      if ($isFile) {
        if ($IncludeAttachments) {
          $slug = [string](Get-PropValue $it @('slug', 'Slug') $null)
          $bytes = SS-GetFieldBytes -apiBase $ApiBase -tok (Get-SrcTok) -secretId $sid -slug $slug
          if ($bytes -and $bytes.Length -gt 0) {
            $val = "[FILE: {0} bytes]" -f $bytes.Length
          }
          else {
            $val = "[FILE FIELD - no data]"
          }
        }
        else {
          $val = "[FILE FIELD] " + [string](Get-PropValue $it @('filename', 'fileName', 'FileName') "")
        }
      }

      $itemNode = $doc.CreateElement("SecretItem")
      [void]$itemsNode.AppendChild($itemNode)

      $fnNode = $doc.CreateElement("FieldName")
      $fnNode.InnerText = $fieldName
      [void]$itemNode.AppendChild($fnNode)

      $vNode = $doc.CreateElement("Value")
      $vNode.InnerText = [string]$val
      [void]$itemNode.AppendChild($vNode)
    }
  }

  # Write folder nodes
  if ($IncludeFolders -and $folderSet.Count -gt 0) {
    $foldersNode = $importFile.SelectSingleNode("Folders")
    $sortedFolders = @($folderSet) | Sort-Object

    foreach ($fp in $sortedFolders) {
      $folderNode = $doc.CreateElement("Folder")
      [void]$foldersNode.AppendChild($folderNode)

      $parts = @($fp.Split('\') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
      $folderName = $parts[-1]

      $folderNameNode = $doc.CreateElement("FolderName")
      $folderNameNode.InnerText = $folderName
      [void]$folderNode.AppendChild($folderNameNode)

      $folderPathNode = $doc.CreateElement("FolderPath")
      $folderPathNode.InnerText = $fp
      [void]$folderNode.AppendChild($folderPathNode)

      $permsNode = $doc.CreateElement("Permissions")
      [void]$folderNode.AppendChild($permsNode)
    }
  }

  Ensure-Dir $OutXmlPath
  $doc.Save($OutXmlPath)

  Write-Log ("Direct API export: XML written to {0} (secrets={1}, folders={2})" -f $OutXmlPath, @($all).Count, $folderSet.Count) 'INFO'
  return @($all).Count
}

function SS-PutFieldValue(
  [string]$apiBase,
  [string]$tok,
  [int]$secretId,
  [string]$slug,
  [string]$value,
  [string]$comment = "migration placeholder",
  [string]$fileName = "placeholder.txt"
){
  if([string]::IsNullOrWhiteSpace($slug)){ return }

  # For file fields, API enforces extension allow-lists.
  # Send a filename with extension + base64 bytes.
  $bytes = [Text.Encoding]::UTF8.GetBytes([string]$value)
  $b64   = [Convert]::ToBase64String($bytes)

  $body = @{
    comment        = $comment
    fileName       = $fileName
    file           = $b64
    fileAttachment = $b64
    value          = $value
  }

  try{
    SS $apiBase PUT ("secrets/{0}/fields/{1}" -f $secretId,$slug) $tok $body $null | Out-Null
  } catch {
    Write-Log ("FILEFIELD PUT failed secretId={0} slug='{1}': {2}" -f $secretId,$slug,($_ | Out-String)) 'WARN'
  }
}

# NOTE: Has-Prop, Get-PropValue, Get-Records defined earlier at ~line 1276

function Get-ExistingSecretIdByName {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Token,
    [Parameter(Mandatory)][string]$SecretName,
    [Parameter(Mandatory)][int]$FolderId
  )
  
  if([string]::IsNullOrWhiteSpace($SecretName) -or $FolderId -le 0){
    return 0
  }
  
  # Get the index for this folder
  $index = Get-SecretNameIndexForFolder -apiBase $ApiBase -tok $Token -folderId $FolderId
  
  # Normalize the name for comparison
  $normalizedName = $SecretName.Trim().ToLowerInvariant()
  
  Write-Log ("DUPLICATE CHECK: Secret '{0}' in folder {1} -> existingId={2}, indexCount={3}" -f `
    $SecretName, $FolderId, $(if($index.ContainsKey($normalizedName)){$index[$normalizedName]}else{0}), $index.Count) 'DEBUG'
  
  if($index.ContainsKey($normalizedName)){
    return [int]$index[$normalizedName]
  }
  
  return 0
}
function Find-SecretByNameInFolder {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Tok,
    [Parameter(Mandatory)][int]$FolderId,
    [Parameter(Mandatory)][string]$SecretName
  )
  
  if([string]::IsNullOrWhiteSpace($SecretName) -or $FolderId -le 0){ return 0 }
  
  $normalizedName = $SecretName.Trim().ToLowerInvariant()
  $page = 1
  $pageSize = 200
  
  while($page -le 20){
    try{
      $params = @{
        'filter.folderId' = $FolderId
        'filter.searchText' = $SecretName
        'filter.page' = $page
        'filter.pageSize' = $pageSize
      }
      
      $resp = SS $ApiBase GET 'secrets/lookup' $Tok $null $params
      $recs = @(Get-Records $resp)
      
      foreach($rec in $recs){
        $recName = [string](Get-PropValue $rec @('name','Name','secretName','SecretName') $null)
        $recId = Get-PropValue $rec @('id','Id','secretId','SecretId') $null
        
        if(-not [string]::IsNullOrWhiteSpace($recName) -and $recId -ne $null){
          if($recName.Trim().ToLowerInvariant() -eq $normalizedName){
            return [int]$recId
          }
        }
      }
      
      if($recs.Count -lt $pageSize){ break }
      $page++
    }
    catch{
      Write-Log ("Find-SecretByNameInFolder: Error searching for '{0}' in folder {1}: {2}" -f $SecretName,$FolderId,$_.Exception.Message) 'DEBUG'
      break
    }
  }
  
  return 0
}
# REPLACE the Get-SecretNameIndexForFolder function with this version:
function Get-SecretNameIndexForFolder([string]$apiBase,[string]$tok,[int]$folderId){
  $index = @{}
  $page = 1
  $ps = 200

  Write-Log ("Get-SecretNameIndexForFolder: Building index for folderId={0} using /secrets endpoint" -f $folderId) 'DEBUG'

  while($true){
    $q = @{
      'filter.folderId'   = $folderId
      'filter.page'       = $page
      'filter.pageSize'   = $ps
    }

    try{
      $resp = SS $apiBase GET 'secrets' $tok $null $q
      $recs = @(Get-Records $resp)
      
      Write-Log ("Get-SecretNameIndexForFolder: folderId={0} page={1} returned {2} records" -f $folderId,$page,$recs.Count) 'DEBUG'

      foreach($x in $recs){
        $id = $null
        foreach($idKey in @('id','Id','secretId','SecretId')){
          if($x.PSObject.Properties.Name -contains $idKey){
            try{ $id = [int]$x.$idKey; if($id -gt 0){ break } } catch {}
          }
        }
        if($id -eq $null -or $id -le 0){ continue }

        $n = $null
        foreach($nameKey in @('name','Name','secretName','SecretName')){
          if($x.PSObject.Properties.Name -contains $nameKey){
            $candidate = [string]$x.$nameKey
            if(-not [string]::IsNullOrWhiteSpace($candidate)){
              $n = $candidate
              break
            }
          }
        }

        if([string]::IsNullOrWhiteSpace($n)){
          Write-Log ("Get-SecretNameIndexForFolder: Could not extract name for secretId={0}" -f $id) 'DEBUG'
          continue
        }

        $key = $n.ToLowerInvariant()
        $keyTrimmed = $n.Trim().ToLowerInvariant()
        
        if(-not $index.ContainsKey($key)){
          $index[$key] = [int]$id
          Write-Log ("  Index: '{0}' -> id={1}" -f $n,$id) 'DEBUG'
        }
        if($keyTrimmed -ne $key -and -not $index.ContainsKey($keyTrimmed)){
          $index[$keyTrimmed] = [int]$id
        }
      }

      if($recs.Count -lt $ps){ break }
      $page++
      if($page -gt 100){
        Write-Log ("Get-SecretNameIndexForFolder: safety stop paging at page={0} folderId={1}" -f $page,$folderId) 'WARN'
        break
      }
    }
    catch{
      Write-Log ("Get-SecretNameIndexForFolder: Error on page {0}: {1}" -f $page,$_.Exception.Message) 'WARN'
      break
    }
  }

  Write-Log ("Get-SecretNameIndexForFolder: folderId={0} total indexed={1}" -f $folderId,$index.Count) 'DEBUG'
  return $index
}

function Add-IfValidInt([hashtable]$h,[string]$key,$value){
  if($null -eq $value){ return }
  try{
    $i=[int]$value
    if($i -ge 1){ $h[$key]=$i }
  }catch{}
}

function Resolve-TargetTemplateId([string]$tgtApiBase,[string]$tgtTok,$exportSecret,[bool]$MapByName=$false){
  $srcTypeId = Get-PropValue $exportSecret @('SecretTypeId','secretTypeId') $null
  $srcTypeName = Get-PropValue $exportSecret @('SecretTypeName','secretTypeName') $null
  
  if($MapByName -and -not [string]::IsNullOrWhiteSpace($srcTypeName)){
    # Try to find template by name
    try{
      $templates = SS $tgtApiBase GET 'secret-templates' $tgtTok $null @{'filter.searchText'=$srcTypeName}
      $recs = @(Get-Records $templates)
      foreach($t in $recs){
        $tname = Get-PropValue $t @('name','Name') $null
        if($tname -eq $srcTypeName){
          return [int](Get-PropValue $t @('id','Id') 0)
        }
      }
    } catch {}
  }
  
  # Fall back to ID mapping
  if($srcTypeId -ne $null -and [int]$srcTypeId -gt 0){
    return [int]$srcTypeId
  }
  
  return $null
}

# FINAL override – place this AFTER all other definitions of Get-SecretNameIndexForFolder
function Get-SecretNameIndexForFolder([string]$apiBase,[string]$tok,[int]$folderId){
  $index = @{}
  $ps    = 200

  Write-Log ("Get-SecretNameIndexForFolder: Building index for folderId={0} using /secrets endpoint" -f $folderId) 'DEBUG'

  # PERF FIX: Some Delinea API versions return 0 results for /secrets?filter.folderId=X
  # unless filter.searchText is also present. Try plain query first, then retry with
  # searchText='' / '*' workarounds if the first pass yields nothing. This drastically
  # reduces per-secret DUPLICATE CHECK FALLBACK calls in Skip/Update mode.
  $attempts = @(
    @{ Label='plain';    Extra=@{} },
    @{ Label='empty-st'; Extra=@{ 'filter.searchText' = '' } },
    @{ Label='wild-st';  Extra=@{ 'filter.searchText' = '*' } }
  )

  foreach($attempt in $attempts){
    if($index.Count -gt 0){ break }   # already got results, no need to retry

    $page  = 1
    $totalThisAttempt = 0
    while($true){
      $q = @{
        'filter.folderId'  = $folderId
        'filter.page'      = $page
        'filter.pageSize'  = $ps
      }
      foreach($k in $attempt.Extra.Keys){ $q[$k] = $attempt.Extra[$k] }

      try{
      $resp = SS $apiBase GET 'secrets' $tok $null $q
      $recs = @(Get-Records $resp)
      $totalThisAttempt += $recs.Count

      Write-Log ("Get-SecretNameIndexForFolder: folderId={0} attempt={1} page={2} returned {3} records" -f $folderId,$attempt.Label,$page,$recs.Count) 'DEBUG'

      foreach($x in $recs){
        $id = $null
        foreach($idKey in @('id','Id','secretId','SecretId')){
          if($x.PSObject.Properties.Name -contains $idKey){
            try{ $id = [int]$x.$idKey; if($id -gt 0){ break } } catch {}
          }
        }
        if($id -le 0 -or $null -eq $id){ continue }

        $n = $null
        foreach($nameKey in @('name','Name','secretName','SecretName')){
          if($x.PSObject.Properties.Name -contains $nameKey){
            $candidate = [string]$x.$nameKey
            if(-not [string]::IsNullOrWhiteSpace($candidate)){
              $n = $candidate
              break
            }
          }
        }

        if([string]::IsNullOrWhiteSpace($n)){
          Write-Log ("Get-SecretNameIndexForFolder: Could not extract name for secretId={0}" -f $id) 'DEBUG'
          continue
        }

        $key = $n.ToLowerInvariant()
        $keyTrimmed = $n.Trim().ToLowerInvariant()
        
        if(-not $index.ContainsKey($key)){
          $index[$key] = [int]$id
          Write-Log ("  Index: '{0}' -> id={1}" -f $n,$id) 'DEBUG'
        }
        if($keyTrimmed -ne $key -and -not $index.ContainsKey($keyTrimmed)){
          $index[$keyTrimmed] = [int]$id
        }
      }

      if($recs.Count -lt $ps){ break }
      $page++
      if($page -gt 100){
        Write-Log ("Get-SecretNameIndexForFolder: safety stop paging at page={0} folderId={1}" -f $page,$folderId) 'WARN'
        break
      }
    }
    catch{
      Write-Log ("Get-SecretNameIndexForFolder: Error on page {0} attempt={1}: {2}" -f $page,$attempt.Label,$_.Exception.Message) 'WARN'
      break
    }
    } # end while
    if($totalThisAttempt -gt 0){
      Write-Log ("Get-SecretNameIndexForFolder: folderId={0} attempt='{1}' succeeded with {2} records" -f $folderId,$attempt.Label,$totalThisAttempt) 'DEBUG'
    }
  } # end foreach attempt

  Write-Log ("Get-SecretNameIndexForFolder: folderId={0} total indexed={1}" -f $folderId,$index.Count) 'DEBUG'
  return $index
}
function Get-SecretLookupPage([string]$ApiBase,[string]$Token,[int]$Page,[int]$PageSize,[string]$Search,[Nullable[int]]$FolderId){
  $q = @{
    'filter.searchText' = $Search
    'filter.page' = $Page
    'filter.pageSize' = $PageSize
  }
  
  if($FolderId -ne $null -and $FolderId -gt 0){
    $q['filter.folderId'] = $FolderId
  }
  
  try{
    $resp = SS $ApiBase GET 'secrets/lookup' $Token $null $q
    return @{
      endpoint = 'secrets/lookup'
      records = @(Get-Records $resp)
    }
  } catch {
    Write-Log ("Secret lookup failed: {0}" -f $_) 'ERROR'
    return @{
      endpoint = 'secrets/lookup'
      records = @()
    }
  }
}

function Get-FolderById([string]$apiBase,[string]$tok,[int]$folderId){
  return SS $apiBase GET ("folders/{0}" -f $folderId) $tok $null $null
}


function Get-FolderPath-Source([string]$srcApi,[string]$srcTok,[int]$srcFolderId){
  try{
    $folder = Get-FolderById -apiBase $srcApi -tok $srcTok -folderId $srcFolderId
    return [string](Get-PropValue $folder @('folderPath','FolderPath','path','Path') "\Folder$srcFolderId")
  } catch {
    return "\Folder$srcFolderId"
  }
}

function Get-FolderPermissions([string]$apiBase,[string]$tok,[int]$folderId){
  $perms = @()
  $page = 1
  while($true){
    $resp = SS $apiBase GET 'folder-permissions' $tok $null @{
      'filter.folderId' = $folderId
      'filter.page' = $page
      'filter.pageSize' = 200
    }
    $recs = @(Get-Records $resp)
    $perms += $recs
    if($recs.Count -lt 200){ break }
    $page++
  }
  return $perms
}

function Get-SecretSettings([string]$apiBase,[string]$tok,[int]$secretId){
  try{
    return SS $apiBase GET ("secrets/{0}/settings" -f $secretId) $tok $null $null
  } catch {
    return $null
  }
}

function Export-TemplateXml([string]$apiBase,[string]$tok,[int]$templateId){
  try{
    return SS $apiBase GET ("secret-templates/{0}/export" -f $templateId) $tok $null $null
  } catch {
    return $null
  }
}

function Get-GroupNameById([string]$apiBase,[string]$tok,[int]$groupId){
  try{
    $g = SS $apiBase GET ("groups/{0}" -f $groupId) $tok $null $null
    return [string](Get-PropValue $g @('name','groupName','Name','GroupName') $null)
  } catch {
    return $null
  }
}

# Stub functions for features not yet implemented

function Export-DelineaWebImportPasteFile($InputJsonPath,$OutCsvPath){
  Write-Log "Web import CSV stub called (not yet implemented)" 'DEBUG'
}

function Export-SecretsJsonToCsvBundle($InputJsonPath,$OutDir){
  Write-Log "CSV bundle export stub called (not yet implemented)" 'DEBUG'
  return @{outDir=$OutDir}
}

function Create-ImportRunRootFolderIfNeeded($tgtApi,$tgtTok,$migrationRootId,$useFolderTree,$dryRun){
  return $migrationRootId
}


function Remap-PermissionPrincipals($TgtApi,$TgtTok,$perm){
  return $perm
}

function Apply-SecretShares($apiBase,$tok,$secretId,$perms){
  foreach($p in @($perms)){
    $gid = Get-PropValue $p @('groupId','GroupId') 0
    $rid = Get-PropValue $p @('secretAccessRoleId','SecretAccessRoleId') $null
    $rn = Get-PropValue $p @('secretAccessRoleName','SecretAccessRoleName') $null
    
    Write-Log ("DEBUG: POST secret-permissions: secretId={0} userId=0 groupId={1} roleId={2} roleName='{3}'" -f $secretId,$gid,$rid,$rn) 'DEBUG'
    
    $payload = @{
      secretId = $secretId
      groupId = $gid
    }
    
    if($rid -ne $null){ $payload['secretAccessRoleId'] = [int]$rid }
    if($rn){ $payload['secretAccessRoleName'] = $rn }
    
    try{
      SS $apiBase POST 'secret-permissions' $tok $payload $null | Out-Null
    } catch {
      Write-Log ("ERROR: Add-SecretPermission PAYLOAD FAILED: {0}" -f ($payload | ConvertTo-Json -Compress)) 'ERROR'
      throw
    }
  }
}

function Add-SecretPermission($apiBase,$tok,$secretId,$perm){
  Apply-SecretShares -apiBase $apiBase -tok $tok -secretId $secretId -perms @($perm)
}

function Snapshot-TargetSecretForRollback($tgtApi,$tgtTok,$secretId,$secretName,$folderId){
  Write-Log ("Rollback snapshot stub: secretId={0}" -f $secretId) 'DEBUG'
}


$script:PrincipalCache = @{
  TgtUserNameToId     = @{}
  TgtUserDisplayToId  = @{}
  TgtGroupNameToId    = @{}
}

function Resolve-TargetUserId([string]$tgtApi,[string]$tgtTok,[string]$userName,[string]$displayNameWithDomain,[string]$displayName){
  # 1) userName exact match
  if(-not [string]::IsNullOrWhiteSpace($userName)){
    $k=$userName.ToLowerInvariant()
    if($script:PrincipalCache.TgtUserNameToId.ContainsKey($k)){ return [int]$script:PrincipalCache.TgtUserNameToId[$k] }

    $r = SS $tgtApi GET 'users' $tgtTok $null @{ 'filter.searchText'=$userName; 'filter.page'=1; 'filter.pageSize'=50 }
    foreach($u in @(Get-Records $r)){
      $un = Get-PropValue $u @('userName','UserName') $null
      $id = Get-PropValue $u @('id','Id') $null
      if($un -and $id -ne $null -and $un.Equals($userName,[System.StringComparison]::OrdinalIgnoreCase)){
        $script:PrincipalCache.TgtUserNameToId[$k]=[int]$id
        return [int]$id
      }
    }
  }

  # 2) displayNameWithDomain then displayName fallback (best effort)
  $dispCandidates=@()
  if($displayNameWithDomain){ $dispCandidates += [string]$displayNameWithDomain }
  if($displayName){ $dispCandidates += [string]$displayName }

  foreach($disp in $dispCandidates){
    if([string]::IsNullOrWhiteSpace($disp)){ continue }
    $k2=$disp.ToLowerInvariant()
    if($script:PrincipalCache.TgtUserDisplayToId.ContainsKey($k2)){ return [int]$script:PrincipalCache.TgtUserDisplayToId[$k2] }

    $r = SS $tgtApi GET 'users' $tgtTok $null @{ 'filter.searchText'=$disp; 'filter.page'=1; 'filter.pageSize'=50 }
    $matches=@()
    foreach($u in @(Get-Records $r)){
      $dn = Get-PropValue $u @('displayName','DisplayName') $null
      $un = Get-PropValue $u @('userName','UserName') $null
      $id = Get-PropValue $u @('id','Id') $null
      if($id -eq $null){ continue }

      if(($dn -and $dn.Equals($disp,[System.StringComparison]::OrdinalIgnoreCase)) -or
         ($un -and $un.Equals($disp,[System.StringComparison]::OrdinalIgnoreCase))){
        $matches += [int]$id
      }
    }
    if($matches.Count -eq 1){
      $script:PrincipalCache.TgtUserDisplayToId[$k2]=[int]$matches[0]
      return [int]$matches[0]
    }
    if($matches.Count -gt 1){
      Write-Log ("REMAP: ambiguous displayName fallback '{0}' (matches={1}); skipping" -f $disp,($matches -join ',')) 'WARN'
      return $null
    }
  }

  return $null
}

function Resolve-TargetGroupId([string]$tgtApi,[string]$tgtTok,[string]$groupName){
  if([string]::IsNullOrWhiteSpace($groupName)){ return $null }
  $k=$groupName.ToLowerInvariant()
  if($script:PrincipalCache.TgtGroupNameToId.ContainsKey($k)){ return [int]$script:PrincipalCache.TgtGroupNameToId[$k] }

  $r = SS $tgtApi GET 'groups' $tgtTok $null @{ 'filter.searchText'=$groupName; 'filter.page'=1; 'filter.pageSize'=50 }
  foreach($g in @(Get-Records $r)){
    $nm = Get-PropValue $g @('name','Name') $null
    $id = Get-PropValue $g @('id','Id') $null
    if($nm -and $id -ne $null -and $nm.Equals($groupName,[System.StringComparison]::OrdinalIgnoreCase)){
      $script:PrincipalCache.TgtGroupNameToId[$k]=[int]$id
      return [int]$id
    }
  }
  return $null
}

function Remap-PermissionPrincipals{
  param(
    [string]$TgtApi,[string]$TgtTok,
    $perm
  )

  # Copy to plain hashtable
  $p = @{}
  foreach($prop in $perm.PSObject.Properties){
    if($prop.MemberType -in @('NoteProperty','Property')){
      $p[$prop.Name] = $prop.Value
    }
  }

  $gid = $null; $uid = $null
  try{ $gid = [int](Get-PropValue $perm @('groupId','GroupId') $null) }catch{}
  try{ $uid = [int](Get-PropValue $perm @('userId','UserId') $null) }catch{}

  # --- User remap (unchanged) ---
  if($uid -and $uid -gt 0){
    $srcUserName = Get-PropValue $perm @('userName','UserName') $null
    $dnwd = Get-PropValue $perm @('displayNameWithDomain','DisplayNameWithDomain') $null
    $dn   = Get-PropValue $perm @('displayName','DisplayName','userDisplayName','UserDisplayName') $null

    $tgtUserId = Resolve-TargetUserId -tgtApi $TgtApi -tgtTok $TgtTok -userName ([string]$srcUserName) -displayNameWithDomain ([string]$dnwd) -displayName ([string]$dn)
    if($tgtUserId -eq $null){
      Write-Log ("REMAP: could not resolve target userId for source (userId={0}, userName='{1}', displayNameWithDomain='{2}', displayName='{3}')" -f $uid,$srcUserName,$dnwd,$dn) 'WARN'
      return $null
    }

    $p['userId']  = $tgtUserId
    $p['groupId'] = 0
    return $p
  }

  # --- Group remap (FIXED) ---
  if($gid -and $gid -gt 0){
    $srcGroupName = Get-PropValue $perm @('groupName','GroupName','name','Name') $null

    # If groupName is missing, DO NOT drop the permission record.
    # Keep groupId as-is (works for same-tenant migrations).
    if([string]::IsNullOrWhiteSpace([string]$srcGroupName)){
      $p['groupId'] = $gid
      $p['userId']  = 0
      Write-Log ("REMAP: groupName missing; keeping groupId={0} as-is (same-tenant safe fallback)." -f $gid) 'DEBUG'
      return $p
    }

    $tgtGroupId = Resolve-TargetGroupId -tgtApi $TgtApi -tgtTok $TgtTok -groupName ([string]$srcGroupName)
    if($tgtGroupId -eq $null){
      Write-Log ("REMAP: could not resolve target groupId for source (groupId={0}, groupName='{1}')" -f $gid,$srcGroupName) 'WARN'
      return $null
    }

    $p['groupId'] = $tgtGroupId
    $p['userId']  = 0
    return $p
  }

  return $p
}

# ---------------- Import-run tracking ----------------
$script:ImportRunCreatedFolderIds = New-Object 'System.Collections.Generic.List[int]'
$script:ImportRunCreatedFoldersById = @{}
$script:ImportRunCreatedSecretIds = New-Object 'System.Collections.Generic.List[int]'
$script:ImportRunCreatedSecretsById = @{}
$script:ImportRunUpdatedSecretIds = New-Object 'System.Collections.Generic.List[int]'
$script:ImportRunUpdatedSecretsById = @{} # id -> @{name; folderId; rollbackFile}
$script:LastImportRunRootFolderId = $null

function Reset-ImportRunCreatedFolders {
  $script:ImportRunCreatedFolderIds = New-Object 'System.Collections.Generic.List[int]'
  $script:ImportRunCreatedFoldersById = @{}
}
function Reset-ImportRunCreatedObjects {
  Reset-ImportRunCreatedFolders
  $script:ImportRunCreatedSecretIds = New-Object 'System.Collections.Generic.List[int]'
  $script:ImportRunCreatedSecretsById = @{}
  $script:ImportRunUpdatedSecretIds = New-Object 'System.Collections.Generic.List[int]'
  $script:ImportRunUpdatedSecretsById = @{}
}


# ---------------- Rollback snapshot helpers ----------------
function Ensure-RollbackDir {
  $dir = $Global:Config.Tgt.RollbackDir
  if([string]::IsNullOrWhiteSpace($dir)){
    $dir = Join-Path $BaseDir "rollback"
    $Global:Config.Tgt.RollbackDir = $dir
  }
  if(-not (Test-Path $dir)){ New-Item -ItemType Directory -Path $dir | Out-Null }
  return $dir
}

function Get-SecretDetail([string]$apiBase,[string]$tok,[int]$secretId){
  SS $apiBase GET ("secrets/{0}" -f $secretId) $tok $null $null
}

function Get-RollbackFilePath([int]$secretId,[string]$secretName){
  $dir = Ensure-RollbackDir
  $safeName = ($secretName -replace '[^\w\-. ]','_')
  if([string]::IsNullOrWhiteSpace($safeName)){ $safeName = "secret" }
  $ts = (Get-Date -Format "yyyyMMdd-HHmmss")
  return (Join-Path $dir ("rollback-secret-{0}-{1}-{2}.json" -f $secretId,$safeName,$ts))
}

function Snapshot-TargetSecretForRollback([string]$tgtApi,[string]$tgtTok,[int]$secretId,[string]$secretName,[int]$folderId){
  $detail = Get-SecretDetail -apiBase $tgtApi -tok $tgtTok -secretId $secretId
  $file = Get-RollbackFilePath -secretId $secretId -secretName $secretName
  Ensure-Dir $file
  ($detail | ConvertTo-Json -Depth 80) | Set-Content -Path $file -Encoding UTF8

  try { [void]$script:ImportRunUpdatedSecretIds.Add($secretId) } catch {}
  $script:ImportRunUpdatedSecretsById[[string]$secretId] = @{ id=$secretId; name=$secretName; folderId=$folderId; rollbackFile=$file }
  Write-Log ("ROLLBACK SNAPSHOT: saved target secretId={0} name='{1}' to {2}" -f $secretId,$secretName,$file) 'INFO'
}

# ---------------- Template migration ----------------
function Export-TemplateXml([string]$apiBase,[string]$tok,[int]$templateId){
  $r = SS $apiBase GET ("secret-templates/{0}/export" -f $templateId) $tok $null $null
  $xml = Get-PropValue $r @('exportFileText','ExportFileText') $null
  if([string]::IsNullOrWhiteSpace($xml)){ throw "Template export returned empty exportFileText for templateId=$templateId" }
  return [string]$xml
}
function Import-TemplateXml([string]$apiBase,[string]$tok,[string]$templateXml){
  $body=@{ data=@{ templateXml=$templateXml } }
  SS $apiBase POST 'secret-templates/import' $tok $body $null | Out-Null
}
function Get-TemplateNameFromXml([string]$templateXml){
  if([string]::IsNullOrWhiteSpace($templateXml)){ return $null }
  try{
    [xml]$x = $templateXml

    function Get-NodeInnerText([xml]$doc,[string]$xpath){
      try{
        $n = $doc.SelectSingleNode($xpath)
        if($n -and -not [string]::IsNullOrWhiteSpace([string]$n.InnerText)){
          return [string]$n.InnerText
        }
      } catch {}
      return $null
    }

    function Get-NodeAttr([xml]$doc,[string]$xpath,[string]$attr){
      try{
        $n = $doc.SelectSingleNode($xpath)
        if($n -and $n.Attributes -and $n.Attributes[$attr]){
          $v = [string]$n.Attributes[$attr].Value
          if(-not [string]::IsNullOrWhiteSpace($v)){ return $v }
        }
      } catch {}
      return $null
    }

    $candidates = @(
      (Get-NodeInnerText $x "//SecretTemplate/Name"),
      (Get-NodeInnerText $x "//SecretTemplate/TemplateName"),
      (Get-NodeAttr     $x "//SecretTemplate" "name"),
      (Get-NodeInnerText $x "//secretTemplate/name"),
      (Get-NodeInnerText $x "//name")
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    if(@($candidates).Count -gt 0){ return [string]$candidates[0] }
    return $null
  } catch {
    return $null
  }
}

function Test-TargetTemplateExistsByName([string]$tgtApiBase,[string]$tgtTok,[string]$templateName){
  if([string]::IsNullOrWhiteSpace($templateName)){ return $false }
  $idx = Get-TemplateNameIndex -apiBase $tgtApiBase -tok $tgtTok
  return $idx.ContainsKey($templateName.ToLowerInvariant())
}

# ---------------- Roles cache (for BULK group secret shares) ----------------
$script:RoleNameToIdCache = @{}
function Get-RoleNameToIdMap([string]$apiBase,[string]$tok){
  if($script:RoleNameToIdCache.ContainsKey($apiBase)){ return $script:RoleNameToIdCache[$apiBase] }
  $map=@{}
  $page=1; $ps=200
  do{
    $q=@{'filter.page'=$page;'filter.pageSize'=$ps}
    $r = SS $apiBase GET 'roles' $tok $null $q
    $recs = if(Has-Prop $r 'records'){ @($r.records) } else { @($r) }
    foreach($role in $recs){
      $name = Get-PropValue $role @('name','Name') $null
      $id   = Get-PropValue $role @('id','Id') $null
      $en   = Get-PropValue $role @('enabled','Enabled') $true
      if($name -and $id -ne $null -and [bool]$en){
        $map[[string]$name.ToLowerInvariant()] = [int]$id
      }
    }
    $page++
  }while(@($recs).Count -ge $ps)
  $script:RoleNameToIdCache[$apiBase] = $map
  return $map
}

function Add-SecretPermission([string]$apiBase,[string]$tok,[int]$secretId,$perm){
  $body=@{ secretId = [int]$secretId }

  # Principal
  $gid = Get-PropValue $perm @('groupId','GroupId') $null
  $uid = Get-PropValue $perm @('userId','UserId') $null
  if($gid -ne $null -and [int]$gid -gt 0){ $body.groupId = [int]$gid }
  elseif($uid -ne $null -and [int]$uid -gt 0){ $body.userId = [int]$uid }
  else{
    Write-Log ("Add-SecretPermission SKIP: no principal userId/groupId for secretId={0}" -f $secretId) 'WARN'
    return
  }

  # Role: accept many key variants
  $rid = Get-PropValue $perm @(
    'secretAccessRoleId','SecretAccessRoleId',
    'secretRoleId','SecretRoleId',
    'roleId','RoleId'
  ) $null

  $rname = [string](Get-PropValue $perm @(
    'secretAccessRoleName','SecretAccessRoleName',
    'secretRoleName','SecretRoleName',
    'roleName','RoleName'
  ) $null)

  # Put roleId if possible
  if($rid -ne $null){
    try{ $body.secretAccessRoleId = [int]$rid } catch {}
  }

  # Also put roleName when present (some tenants require it even if id exists)
  if(-not [string]::IsNullOrWhiteSpace($rname)){
    $body.secretAccessRoleName = $rname
  }

  # If still missing role, do NOT call the API (this prevents your 400)
  if((-not $body.ContainsKey('secretAccessRoleId')) -and (-not $body.ContainsKey('secretAccessRoleName'))){
    Write-Log ("Add-SecretPermission SKIP: missing role (secretId={0}) permKeys={1}" -f `
      $secretId, ($perm.PSObject.Properties.Name -join ',')) 'WARN'
    
    # Log the actual permission object for debugging
    Write-Log ("Add-SecretPermission DEBUG: perm content: {0}" -f ($perm | ConvertTo-Json -Compress)) 'DEBUG'
    return
  }

  # Optional domain
  $dn = Get-PropValue $perm @('domainName','DomainName') $null
  if($dn){ $body.domainName = [string]$dn }

  # Log what we're about to send
  Write-Log ("POST secret-permissions: secretId={0} userId={1} groupId={2} roleId={3} roleName='{4}'" -f `
    $secretId,
    ($(if($body.ContainsKey('userId')){$body.userId}else{0})),
    ($(if($body.ContainsKey('groupId')){$body.groupId}else{0})),
    ($(if($body.ContainsKey('secretAccessRoleId')){$body.secretAccessRoleId}else{''})),
    ($(if($body.ContainsKey('secretAccessRoleName')){$body.secretAccessRoleName}else{''}))
  ) 'DEBUG'

  try{
    SS $apiBase POST 'secret-permissions' $tok $body $null | Out-Null
  }
  catch{
    # Log the payload that failed
    Write-Log ("Add-SecretPermission PAYLOAD FAILED: {0}" -f ($body | ConvertTo-Json -Compress)) 'ERROR'
    throw
  }
}

function Apply-SecretShares([string]$apiBase,[string]$tok,[int]$secretId,$perms){
  $roleMap = Get-RoleNameToIdMap $apiBase $tok
  $bulkGroupPerms=@()
  $userPerms=@()

  # normalize perms to array
  $permArr=@()
  if($null -eq $perms){
    $permArr=@()
  } elseif(($perms -is [System.Collections.IEnumerable]) -and -not ($perms -is [string])){
    foreach($x in $perms){ $permArr += $x }
  } else {
    $permArr = @($perms)
  }

  foreach($p in $permArr){
    if($null -eq $p){ continue }

    $gid = Get-PropValue $p @('groupId','GroupId') $null
    $uid = Get-PropValue $p @('userId','UserId') $null

    if($gid -ne $null -and [int]$gid -gt 0){
      # Prefer roleId from export
      $roleId = $null
      $rid = Get-PropValue $p @('secretAccessRoleId','SecretAccessRoleId') $null
      if($rid -ne $null){
        try{ $roleId = [int]$rid } catch {}
      }

      if($roleId -eq $null){
        $roleName = [string](Get-PropValue $p @('secretAccessRoleName','SecretAccessRoleName') $null)
        if([string]::IsNullOrWhiteSpace($roleName)){ continue }
        $rk = $roleName.ToLowerInvariant()
        if(-not $roleMap.ContainsKey($rk)){
          Write-Log ("SHARE: unknown role '{0}' in target roles; skipping groupId={1}" -f $roleName,$gid) 'WARN'
          continue
        }
        $roleId = [int]$roleMap[$rk]
      }

      $bulkGroupPerms += @{ groupId=[int]$gid; isPersonal=$false; secretAccessRoleId=[int]$roleId }
    }
    elseif($uid -ne $null -and [int]$uid -gt 0){
      $userPerms += $p
    }
  }

  if($bulkGroupPerms.Count -gt 0){
    $body=@{ data=@{ secretIds=@([int]$secretId); permissions=@($bulkGroupPerms) } }
    $r = SS $apiBase POST 'bulk-secret-operations/add-share' $tok $body $null
    $bid = Get-PropValue $r @('bulkOperationId','BulkOperationId') $null
    Write-Log ("BULK SHARE: secretId={0} groupPerms={1} bulkOperationId={2}" -f $secretId,$bulkGroupPerms.Count,$bid) 'DEBUG'
  } else {
    Write-Log ("BULK SHARE: secretId={0} groupPerms=0" -f $secretId) 'DEBUG'
  }

  foreach($up in @($userPerms)){
    try{
      Add-SecretPermission -apiBase $apiBase -tok $tok -secretId $secretId -perm $up
      $uid2 = Get-PropValue $up @('userId','UserId') $null
      $rid2 = Get-PropValue $up @('secretAccessRoleId','SecretAccessRoleId') $null
      $rn2  = [string](Get-PropValue $up @('secretAccessRoleName','SecretAccessRoleName') $null)
      Write-Log ("USER SHARE: secretId={0} userId={1} roleId={2} roleName='{3}'" -f $secretId,$uid2,$rid2,$rn2) 'INFO'
    }
    catch{
      Write-Log ("USER SHARE failed for secretId={0}: {1}" -f $secretId,($_ | Out-String)) 'WARN'
    }
  }
}

# ---- Parallel bulk-share dispatcher (used by Reconcile Missing Permissions) ----
# Sends multiple bulk-secret-operations/add-share POSTs concurrently via a single
# reused HttpClient. Each input item is one secret's worth of perms; the helper
# returns an array (same order) of @{ SecretId; Ok; Error }. User-level perms
# (rare in practice; only when groupId is absent) fall through to the existing
# sequential Add-SecretPermission for that secret so per-user logic is preserved.
$script:ReconHttpClient = $null
function Get-ReconHttpClient([string]$tok){
  if($script:ReconHttpClient -ne $null){
    try{
      $script:ReconHttpClient.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer',$tok)
      return $script:ReconHttpClient
    } catch {
      try{ $script:ReconHttpClient.Dispose() } catch {}
      $script:ReconHttpClient = $null
    }
  }
  $h = New-Object System.Net.Http.HttpClientHandler
  $h.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
  $c = New-Object System.Net.Http.HttpClient($h)
  $c.Timeout = [TimeSpan]::FromSeconds(120)
  $c.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer',$tok)
  $c.DefaultRequestHeaders.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('application/json'))
  $script:ReconHttpClient = $c
  return $c
}

function Apply-SecretShares-Batch-Parallel([string]$apiBase,[string]$tok,$items,[ref]$TokenRef = $null){
  # items: array of hashtables @{ SecretId=<int>; Perms=<array> }
  # Returns: array of @{ SecretId; Ok; Error } in input order.
  # If any task returns HTTP 401, this helper does ONE token refresh (via the
  # same Token() function the SS wrapper uses) and re-submits only the failed
  # items. When $TokenRef is supplied, the refreshed token is written back so
  # the caller's $tgtTok stays in sync across subsequent batches.
  if(-not $items -or @($items).Count -eq 0){ return ,@() }
  $itemArr = @($items)
  $results = New-Object 'System.Collections.Generic.List[hashtable]'
  $roleMap = Get-RoleNameToIdMap $apiBase $tok
  $client  = Get-ReconHttpClient $tok
  $url     = $apiBase.TrimEnd('/') + '/bulk-secret-operations/add-share'

  $built = New-Object 'System.Collections.Generic.List[psobject]'
  foreach($it in $itemArr){
    $secretId = [int]$it.SecretId
    $bulkGroupPerms = @()
    $userPerms      = @()
    foreach($p in @($it.Perms)){
      if($null -eq $p){ continue }
      $gid = Get-PropValue $p @('groupId','GroupId') $null
      $uid = Get-PropValue $p @('userId','UserId') $null
      if($gid -ne $null -and [int]$gid -gt 0){
        $roleId = $null
        $rid = Get-PropValue $p @('secretAccessRoleId','SecretAccessRoleId') $null
        if($rid -ne $null){ try{ $roleId = [int]$rid } catch {} }
        if($roleId -eq $null){
          $rn = [string](Get-PropValue $p @('secretAccessRoleName','SecretAccessRoleName') $null)
          if(-not [string]::IsNullOrWhiteSpace($rn)){
            $rk = $rn.ToLowerInvariant()
            if($roleMap.ContainsKey($rk)){ $roleId = [int]$roleMap[$rk] }
          }
        }
        if($roleId -ne $null){
          $bulkGroupPerms += @{ groupId=[int]$gid; isPersonal=$false; secretAccessRoleId=[int]$roleId }
        }
      } elseif($uid -ne $null -and [int]$uid -gt 0){
        $userPerms += $p
      }
    }
    $body = $null
    if($bulkGroupPerms.Count -gt 0){
      $body = @{ data = @{ secretIds = @($secretId); permissions = @($bulkGroupPerms) } }
    }
    [void]$built.Add([PSCustomObject]@{ SecretId=$secretId; GroupBody=$body; UserPerms=$userPerms })
  }

  # ---- Inner dispatcher: POST all GroupBody items concurrently, return per-item ok/err/status.
  $dispatch = {
    param($itemsToSend,$httpClient)
    $tList = New-Object 'System.Collections.Generic.List[psobject]'
    foreach($b in $itemsToSend){
      if($null -eq $b.GroupBody){
        [void]$tList.Add([PSCustomObject]@{ Item=$b; Task=$null })
        continue
      }
      $j = $b.GroupBody | ConvertTo-Json -Depth 10 -Compress
      $c = New-Object System.Net.Http.StringContent($j,[System.Text.Encoding]::UTF8,'application/json')
      [void]$tList.Add([PSCustomObject]@{ Item=$b; Task=$httpClient.PostAsync($url,$c) })
    }
    $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
    while($true){
      $allDone = $true
      foreach($t in $tList){ if($t.Task -ne $null -and -not $t.Task.IsCompleted){ $allDone=$false; break } }
      if($allDone){ break }
      if($sw2.Elapsed.TotalSeconds -ge 180){ break }
      try{ [System.Windows.Forms.Application]::DoEvents() } catch {}
      Start-Sleep -Milliseconds 25
    }
    $out = New-Object 'System.Collections.Generic.List[psobject]'
    foreach($t in $tList){
      $ok = $true; $errMsg = $null; $sc = 0
      if($t.Task -ne $null){
        try{
          $resp = $t.Task.Result
          $sc   = [int]$resp.StatusCode
          if(-not $resp.IsSuccessStatusCode){
            $ok = $false
            $errMsg = ("HTTP {0}" -f $sc)
            try{
              $rb = $resp.Content.ReadAsStringAsync().Result
              if($rb){ $errMsg += " - " + ($rb.Substring(0,[Math]::Min(200,$rb.Length))) }
            } catch {}
          }
        } catch {
          $ok = $false; $errMsg = $_.Exception.Message
        }
      }
      [void]$out.Add([PSCustomObject]@{ Item=$t.Item; Ok=$ok; Error=$errMsg; Status=$sc })
    }
    return ,$out.ToArray()
  }

  $first = & $dispatch $built.ToArray() $client

  # Detect 401s and do ONE token refresh + retry of just those items.
  $needsRefresh = @($first | Where-Object { $_.Status -eq 401 })
  if($needsRefresh.Count -gt 0){
    $refreshedTok = $null
    try{
      # Determine which side this token belongs to and re-acquire.
      $__side = $null
      try{
        if($Global:TokenCache.Tgt -and $Global:TokenCache.Tgt.access_token -eq $tok){ $__side = 'Tgt' }
        elseif($Global:TokenCache.Src -and $Global:TokenCache.Src.access_token -eq $tok){ $__side = 'Src' }
      } catch {}
      if(-not $__side){ $__side = 'Tgt' }   # recon always runs against Tgt, default if cache lookup misses
      Write-Log ("Recon parallel: {0} POSTs returned 401 - refreshing {1} token and retrying." -f $needsRefresh.Count,$__side) 'WARN'
      $Global:TokenCache[$__side] = $null
      $__pwdTb = $null
      try{
        if($__side -eq 'Src'){ $__pwdTb = Get-Variable -Name 'tbSrcPwd' -Scope Script -ValueOnly -ErrorAction SilentlyContinue }
        else                 { $__pwdTb = Get-Variable -Name 'tbTgtPwd' -Scope Script -ValueOnly -ErrorAction SilentlyContinue }
      } catch {}
      $refreshedTok = Token $__side $__pwdTb
    } catch {
      Write-Log ("Recon parallel: token refresh failed ({0}); reporting 401s as errors." -f $_.Exception.Message) 'WARN'
      $refreshedTok = $null
    }

    if(-not [string]::IsNullOrWhiteSpace($refreshedTok)){
      # Update the cached HttpClient's auth header and let caller pick up new token.
      try{
        $client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer',$refreshedTok)
      } catch {}
      if($TokenRef){ $TokenRef.Value = $refreshedTok }
      $tok = $refreshedTok

      $retryItems = @($needsRefresh | ForEach-Object { $_.Item })
      $retry      = & $dispatch $retryItems $client
      # Merge retry results back into the first-pass list.
      $byId = @{}
      foreach($r in $retry){ $byId[[int]$r.Item.SecretId + 0] = $r }
      $merged = New-Object 'System.Collections.Generic.List[psobject]'
      foreach($r0 in $first){
        if($r0.Status -eq 401 -and $byId.ContainsKey([int]$r0.Item.SecretId + 0)){
          [void]$merged.Add($byId[[int]$r0.Item.SecretId + 0])
        } else {
          [void]$merged.Add($r0)
        }
      }
      $first = $merged.ToArray()
    }
  }

  foreach($t in $first){
    $ok     = [bool]$t.Ok
    $errMsg = [string]$t.Error
    if($ok -and $t.Item.UserPerms -and $t.Item.UserPerms.Count -gt 0){
      foreach($up in $t.Item.UserPerms){
        try{ Add-SecretPermission -apiBase $apiBase -tok $tok -secretId ([int]$t.Item.SecretId) -perm $up }
        catch { $ok = $false; $errMsg = $_.Exception.Message; break }
      }
    }
    [void]$results.Add(@{ SecretId=[int]$t.Item.SecretId; Ok=$ok; Error=$errMsg })
  }
  return ,$results.ToArray()
}

# ---------------- Folder-tree create + mapping ----------------
$script:FolderPathCacheSrc = @{}
$script:FolderMapTgt = @{}
function Normalize-FolderPath([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ return $null }
  $p = $p.Trim()
  if(-not $p.StartsWith('\')){ $p = "\" + $p }
  while($p -match '\\\\'){ $p = $p -replace '\\\\','\' }
  $p
}

function Get-FolderById([string]$apiBase,[string]$tok,[int]$folderId){
  return SS $apiBase GET ("folders/{0}" -f $folderId) $tok $null $null
}

function Create-Folder([string]$apiBase,[string]$tok,[int]$parentId,[string]$name){
  if([string]::IsNullOrWhiteSpace($name)){ throw "Create-Folder: name is blank." }
  if($parentId -le 0){ throw "Create-Folder: parentId must be > 0." }

  Write-Log ("TREE: creating folder '{0}' under parentFolderId={1}" -f $name,$parentId) 'INFO'

  $body = @{
  folderName = $folderName
  parentFolderId = $parentId
  folderTypeId = 1
  inheritPermissions = $true
  inheritSecretPolicy = $true
}

  try{
    $r = SS $apiBase POST 'folders' $tok $body $null

    $id = $null
    foreach($k in @('id','folderId','Id','FolderId')){
      if($r -and ($r.PSObject.Properties.Name -contains $k)){
        try{ $id = [int]$r.$k } catch {}
        if($id -gt 0){ break }
      }
    }
    if(-not $id -or $id -le 0){
      throw ("Folder created but id was not returned. Response keys: {0}" -f (($r.PSObject.Properties.Name -join ', ')))
    }

    # Best-effort path for logging only
    $path = ""
    try{
      $pf = Get-FolderById $apiBase $tok $parentId
      $pp = [string](Get-PropValue $pf @('folderPath','FolderPath') $null)
      if($pp){
        $path = (Normalize-FolderPath $pp) + "\" + $body.folderName
      }
    } catch {}

    try{
      Track-CreatedFolder -id $id -name $body.folderName -path $path -parentId $parentId
    } catch {}

    return [int]$id
  }
  catch{
    $t = [string]$_
    if($t -match "already exists at this level"){
      Write-Log ("TREE: folder already exists at this level: '{0}' under parentFolderId={1}. (Tenant cannot list children to reuse id; use per-run root to avoid collisions.)" -f $body.folderName,$parentId) 'WARN'
    }
    throw
  }
}

function Get-FolderPath-Source([string]$srcApi,[string]$srcTok,[int]$srcFolderId){
  if($srcFolderId -le 0){ return "" }
  
  try{
    $folder = SS $srcApi GET ("folders/{0}" -f $srcFolderId) $srcTok $null $null
    $path = Get-PropValue $folder @('folderPath','FolderPath','path','Path') ""
    return [string]$path
  }
  catch{
    Write-Log ("Get-FolderPath-Source failed for folderId={0}: {1}" -f $srcFolderId,$_) 'WARN'
    return ""
  }
}

function Create-ImportRunRootFolderIfNeeded(
  [string]$tgtApi,[string]$tgtTok,
  [int]$migrationRootId,
  [bool]$useFolderTree,
  [bool]$dryRun
){
  if(-not $useFolderTree){
  Write-Log "TREE: Create-ImportRunRootFolderIfNeeded() running (NO ImportRun mode)" 'INFO'
  return [int]$migrationRootId
    
  }

  # Behavior B: never create ImportRun-* folders.
  # Always import directly under the configured TargetRootFolderId (migrationRootId).
  if($dryRun){
    Write-Log ("DRY-RUN: TREE enabled. Would import directly under TargetRootFolderId={0} (no ImportRun folder)." -f $migrationRootId) 'INFO'
  } else {
    Write-Log ("TREE: using configured TargetRootFolderId={0} (no ImportRun folder)." -f $migrationRootId) 'INFO'
  }

  return [int]$migrationRootId
}

function Find-ChildFolderIdByName([string]$tgtApi,[string]$tgtTok,[int]$parentId,[string]$childName){
  if([string]::IsNullOrWhiteSpace($childName)){ return $null }

  # In this tenant, /api/v1/folders works; /folder-lookup, /v1/folders, /v2/folders do NOT (404).
  $page=1; $ps=200
  do{
    $q=@{
      'filter.page'=$page
      'filter.pageSize'=$ps
      'filter.parentFolderId'=$parentId
      'filter.searchText'=$childName
    }

    $r = SS $tgtApi GET 'folders' $tgtTok $null $q
    $recs = @(Get-Records $r)

    foreach($f in @($recs)){
      $nm = [string](Get-PropValue $f @('folderName','FolderName','name','Name') $null)
      $id = Get-PropValue $f @('id','Id','folderId','FolderId') $null
      $pid = Get-PropValue $f @('parentFolderId','ParentFolderId') $null
      if($id -ne $null -and $nm -and $nm.Equals($childName,[System.StringComparison]::OrdinalIgnoreCase)){
        if($pid -eq $null -or [int]$pid -eq $parentId){
          return [int]$id
        }
      }
    }

    $page++
  }while(@($recs).Count -ge $ps)

  return $null
}

function Get-OrCreate-ChildFolder([string]$tgtApi,[string]$tgtTok,[int]$parentId,[string]$childName){
  $key = "{0}|{1}" -f $parentId, $childName.ToLowerInvariant()
  if($script:FolderMapTgt.ContainsKey($key)){ return [int]$script:FolderMapTgt[$key] }

  # 0) Try explicit search/list endpoints first (most reliable in tenants without childFolders)
  try{
    $found = Find-ChildFolderIdByName -tgtApi $tgtApi -tgtTok $tgtTok -parentId $parentId -childName $childName
    if($found -and [int]$found -gt 0){
      $script:FolderMapTgt[$key] = [int]$found
      return [int]$found
    }
  } catch {}

  # 1) Try to find existing child via parent.childFolders (best-effort; may not exist in your tenant)
  try{
    $pf = Get-FolderById $tgtApi $tgtTok $parentId
    if(Has-Prop $pf 'childFolders' -and $pf.childFolders){
      foreach($c in @($pf.childFolders)){
        $nm = [string](Get-PropValue $c @('folderName','FolderName','name','Name') $null)
        $id = Get-PropValue $c @('id','Id','folderId','FolderId') $null
        if($nm -and $id -ne $null -and $nm.Equals($childName,[System.StringComparison]::OrdinalIgnoreCase)){
          $script:FolderMapTgt[$key] = [int]$id
          return [int]$id
        }
      }
    }
  } catch {}

  # 2) Create new folder
  try{
    $newId = Create-Folder $tgtApi $tgtTok $parentId $childName
    $script:FolderMapTgt[$key] = $newId
    return $newId
  } catch {
    $errText = [string]$_

    # 3) If it already exists, resolve id via Find-ChildFolderIdByName
    if($errText -match "already exists at this level"){
      try{
        $found2 = Find-ChildFolderIdByName -tgtApi $tgtApi -tgtTok $tgtTok -parentId $parentId -childName $childName
        if($found2 -and [int]$found2 -gt 0){
          $script:FolderMapTgt[$key] = [int]$found2
          Write-Log ("TREE: folder exists; resolved id={0} for '{1}' under parentId={2}" -f $found2,$childName,$parentId) 'INFO'
          return [int]$found2
        }
      } catch {}

      Write-Log ("TREE: folder exists but cannot resolve id for '{0}' under parentId={1}. Skipping this branch (tenant limitation)." -f $childName,$parentId) 'WARN'
      return $null
    }

    throw
  }
}

# ---------------- Folder ACL helpers ----------------
function Get-FolderPermissions([string]$apiBase,[string]$tok,[int]$folderId){
  $perms = @()
  $page = 1
  $ps = 200
  
  while($true){
    $resp = SS $apiBase GET 'folder-permissions' $tok $null @{
      'filter.folderId' = $folderId
      'filter.page' = $page
      'filter.pageSize' = $ps
    }
    
    $recs = @(Get-Records $resp)
    $perms += $recs
    
    if($recs.Count -lt $ps){ break }
    $page++
  }
  
  return $perms
}

function Add-FolderPermission([string]$apiBase,[string]$tok,[int]$folderId,$perm){
  $body=@{
    breakInheritance      = $false   # <-- change from $true to $false (prevents self-lockout)
    folderId              = $folderId
    folderAccessRoleName  = [string](Get-PropValue $perm @('folderAccessRoleName','FolderAccessRoleName') $null)
    secretAccessRoleName  = [string](Get-PropValue $perm @('secretAccessRoleName','SecretAccessRoleName') $null)
  }
  $gid = Get-PropValue $perm @('groupId','GroupId') $null
  $uid = Get-PropValue $perm @('userId','UserId') $null
  if($gid -ne $null -and [int]$gid -gt 0){ $body.groupId = [int]$gid }
  elseif($uid -ne $null -and [int]$uid -gt 0){ $body.userId = [int]$uid }
  else{ return }
  if([string]::IsNullOrWhiteSpace($body.folderAccessRoleName) -or [string]::IsNullOrWhiteSpace($body.secretAccessRoleName)){ return }
  SS $apiBase POST 'folder-permissions' $tok $body $null | Out-Null
}

# ---------------- Secret settings (export-only; PUT blocked) ----------------
function Get-SecretSettings([string]$apiBase,[string]$tok,[int]$secretId){
  try{
    return SS $apiBase GET ("secrets/{0}/settings" -f $secretId) $tok $null $null
  }
  catch{
    Write-Log ("Get-SecretSettings failed for secretId={0}: {1}" -f $secretId,$_) 'DEBUG'
    return $null
  }
}

# ---------------- Template fields indexing + Build items ----------------
$script:TemplateFieldIndexCache = @{}
function Get-TemplateFieldIndex([string]$tgtApiBase,[string]$tgtTok,[int]$templateId){
  if($script:TemplateFieldIndexCache.ContainsKey($templateId)){ return $script:TemplateFieldIndexCache[$templateId] }
  $idx=@{}
  $t = SS $tgtApiBase GET ("secret-templates/{0}" -f $templateId) $tgtTok $null $null
  $fields = @()
  if(Has-Prop $t 'fields'){ $fields = @($t.fields) }
  foreach($f in $fields){
    $fid = Get-PropValue $f @('secretTemplateFieldId','fieldId','id','Id') $null
    if($fid -eq $null){ continue }
    $name = Get-PropValue $f @('name','Name','displayName','DisplayName') $null
    $slug = Get-PropValue $f @('fieldSlugName','FieldSlugName','slug','Slug') $null
    if($name){ $idx[[string]$name.ToLowerInvariant()] = [int]$fid }
    if($slug){ $idx[[string]$slug.ToLowerInvariant()] = [int]$fid }
  }
  $script:TemplateFieldIndexCache[$templateId] = $idx
  return $idx
}

function New-SSItemObject([int]$fieldId,[string]$value){
  $o = New-Object PSObject
  foreach($n in @('SecretTemplateFieldId','secretTemplateFieldId','FieldId','fieldId')){
    $o | Add-Member -MemberType NoteProperty -Name $n -Value $fieldId -Force
  }
  foreach($n in @('ItemValue','itemValue','Value','value')){
    $o | Add-Member -MemberType NoteProperty -Name $n -Value $value -Force
  }
  return $o
}

# ---------------- Template mapping by name ----------------
$script:TemplateNameIndexCache = @{}
function Get-TemplateNameIndex([string]$apiBase,[string]$tok){
  $index = @{}
  $page = 1
  do{
    $r = SS $apiBase GET 'secret-templates' $tok $null @{'filter.page'=$page;'filter.pageSize'=200}
    $recs = @(Get-Records $r)
    foreach($t in $recs){
      $name = Get-PropValue $t @('name','Name') $null
      $id = Get-PropValue $t @('id','Id') $null
      if($name -and $id){ $index[$name.ToLowerInvariant()] = [int]$id }
    }
    $page++
  }while($recs.Count -ge 200)
  return $index
}

function Resolve-TargetTemplateId([string]$tgtApiBase,[string]$tgtTok,$exportSecret,[bool]$MapByName){
  $srcId = Get-PropValue $exportSecret @('SecretTypeId','secretTypeId') $null
  $srcName = Get-PropValue $exportSecret @('SecretTypeName','secretTypeName') $null
  
  if($MapByName -and $srcName){
    $idx = Get-TemplateNameIndex -apiBase $tgtApiBase -tok $tgtTok
    if($idx.ContainsKey($srcName.ToLowerInvariant())){
      return [int]$idx[$srcName.ToLowerInvariant()]
    }
  }
  
  return $srcId
}

function Create-ImportRunRootFolderIfNeeded([string]$tgtApi,[string]$tgtTok,[int]$migrationRootId,[bool]$useFolderTree,[bool]$dryRun){
  if(-not $useFolderTree){ return $migrationRootId }
  return $migrationRootId
}
function Find-ChildFolderByName{
  param(
    [string]$TgtApi,
    [string]$TgtTok,
    [int]$ParentId,
    [string]$FolderName
  )
  
  try{
    $resp = SS $TgtApi GET 'folders' $TgtTok $null @{
      'filter.parentFolderId' = $ParentId
      'filter.searchText' = $FolderName
      'filter.page' = 1
      'filter.pageSize' = 100
    }
    
    foreach($f in @(Get-Records $resp)){
      $fn = [string](Get-PropValue $f @('folderName','FolderName','name','Name') $null)
      $fid = Get-PropValue $f @('id','Id','folderId','FolderId') $null
      $fpid = Get-PropValue $f @('parentFolderId','ParentFolderId') $null
      
      if($fn -and $fid -ne $null -and $fn.Equals($FolderName,[System.StringComparison]::OrdinalIgnoreCase)){
        if($fpid -eq $null -or [int]$fpid -eq $ParentId){
          return [int]$fid
        }
      }
    }
  }
  catch{
    Write-Log ("Find-ChildFolderByName: error for '{0}' under {1}: {2}" -f $FolderName,$ParentId,$_.Exception.Message) 'DEBUG'
  }
  
  return $null
}

function Create-Folder-Safe{
  param(
    [string]$TgtApi,
    [string]$TgtTok,
    [int]$ParentId,
    [string]$FolderName
  )
  
  $body = @{
    folderName = $FolderName
    folderTypeId = 1
    inheritPermissions = $true
    inheritSecretPolicy = $true
    parentFolderId = $ParentId
  }
  
  try{
    $resp = SS $TgtApi POST 'folders' $TgtTok $body $null
    
    $newId = Get-PropValue $resp @('id','Id','folderId','FolderId') $null
    if($newId -ne $null -and [int]$newId -gt 0){
      return [int]$newId
    }
  }
  catch{
    throw
  }
  
  return $null
}
$script:CreatedFolderCache = @{}


# Initialize at script scope
$script:ImportRunCreatedFolderIds = New-Object 'System.Collections.Generic.List[int]'
$script:ImportRunCreatedFoldersById = @{}

function Reset-ImportRunTracking {
  $script:ImportRunCreatedFolderIds = New-Object 'System.Collections.Generic.List[int]'
  $script:ImportRunCreatedFoldersById = @{}
  $script:ImportRunCreatedSecretIds = New-Object 'System.Collections.Generic.List[int]'
  $script:ImportRunCreatedSecretsById = @{}
  $script:CreatedFolderCache = @{}
  
  Write-Log "IMPORT: Reset tracking for new import run" 'DEBUG'
}
function Update-ImportButtonState {
  $canImport = $true
  
  # Check target tenant config
  if([string]::IsNullOrWhiteSpace($Global:Config.Tgt.TenantBase)){ $canImport = $false }
  if([string]::IsNullOrWhiteSpace($Global:Config.Tgt.Username)){ $canImport = $false }
  if([string]::IsNullOrWhiteSpace($Global:Config.Tgt.SSApiBase)){ $canImport = $false }
  
  # Check export file exists
  if(-not (Test-Path $Global:Config.ExportFile)){ $canImport = $false }
  
  $btnImport.Enabled = $canImport
}

function Create-Folder-Tracked {
  param(
    [Parameter(Mandatory)][string]$TgtApi,
    [Parameter(Mandatory)][string]$TgtTok,
    [Parameter(Mandatory)][int]$ParentId,
    [Parameter(Mandatory)][string]$Name
  )
  
  $body = @{
    folderName          = $Name.Trim()
    folderTypeId        = 1
    inheritPermissions  = $true
    inheritSecretPolicy = $true
    parentFolderId      = [int]$ParentId
  }
  
  $result = SS $TgtApi POST 'folders' $TgtTok $body $null
  
  $newId = [int](Get-PropValue $result @('id','Id','folderId','FolderId') 0)
  
  if($newId -gt 0){
    # CRITICAL: Track the created folder for cleanup
    Track-CreatedFolder -id $newId -name $Name -path "" -parentId $ParentId
    Write-Log ("FOLDER: Created '{0}' (id={1}) under parent {2}" -f $Name,$newId,$ParentId) 'INFO'
  }
  
  return $newId
}

# NOTE: Add-FolderPermission defined earlier at ~line 6086 with full implementation
# NOTE: Apply-SecretShares defined earlier at ~line 5800 with full bulk operations support

function Parse-NullableInt([string]$text){
  if([string]::IsNullOrWhiteSpace($text)){ return $null }
  try{ return [int]$text } catch { return $null }
}

# PATCH 1: add this function immediately AFTER Parse-NullableInt (script scope)
function Find-SecretIdByNameInFolder-FallbackByDetail([string]$apiBase,[string]$tok,[int]$folderId,[string]$secretName){
  if([string]::IsNullOrWhiteSpace($secretName)){ return $null }

  $page=1; $ps=200
  do{
    $q=@{
      'filter.page'       = $page
      'filter.pageSize'   = $ps
      'filter.searchText' = $secretName
    }

    $r = SS $apiBase GET 'secrets/lookup' $tok $null $q
    $recs = @(Get-Records $r)

    foreach($x in $recs){
      $n  = [string](Get-PropValue $x @('name','Name','secretName','SecretName') $null)
      if(-not $n -or -not $n.Equals($secretName,[System.StringComparison]::OrdinalIgnoreCase)){ continue }

      $id = Get-PropValue $x @('id','Id','secretId','SecretId') $null
      if($id -eq $null){ continue }

      # Verify the folderId via secret detail
      try{
        $d = SS $apiBase GET ("secrets/{0}" -f [int]$id) $tok $null $null
        $fid = Get-PropValue $d @('folderId','FolderId') $null
        if($fid -ne $null -and [int]$fid -eq $folderId){
          return [int]$id
        }
      } catch {}
    }

    $page++
  }while($recs.Count -ge $ps)

  return $null
}

# --- V1 export service: POST /api/v1/secrets/export (CSV string) ---

function Export-SecretsCsvV1Service{
  param(
    [string]$ApiBase,
    [string]$Token,
    [int]$FolderId,
    [bool]$ExportChildFolders,
    [string]$OutCsvPath,
    [Security.SecureString]$ExportPasswordSecure
  )

  if($null -eq $ExportPasswordSecure){
    throw "CSV export requires a password. (Using Source login password failed to load.)"
  }

  $exportPwdPlain = Plain $ExportPasswordSecure
  if([string]::IsNullOrWhiteSpace($exportPwdPlain)){
    throw "CSV export password is blank."
  }

  $body=@{
    data=@{
      folderId = $FolderId
      exportChildFolders = [bool]$ExportChildFolders
      exportFileType = "Csv"
      exportFolderPath = $true
      exportTotp = $false
      requireMultifactorAuthenticationToExport = $false
      notes = "Exported by migration script $(Get-Date -Format s)"

      # FIX: must be non-empty in your tenant
      password = $exportPwdPlain

      # keep empty unless your tenant explicitly requires a second password
      doubleLockPassword = ""
    }
  }

  $r = SS $ApiBase POST 'secrets/export' $Token $body $null
  $csv = Get-PropValue $r @('exportedSecretsFileText','ExportedSecretsFileText') $null
  if([string]::IsNullOrWhiteSpace($csv)){ throw "Export service did not return exportedSecretsFileText." }

  Ensure-Dir $OutCsvPath
  $csv | Set-Content -Path $OutCsvPath -Encoding UTF8
  $cnt = Get-PropValue $r @('secretsCount','SecretsCount') 0
  $errs = if(Has-Prop $r 'errors'){ @($r.errors) } else { @() }

  Write-Log ("Export service wrote CSV: {0} (secretsCount={1}, errors={2})" -f $OutCsvPath,$cnt,(@($errs).Count)) 'INFO'
  return [pscustomobject]@{ secretsCount=$cnt; errors=$errs; outCsv=$OutCsvPath }
}

function Export-SecretsJsonToCsvBundle {
  param(
    [Parameter(Mandatory)][string]$InputJsonPath,
    [Parameter(Mandatory)][string]$OutDir
  )

  if(-not (Test-Path $InputJsonPath)){ throw "Input JSON not found: $InputJsonPath" }
  Ensure-Dir (Join-Path $OutDir "dummy.txt") | Out-Null  # uses your existing Ensure-Dir

  $root = Get-Content $InputJsonPath -Raw | ConvertFrom-Json
  $secrets = @($root.Secrets)
  if(@($secrets).Count -eq 0){
    throw "JSON has no Secrets array: $InputJsonPath"
  }

  # Use List<T> instead of += on arrays for O(1) append performance
  $secretsRows    = [System.Collections.Generic.List[object]]::new()
  $itemsRows      = [System.Collections.Generic.List[object]]::new()
  $secretPermRows = [System.Collections.Generic.List[object]]::new()
  $folderPermRows = [System.Collections.Generic.List[object]]::new()
  $settingsRows   = [System.Collections.Generic.List[object]]::new()
  $attachRows     = [System.Collections.Generic.List[object]]::new()

  $secretCount = @($secrets).Count
  $secretIndex = 0
  $lastLogTime = [DateTime]::MinValue

  Write-Log ("CSV bundle: processing {0} secrets..." -f $secretCount) 'INFO'

  foreach($s in $secrets){
    $secretIndex++
    
    # Log progress every 10 secrets OR every 2 seconds + keep GUI responsive
    $now = Get-Date
    if(($secretIndex % 10 -eq 0) -or (($now - $lastLogTime).TotalSeconds -ge 2)){
      Write-Log ("CSV bundle: {0}/{1} secrets ({2:P0})" -f $secretIndex, $secretCount, ($secretIndex/$secretCount)) 'INFO'
      $lastLogTime = $now
      [System.Windows.Forms.Application]::DoEvents()
    }

    $sid  = Get-PropValue $s @('Id','id','SecretId','secretId') $null
    $name = [string](Get-PropValue $s @('Name','name') $null)
    $fid  = Get-PropValue $s @('FolderId','folderId') $null
    $fpth = [string](Get-PropValue $s @('FolderPath','folderPath') $null)
    $stId = Get-PropValue $s @('SecretTypeId','secretTypeId','SecretTemplateId','secretTemplateId') $null
    $site = Get-PropValue $s @('SiteId','siteId') $null

    [void]$secretsRows.Add([pscustomobject]@{
      SecretId        = $sid
      SecretName      = $name
      FolderId        = $fid
      FolderPath      = $fpth
      SecretTypeId    = $stId
      SiteId          = $site
      ItemsCount      = @($s.Items).Count
      SecretPermCount = @($s.SecretPermissions).Count
      FolderPermCount = @($s.FolderPermissions).Count
      HasSettings     = [bool]($s.PSObject.Properties.Name -contains 'SecretSettings' -and $null -ne $s.SecretSettings)
    })

    # Items (one row per field)
    foreach($it in @($s.Items)){
      [void]$itemsRows.Add([pscustomobject]@{
        SecretId          = $sid
        SecretName        = $name
        FolderPath        = $fpth
        FieldName         = [string](Get-PropValue $it @('name','Name') $null)
        Slug              = [string](Get-PropValue $it @('slug','Slug') $null)
        Value             = [string](Get-PropValue $it @('value','Value') $null)
        IsFile            = [bool](Get-PropValue $it @('isFile','IsFile') $false)
        FileName          = [string](Get-PropValue $it @('filename','Filename') $null)
        FileAttachmentId  = Get-PropValue $it @('fileAttachmentId','FileAttachmentId') $null
        FileExportPath    = [string](Get-PropValue $it @('fileExportPath','FileExportPath') $null)
        FileExportBytes   = Get-PropValue $it @('fileExportBytes','FileExportBytes') $null
        ItemId            = Get-PropValue $it @('itemId','ItemId') $null
        FieldId           = Get-PropValue $it @('fieldId','FieldId') $null
        Note              = [string](Get-PropValue $it @('note','Note') $null)
      })

      # Attachments convenience CSV (subset of file items)
      $isFile = $false
      try{ $isFile = [bool](Get-PropValue $it @('isFile','IsFile') $false) } catch {}
      if($isFile){
        [void]$attachRows.Add([pscustomobject]@{
          SecretId       = $sid
          SecretName     = $name
          FolderPath     = $fpth
          Slug           = [string](Get-PropValue $it @('slug','Slug') $null)
          FieldName      = [string](Get-PropValue $it @('name','Name') $null)
          FileName       = [string](Get-PropValue $it @('filename','Filename') $null)
          FileExportPath = [string](Get-PropValue $it @('fileExportPath','FileExportPath') $null)
          FileBytes      = Get-PropValue $it @('fileExportBytes','FileExportBytes') $null
        })
      }
    }

    # Secret permissions (one row per permission)
    foreach($p in @($s.SecretPermissions)){
      [void]$secretPermRows.Add([pscustomobject]@{
        SecretId              = $sid
        SecretName            = $name
        FolderPath            = $fpth
        PermissionId          = Get-PropValue $p @('id','Id') $null
        UserId                = Get-PropValue $p @('userId','UserId') $null
        UserName              = [string](Get-PropValue $p @('userName','UserName') $null)
        GroupId               = Get-PropValue $p @('groupId','GroupId') $null
        GroupName             = [string](Get-PropValue $p @('groupName','GroupName') $null)
        KnownAs               = [string](Get-PropValue $p @('knownAs','KnownAs') $null)
        DomainName            = [string](Get-PropValue $p @('domainName','DomainName') $null)
        SecretAccessRoleId    = Get-PropValue $p @('secretAccessRoleId','SecretAccessRoleId') $null
        SecretAccessRoleName  = [string](Get-PropValue $p @('secretAccessRoleName','SecretAccessRoleName') $null)
      })
    }

    # Folder permissions (one row per permission)
    foreach($fp in @($s.FolderPermissions)){
      [void]$folderPermRows.Add([pscustomobject]@{
        SecretId              = $sid
        SecretName            = $name
        FolderId              = Get-PropValue $fp @('folderId','FolderId') $null
        FolderPath            = $fpth
        PermissionId          = Get-PropValue $fp @('id','Id') $null
        UserId                = Get-PropValue $fp @('userId','UserId') $null
        UserName              = [string](Get-PropValue $fp @('userName','UserName') $null)
        GroupId               = Get-PropValue $fp @('groupId','GroupId') $null
        GroupName             = [string](Get-PropValue $fp @('groupName','GroupName') $null)
        KnownAs               = [string](Get-PropValue $fp @('knownAs','KnownAs') $null)
        DomainName            = [string](Get-PropValue $fp @('domainName','DomainName') $null)
        FolderAccessRoleId    = Get-PropValue $fp @('folderAccessRoleId','FolderAccessRoleId') $null
        FolderAccessRoleName  = [string](Get-PropValue $fp @('folderAccessRoleName','FolderAccessRoleName') $null)
        SecretAccessRoleId    = Get-PropValue $fp @('secretAccessRoleId','SecretAccessRoleId') $null
        SecretAccessRoleName  = [string](Get-PropValue $fp @('secretAccessRoleName','SecretAccessRoleName') $null)
      })
    }

    # Secret settings (store full settings as JSON string + a few common fields)
    if($s.PSObject.Properties.Name -contains 'SecretSettings' -and $null -ne $s.SecretSettings){
      $ss = $s.SecretSettings
      [void]$settingsRows.Add([pscustomobject]@{
        SecretId                    = $sid
        SecretName                  = $name
        FolderPath                  = $fpth
        SendEmailWhenViewed         = Get-PropValue $ss @('sendEmailWhenViewed') $null
        SendEmailWhenChanged        = Get-PropValue $ss @('sendEmailWhenChanged') $null
        SendEmailWhenHeartbeatFails = Get-PropValue $ss @('sendEmailWhenHeartbeatFails') $null
        ExpirationType              = [string](Get-PropValue $ss @('expirationType') $null)
        ExpirationDayInterval       = Get-PropValue $ss @('expirationDayInterval') $null
        ExpirationDate              = Get-PropValue $ss @('expirationDate') $null
        SettingsJson                = ($ss | ConvertTo-Json -Depth 50 -Compress)
      })
    }
  }

  Write-Log ("CSV bundle: finished processing {0} secrets" -f $secretCount) 'INFO'

  $paths = [ordered]@{
    SecretsCsv           = (Join-Path $OutDir 'secrets.csv')
    SecretItemsCsv       = (Join-Path $OutDir 'secret_items.csv')
    SecretPermissionsCsv = (Join-Path $OutDir 'secret_permissions.csv')
    FolderPermissionsCsv = (Join-Path $OutDir 'folder_permissions.csv')
    SecretSettingsCsv    = (Join-Path $OutDir 'secret_settings.csv')
    AttachmentsCsv       = (Join-Path $OutDir 'attachments.csv')
  }

  $secretsRows     | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.SecretsCsv
  $itemsRows       | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.SecretItemsCsv
  $secretPermRows  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.SecretPermissionsCsv
  $folderPermRows  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.FolderPermissionsCsv
  $settingsRows    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.SecretSettingsCsv
  $attachRows      | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.AttachmentsCsv

  Write-Log ("CSV bundle written to: {0}" -f $OutDir) 'INFO'
  $c0=if($null -ne $secretsRows){$secretsRows.Count}else{0}; $c1=if($null -ne $itemsRows){$itemsRows.Count}else{0}; $c2=if($null -ne $secretPermRows){$secretPermRows.Count}else{0}; $c3=if($null -ne $folderPermRows){$folderPermRows.Count}else{0}; $c4=if($null -ne $settingsRows){$settingsRows.Count}else{0}; $c5=if($null -ne $attachRows){$attachRows.Count}else{0}
  Write-Log "CSV counts: secrets=$c0, items=$c1, secretPerms=$c2, folderPerms=$c3, settings=$c4, attachments=$c5" 'INFO'

  return [pscustomobject]@{
    outDir = $OutDir
    csv = $paths
    counts = [pscustomobject]@{
      secrets = $c0
      items = $c1
      secretPermissions = $c2
      folderPermissions = $c3
      secretSettings = $c4
      attachments = $c5
    }
  }
}

function Export-DelineaWebImportPasteFile {
  param(
    [Parameter(Mandatory)][string]$InputJsonPath,
    [Parameter(Mandatory)][string]$OutCsvPath
  )

  if(-not (Test-Path $InputJsonPath)){ throw "Input JSON not found: $InputJsonPath" }

  $root = Get-Content $InputJsonPath -Raw | ConvertFrom-Json
  $secrets = @($root.Secrets)
  if(@($secrets).Count -eq 0){ throw "JSON has no Secrets array: $InputJsonPath" }

  function CsvEscape([string]$s){
    if($null -eq $s){ return "" }
    $s = [string]$s
    # Delinea paste-import: escape internal quotes with backslash
    $s = $s -replace '"','\"'
    # Quote if contains comma, tab, or newline
    if($s -match '[,\t\r\n]'){ return '"' + $s + '"' }
    return $s
  }

  function GetItemValueByAnyName($secret, [string[]]$candidates){
    foreach($it in @($secret.Items)){
      $nm = [string](Get-PropValue $it @('name','Name') $null)
      $sl = [string](Get-PropValue $it @('slug','Slug') $null)
      foreach($c in $candidates){
        if($nm -and $nm.Equals($c,[System.StringComparison]::OrdinalIgnoreCase)){
          return [string](Get-PropValue $it @('value','Value') "")
        }
        if($sl -and $sl.Equals($c,[System.StringComparison]::OrdinalIgnoreCase)){
          return [string](Get-PropValue $it @('value','Value') "")
        }
      }
    }
    return ""
  }

  $lines = New-Object 'System.Collections.Generic.List[string]'

  $secretCount = @($secrets).Count
  $secretIndex = 0
  $lastLogTime = [DateTime]::MinValue

  Write-Log ("Web import CSV: processing {0} secrets..." -f $secretCount) 'INFO'

  foreach($s in $secrets){
    $secretIndex++
    
    # Log progress every 50 secrets OR every 2 seconds
    $now = Get-Date
    if(($secretIndex % 50 -eq 0) -or (($now - $lastLogTime).TotalSeconds -ge 2)){
      Write-Log ("Web import CSV: {0}/{1} secrets ({2:P0})" -f $secretIndex, $secretCount, ($secretIndex/$secretCount)) 'DEBUG'
      $lastLogTime = $now
    }

    $name = [string](Get-PropValue $s @('Name','name') $null)
    if([string]::IsNullOrWhiteSpace($name)){ continue }

    # Required order (NO HEADER):
    # Secret Name, AccessKey, SecretKey, Username, SecretId, Trigger
    $accessKey = GetItemValueByAnyName $s @('AccessKey','accesskey','access_key','aws_access_key_id','accessKeyId','Access Key')
    $secretKey = GetItemValueByAnyName $s @('SecretKey','secretkey','secret_key','aws_secret_access_key','Secret Key')
    $username  = GetItemValueByAnyName $s @('Username','username','user','User Name','login')
    $secretId  = GetItemValueByAnyName $s @('SecretId','secretid','id','AccountId','account_id')
    $trigger   = GetItemValueByAnyName $s @('Trigger','trigger')

    $row = (@(
      (CsvEscape $name),
      (CsvEscape $accessKey),
      (CsvEscape $secretKey),
      (CsvEscape $username),
      (CsvEscape $secretId),
      (CsvEscape $trigger)
    ) -join ',')

    $lines.Add($row) | Out-Null
  }

  Ensure-Dir $OutCsvPath
  $lines | Set-Content -Path $OutCsvPath -Encoding UTF8

  Write-Log ("WEB IMPORT paste-file written: {0} (rows={1})" -f $OutCsvPath,$lines.Count) 'INFO'
  return $OutCsvPath
}

function Create-ExportZip {
  param(
    [Parameter(Mandatory)][string]$SourceDir,
    [Parameter(Mandatory)][string]$ZipOutDir
  )

  if(-not (Test-Path $SourceDir)){ 
    Write-Log "ZIP: Source directory not found: $SourceDir" 'WARN'
    return $null 
  }

  $ts = Get-Date -Format "yyyyMMdd-HHmmss"
  $zipName = "DelineaMigration-Export-{0}.zip" -f $ts
  $zipPath = Join-Path $ZipOutDir $zipName

  try{
    # Ensure output directory exists
    if(-not (Test-Path $ZipOutDir)){ 
      New-Item -ItemType Directory -Path $ZipOutDir | Out-Null 
    }

    # Remove existing zip if present
    if(Test-Path $zipPath){ 
      Remove-Item $zipPath -Force 
    }

    # Create zip archive
    Write-Log ("ZIP: Creating archive from '{0}' to '{1}'" -f $SourceDir,$zipPath) 'INFO'
    
    Compress-Archive -Path (Join-Path $SourceDir '*') -DestinationPath $zipPath -CompressionLevel Optimal -Force
    
    $zipSize = (Get-Item $zipPath).Length
    Write-Log ("ZIP: Archive created successfully. Size={0} bytes" -f $zipSize) 'INFO'
    
    return $zipPath
  }
  catch{
    Write-Log ("ZIP: Archive creation failed: {0}" -f ($_ | Out-String)) 'ERROR'
    return $null
  }
}

# Add this helper so the CSV bundle paths come from Global config (same style as the rest of your script)
function Export-SecretsJsonToCsvBundleFromConfig {
  param(
    # NEW: allow caller (other tab) to provide an explicit JSON path
    [string]$InputJsonPath = $null,

    [string[]]$JsonPathKeys = @('ExportJsonPath','SecretsExportJsonPath','LastExportJsonPath','OutJsonPath'),
    [string[]]$OutDirKeys   = @('OutDir','ExportOutDir','MigrationRoot','WorkDir','OutputDir'),
    [string]$BundleFolderName = 'csv-bundle'
  )

  # 0) If caller provided a path, use it
  $jsonPath = $null
  if(-not [string]::IsNullOrWhiteSpace($InputJsonPath)){
    if(-not (Test-Path $InputJsonPath)){ throw "CSV-BUNDLE: Input JSON not found: $InputJsonPath" }
    $jsonPath = [string]$InputJsonPath
  }

  # 1) Try Global config keys (if you ever add them)
  if(-not $jsonPath){
    foreach($k in $JsonPathKeys){
      try{
        $v = Get-PropValue $Global:Config @($k) $null
        if(-not [string]::IsNullOrWhiteSpace([string]$v) -and (Test-Path ([string]$v))){
          $jsonPath = [string]$v
          break
        }
      } catch {}
    }
  }

  # 2) Best default: use Global config ExportFile (this EXISTS in your config)
  if(-not $jsonPath){
    try{
      if($Global:Config -and $Global:Config.ExportFile -and (Test-Path $Global:Config.ExportFile)){
        $jsonPath = [string]$Global:Config.ExportFile
      }
    } catch {}
  }

  # 3) Fallback: last export in current session
  if(-not $jsonPath){
    try{
      if($script:LastExportJsonPath -and (Test-Path $script:LastExportJsonPath)){
        $jsonPath = [string]$script:LastExportJsonPath
      }
    } catch {}
  }

  if(-not $jsonPath){
    throw "CSV-BUNDLE: Could not resolve JSON export path. Provide -InputJsonPath or ensure Config.ExportFile exists."
  }

  # Resolve output directory (default: same directory as JSON)
  $outBase = $null
  foreach($k in $OutDirKeys){
    try{
      $v = Get-PropValue $Global:Config @($k) $null
      if(-not [string]::IsNullOrWhiteSpace([string]$v)){
        $outBase = [string]$v
        break
      }
    } catch {}
  }
  if([string]::IsNullOrWhiteSpace($outBase)){
    $outBase = Split-Path -Parent $jsonPath
  }

  $outDir = Join-Path $outBase $BundleFolderName
  Write-Log ("CSV-BUNDLE: using json='{0}' outDir='{1}'" -f $jsonPath,$outDir) 'INFO'

  Export-SecretsJsonToCsvBundle -InputJsonPath $jsonPath -OutDir $outDir
}

# --- Stub functions for export formats (implement if needed) ---
# Full Delinea Web Portal compatible XML export - matches exact format for web portal import
# Uses streaming XmlTextWriter for performance with large datasets

function Export-SecretsJsonToDelineaImportXml {
  param(
    [Parameter(Mandatory)][string]$InputJsonPath,
    [Parameter(Mandatory)][string]$OutXmlPath,
    [switch]$IncludeFolders,
    [switch]$IncludePermissions
  )

  if(-not (Test-Path $InputJsonPath)){
    throw "Input JSON not found: $InputJsonPath"
  }

  Write-Log ("XML EXPORT: Starting from JSON: {0}" -f $InputJsonPath) 'INFO'
  [System.Windows.Forms.Application]::DoEvents()

  $fileSizeMB = [math]::Round((Get-Item $InputJsonPath).Length / 1MB, 1)
  Write-Log ("XML EXPORT: Loading JSON file ({0} MB) - using fast parser..." -f $fileSizeMB) 'INFO'
  [System.Windows.Forms.Application]::DoEvents()
  $root = Read-LargeJsonAsPSObject $InputJsonPath
  $secrets = @($root.Secrets)
  if(@($secrets).Count -eq 0){
    throw "JSON has no Secrets array: $InputJsonPath"
  }
  
  # Build template lookup and store full XML from TemplateExports
  $templateLookup = @{}
  $templateXmlLookup = @{}
  if($root.PSObject.Properties.Name -contains 'TemplateExports'){
    foreach($t in @($root.TemplateExports)){
      $tid = Get-PropValue $t @('templateId','TemplateId','Id','id') $null
      $xmlText = Get-PropValue $t @('exportFileText','ExportFileText') $null
      if($tid -and $xmlText){
        $templateXmlLookup[$tid] = $xmlText
        if($xmlText -match '<name>([^<]+)</name>'){
          $templateLookup[$tid] = $matches[1]
        }
      }
    }
  }

  Write-Log ("XML EXPORT: Processing {0} secrets, {1} templates..." -f $secrets.Count, $templateXmlLookup.Count) 'INFO'
  [System.Windows.Forms.Application]::DoEvents()

  # Collect folder data in first pass
  $folderPathToPermissions = @{}
  $usedTemplateIds = @{}

  # Use streaming XmlTextWriter for fast output
  Ensure-Dir $OutXmlPath
  $stream = $null
  $xw = $null
  try {
  $stream = New-Object System.IO.StreamWriter($OutXmlPath, $false, [System.Text.Encoding]::UTF8)
  $xw = New-Object System.Xml.XmlTextWriter($stream)
  $xw.Formatting = [System.Xml.Formatting]::Indented
  $xw.Indentation = 2

  $xw.WriteStartDocument()
  $xw.WriteStartElement("ImportFile")
  $xw.WriteAttributeString("xmlns", "xsd", "http://www.w3.org/2000/xmlns/", "http://www.w3.org/2001/XMLSchema")
  $xw.WriteAttributeString("xmlns", "xsi", "http://www.w3.org/2000/xmlns/", "http://www.w3.org/2001/XMLSchema-instance")

  # Placeholder - we'll write Folders after secrets pass to collect folder data
  # Write Folders, SecretTemplates, then Secrets in correct order
  # Strategy: collect folder/template info during secret iteration, then write all at end
  # But Delinea format has Folders first, so we need two passes or buffer folders

  # First pass: collect folders and template usage from secrets (fast, no XML writing)
  $secretIndex = 0
  $lastLogTime = [DateTime]::MinValue
  foreach($sec in $secrets){
    $secretIndex++
    $tmplId = Get-PropValue $sec @('SecretTypeId','secretTypeId','SecretTemplateId') $null
    if($tmplId){ $usedTemplateIds[$tmplId] = $true }

    if($IncludeFolders){
      $folderPath = [string](Get-PropValue $sec @('FolderPath','folderPath') "")
      $normalizedPath = $folderPath.Trim()
      if(-not [string]::IsNullOrWhiteSpace($normalizedPath)){
        if(-not $normalizedPath.StartsWith('\')){ $normalizedPath = "\$normalizedPath" }
        $cleanPath = $normalizedPath.TrimStart('\')
        $parts = @($cleanPath.Split('\') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $cur = ""
        foreach($part in $parts){
          $cur = if($cur){ "$cur\$part" } else { $part }
          $fullPath = "\$cur"
          if(-not $folderPathToPermissions.ContainsKey($fullPath)){
            $folderPathToPermissions[$fullPath] = @()
          }
        }
        $folderPerms = Get-PropValue $sec @('FolderPermissions','folderPermissions') @()
        if(@($folderPerms).Count -gt 0 -and (-not $folderPathToPermissions.ContainsKey($normalizedPath) -or $folderPathToPermissions[$normalizedPath].Count -eq 0)){
          $folderPathToPermissions[$normalizedPath] = @($folderPerms)
        }
      }
    }
  }

  # Write Folders section
  $xw.WriteStartElement("Folders")
  if($IncludeFolders -and $folderPathToPermissions.Count -gt 0){
    $sortedFolders = @($folderPathToPermissions.Keys) | Sort-Object
    Write-Log ("XML EXPORT: Writing {0} folders..." -f $sortedFolders.Count) 'INFO'
    [System.Windows.Forms.Application]::DoEvents()
    foreach($fp in $sortedFolders){
      $xw.WriteStartElement("Folder")
      $parts = @($fp.TrimStart('\').Split('\') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
      $folderName = if($parts.Count -gt 0){ $parts[-1] } else { $fp.TrimStart('\') }
      $xw.WriteElementString("FolderName", $folderName)
      $xw.WriteElementString("FolderPath", $fp)
      $xw.WriteStartElement("Permissions")
      if($IncludePermissions){
        foreach($perm in @($folderPathToPermissions[$fp])){
          $xw.WriteStartElement("Permission")
          $sarName = Get-PropValue $perm @('secretAccessRoleName','SecretAccessRoleName') "None"
          $xw.WriteElementString("SecretAccessRoleName", [string]$sarName)
          $farName = Get-PropValue $perm @('folderAccessRoleName','FolderAccessRoleName') "View"
          $xw.WriteElementString("FolderAccessRoleName", [string]$farName)
          $userName = Get-PropValue $perm @('userName','UserName') $null
          $groupName = Get-PropValue $perm @('groupName','GroupName') $null
          $knownAs = Get-PropValue $perm @('knownAs','KnownAs') $null
          if(-not [string]::IsNullOrWhiteSpace([string]$userName)){
            $xw.WriteElementString("UserName", [string]$userName)
          } elseif(-not [string]::IsNullOrWhiteSpace([string]$groupName)){
            $xw.WriteElementString("GroupName", [string]$groupName)
          } elseif(-not [string]::IsNullOrWhiteSpace([string]$knownAs)){
            $xw.WriteElementString("GroupName", [string]$knownAs)
          }
          $xw.WriteEndElement() # Permission
        }
      }
      $xw.WriteEndElement() # Permissions
      $xw.WriteStartElement("MappedSecretTypes"); $xw.WriteEndElement()
      $xw.WriteEndElement() # Folder
    }
  }
  $xw.WriteEndElement() # Folders

  # Write SecretTemplates section
  $xw.WriteStartElement("SecretTemplates")
  Write-Log ("XML EXPORT: Writing {0} secret templates..." -f $usedTemplateIds.Count) 'INFO'
  foreach($tid in $templateXmlLookup.Keys){
    $xmlText = $templateXmlLookup[$tid]
    if([string]::IsNullOrWhiteSpace($xmlText)){ continue }
    try{
      # Strip XML declaration (<?xml ...?>) that would be invalid mid-document
      $cleanXml = $xmlText -replace '^\s*<\?xml[^?]*\?>\s*', ''
      $xw.WriteRaw("`n  ")
      $xw.Flush()
      $stream.Write($cleanXml)
      $stream.Flush()
    } catch {
      Write-Log ("XML EXPORT: Failed to write template {0}: {1}" -f $tid, $_.Exception.Message) 'DEBUG'
    }
  }
  $xw.WriteEndElement() # SecretTemplates

  # Write Secrets section (streaming - no DOM)
  $xw.WriteStartElement("Secrets")
  $secretIndex = 0
  $lastLogTime = [DateTime]::MinValue

  foreach($sec in $secrets){
    $secretIndex++
    
    # Log progress every 200 secrets OR every 3 seconds
    $now = Get-Date
    if(($secretIndex % 200 -eq 0) -or (($now - $lastLogTime).TotalSeconds -ge 3)){
      Write-Log ("XML EXPORT: {0}/{1} secrets ({2:P0})" -f $secretIndex, $secrets.Count, ($secretIndex/$secrets.Count)) 'INFO'
      [System.Windows.Forms.Application]::DoEvents()
      $lastLogTime = $now
    }

    $sid = Get-PropValue $sec @('Id','id','SecretId','secretId') $null
    $secName = [string](Get-PropValue $sec @('Name','name') ("secret_$sid"))
    $tmplName = [string](Get-PropValue $sec @('SecretTypeName','secretTypeName','templateName','TemplateName') "")
    $tmplId = Get-PropValue $sec @('SecretTypeId','secretTypeId','SecretTemplateId') $null
    $siteId = Get-PropValue $sec @('SiteId','siteId') -1
    
    if([string]::IsNullOrWhiteSpace($tmplName) -and $tmplId -and $templateLookup.ContainsKey($tmplId)){
      $tmplName = $templateLookup[$tmplId]
    }
    if([string]::IsNullOrWhiteSpace($tmplName)){ $tmplName = "Unknown Template" }
    
    $folderPath = [string](Get-PropValue $sec @('FolderPath','folderPath') "")
    $normalizedPath = $folderPath.Trim()
    if(-not [string]::IsNullOrWhiteSpace($normalizedPath)){
      if(-not $normalizedPath.StartsWith('\')){ $normalizedPath = "\$normalizedPath" }
    }

    $xw.WriteStartElement("Secret")
    $xw.WriteElementString("SecretName", $secName)
    $xw.WriteElementString("SecretTemplateName", [string]$tmplName)
    $xw.WriteElementString("FolderPath", $normalizedPath)
    $xw.WriteElementString("SiteId", [string]$siteId)
    $xw.WriteStartElement("TotpKey"); $xw.WriteEndElement()
    $xw.WriteStartElement("TotpBackupCodes"); $xw.WriteEndElement()

    # SecretItems
    $xw.WriteStartElement("SecretItems")
    $rawItems = Get-PropValue $sec @('Items','items','fields','Fields') @()
    foreach($it in @($rawItems)){
      $fieldName = [string](Get-PropValue $it @('name','Name','FieldName','fieldName') $null)
      if([string]::IsNullOrWhiteSpace($fieldName)){ continue }
      $val = [string](Get-PropValue $it @('value','Value','itemValue','ItemValue') "")
      $isFile = $false
      try{ $isFile = [bool](Get-PropValue $it @('isFile','IsFile') $false) } catch {}
      if($isFile){
        $fn = [string](Get-PropValue $it @('filename','fileName','FileName') "")
        $val = "[FILE FIELD: $fn]"
      }
      $xw.WriteStartElement("SecretItem")
      $xw.WriteElementString("FieldName", $fieldName)
      $xw.WriteElementString("Value", $val)
      $xw.WriteEndElement() # SecretItem
    }
    $xw.WriteEndElement() # SecretItems

    $xw.WriteStartElement("SecretDependencies"); $xw.WriteEndElement()
    $xw.WriteStartElement("SecretDependencyGroups"); $xw.WriteEndElement()
    $xw.WriteStartElement("Permissions"); $xw.WriteEndElement()
    $xw.WriteEndElement() # Secret
  }
  $xw.WriteEndElement() # Secrets

  # Groups section (empty)
  $xw.WriteStartElement("Groups"); $xw.WriteEndElement()

  # Sites section
  $xw.WriteStartElement("Sites")
  $xw.WriteElementString("SystemSiteId", "1")
  $xw.WriteEndElement()

  # SiteConnectors section (empty)
  $xw.WriteStartElement("SiteConnectors"); $xw.WriteEndElement()

  $xw.WriteEndElement() # ImportFile
  $xw.WriteEndDocument()
  $xw.Flush()
  $xw.Close()
  $stream.Close()
  } finally {
    # Ensure file handles are always released even on error
    try{ if($xw){ $xw.Close() } } catch{}
    try{ if($stream){ $stream.Close(); $stream.Dispose() } } catch{}
  }

  Write-Log ("[OK] XML export complete: {0} (secrets={1}, folders={2}, templates={3})" -f $OutXmlPath,$secrets.Count,$folderPathToPermissions.Count,$templateXmlLookup.Count) 'INFO'
  
  # Also export settings to a separate file
  $settingsPath = $OutXmlPath -replace '\.xml$', '-settings.xml'
  try{
    Export-SettingsToXml -InputJsonPath $InputJsonPath -OutXmlPath $settingsPath
  }
  catch{
    Write-Log ("XML EXPORT: Settings export failed: {0}" -f $_.Exception.Message) 'WARN'
  }
  
  return $OutXmlPath
}

function Export-DelineaWebImportPasteFile {
  param([string]$InputJsonPath,[string]$OutCsvPath)
  Write-Log "Web import CSV stub called (not yet implemented)" 'DEBUG'
}

function Export-SecretsJsonToCsvBundle {
  param(
    [Parameter(Mandatory)][string]$InputJsonPath,
    [Parameter(Mandatory)][string]$OutDir
  )

  if(-not (Test-Path $InputJsonPath)){ 
    throw "Input JSON not found: $InputJsonPath" 
  }

  Write-Log ("CSV BUNDLE: Starting from JSON: {0}" -f $InputJsonPath) 'INFO'

  Ensure-Dir (Join-Path $OutDir "dummy.txt") | Out-Null

  $root = Get-Content $InputJsonPath -Raw | ConvertFrom-Json
  $secrets = @($root.Secrets)
  if(@($secrets).Count -eq 0){
    throw "JSON has no Secrets array: $InputJsonPath"
  }

  Write-Log ("CSV BUNDLE: Processing {0} secrets..." -f $secrets.Count) 'INFO'

  # Use List<object> instead of @() += to avoid O(n^2) array copies
  $secretsRows = New-Object 'System.Collections.Generic.List[object]'
  $itemsRows = New-Object 'System.Collections.Generic.List[object]'
  $secretPermRows = New-Object 'System.Collections.Generic.List[object]'
  $folderPermRows = New-Object 'System.Collections.Generic.List[object]'
  $settingsRows = New-Object 'System.Collections.Generic.List[object]'
  $attachRows = New-Object 'System.Collections.Generic.List[object]'

  $secretCount = @($secrets).Count
  $secretIndex = 0
  $lastLogTime = [DateTime]::MinValue

  foreach($s in $secrets){
    $secretIndex++
    
    # Log progress every 500 secrets OR every 5 seconds
    $now = Get-Date
    if(($secretIndex % 500 -eq 0) -or (($now - $lastLogTime).TotalSeconds -ge 5)){
      Write-Log ("CSV BUNDLE: {0}/{1} secrets ({2:P0})" -f $secretIndex, $secretCount, ($secretIndex/$secretCount)) 'INFO'
      $lastLogTime = $now
    }

    $sid  = Get-PropValue $s @('Id','id','SecretId','secretId') $null
    $name = [string](Get-PropValue $s @('Name','name') $null)
    $fid  = Get-PropValue $s @('FolderId','folderId') $null
    $fpth = [string](Get-PropValue $s @('FolderPath','folderPath') $null)
    $stId = Get-PropValue $s @('SecretTypeId','secretTypeId','SecretTemplateId','secretTemplateId') $null
    $site = Get-PropValue $s @('SiteId','siteId') $null

    [void]$secretsRows.Add([pscustomobject]@{
      SecretId        = $sid
      SecretName      = $name
      FolderId        = $fid
      FolderPath      = $fpth
      SecretTypeId    = $stId
      SiteId          = $site
      ItemsCount      = @($s.Items).Count
      SecretPermCount = if($s.PSObject.Properties.Name -contains 'SecretPermissions'){ @($s.SecretPermissions).Count } else { 0 }
      FolderPermCount = if($s.PSObject.Properties.Name -contains 'FolderPermissions'){ @($s.FolderPermissions).Count } else { 0 }
      HasSettings     = [bool]($s.PSObject.Properties.Name -contains 'SecretSettings' -and $null -ne $s.SecretSettings)
    })

    # Items (one row per field)
    foreach($it in @($s.Items)){
      [void]$itemsRows.Add([pscustomobject]@{
        SecretId          = $sid
        SecretName        = $name
        FolderPath        = $fpth
        FieldName         = [string](Get-PropValue $it @('name','Name') $null)
        Slug              = [string](Get-PropValue $it @('slug','Slug') $null)
        Value             = [string](Get-PropValue $it @('value','Value') $null)
        IsFile            = [bool](Get-PropValue $it @('isFile','IsFile') $false)
        FileName          = [string](Get-PropValue $it @('filename','Filename','fileName','FileName') $null)
        FileAttachmentId  = Get-PropValue $it @('fileAttachmentId','FileAttachmentId') $null
        FileExportPath    = [string](Get-PropValue $it @('fileExportPath','FileExportPath') $null)
        FileExportBytes   = Get-PropValue $it @('fileExportBytes','FileExportBytes') $null
        ItemId            = Get-PropValue $it @('itemId','ItemId') $null
        FieldId           = Get-PropValue $it @('fieldId','FieldId') $null
      })

      # Attachments convenience CSV (subset of file items)
      $isFile = $false
      try{ $isFile = [bool](Get-PropValue $it @('isFile','IsFile') $false) } catch {}
      if($isFile){
        [void]$attachRows.Add([pscustomobject]@{
          SecretId       = $sid
          SecretName     = $name
          FolderPath     = $fpth
          Slug           = [string](Get-PropValue $it @('slug','Slug') $null)
          FieldName      = [string](Get-PropValue $it @('name','Name') $null)
          FileName       = [string](Get-PropValue $it @('filename','Filename','fileName','FileName') $null)
          FileExportPath = [string](Get-PropValue $it @('fileExportPath','FileExportPath') $null)
          FileBytes      = Get-PropValue $it @('fileExportBytes','FileExportBytes') $null
        })
      }
    }

    # Secret permissions (one row per permission)
    if($s.PSObject.Properties.Name -contains 'SecretPermissions'){
      foreach($p in @($s.SecretPermissions)){
        [void]$secretPermRows.Add([pscustomobject]@{
          SecretId              = $sid
          SecretName            = $name
          FolderPath            = $fpth
          PermissionId          = Get-PropValue $p @('id','Id') $null
          UserId                = Get-PropValue $p @('userId','UserId') $null
          UserName              = [string](Get-PropValue $p @('userName','UserName') $null)
          GroupId               = Get-PropValue $p @('groupId','GroupId') $null
          GroupName             = [string](Get-PropValue $p @('groupName','GroupName') $null)
          KnownAs               = [string](Get-PropValue $p @('knownAs','KnownAs') $null)
          DomainName            = [string](Get-PropValue $p @('domainName','DomainName') $null)
          SecretAccessRoleId    = Get-PropValue $p @('secretAccessRoleId','SecretAccessRoleId') $null
          SecretAccessRoleName  = [string](Get-PropValue $p @('secretAccessRoleName','SecretAccessRoleName') $null)
        })
      }
    }

    # Folder permissions (one row per permission)
    if($s.PSObject.Properties.Name -contains 'FolderPermissions'){
      foreach($fp in @($s.FolderPermissions)){
        [void]$folderPermRows.Add([pscustomobject]@{
          SecretId              = $sid
          SecretName            = $name
          FolderId              = Get-PropValue $fp @('folderId','FolderId') $null
          FolderPath            = $fpth
          PermissionId          = Get-PropValue $fp @('id','Id') $null
          UserId                = Get-PropValue $fp @('userId','UserId') $null
          UserName              = [string](Get-PropValue $fp @('userName','UserName') $null)
          GroupId               = Get-PropValue $fp @('groupId','GroupId') $null
          GroupName             = [string](Get-PropValue $fp @('groupName','GroupName') $null)
          KnownAs               = [string](Get-PropValue $fp @('knownAs','KnownAs') $null)
          DomainName            = [string](Get-PropValue $fp @('domainName','DomainName') $null)
          FolderAccessRoleId    = Get-PropValue $fp @('folderAccessRoleId','FolderAccessRoleId') $null
          FolderAccessRoleName  = [string](Get-PropValue $fp @('folderAccessRoleName','FolderAccessRoleName') $null)
          SecretAccessRoleId    = Get-PropValue $fp @('secretAccessRoleId','SecretAccessRoleId') $null
          SecretAccessRoleName  = [string](Get-PropValue $fp @('secretAccessRoleName','SecretAccessRoleName') $null)
        })
      }
    }

    # Secret settings (store full settings as JSON string + a few common fields)
    if($s.PSObject.Properties.Name -contains 'SecretSettings' -and $null -ne $s.SecretSettings){
      $ss = $s.SecretSettings
      [void]$settingsRows.Add([pscustomobject]@{
        SecretId                    = $sid
        SecretName                  = $name
        FolderPath                  = $fpth
        SendEmailWhenViewed         = Get-PropValue $ss @('sendEmailWhenViewed') $null
        SendEmailWhenChanged        = Get-PropValue $ss @('sendEmailWhenChanged') $null
        SendEmailWhenHeartbeatFails = Get-PropValue $ss @('sendEmailWhenHeartbeatFails') $null
        ExpirationType              = [string](Get-PropValue $ss @('expirationType') $null)
        ExpirationDayInterval       = Get-PropValue $ss @('expirationDayInterval') $null
        ExpirationDate              = Get-PropValue $ss @('expirationDate') $null
        SettingsJson                = ($ss | ConvertTo-Json -Depth 50 -Compress)
      })
    }
  }

  Write-Log ("CSV BUNDLE: Finished processing {0} secrets. Writing CSV files..." -f $secretCount) 'INFO'

  $paths = [ordered]@{
    SecretsCsv           = (Join-Path $OutDir 'secrets.csv')
    SecretItemsCsv       = (Join-Path $OutDir 'secret_items.csv')
    SecretPermissionsCsv = (Join-Path $OutDir 'secret_permissions.csv')
    FolderPermissionsCsv = (Join-Path $OutDir 'folder_permissions.csv')
    SecretSettingsCsv    = (Join-Path $OutDir 'secret_settings.csv')
    AttachmentsCsv       = (Join-Path $OutDir 'attachments.csv')
  }

  try{
    $secretsRows     | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.SecretsCsv
    $itemsRows       | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.SecretItemsCsv
    $secretPermRows  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.SecretPermissionsCsv
    $folderPermRows  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.FolderPermissionsCsv
    $settingsRows    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.SecretSettingsCsv
    $attachRows      | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $paths.AttachmentsCsv

    Write-Log ("[OK] CSV bundle complete: {0}" -f $OutDir) 'INFO'
    try{
      $c0 = if($null -ne $secretsRows){$secretsRows.Count}else{0}
      $c1 = if($null -ne $itemsRows){$itemsRows.Count}else{0}
      $c2 = if($null -ne $secretPermRows){$secretPermRows.Count}else{0}
      $c3 = if($null -ne $folderPermRows){$folderPermRows.Count}else{0}
      $c4 = if($null -ne $settingsRows){$settingsRows.Count}else{0}
      $c5 = if($null -ne $attachRows){$attachRows.Count}else{0}
      Write-Log "CSV counts: secrets=$c0, items=$c1, secretPerms=$c2, folderPerms=$c3, settings=$c4, attachments=$c5" 'INFO'
    }catch{ Write-Log "CSV counts: (unable to determine counts)" 'WARN' }
  }
  catch{
    Write-Log ("[ERROR] CSV bundle write failed: {0}" -f ($_ | Out-String)) 'ERROR'
    throw
  }

  return [pscustomobject]@{
    outDir = $OutDir
    csv = $paths
    counts = [pscustomobject]@{
      secrets = if($null -ne $secretsRows){$secretsRows.Count}else{0}
      items = if($null -ne $itemsRows){$itemsRows.Count}else{0}
      secretPermissions = if($null -ne $secretPermRows){$secretPermRows.Count}else{0}
      folderPermissions = if($null -ne $folderPermRows){$folderPermRows.Count}else{0}
      secretSettings = if($null -ne $settingsRows){$settingsRows.Count}else{0}
      attachments = if($null -ne $attachRows){$attachRows.Count}else{0}
    }
  }
}

# =====================================================
# EXPORT TEMPLATES CSV (with secrets count, fields, launchers)
# =====================================================
function Export-TemplateSummaryToCsv {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Tok,
    [Parameter(Mandatory)][string]$InputJsonPath,
    [Parameter(Mandatory)][string]$OutDir
  )

  Write-Log "TEMPLATE CSV: Generating template summary..." 'INFO'

  # Load JSON to count secrets per template
  $root = Get-Content $InputJsonPath -Raw | ConvertFrom-Json
  $secrets = @($root.Secrets)

  # Build secret count per template ID
  $templateSecretCount = @{}
  $templateSecretNames = @{}
  foreach($s in $secrets){
    $tid = Get-PropValue $s @('SecretTypeId','secretTypeId','SecretTemplateId','secretTemplateId') $null
    if($tid -ne $null){
      $tidStr = [string]$tid
      if(-not $templateSecretCount.ContainsKey($tidStr)){ $templateSecretCount[$tidStr] = 0; $templateSecretNames[$tidStr] = @() }
      $templateSecretCount[$tidStr]++
      $sn = [string](Get-PropValue $s @('Name','name') '')
      if($templateSecretNames[$tidStr].Count -lt 5){ $templateSecretNames[$tidStr] += $sn }
    }
  }

  # Get all templates from the source API
  $templates = @()
  # Only fetch full details (fields) for templates that have secrets in the export
  $usedTemplateIds = @($templateSecretCount.Keys)
  try{
    $templates = Get-AllSecretTemplatesDetailed $ApiBase $Tok $usedTemplateIds
  }
  catch{
    Write-Log ("TEMPLATE CSV: Failed to retrieve templates from API: {0}" -f $_.Exception.Message) 'WARN'
  }

  # Also include TemplateExports from JSON (for offline info)
  $templateExportNames = @{}
  if($root.PSObject.Properties.Name -contains 'TemplateExports'){
    foreach($te in @($root.TemplateExports)){
      $teId = [string](Get-PropValue $te @('templateId','TemplateId') '')
      $xmlText = Get-PropValue $te @('exportFileText','ExportFileText') $null
      if($xmlText){
        $teName = Get-TemplateNameFromXml -templateXml $xmlText
        if($teName){ $templateExportNames[$teId] = $teName }
      }
    }
  }

  $templateRows = @()
  $templateFieldRows = @()
  $script:_launcherByTemplate = @{}
  $script:_allLauncherTypes = $null  # cache global launcher types

  # Process API templates
  foreach($tmpl in $templates){
    $tid = [string](Get-PropValue $tmpl @('id','Id') 0)
    $tName = [string](Get-PropValue $tmpl @('name','Name') '')
    $isActive = Get-PropValue $tmpl @('active','Active') $true
    $fields = @(Get-PropValue $tmpl @('fields','Fields') @())

    # Only fetch OTP/launcher details for templates that have secrets in the export (performance)
    $hasSecretsInExport = $templateSecretCount.ContainsKey($tid) -and $templateSecretCount[$tid] -gt 0

    # Get OTP and Launchers from template export XML (the detail endpoint doesn't include them)
    $otpEnabled = $null
    $launcherList = @()
    if($hasSecretsInExport){
    try{
      $exportResp = SS $ApiBase GET ("secret-templates/{0}/export" -f $tid) $Tok $null $null
      $xmlText = Get-PropValue $exportResp @('exportFileText','ExportFileText') $null
      if(-not [string]::IsNullOrWhiteSpace($xmlText)){
        [xml]$xDoc = $xmlText
        # OTP
        $otpNode = $xDoc.SelectSingleNode('//onetimepasswordenabled')
        if($otpNode -and -not $otpNode.GetAttribute('nil').EndsWith('true')){
          $otpVal = $otpNode.InnerText
          if(-not [string]::IsNullOrWhiteSpace($otpVal)){ $otpEnabled = $otpVal }
        }
      }
    }
    catch{
      Write-Log ("TEMPLATE CSV: Could not export template {0} for OTP info: {1}" -f $tid,$_.Exception.Message) 'DEBUG'
    }

    # Get launchers for this template
    if(-not $script:_launcherByTemplate.ContainsKey($tid)){
      $foundLaunchers = $false
      $sId = $null
      # Find a secret using this template (from export or via API search)
      $sampleSecret = $secrets | Where-Object {
        $sTid = Get-PropValue $_ @('SecretTypeId','secretTypeId','SecretTemplateId','secretTemplateId') $null
        [string]$sTid -eq $tid
      } | Select-Object -First 1
      if($sampleSecret){
        $sId = Get-PropValue $sampleSecret @('Id','id','SecretId','secretId') $null
      }
      if(-not $sId){
        try{
          $searchResp = SS $ApiBase GET 'secrets' $Tok $null @{'filter.secretTemplateId'=$tid;'take'=1}
          $searchRecs = @(Get-Records $searchResp)
          if($searchRecs.Count -gt 0){
            $sId = Get-PropValue $searchRecs[0] @('id','Id') $null
          }
        }
        catch{}
      }
      # Try per-secret launcher endpoint
      if($sId){
        try{
          $slResp = Invoke-RestMethod -Method GET -Uri ($ApiBase.TrimEnd('/') + "/secrets/$sId/launchers") -Headers @{Authorization="Bearer $Tok"} -TimeoutSec 10 -ErrorAction Stop
          $slRecs = @(if($slResp.records){ $slResp.records } elseif($slResp -is [array]){ $slResp } else { @($slResp) })
          $names = @()
          foreach($sl in $slRecs){
            $n = [string](Get-PropValue $sl @('launcherTypeName','LauncherTypeName','typeName','TypeName','name','Name','launcherName','LauncherName') '')
            if(-not [string]::IsNullOrWhiteSpace($n)){ $names += $n }
          }
          $script:_launcherByTemplate[$tid] = $names
          $foundLaunchers = $true
        }
        catch{}
      }
      # Fallback: use global /launchers list for templates that have a password field
      if(-not $foundLaunchers){
        if($null -eq $script:_allLauncherTypes){
          $script:_allLauncherTypes = @()
          try{
            $glResp = Invoke-RestMethod -Method GET -Uri ($ApiBase.TrimEnd('/') + "/launchers?take=100") -Headers @{Authorization="Bearer $Tok"} -TimeoutSec 10 -ErrorAction Stop
            $glRecs = @(if($glResp.records){ $glResp.records } elseif($glResp -is [array]){ $glResp } else { @() })
            foreach($gl in $glRecs){
              $glActive = Get-PropValue $gl @('active','Active') $true
              if($glActive){
                $gn = [string](Get-PropValue $gl @('name','Name') '')
                if(-not [string]::IsNullOrWhiteSpace($gn)){ $script:_allLauncherTypes += $gn }
              }
            }
            Write-Log ("TEMPLATE CSV: Using global launcher types ({0} active)" -f $script:_allLauncherTypes.Count) 'INFO'
          }
          catch{
            Write-Log ("TEMPLATE CSV: Could not retrieve global launchers: {0}" -f $_.Exception.Message) 'DEBUG'
          }
        }
        # Only assign launchers to templates that have a password field (launcher-capable)
        $hasPasswordField = $false
        foreach($f in $fields){
          if([bool](Get-PropValue $f @('isPassword','IsPassword') $false)){ $hasPasswordField = $true; break }
        }
        if($hasPasswordField -and $script:_allLauncherTypes.Count -gt 0){
          $script:_launcherByTemplate[$tid] = $script:_allLauncherTypes
        } else {
          $script:_launcherByTemplate[$tid] = @()
        }
      }
    }
    if($script:_launcherByTemplate.ContainsKey($tid)){
      $launcherList = @($script:_launcherByTemplate[$tid])
    }
    } # end if($hasSecretsInExport)

    $secCount = if($templateSecretCount.ContainsKey($tid)){ $templateSecretCount[$tid] } else { 0 }
    $sampleSecrets = if($templateSecretNames.ContainsKey($tid)){ ($templateSecretNames[$tid] -join '; ') } else { '' }

    $fieldNames = @()
    $fieldSlugs = @()
    $requiredFields = @()
    $fileFields = @()
    $passwordFields = @()

    foreach($f in $fields){
      $fName = [string](Get-PropValue $f @('name','Name','displayName','DisplayName') '')
      $fSlug = [string](Get-PropValue $f @('fieldSlugName','FieldSlugName','slug','Slug') '')
      $isRequired = [bool](Get-PropValue $f @('isRequired','IsRequired') $false)
      $isFile = [bool](Get-PropValue $f @('isFile','IsFile') $false)
      $isPassword = [bool](Get-PropValue $f @('isPassword','IsPassword') $false)

      $fieldNames += $fName
      $fieldSlugs += $fSlug
      if($isRequired){ $requiredFields += $fName }
      if($isFile){ $fileFields += $fName }
      if($isPassword){ $passwordFields += $fName }

      # Per-field row
      $templateFieldRows += [pscustomobject]@{
        TemplateId    = $tid
        TemplateName  = $tName
        FieldName     = $fName
        FieldSlug     = $fSlug
        IsRequired    = $isRequired
        IsFile        = $isFile
        IsPassword    = $isPassword
        IsNotes       = [bool](Get-PropValue $f @('isNotes','IsNotes') $false)
        IsUrl         = [bool](Get-PropValue $f @('isUrl','IsUrl') $false)
        FieldId       = Get-PropValue $f @('secretTemplateFieldId','SecretTemplateFieldId','fieldId','FieldId') $null
      }
    }

    $templateRows += [pscustomobject]@{
      TemplateId       = $tid
      TemplateName     = $tName
      IsActive         = $isActive
      OneTimePasswordEnabled = if($otpEnabled -ne $null){ $otpEnabled } else { '' }
      FieldCount       = $fields.Count
      Fields           = ($fieldNames -join ', ')
      FieldSlugs       = ($fieldSlugs -join ', ')
      RequiredFields   = ($requiredFields -join ', ')
      FileFields       = ($fileFields -join ', ')
      PasswordFields   = ($passwordFields -join ', ')
      Launchers        = ($launcherList -join ', ')
      LauncherCount    = $launcherList.Count
      SecretsUsingThis = $secCount
      SampleSecrets    = $sampleSecrets
    }
  }

  # Add any template IDs from JSON that weren't in the API results
  $apiTemplateIds = @($templateRows | ForEach-Object { $_.TemplateId })
  foreach($tidStr in $templateSecretCount.Keys){
    if($tidStr -notin $apiTemplateIds){
      $tName = if($templateExportNames.ContainsKey($tidStr)){ $templateExportNames[$tidStr] } else { '(Unknown - not in target)' }
      $templateRows += [pscustomobject]@{
        TemplateId       = $tidStr
        TemplateName     = $tName
        IsActive         = '(not on API)'
        OneTimePasswordEnabled = ''
        FieldCount       = ''
        Fields           = ''
        FieldSlugs       = ''
        RequiredFields   = ''
        FileFields       = ''
        PasswordFields   = ''
        Launchers        = ''
        LauncherCount    = ''
        SecretsUsingThis = $templateSecretCount[$tidStr]
        SampleSecrets    = if($templateSecretNames.ContainsKey($tidStr)){ ($templateSecretNames[$tidStr] -join '; ') } else { '' }
      }
    }
  }

  # Write CSVs
  if(-not (Test-Path $OutDir)){ New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

  $templateCsvPath = Join-Path $OutDir 'templates.csv'
  $templateFieldsCsvPath = Join-Path $OutDir 'template_fields.csv'

  if($templateRows.Count -gt 0){
    $templateRows | Export-Csv -Path $templateCsvPath -NoTypeInformation -Encoding UTF8
    Write-Log ("[OK] TEMPLATE CSV: {0} templates exported to: {1}" -f $templateRows.Count,$templateCsvPath) 'INFO'
  }
  if($templateFieldRows.Count -gt 0){
    $templateFieldRows | Export-Csv -Path $templateFieldsCsvPath -NoTypeInformation -Encoding UTF8
    Write-Log ("[OK] TEMPLATE CSV: {0} template fields exported to: {1}" -f $templateFieldRows.Count,$templateFieldsCsvPath) 'INFO'
  }

  return @{ Templates = $templateRows.Count; Fields = $templateFieldRows.Count }
}

# =====================================================
# EXPORT SECRET POLICIES CSV
# =====================================================
function Export-SecretPoliciesToCsv {
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Tok,
    [Parameter(Mandatory)][string]$OutDir
  )

  Write-Log "SECRET POLICIES CSV: Retrieving secret policies..." 'INFO'

  $policyRows = @()
  $policyItemRows = @()

  try{
    $skip = 0
    $take = 100
    $allPolicies = @()

    do{
      $resp = SS $ApiBase GET 'secret-policy/search' $Tok $null @{ 'skip'=$skip; 'take'=$take }
      $recs = @(Get-Records $resp)
      if($recs.Count -eq 0){ break }
      $allPolicies += $recs
      $skip += $recs.Count
      if($recs.Count -lt $take){ break }
    }while($true)

    Write-Log ("SECRET POLICIES CSV: Found {0} policies" -f $allPolicies.Count) 'INFO'

    foreach($pol in $allPolicies){
      $polId = Get-PropValue $pol @('secretPolicyId','SecretPolicyId','id','Id') $null
      $polName = [string](Get-PropValue $pol @('secretPolicyName','SecretPolicyName','name','Name') '')
      $polDesc = [string](Get-PropValue $pol @('secretPolicyDescription','SecretPolicyDescription','description','Description') '')
      $isActive = Get-PropValue $pol @('active','Active','isActive','IsActive') $true

      # Get detailed policy info
      $policyDetail = $null
      $policyItems = @()
      try{
        $policyDetail = SS $ApiBase GET ("secret-policy/{0}" -f $polId) $Tok $null $null
        $policyItems = @(Get-PropValue $policyDetail @('secretPolicyItems','SecretPolicyItems','items','Items') @())
      }
      catch{
        Write-Log ("SECRET POLICIES CSV: Could not get details for policy {0}: {1}" -f $polId,$_.Exception.Message) 'DEBUG'
      }

      $policyRows += [pscustomobject]@{
        PolicyId     = $polId
        PolicyName   = $polName
        Description  = $polDesc
        IsActive     = $isActive
        ItemCount    = $policyItems.Count
      }

      foreach($item in $policyItems){
        $itemName = [string](Get-PropValue $item @('secretPolicyItemName','SecretPolicyItemName','name','Name','policyApplyType','PolicyApplyType') '')
        $itemValue = Get-PropValue $item @('valueBool','ValueBool','valueInt','ValueInt','valueString','ValueString') $null
        $itemType = [string](Get-PropValue $item @('policyApplyType','PolicyApplyType','itemType','ItemType') '')
        $parentName = [string](Get-PropValue $item @('parentSecretPolicyItemName','ParentSecretPolicyItemName') '')
        $sshCmd = [string](Get-PropValue $item @('sshCommandMenuName','SshCommandMenuName') '')
        $enabledStr = Get-PropValue $item @('enabledByDefault','EnabledByDefault') $null

        $policyItemRows += [pscustomobject]@{
          PolicyId          = $polId
          PolicyName        = $polName
          ItemName          = $itemName
          ParentItemName    = $parentName
          PolicyApplyType   = $itemType
          Value             = $itemValue
          EnabledByDefault  = $enabledStr
          SshCommandMenu    = $sshCmd
        }
      }
    }
  }
  catch{
    Write-Log ("SECRET POLICIES CSV: API error: {0}" -f $_.Exception.Message) 'WARN'
    # Try alternative endpoint
    try{
      $resp = SS $ApiBase GET 'secret-policy' $Tok $null @{ 'skip'=0; 'take'=200 }
      $recs = @(Get-Records $resp)
      Write-Log ("SECRET POLICIES CSV: Fallback found {0} policies" -f $recs.Count) 'INFO'
      foreach($pol in $recs){
        $polId = Get-PropValue $pol @('secretPolicyId','SecretPolicyId','id','Id') $null
        $polName = [string](Get-PropValue $pol @('secretPolicyName','SecretPolicyName','name','Name') '')
        $policyRows += [pscustomobject]@{
          PolicyId     = $polId
          PolicyName   = $polName
          Description  = ''
          IsActive     = $true
          ItemCount    = 0
        }
      }
    }
    catch{
      Write-Log ("SECRET POLICIES CSV: Fallback also failed: {0}" -f $_.Exception.Message) 'WARN'
    }
  }

  # Write CSVs
  if(-not (Test-Path $OutDir)){ New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

  $policyCsvPath = Join-Path $OutDir 'secret_policies.csv'
  $policyItemsCsvPath = Join-Path $OutDir 'secret_policy_items.csv'

  if($policyRows.Count -gt 0){
    $policyRows | Export-Csv -Path $policyCsvPath -NoTypeInformation -Encoding UTF8
    Write-Log ("[OK] SECRET POLICIES CSV: {0} policies exported to: {1}" -f $policyRows.Count,$policyCsvPath) 'INFO'
  } else {
    Write-Log "SECRET POLICIES CSV: No policies found on this tenant" 'INFO'
  }
  if($policyItemRows.Count -gt 0){
    $policyItemRows | Export-Csv -Path $policyItemsCsvPath -NoTypeInformation -Encoding UTF8
    Write-Log ("[OK] SECRET POLICIES CSV: {0} policy items exported to: {1}" -f $policyItemRows.Count,$policyItemsCsvPath) 'INFO'
  }

  return @{ Policies = $policyRows.Count; PolicyItems = $policyItemRows.Count }
}

function Resolve-TargetUserIdByExactUserName([string]$tgtApi,[string]$tgtTok,[string]$userName){
  if([string]::IsNullOrWhiteSpace($userName)){ return $null }
  $r = SS $tgtApi GET 'users' $tgtTok $null @{ 'filter.searchText'=$userName; 'filter.page'=1; 'filter.pageSize'=50 }
  foreach($u in @(Get-Records $r)){
    $un = Get-PropValue $u @('userName','UserName') $null
    $id = Get-PropValue $u @('id','Id') $null
    if($un -and $id -ne $null -and $un.Equals($userName,[System.StringComparison]::OrdinalIgnoreCase)){
      return [int]$id
    }
  }
  return $null
}

function Ensure-FolderSafetyPermissionForCurrentUser(
  [string]$tgtApi,[string]$tgtTok,[int]$folderId,[string]$currentUserName,
  [string]$folderAccessRoleName = 'Owner',
  [string]$secretAccessRoleName = 'Owner'
){
  $uid = Resolve-TargetUserIdByExactUserName -tgtApi $tgtApi -tgtTok $tgtTok -userName $currentUserName
  if($uid -eq $null){
    Write-Log ("SAFETY ACL: could not resolve current target userId for '{0}'. Skipping safety ACL." -f $currentUserName) 'WARN'
    return
  }

  $perm = [pscustomobject]@{
    userId = $uid
    folderAccessRoleName = $folderAccessRoleName
    secretAccessRoleName = $secretAccessRoleName
  }

  try{
    Add-FolderPermission -apiBase $tgtApi -tok $tgtTok -folderId $folderId -perm $perm
    Write-Log ("SAFETY ACL: ensured current user '{0}' (userId={1}) has FolderRole='{2}' SecretRole='{3}' on folderId={4}" -f `
      $currentUserName,$uid,$folderAccessRoleName,$secretAccessRoleName,$folderId) 'INFO'
  } catch {
    Write-Log ("SAFETY ACL: failed to add safety permission on folderId={0}: {1}" -f $folderId,$_) 'WARN'
  }
}

# --- Import (UPDATED: Remap applied to BOTH folder perms + secret perms; NO overrides) ---

function Delete-SecretById([string]$apiBase,[string]$tok,[int]$secretId){
  SS $apiBase DELETE ("secrets/{0}" -f $secretId) $tok $null $null | Out-Null
}

function Delete-FolderById([string]$apiBase,[string]$tok,[int]$folderId){
  # Verify folder exists first
  try{
    $folder = SS $apiBase GET ("folders/{0}" -f $folderId) $tok $null $null
    Write-Log ("DELETE: Folder id={0} exists. Name='{1}'" -f $folderId,(Get-PropValue $folder @('folderName','FolderName','name','Name') 'Unknown')) 'DEBUG'
  }
  catch{
    Write-Log ("DELETE: Folder id={0} does not exist (already deleted). Skipping." -f $folderId) 'DEBUG'
    return
  }
  
  # Attempt deletion
  try{
    SS $apiBase DELETE ("folders/{0}" -f $folderId) $tok $null $null | Out-Null
    Write-Log ("DELETE: Successfully deleted folder id={0}" -f $folderId) 'DEBUG'
  }
  catch{
    # Re-throw with more context
    $errMsg = $_.Exception.Message
    throw "Failed to delete folder id=$folderId : $errMsg"
  }
}

function Restore-TargetSecretFromSnapshot([string]$tgtApi,[string]$tgtTok,[int]$secretId,[string]$rollbackFile){
  if(-not (Test-Path $rollbackFile)){ throw "Rollback file not found: $rollbackFile" }
  $old = Get-Content $rollbackFile -Raw | ConvertFrom-Json

  $oldTemplateId = Get-PropValue $old @('secretTemplateId','SecretTemplateId','secretTypeId','SecretTypeId') $null
  if(-not $oldTemplateId){ throw "Rollback snapshot missing SecretTemplateId/SecretTypeId for secretId=$secretId" }

  $oldName = Get-PropValue $old @('name','Name') ("secret_$secretId")
  $oldFolderId = Get-PropValue $old @('folderId','FolderId') $null
  if($oldFolderId -eq $null){ throw "Rollback snapshot missing FolderId for secretId=$secretId" }

  $rawItems = Get-PropValue $old @('items','Items','fields','Fields') @()
  $normItems=@()
  foreach($it in @($rawItems)){
    $n    = Get-PropValue $it @('name','Name','fieldName','FieldName') $null
    $slug = Get-PropValue $it @('slug','Slug','fieldSlugName','FieldSlugName') $null
    $val  = Get-PropValue $it @('value','Value','itemValue','ItemValue') $null
    $normItems += [pscustomobject]@{ name=$n; slug=$slug; value=$val }
  }

  $payload = @{
    Name = $oldName
    FolderId = [int]$oldFolderId
    SecretTemplateId = [int]$oldTemplateId
    Items = (Build-SecretCreateItems $tgtApi $tgtTok ([int]$oldTemplateId) $normItems)
  }
  $site = Get-PropValue $old @('siteId','SiteId') $null
  Add-IfValidInt $payload 'siteId' $site
  Add-IfValidInt $payload 'SiteId' $site

  Write-Log ("ROLLBACK RESTORE: restoring secretId={0} from {1}" -f $secretId,$rollbackFile) 'INFO'
  SS $tgtApi PUT ("secrets/{0}" -f $secretId) $tgtTok $payload $null | Out-Null
}

function Cleanup-RollbackUpdatedSecrets([string]$tgtApi,[string]$tgtTok){
  if(-not $script:ImportRunUpdatedSecretIds -or $script:ImportRunUpdatedSecretIds.Count -eq 0){
    Write-Log "CLEANUP: no updated secrets to rollback." 'INFO'
    return
  }
  foreach($sid in @($script:ImportRunUpdatedSecretIds)){
    $meta = $script:ImportRunUpdatedSecretsById[[string]$sid]
    if(-not $meta){ continue }
    $file = [string]$meta.rollbackFile
    $nm = [string]$meta.name
    try{
      Restore-TargetSecretFromSnapshot -tgtApi $tgtApi -tgtTok $tgtTok -secretId ([int]$sid) -rollbackFile $file
      Write-Log ("CLEANUP: rolled back UPDATED secretId={0} name='{1}'" -f $sid,$nm) 'INFO'
    } catch {
      Write-Log ("CLEANUP: FAILED rollback UPDATED secretId={0} name='{1}': {2}" -f $sid,$nm,$_) 'WARN'
    }
  }
}

# =============================================================================
# Parallel page fetcher using HttpClient — fetches multiple pages concurrently
# Returns all records from all pages as a single array
# =============================================================================
function Get-AllSecretsPaged-Parallel{
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Token,
    [string]$SearchText = '*',
    [int]$PageSize = 500,
    [int]$MaxPages = 500,
    [int]$ConcurrentPages = 5,
    [bool]$OnlyActive = $true,
    [scriptblock]$OnProgress = $null
  )

  $baseUri = $ApiBase.TrimEnd('/')
  $allRecords = [System.Collections.ArrayList]::new()
  # When OnlyActive, ask the API to exclude inactive/disabled secrets.
  # Delinea SS supports filter.includeInactive (default behaviour can vary; be explicit).
  $activeFlag = if($OnlyActive){ 'false' } else { 'true' }
  $activeQs = "&filter.includeInactive=$activeFlag"
  # Stable sort by id so concurrent skip/take pages don't overlap or skip rows.
  $sortQs = '&filter.sortBy%5B0%5D.direction=Ascending&filter.sortBy%5B0%5D.name=id'

  # First, get page 1 to determine total count
  $firstPageParams = "filter.searchText=$([uri]::EscapeDataString($SearchText))&filter.page=1&filter.pageSize=$PageSize&take=$PageSize&skip=0$activeQs$sortQs"
  $firstUrl = "$baseUri/secrets?$firstPageParams"
  
  $handler = New-Object System.Net.Http.HttpClientHandler
  $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
  $client = New-Object System.Net.Http.HttpClient($handler)
  $client.Timeout = [TimeSpan]::FromSeconds(120)
  $client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer',$Token)
  $client.DefaultRequestHeaders.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('application/json'))
  
  try{
    # Page 1
    $resp1 = $client.GetAsync($firstUrl).Result
    if(-not $resp1.IsSuccessStatusCode){
      Write-Log ("Parallel pager: page 1 failed HTTP {0}" -f $resp1.StatusCode) 'ERROR'
      return @()
    }
    $json1 = $resp1.Content.ReadAsStringAsync().Result
    $parsed1 = $json1 | ConvertFrom-Json
    $recs1 = @(Get-Records $parsed1)
    [void]$allRecords.AddRange($recs1)
    
    # Determine total from response
    $total = 0
    try{ $total = [int](Get-PropValue $parsed1 @('total','Total','totalCount','TotalCount') 0) } catch {}
    
    if($OnProgress){ & $OnProgress 1 $recs1.Count $allRecords.Count $total }
    
    if($recs1.Count -lt $PageSize -or $total -le $PageSize){
      # Only 1 page needed
      return $allRecords.ToArray()
    }
    
    # Calculate remaining pages
    $totalPages = [Math]::Ceiling($total / $PageSize)
    if($totalPages -gt $MaxPages){ $totalPages = $MaxPages }
    
    Write-Log ("Parallel pager: total={0}, pages={1}, fetching {2} pages concurrently" -f $total,$totalPages,$ConcurrentPages) 'DEBUG'
    
    # Fetch remaining pages in parallel batches
    for($batchStart = 2; $batchStart -le $totalPages; $batchStart += $ConcurrentPages){
      # Cooperative cancel: honor the Reconcile-tab Cancel button. Break here
      # so cancel during a long target paging run is observed within one
      # batch (~5-15 seconds) instead of waiting for full pagination.
      if($script:ReconCancelled){
        Write-Log ("Parallel pager: cancel observed at batch starting page {0}; returning {1} records so far." -f $batchStart,$allRecords.Count) 'WARN'
        break
      }
      $batchEnd = [Math]::Min($batchStart + $ConcurrentPages - 1, $totalPages)
      $tasks = @()
      
      for($pg = $batchStart; $pg -le $batchEnd; $pg++){
        $skip = ($pg - 1) * $PageSize
        $url = "$baseUri/secrets?filter.searchText=$([uri]::EscapeDataString($SearchText))&filter.page=$pg&filter.pageSize=$PageSize&take=$PageSize&skip=$skip$activeQs$sortQs"
        $tasks += @{ Page = $pg; Task = $client.GetAsync($url) }
      }
      
      try{
        # Poll-wait with DoEvents pumping so the Reconcile-tab Cancel button
        # click can be processed while the parallel page batch is in flight.
        # WaitAll blocks the UI thread and starves window messages; this loop
        # yields every 100ms so a clicked Cancel sets $script:ReconCancelled
        # within ~0.1s instead of waiting for the entire batch to complete.
        $__waitSw = [System.Diagnostics.Stopwatch]::StartNew()
        while($true){
          $allDone = $true
          foreach($t in $tasks){ if(-not $t.Task.IsCompleted){ $allDone = $false; break } }
          if($allDone){ break }
          if($__waitSw.Elapsed.TotalSeconds -ge 60){ break } # safety cap (matches prior 60s WaitAll)
          try{ [System.Windows.Forms.Application]::DoEvents() } catch {}
          if($script:ReconCancelled){ break }
          Start-Sleep -Milliseconds 100
        }
      } catch {}
      
      foreach($t in $tasks){
        try{
          $resp = $t.Task.Result
          if($resp.IsSuccessStatusCode){
            $jsonStr = $resp.Content.ReadAsStringAsync().Result
            $parsed = $jsonStr | ConvertFrom-Json
            $recs = @(Get-Records $parsed)
            [void]$allRecords.AddRange($recs)
          } else {
            Write-Log ("Parallel pager: page {0} HTTP {1}" -f $t.Page,$resp.StatusCode) 'WARN'
          }
        }
        catch{
          Write-Log ("Parallel pager: page {0} error: {1}" -f $t.Page,$_.Exception.Message) 'WARN'
        }
      }
      
      if($OnProgress){ & $OnProgress $batchEnd 0 $allRecords.Count $total }
    }
    
    # Gap-detection: warn when fetched count < API total (pagination drift).
    if($total -gt 0 -and $allRecords.Count -lt $total){
      Write-Log ("Parallel pager: WARNING gap detected - fetched {0} records but API reported total={1} (missing {2}). Concurrent pagination may have drifted." -f $allRecords.Count,$total,($total - $allRecords.Count)) 'WARN'
    }

    return $allRecords.ToArray()
  }
  catch{
    Write-Log ("Parallel pager error: {0}" -f $_.Exception.Message) 'ERROR'
    return $allRecords.ToArray()
  }
  finally{
    $client.Dispose()
    $handler.Dispose()
  }
}


function Verify-SS{
  param(
    [Parameter(Mandatory)][string]$ApiBase,
    [Parameter(Mandatory)][string]$Token,
    [Parameter(Mandatory)][int]$RootFolderId
  )

  Write-Log ("VERIFY: scanning secrets under rootFolderId={0} (includes descendants)" -f $RootFolderId) 'INFO'

  # Get all descendant folders (includes root)
  $folderIds = @()
  try{
    $folderIds = @(Get-DescendantFolderIds -ApiBase $ApiBase -Tok $Token -RootFolderId $RootFolderId)
  } catch {
    throw ("VERIFY: failed to enumerate descendant folders for rootFolderId={0}: {1}" -f $RootFolderId,($_ | Out-String))
  }

  Write-Log ("VERIFY: found {0} folders to scan" -f $folderIds.Count) 'INFO'

  $totalSecrets = 0
  $foldersWithErrors = 0
  $folderCount = $folderIds.Count
  $folderIndex = 0
  $lastLogTime = [DateTime]::MinValue

  foreach($fid in $folderIds){
    $folderIndex++
    
    # Log progress every 5 folders OR every 3 seconds
    $now = Get-Date
    if(($folderIndex % 5 -eq 0) -or (($now - $lastLogTime).TotalSeconds -ge 3)){
      Write-Log ("VERIFY: scanning folder {0}/{1} ({2:P0}) - {3} secrets found so far" -f `
        $folderIndex, $folderCount, ($folderIndex/$folderCount), $totalSecrets) 'INFO'
      $lastLogTime = $now
    }

    $page=1; $ps=200
    $folderSecretCount = 0

    while($true){
      try{
        # secrets/lookup is what you already use elsewhere; use it here too
        $q=@{
          'filter.folderId'   = [int]$fid
          'filter.page'       = $page
          'filter.pageSize'   = $ps
          'filter.searchText' = '*'
        }
        $resp = SS $ApiBase GET 'secrets/lookup' $Token $null $q
        $recs = @(Get-Records $resp)

        $folderSecretCount += $recs.Count
        $totalSecrets += $recs.Count

        if($recs.Count -lt $ps){ break }
        $page++
        if($page -gt 2000){
          Write-Log ("VERIFY: safety stop paging secrets at page={0} folderId={1}" -f $page,$fid) 'WARN'
          break
        }
      }
      catch{
        $foldersWithErrors++
        Write-Log ("VERIFY: failed to list secrets for folderId={0}: {1}" -f $fid,($_ | Out-String)) 'WARN'
        break
      }
    }

    Write-Log ("VERIFY: folderId={0} secrets={1}" -f $fid,$folderSecretCount) 'DEBUG'
  }

  Write-Log ("VERIFY SUMMARY: foldersScanned={0}, totalSecretsFound={1}, foldersWithErrors={2}" -f $folderIds.Count,$totalSecrets,$foldersWithErrors) 'INFO'

  return [pscustomobject]@{
    RootFolderId      = $RootFolderId
    FoldersScanned    = $folderIds.Count
    TotalSecretsFound = $totalSecrets
    FoldersWithErrors = $foldersWithErrors
  }
}

function Cleanup-LastImport{
  param(
    [Parameter(Mandatory)][string]$tgtApi,
    [Parameter(Mandatory)][string]$tgtTok,
    [bool]$rollbackUpdated = $false
  )

  Write-Log "CLEANUP: starting cleanup of last import run objects..." 'INFO'

  $secretsDeleted = 0
  $secretsFailed = 0
  $foldersDeleted = 0
  $foldersFailed = 0

  # 1) Rollback updated secrets first (optional)
  if($rollbackUpdated){
    try{
      Cleanup-RollbackUpdatedSecrets -tgtApi $tgtApi -tgtTok $tgtTok
    } catch {
      Write-Log ("CLEANUP: rollback of updated secrets encountered errors: {0}" -f ($_ | Out-String)) 'WARN'
    }
  }

  # 2) Delete created secrets (reverse order best-effort)
  if($script:ImportRunCreatedSecretIds -and $script:ImportRunCreatedSecretIds.Count -gt 0){
    $ids = @($script:ImportRunCreatedSecretIds)
    [array]::Reverse($ids)

    Write-Log ("CLEANUP: deleting {0} created secrets..." -f $ids.Count) 'INFO'

    foreach($sid in $ids){
      try{
        Delete-SecretById -apiBase $tgtApi -tok $tgtTok -secretId ([int]$sid)
        
        $meta = $script:ImportRunCreatedSecretsById[[string]$sid]
        $nm = if($meta){ [string]$meta.name } else { "" }
        
        Write-Log ("CLEANUP: deleted secret id={0} name='{1}'" -f $sid,$nm) 'INFO'
        $secretsDeleted++
      } 
      catch {
        $meta = $script:ImportRunCreatedSecretsById[[string]$sid]
        $nm = if($meta){ [string]$meta.name } else { "" }
        
        Write-Log ("CLEANUP: FAILED deleting secret id={0} name='{1}': {2}" -f $sid,$nm,($_.Exception.Message)) 'ERROR'
        $secretsFailed++
      }
    }
  } else {
    Write-Log "CLEANUP: no created secrets recorded for last import run." 'INFO'
  }

  # 3) Delete created folders (CRITICAL: reverse order so children go first)
  if($script:ImportRunCreatedFolderIds -and $script:ImportRunCreatedFolderIds.Count -gt 0){
    $fids = @($script:ImportRunCreatedFolderIds)
    [array]::Reverse($fids)

    Write-Log ("CLEANUP: deleting {0} created folders (children first)..." -f $fids.Count) 'INFO'

    foreach($fid in $fids){
      $meta = $script:ImportRunCreatedFoldersById[[string]$fid]
      $nm = if($meta){ [string]$meta.name } else { "" }
      $pp = if($meta){ [string]$meta.path } else { "" }

      # CRITICAL: Check if folder still has secrets before deletion
      try{
        # First, try to get folder details to verify it still exists
        $folderExists = $false
        try{
          $folderDetail = SS $tgtApi GET ("folders/{0}" -f [int]$fid) $tgtTok $null $null
          $folderExists = $true
          Write-Log ("CLEANUP: folder id={0} exists. Checking for secrets..." -f $fid) 'DEBUG'
        }
        catch{
          # Folder already deleted or doesn't exist
          Write-Log ("CLEANUP: folder id={0} already deleted or doesn't exist. Skipping." -f $fid) 'DEBUG'
          $foldersDeleted++
          continue
        }

        # Check if folder has any secrets (must be empty to delete)
        $secretCheckPassed = $true
        try{
          $secretsInFolder = @()
          
          # Try multiple endpoints to check for secrets
          $secretEndpoints = @(
            "folders/$fid/secrets?take=1",
            "secrets?filter.folderId=$fid&take=1",
            "secrets/lookup?filter.folderId=$fid&filter.pageSize=1"
          )
          
          foreach($secEndpoint in $secretEndpoints){
            try{
              $secResp = SS $tgtApi GET $secEndpoint $tgtTok $null $null
              $secretsInFolder = @(Get-Records $secResp)
              if($secretsInFolder.Count -gt 0){
                Write-Log ("CLEANUP: folder id={0} still contains {1} secrets. Cannot delete." -f $fid,$secretsInFolder.Count) 'WARN'
                $secretCheckPassed = $false
                $foldersFailed++
                break
              }
            }
            catch{
              # Endpoint not available, try next one
              continue
            }
          }
        }
        catch{
          # If we can't check secrets, proceed with caution
          Write-Log ("CLEANUP: could not verify secrets in folder id={0}. Attempting delete anyway..." -f $fid) 'WARN'
        }

        if(-not $secretCheckPassed){
          continue
        }

        # Check if folder has child folders (must have no children to delete)
        $childCheckPassed = $true
        try{
          $children = @(Get-ChildFolders -ApiBase $tgtApi -Tok $tgtTok -ParentFolderId $fid)
          if($children.Count -gt 0){
            Write-Log ("CLEANUP: folder id={0} still contains {1} child folders. Cannot delete." -f $fid,$children.Count) 'WARN'
            $childCheckPassed = $false
            $foldersFailed++
          }
        }
        catch{
          # If we can't check children, proceed with caution
          Write-Log ("CLEANUP: could not verify child folders in folder id={0}. Attempting delete anyway..." -f $fid) 'WARN'
        }

        if(-not $childCheckPassed){
          continue
        }

        # Attempt folder deletion
        Write-Log ("CLEANUP: attempting to delete folder id={0} name='{1}' path='{2}'" -f $fid,$nm,$pp) 'DEBUG'
        
        SS $tgtApi DELETE ("folders/{0}" -f [int]$fid) $tgtTok $null $null | Out-Null
        
        Write-Log ("CLEANUP: deleted folder id={0} name='{1}' path='{2}'" -f $fid,$nm,$pp) 'INFO'
        $foldersDeleted++
      }
      catch{
        $errMsg = $_.Exception.Message
        
        # Parse common error scenarios
        if($errMsg -match "folder is not empty" -or $errMsg -match "has secrets" -or $errMsg -match "has children"){
          Write-Log ("CLEANUP: âœ— folder id={0} cannot be deleted (not empty or has children). Manual cleanup required." -f $fid) 'WARN'
        }
        elseif($errMsg -match "404" -or $errMsg -match "not found"){
          Write-Log ("CLEANUP: folder id={0} not found (already deleted or never existed). Counting as success." -f $fid) 'DEBUG'
          $foldersDeleted++
          continue
        }
        elseif($errMsg -match "403" -or $errMsg -match "forbidden" -or $errMsg -match "unauthorized"){
          Write-Log ("CLEANUP: âœ— folder id={0} cannot be deleted (permission denied). Check user permissions." -f $fid) 'ERROR'
        }
        else{
          Write-Log ("CLEANUP: âœ— FAILED deleting folder id={0} name='{1}': {2}" -f $fid,$nm,$errMsg) 'ERROR'
        }
        
        $foldersFailed++
      }
    }
  } else {
    Write-Log "CLEANUP: no created folders recorded for last import run." 'INFO'
  }

  # 4) Reset run state
  try{
    Reset-ImportRunCreatedObjects
    $script:LastImportRunRootFolderId = $null
  } catch {}

  Write-Log ("CLEANUP: completed. Secrets: {0} deleted, {1} failed. Folders: {2} deleted, {3} failed." -f `
    $secretsDeleted,$secretsFailed,$foldersDeleted,$foldersFailed) 'INFO'
  
  if($foldersFailed -gt 0){
    Write-Log "CLEANUP: Some folders could not be deleted. Common reasons: 1) Folder still contains secrets, 2) Folder has child folders, 3) Permission denied. Check log above for details." 'WARN'
  }
  
  # Return cleanup summary
  return [pscustomobject]@{
    SecretsDeleted = $secretsDeleted
    SecretsFailed = $secretsFailed
    FoldersDeleted = $foldersDeleted
    FoldersFailed = $foldersFailed
  }
}

function Update-SourceTargetEnabledState {
  $srcEnabled = [bool]$cbEnableSrc.Checked
  $tgtEnabled = [bool]$cbEnableTgt.Checked

  # ========== SOURCE CONTROLS ==========
  $tbSrcBase.Enabled = $srcEnabled
  $tbSrcUser.Enabled = $srcEnabled
  $tbSrcPwd.Enabled = $srcEnabled
  $tbSrcApi.Enabled = $srcEnabled
  $tbSrcSearch.Enabled = $srcEnabled
  $tbSrcFld.Enabled = $srcEnabled

  # ========== TARGET CONTROLS ==========
  $tbTgtBase.Enabled = $tgtEnabled
  $tbTgtUser.Enabled = $tgtEnabled
  $tbTgtPwd.Enabled = $tgtEnabled
  $tbTgtApi.Enabled = $tgtEnabled
  $tbTgtFld.Enabled = $tgtEnabled
  $tbTgtRoot.Enabled = $tgtEnabled

  # ========== ACTION BUTTONS ==========
  # Export: requires Source
  $btnExport.Enabled = $srcEnabled

  # Get # Secrets: requires either Source OR Target (based on radio selection)
  $countSrcSelected = $rbCountSrc.Checked
  $btnGetCount.Enabled = ($countSrcSelected -and $srcEnabled) -or (-not $countSrcSelected -and $tgtEnabled)
  
  # Update radio button states
  $rbCountSrc.Enabled = $srcEnabled
  $rbCountTgt.Enabled = $tgtEnabled
  
  # If current selection is disabled, switch to enabled one
  if($rbCountSrc.Checked -and -not $srcEnabled -and $tgtEnabled){
    $rbCountTgt.Checked = $true
  }
  elseif($rbCountTgt.Checked -and -not $tgtEnabled -and $srcEnabled){
    $rbCountSrc.Checked = $true
  }

  # Verify: requires Source OR Target
  $btnVerify.Enabled = $srcEnabled -or $tgtEnabled

  # Import: requires Target (source token is optional, JSON file has the data)
  $btnImport.Enabled = $tgtEnabled

  # Cleanup: requires Target OR cleanup rollback checkbox is checked
  # (Allows cleanup even if Target is disabled, as long as rollback is enabled)
  $btnCleanup.Enabled = $tgtEnabled -or ([bool]$cbCleanupUpdated.Checked)

  # Always enabled: Close, Clear Log
  # (no change needed)

  Write-Log ("Controls state updated: Source={0}, Target={1}, Cleanup={2}" -f $srcEnabled,$tgtEnabled,$btnCleanup.Enabled) 'DEBUG'
}

# =========================
# UI (Ocean only, no Theme dropdown)
# =========================

# --- THEME (Ocean only) ---
$Palettes = @{
  Ocean    = @{
    Form      = [System.Drawing.Color]::FromArgb(225, 242, 252)
    Panel     = [System.Drawing.Color]::FromArgb(235, 248, 255)
    Group     = [System.Drawing.Color]::FromArgb(248, 253, 255)
    Text      = [System.Drawing.Color]::FromArgb(18, 42, 62)
    Accent    = [System.Drawing.Color]::FromArgb(0, 122, 204)
    Accent2   = [System.Drawing.Color]::FromArgb(0, 153, 188)
    Accent3   = [System.Drawing.Color]::FromArgb(94, 129, 172)
    Danger    = [System.Drawing.Color]::FromArgb(204, 72, 72)
    InputBack = [System.Drawing.Color]::FromArgb(255, 255, 255)
    InputText = [System.Drawing.Color]::FromArgb(18, 42, 62)
  }
}

function Style-Button([System.Windows.Forms.Button]$btn,$t,[string]$kind='primary'){
  $btn.FlatStyle = 'Flat'
  $btn.FlatAppearance.BorderSize = 0
  $btn.UseVisualStyleBackColor = $false
  $btn.ForeColor = [System.Drawing.Color]::White
  $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
  switch($kind){
    'primary'   { $btn.BackColor = $t.Accent }
    'secondary' { $btn.BackColor = $t.Accent2 }
    'neutral'   { $btn.BackColor = $t.Accent3 }
    'danger'    { $btn.BackColor = $t.Danger }
    default     { $btn.BackColor = $t.Accent }
  }
  # Hover highlight
  $baseColor = $btn.BackColor
  $btn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(
    [Math]::Min(255,[int]$baseColor.R + 30),
    [Math]::Min(255,[int]$baseColor.G + 30),
    [Math]::Min(255,[int]$baseColor.B + 30))
  $btn.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(
    [Math]::Max(0,[int]$baseColor.R - 20),
    [Math]::Max(0,[int]$baseColor.G - 20),
    [Math]::Max(0,[int]$baseColor.B - 20))
  # Keep color visible even when disabled (owner-draw)
  $btn.Add_EnabledChanged({
    $this.Invalidate()
  })
  $btn.Add_Paint({
    param($sender,$e)
    if(-not $sender.Enabled){
      $g = $e.Graphics
      $g.Clear($sender.BackColor)
      $sf = New-Object System.Drawing.StringFormat
      $sf.Alignment = 'Center'
      $sf.LineAlignment = 'Center'
      $dimBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(180,255,255,255))
      $g.DrawString($sender.Text, $sender.Font, $dimBrush, [System.Drawing.RectangleF]::new(0,0,$sender.Width,$sender.Height), $sf)
      $dimBrush.Dispose()
      $sf.Dispose()
    }
  })
}

function Set-Colors($ctrl,$t){
  if($ctrl -is [System.Windows.Forms.ProgressBar]){ return }
  $keepColor = ($ctrl.Tag -eq 'KeepColor')
  if($ctrl -is [System.Windows.Forms.GroupBox]){ $ctrl.BackColor=$t.Group; if(-not $keepColor){ $ctrl.ForeColor=$t.Text } }
  elseif($ctrl -is [System.Windows.Forms.Panel]){ $ctrl.BackColor=$t.Panel; if(-not $keepColor){ $ctrl.ForeColor=$t.Text } }
  elseif($ctrl -is [System.Windows.Forms.TabPage]){ $ctrl.BackColor=$t.Panel; if(-not $keepColor){ $ctrl.ForeColor=$t.Text } }
  else{ if(-not $keepColor){ $ctrl.ForeColor=$t.Text } }

  if($t.PSObject.Properties.Name -contains 'InputBack'){
    if($ctrl -is [System.Windows.Forms.TextBox] -or $ctrl -is [System.Windows.Forms.MaskedTextBox] -or $ctrl -is [System.Windows.Forms.RichTextBox]){
      try{ $ctrl.BackColor=$t.InputBack; if(-not $keepColor){ $ctrl.ForeColor=$t.InputText } } catch {}
    }
  }

  if($ctrl -is [System.Windows.Forms.Button]){
    # Buttons tagged 'KeepColor' keep their custom BackColor/ForeColor exactly
    # as set by the construction site (used by Reconciliation tab so its
    # buttons aren't overwritten when we re-apply the theme after that tab is
    # built).
    if(-not $keepColor){
    try{
      switch($ctrl.Name){
        # Actions tab buttons
        'btnClose'    { Style-Button $ctrl $t 'danger' }
        'btnExport'   { Style-Button $ctrl $t 'primary' }
        'btnImport'   { Style-Button $ctrl $t 'secondary' }
        'btnVerify'   { Style-Button $ctrl $t 'neutral' }
        'btnGetCount' { Style-Button $ctrl $t 'secondary' }
        'btnClear'    { Style-Button $ctrl $t 'neutral' }
        'btnCleanup'  { Style-Button $ctrl $t 'danger' }
        # Tools tab buttons
        'btnRunTools'        { Style-Button $ctrl $t 'primary' }
        'btnCloseTools'      { Style-Button $ctrl $t 'danger' }
        'btnClearToolsLog'   { Style-Button $ctrl $t 'neutral' }
        'btnBrowseMapCsv'    { Style-Button $ctrl $t 'neutral' }
        'btnBrowsePermsJson' { Style-Button $ctrl $t 'neutral' }
        'btnBrowseOutJson'   { Style-Button $ctrl $t 'neutral' }
        # Template Check tab buttons
        'btnCompareTemplates'     { Style-Button $ctrl $t 'primary' }
        'btnOpenTemplateCsv'      { Style-Button $ctrl $t 'secondary' }
        'btnClearTemplateLog'     { Style-Button $ctrl $t 'neutral' }
        'btnCloseTemplateCheck'   { Style-Button $ctrl $t 'danger' }
        'btnBrowseTemplateCsv'    { Style-Button $ctrl $t 'neutral' }
        default       { Style-Button $ctrl $t 'neutral' }
      }
    } catch {}
    }
  }

  foreach($child in $ctrl.Controls){ Set-Colors $child $t }
}

function Apply-Theme([string]$name){
  if(-not $Palettes.ContainsKey($name)){$name='Ocean'}
  $t=$Palettes[$name]
  $form.BackColor=$t.Form
  foreach($tp in $tabs.TabPages){ Set-Colors $tp $t }
}

# --- GUI LAYOUT ---
$Global:Config = Load-Config
#===========================#
$form = New-Object System.Windows.Forms.Form
$form.Text = "Delinea Migration-EXPORT-IMPORT-VIJAYA REDDY MADDURI(VJ)"
$form.Size = Sz 1280 900
$form.MinimumSize = Sz 1200 800
$form.StartPosition='CenterScreen'
$form.FormBorderStyle = 'Sizable'
$form.MaximizeBox = $true
$form.SizeGripStyle = 'Show'

# Confirm-on-close for the main form (catches X button, Alt-F4, and any Close button).
$form.Add_FormClosing({
  param($s,$e)
  try{
    # Skip prompt if the OS is shutting down or app is exiting non-interactively.
    if($e.CloseReason -eq [System.Windows.Forms.CloseReason]::WindowsShutDown -or `
       $e.CloseReason -eq [System.Windows.Forms.CloseReason]::TaskManagerClosing -or `
       $e.CloseReason -eq [System.Windows.Forms.CloseReason]::ApplicationExitCall){ return }
    $msg = "Are you sure you want to close the Delinea Migration tool?"
    $warnRunning = $false
    try{ if($script:ImportRunning -or $script:ExportRunning -or $script:ReconRunning){ $warnRunning = $true } } catch {}
    if($warnRunning){ $msg = "A job is currently running. Closing now may leave it incomplete.`r`n`r`n$msg" }
    $r = [System.Windows.Forms.MessageBox]::Show($form,$msg,'Confirm Close',[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Question,[System.Windows.Forms.MessageBoxDefaultButton]::Button2)
    if($r -ne [System.Windows.Forms.DialogResult]::Yes){ $e.Cancel = $true }
  } catch {}
})

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock='Fill'
$tabs.Multiline = $true
$tabs.SizeMode = [System.Windows.Forms.TabSizeMode]::Normal

# --- Disclaimer Panel (visible on all tabs) ---
$disclaimerPanel = New-Object System.Windows.Forms.Panel
$disclaimerPanel.Dock = 'Bottom'
$disclaimerPanel.Height = 26
$disclaimerPanel.BackColor = [System.Drawing.Color]::LightGray
$disclaimerLbl = New-Object System.Windows.Forms.Label
$disclaimerLbl.Dock = 'Fill'
$disclaimerLbl.AutoEllipsis = $false
$disclaimerLbl.AutoSize = $false
$disclaimerLbl.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$disclaimerLbl.Text = 'DISCLAIMER: This is a generic tool created for Delinea cross-tenant migration use cases. It does not contain any proprietary or company-specific logic. Ensure you follow your organization''s security and compliance policies before use.'
$disclaimerLbl.Font = New-Object System.Drawing.Font('Lucida Sans Typewriter', 8, [System.Drawing.FontStyle]::Regular)
$disclaimerLbl.ForeColor = [System.Drawing.Color]::Black
$disclaimerPanel.Controls.Add($disclaimerLbl)
$form.Controls.Add($disclaimerPanel)
$form.Controls.Add($tabs)

$tabSettings = New-Object System.Windows.Forms.TabPage; $tabSettings.Text='Settings'; $tabs.Controls.Add($tabSettings)
$tabActions  = New-Object System.Windows.Forms.TabPage; $tabActions.Text='Actions';  $tabs.Controls.Add($tabActions)
$tabTools    = New-Object System.Windows.Forms.TabPage; $tabTools.Text='Tools';     $tabs.Controls.Add($tabTools)
$tabTemplateCheck = New-Object System.Windows.Forms.TabPage; $tabTemplateCheck.Text='Template Check'; $tabs.Controls.Add($tabTemplateCheck)

$settingsPanel = New-Object System.Windows.Forms.Panel
$settingsPanel.Dock='Fill'; $settingsPanel.AutoScroll=$true
$tabSettings.Controls.Add($settingsPanel)

# ========== TOP OF SETTINGS TAB: SOURCE/TARGET ENABLE CHECKBOXES ==========
$yTop = 65 # Start at top of Settings panel

$cbEnableSrc = New-Object System.Windows.Forms.CheckBox
$cbEnableSrc.Text = 'Enable Source'
$cbEnableSrc.Location = Pt 10 $yTop
$cbEnableSrc.AutoSize = $true
$cbEnableSrc.Checked = $true  # Default: Source enabled
$settingsPanel.Controls.Add($cbEnableSrc)

$cbEnableTgt = New-Object System.Windows.Forms.CheckBox
$cbEnableTgt.Text = 'Enable Target'
$cbEnableTgt.Location = Pt 632 $yTop
$cbEnableTgt.AutoSize = $true
$cbEnableTgt.Checked = $true  # Default: Target enabled
$settingsPanel.Controls.Add($cbEnableTgt)

$cbEnableSrc.Add_CheckedChanged({ Update-SourceTargetEnabledState })
$cbEnableTgt.Add_CheckedChanged({ Update-SourceTargetEnabledState })

$yTop += 30  # Add spacing before next controls

# Now update the first row Y position:
$y = $yTop

$y=10
$lblTokenPath = New-Object System.Windows.Forms.Label; $lblTokenPath.Text='OAuth Token Path:'; $lblTokenPath.AutoSize=$true; $lblTokenPath.Location=Pt 10 ($y+4); $settingsPanel.Controls.Add($lblTokenPath)
$tbTokenPath  = New-Object System.Windows.Forms.TextBox; $tbTokenPath.Location=Pt 130 $y; $tbTokenPath.Size=Sz 180 24; $settingsPanel.Controls.Add($tbTokenPath)
$cbStore=New-Object System.Windows.Forms.CheckBox; $cbStore.Text='DPAPI store'; $cbStore.Location=Pt 320 ($y+2); $cbStore.AutoSize=$true; $settingsPanel.Controls.Add($cbStore)

# --- Config file path + browse/save/load ---
$lblCfg=New-Object System.Windows.Forms.Label
$lblCfg.Text='Config File:'
$lblCfg.AutoSize=$true
$lblCfg.Location=Pt 530 ($y+4)
$settingsPanel.Controls.Add($lblCfg)

$tbCfgPath=New-Object System.Windows.Forms.TextBox
$tbCfgPath.Location=Pt 600 $y
$tbCfgPath.Size=Sz 475 24
$settingsPanel.Controls.Add($tbCfgPath)

$btnCfgBrowse=New-Object System.Windows.Forms.Button
$btnCfgBrowse.Text='...'
$btnCfgBrowse.Location=Pt 1080 ($y-2)
$btnCfgBrowse.Size=Sz 28 28
$settingsPanel.Controls.Add($btnCfgBrowse)

$btnSaveCfgTop=New-Object System.Windows.Forms.Button
$btnSaveCfgTop.Text='Save'
$btnSaveCfgTop.Location=Pt 1114 ($y-2)
$btnSaveCfgTop.Size=Sz 60 28
$settingsPanel.Controls.Add($btnSaveCfgTop)

$btnLoadCfgTop=New-Object System.Windows.Forms.Button
$btnLoadCfgTop.Text='Load'
$btnLoadCfgTop.Location=Pt 1178 ($y-2)
$btnLoadCfgTop.Size=Sz 60 28
$settingsPanel.Controls.Add($btnLoadCfgTop)

$y+=34
$lblLogPath=New-Object System.Windows.Forms.Label; $lblLogPath.Text='Log File:'; $lblLogPath.AutoSize=$true; $lblLogPath.Location=Pt 10 ($y+4); $settingsPanel.Controls.Add($lblLogPath)
$tbLogPath=New-Object System.Windows.Forms.TextBox; $tbLogPath.Location=Pt 70 $y; $tbLogPath.Size=Sz 400 24; $settingsPanel.Controls.Add($tbLogPath)
$cbLogDateStamp=New-Object System.Windows.Forms.CheckBox; $cbLogDateStamp.Text='Add Date/Time'; $cbLogDateStamp.AutoSize=$true; $cbLogDateStamp.Location=Pt 478 ($y+2); $settingsPanel.Controls.Add($cbLogDateStamp)
$lblRootFolder=New-Object System.Windows.Forms.Label; $lblRootFolder.Text='Root Folder:'; $lblRootFolder.AutoSize=$true; $lblRootFolder.Location=Pt 600 ($y+4); $settingsPanel.Controls.Add($lblRootFolder)
$tbRootFolder=New-Object System.Windows.Forms.TextBox; $tbRootFolder.Location=Pt 680 $y; $tbRootFolder.Size=Sz 530 24; $tbRootFolder.Text=$script:BaseDir; $settingsPanel.Controls.Add($tbRootFolder)
$btnRootBrowse=New-Object System.Windows.Forms.Button; $btnRootBrowse.Text='...'; $btnRootBrowse.Location=Pt 1214 ($y-2); $btnRootBrowse.Size=Sz 28 28; $settingsPanel.Controls.Add($btnRootBrowse)
$btnRootBrowse.Add_Click({
  $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
  $fbd.Description = 'Select Root Folder for all migration files'
  $fbd.SelectedPath = $tbRootFolder.Text
  if($fbd.ShowDialog() -eq 'OK'){
    $tbRootFolder.Text = $fbd.SelectedPath
  }
})

$y += 45
$boxW=610; $boxH=170
$grpSrc = New-Object System.Windows.Forms.GroupBox; $grpSrc.Text='Source'; $grpSrc.Location=Pt 10 $y; $grpSrc.Size=Sz $boxW $boxH; $settingsPanel.Controls.Add($grpSrc)
$grpTgt = New-Object System.Windows.Forms.GroupBox; $grpTgt.Text='Target'; $grpTgt.Location=Pt (10+$boxW+10) $y; $grpTgt.Size=Sz $boxW $boxH; $settingsPanel.Controls.Add($grpTgt)

function New-LabeledTB($parent,$caption,[int]$x,[int]$y,[int]$w=430){
  $lbl=New-Object System.Windows.Forms.Label; $lbl.Text=$caption; $lbl.AutoSize=$true; $lbl.Location=Pt $x ($y+2); $parent.Controls.Add($lbl)
  $tb=New-Object System.Windows.Forms.TextBox; $tb.Location=Pt ($x+150) $y; $tb.Size=Sz $w 20; $parent.Controls.Add($tb)
  return $tb
}
function New-LabeledMTB($parent,$caption,[int]$x,[int]$y,[int]$w=430){
  $lbl=New-Object System.Windows.Forms.Label; $lbl.Text=$caption; $lbl.AutoSize=$true; $lbl.Location=Pt $x ($y+2); $parent.Controls.Add($lbl)
  $tb=New-Object System.Windows.Forms.MaskedTextBox; $tb.UseSystemPasswordChar=$true; $tb.Location=Pt ($x+150) $y; $tb.Size=Sz $w 20; $parent.Controls.Add($tb)
  return $tb
}



# Source
$sy=16; $rowGap=22
$tbSrcBase   = New-LabeledTB  $grpSrc 'Tenant Base:'   10 $sy; $sy+=$rowGap
$tbSrcUser   = New-LabeledTB  $grpSrc 'Username:'      10 $sy; $sy+=$rowGap
$tbSrcPwd    = New-LabeledMTB $grpSrc 'Password:'      10 $sy; $sy+=$rowGap
$tbSrcApi    = New-LabeledTB  $grpSrc 'SS API Base:'   10 $sy; $sy+=$rowGap
$tbSrcSearch = New-LabeledTB  $grpSrc 'Search Text:'   10 $sy; $sy+=$rowGap
$lblSrcFld   = New-Object System.Windows.Forms.Label; $lblSrcFld.Text='Limit to FolderId (blank=all):'; $lblSrcFld.AutoSize=$true; $lblSrcFld.Location=Pt 10 ($sy+2); $grpSrc.Controls.Add($lblSrcFld)
$tbSrcFld    = New-Object System.Windows.Forms.TextBox; $tbSrcFld.Location=Pt 160 $sy; $tbSrcFld.Size=Sz 120 20; $grpSrc.Controls.Add($tbSrcFld)

# Target
$ty=16; $rowGapT=22
$tbTgtBase = New-LabeledTB  $grpTgt 'Tenant Base:'   10 $ty; $ty+=$rowGapT
$tbTgtUser = New-LabeledTB  $grpTgt 'Username:'      10 $ty; $ty+=$rowGapT
$tbTgtPwd  = New-LabeledMTB $grpTgt 'Password:'      10 $ty; $ty+=$rowGapT
$tbTgtApi  = New-LabeledTB  $grpTgt 'SS API Base:'   10 $ty; $ty+=$rowGapT

$rx=10; $ry=$ty
$tbW=110
$tbLeftX = 10 + 150
$lblTgtFld = New-Object System.Windows.Forms.Label
$lblTgtFld.Text = "Target FolderId (default=0):`r`nRequired when Tree Off"
$lblTgtFld.AutoSize=$true
$lblTgtFld.Location=Pt $rx ($ry+2)
$grpTgt.Controls.Add($lblTgtFld)

$tbTgtFld  = New-Object System.Windows.Forms.TextBox; $tbTgtFld.Location=Pt $tbLeftX $ry; $tbTgtFld.Size=Sz $tbW 20; $grpTgt.Controls.Add($tbTgtFld)
$apiRight = $tbTgtApi.Location.X + $tbTgtApi.Size.Width
$tgtRootTbX = $apiRight - $tbW
$tbTgtRoot  = New-Object System.Windows.Forms.TextBox; $tbTgtRoot.Location=Pt $tgtRootTbX $ry; $tbTgtRoot.Size=Sz $tbW 20; $grpTgt.Controls.Add($tbTgtRoot)
$lblRoot    = New-Object System.Windows.Forms.Label; $lblRoot.Text='Target ROOT Id:'; $lblRoot.AutoSize=$true
$lw=[System.Windows.Forms.TextRenderer]::MeasureText($lblRoot.Text, $lblRoot.Font).Width
$lblRoot.Location = Pt ($tgtRootTbX - $lw - 6) ($ry+2)
$grpTgt.Controls.Add($lblRoot)

# Auto-populate SS API Base when Tenant Base changes (as user types)
$tbSrcBase.add_TextChanged({
  $baseUrl = $tbSrcBase.Text.Trim()
  if(-not [string]::IsNullOrWhiteSpace($baseUrl)){
    $tbSrcApi.Text = $baseUrl.TrimEnd('/') + '/api/v1'
  }
})
$tbTgtBase.add_TextChanged({
  $baseUrl = $tbTgtBase.Text.Trim()
  if(-not [string]::IsNullOrWhiteSpace($baseUrl)){
    $tbTgtApi.Text = $baseUrl.TrimEnd('/') + '/api/v1'
  }
})

# Options - Main container (V22 layout: 3 sub-groupboxes for Export / Import / Common)
$y += ($boxH + 8)
$grpOpt = New-Object System.Windows.Forms.GroupBox; $grpOpt.Text='Options'; $grpOpt.Location=Pt 10 $y; $grpOpt.Size=Sz 1235 290; $settingsPanel.Controls.Add($grpOpt)

# Export/Import file paths at top of $grpOpt
$lblExport=New-Object System.Windows.Forms.Label; $lblExport.Text='Export JSON:'; $lblExport.AutoSize=$true; $lblExport.Location=Pt 10 22; $grpOpt.Controls.Add($lblExport)
$tbExport=New-Object System.Windows.Forms.TextBox; $tbExport.Location=Pt 100 20; $tbExport.Size=Sz 930 24; $grpOpt.Controls.Add($tbExport)
$btnExportBrowse=New-Object System.Windows.Forms.Button; $btnExportBrowse.Text='...'; $btnExportBrowse.Location=Pt 1040 18; $btnExportBrowse.Size=Sz 30 28; $grpOpt.Controls.Add($btnExportBrowse)

$lblExportCsv=New-Object System.Windows.Forms.Label; $lblExportCsv.Text='Export CSV:'; $lblExportCsv.AutoSize=$true; $lblExportCsv.Location=Pt 10 50; $grpOpt.Controls.Add($lblExportCsv)
$tbExportCsv=New-Object System.Windows.Forms.TextBox; $tbExportCsv.Location=Pt 100 48; $tbExportCsv.Size=Sz 930 24; $grpOpt.Controls.Add($tbExportCsv)
$btnExportCsvBrowse=New-Object System.Windows.Forms.Button; $btnExportCsvBrowse.Text='...'; $btnExportCsvBrowse.Location=Pt 1040 46; $btnExportCsvBrowse.Size=Sz 30 28; $grpOpt.Controls.Add($btnExportCsvBrowse)

# ============ EXPORT OPTIONS (Left) ============
$grpExport = New-Object System.Windows.Forms.GroupBox
$grpExport.Text = 'Export Options'
$grpExport.Location = Pt 10 78
$grpExport.Size = Sz 390 200
$grpExport.ForeColor = [System.Drawing.Color]::Black
$grpExport.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
$grpExport.Tag = 'KeepColor'
$grpOpt.Controls.Add($grpExport)

$ey = 18
$cbExportJson = New-Object System.Windows.Forms.CheckBox; $cbExportJson.Text='Export JSON'; $cbExportJson.Location=Pt 10 $ey; $cbExportJson.AutoSize=$true; $grpExport.Controls.Add($cbExportJson)
$cbExportXml = New-Object System.Windows.Forms.CheckBox; $cbExportXml.Text='Export XML'; $cbExportXml.Location=Pt 110 $ey; $cbExportXml.AutoSize=$true; $grpExport.Controls.Add($cbExportXml)
$cbExportCsv = New-Object System.Windows.Forms.CheckBox; $cbExportCsv.Text='Export CSV'; $cbExportCsv.Location=Pt 210 $ey; $cbExportCsv.AutoSize=$true; $grpExport.Controls.Add($cbExportCsv)

$ey += 22
$cbExportZip = New-Object System.Windows.Forms.CheckBox; $cbExportZip.Text='Bundle as ZIP'; $cbExportZip.Location=Pt 10 $ey; $cbExportZip.AutoSize=$true; $grpExport.Controls.Add($cbExportZip)
$cbSrcHist = New-Object System.Windows.Forms.CheckBox; $cbSrcHist.Text='Include Password History'; $cbSrcHist.Location=Pt 130 $ey; $cbSrcHist.AutoSize=$true; $grpExport.Controls.Add($cbSrcHist)

$ey += 22
$cbIncremental = New-Object System.Windows.Forms.CheckBox; $cbIncremental.Text='Incremental (skip existing)'; $cbIncremental.Location=Pt 10 $ey; $cbIncremental.AutoSize=$true; $grpExport.Controls.Add($cbIncremental)

$ey += 22
$cbV1ExportService = New-Object System.Windows.Forms.CheckBox; $cbV1ExportService.Text='Use v1 export service (CSV)'; $cbV1ExportService.Location=Pt 10 $ey; $cbV1ExportService.AutoSize=$true; $grpExport.Controls.Add($cbV1ExportService)

$ey += 22
$cbExportChild = New-Object System.Windows.Forms.CheckBox; $cbExportChild.Text='Export child folders'; $cbExportChild.Location=Pt 10 $ey; $cbExportChild.AutoSize=$true; $grpExport.Controls.Add($cbExportChild)
$cbExportTemplates = New-Object System.Windows.Forms.CheckBox; $cbExportTemplates.Text='Export templates'; $cbExportTemplates.Location=Pt 150 $ey; $cbExportTemplates.AutoSize=$true; $grpExport.Controls.Add($cbExportTemplates)

$ey += 22
$cbEncryptPasswords = New-Object System.Windows.Forms.CheckBox; $cbEncryptPasswords.Text='Encrypt passwords (DPAPI)'; $cbEncryptPasswords.Location=Pt 10 $ey; $cbEncryptPasswords.AutoSize=$true; $grpExport.Controls.Add($cbEncryptPasswords)

$ey += 22
$cbVerboseHttp = New-Object System.Windows.Forms.CheckBox; $cbVerboseHttp.Text='Verbose HTTP logging'; $cbVerboseHttp.Location=Pt 10 $ey; $cbVerboseHttp.AutoSize=$true; $cbVerboseHttp.Checked=$false
$cbVerboseHttp.Add_CheckedChanged({ Set-VerboseHttp -Enabled ([bool]$cbVerboseHttp.Checked) })
$grpExport.Controls.Add($cbVerboseHttp)

# ============ IMPORT OPTIONS (Middle) ============
$grpImport = New-Object System.Windows.Forms.GroupBox
$grpImport.Text = 'Import Options'
$grpImport.Location = Pt 410 78
$grpImport.Size = Sz 420 200
$grpImport.ForeColor = [System.Drawing.Color]::DarkBlue
$grpImport.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
$grpImport.Tag = 'KeepColor'
$grpOpt.Controls.Add($grpImport)

$iy = 18
$cbTree = New-Object System.Windows.Forms.CheckBox; $cbTree.Text='Folder-tree migration'; $cbTree.Location=Pt 10 $iy; $cbTree.AutoSize=$true; $grpImport.Controls.Add($cbTree)
$cbTypeMap = New-Object System.Windows.Forms.CheckBox; $cbTypeMap.Text='SecretType map by name'; $cbTypeMap.Location=Pt 200 $iy; $cbTypeMap.AutoSize=$true; $grpImport.Controls.Add($cbTypeMap)

$iy += 22
$cbOverwrite = New-Object System.Windows.Forms.CheckBox; $cbOverwrite.Text='Overwrite if exists'; $cbOverwrite.Location=Pt 10 $iy; $cbOverwrite.AutoSize=$true; $grpImport.Controls.Add($cbOverwrite)
$cbDisableInherit = New-Object System.Windows.Forms.CheckBox; $cbDisableInherit.Text='Disable inherit permissions'; $cbDisableInherit.Location=Pt 200 $iy; $cbDisableInherit.AutoSize=$true; $grpImport.Controls.Add($cbDisableInherit)

$iy += 22
$cbDecryptPasswords = New-Object System.Windows.Forms.CheckBox; $cbDecryptPasswords.Text='Decrypt passwords (DPAPI)'; $cbDecryptPasswords.Location=Pt 10 $iy; $cbDecryptPasswords.AutoSize=$true; $grpImport.Controls.Add($cbDecryptPasswords)
$cbSkipPwdVal = New-Object System.Windows.Forms.CheckBox; $cbSkipPwdVal.Text='Skip Password Validation'; $cbSkipPwdVal.Location=Pt 200 $iy; $cbSkipPwdVal.AutoSize=$true; $cbSkipPwdVal.ForeColor=[System.Drawing.Color]::DarkRed; $grpImport.Controls.Add($cbSkipPwdVal)

$iy += 22
$cbStopOnError = New-Object System.Windows.Forms.CheckBox; $cbStopOnError.Text='Stop on Error (pause for review)'; $cbStopOnError.Location=Pt 10 $iy; $cbStopOnError.AutoSize=$true; $cbStopOnError.Checked=$false; $grpImport.Controls.Add($cbStopOnError)
$chkSyncTemplateFields = New-Object System.Windows.Forms.CheckBox; $chkSyncTemplateFields.Text='Sync template fields'; $chkSyncTemplateFields.Location=Pt 200 $iy; $chkSyncTemplateFields.AutoSize=$true; $grpImport.Controls.Add($chkSyncTemplateFields)

$iy += 22
$cbCleanupUpdated = New-Object System.Windows.Forms.CheckBox; $cbCleanupUpdated.Text='Rollback UPDATED secrets'; $cbCleanupUpdated.Location=Pt 10 $iy; $cbCleanupUpdated.AutoSize=$true; $grpImport.Controls.Add($cbCleanupUpdated)
$cbApplyPwdHistory = New-Object System.Windows.Forms.CheckBox; $cbApplyPwdHistory.Text='Apply Password History'; $cbApplyPwdHistory.Location=Pt 200 $iy; $cbApplyPwdHistory.AutoSize=$true; $cbApplyPwdHistory.Checked=$true; $grpImport.Controls.Add($cbApplyPwdHistory)

$iy += 22
$cbImportTemplates = New-Object System.Windows.Forms.CheckBox; $cbImportTemplates.Text='Import templates, suffix:'; $cbImportTemplates.Location=Pt 10 $iy; $cbImportTemplates.AutoSize=$true; $grpImport.Controls.Add($cbImportTemplates)
$tbTemplateSuffix = New-Object System.Windows.Forms.TextBox; $tbTemplateSuffix.Location=Pt 175 $iy; $tbTemplateSuffix.Size=Sz 80 22; $tbTemplateSuffix.Text='MIGRATED'; $tbTemplateSuffix.Enabled=$false; $grpImport.Controls.Add($tbTemplateSuffix)

$cbImportTemplates.Add_CheckedChanged({
  $tbTemplateSuffix.Enabled = $cbImportTemplates.Checked
  if($cbImportTemplates.Checked -and $chkSyncTemplateFields.Checked){ $chkSyncTemplateFields.Checked = $false }
})
$chkSyncTemplateFields.Add_CheckedChanged({
  if($chkSyncTemplateFields.Checked -and $cbImportTemplates.Checked){ $cbImportTemplates.Checked = $false }
})

$iy += 22
$lblDup = New-Object System.Windows.Forms.Label; $lblDup.Text='On duplicate:'; $lblDup.Location=Pt 10 $iy; $lblDup.AutoSize=$true; $grpImport.Controls.Add($lblDup)
$rbDupSkip = New-Object System.Windows.Forms.RadioButton; $rbDupSkip.Text='Skip'; $rbDupSkip.Location=Pt 90 $iy; $rbDupSkip.Size=Sz 55 20; $grpImport.Controls.Add($rbDupSkip)
$rbDupUpdate = New-Object System.Windows.Forms.RadioButton; $rbDupUpdate.Text='Update existing'; $rbDupUpdate.Location=Pt 150 $iy; $rbDupUpdate.Size=Sz 120 20; $grpImport.Controls.Add($rbDupUpdate)

# ============ COMMON OPTIONS (Right) ============
$grpCommon = New-Object System.Windows.Forms.GroupBox
$grpCommon.Text = 'Common Options (Export & Import)'
$grpCommon.Location = Pt 840 78
$grpCommon.Size = Sz 385 200
$grpCommon.ForeColor = [System.Drawing.Color]::Chocolate
$grpCommon.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
$grpCommon.Tag = 'KeepColor'
$grpOpt.Controls.Add($grpCommon)

$cy = 18
$cbFA = New-Object System.Windows.Forms.CheckBox; $cbFA.Text='Copy Folder ACLs'; $cbFA.Location=Pt 10 $cy; $cbFA.AutoSize=$true; $grpCommon.Controls.Add($cbFA)
$cbSA = New-Object System.Windows.Forms.CheckBox; $cbSA.Text='Copy Secret ACLs'; $cbSA.Location=Pt 180 $cy; $cbSA.AutoSize=$true; $grpCommon.Controls.Add($cbSA)

$cy += 22
$cbSet = New-Object System.Windows.Forms.CheckBox; $cbSet.Text='Copy Secret Settings'; $cbSet.Location=Pt 10 $cy; $cbSet.AutoSize=$true; $grpCommon.Controls.Add($cbSet)
$cbAtt = New-Object System.Windows.Forms.CheckBox; $cbAtt.Text='Copy Attachments'; $cbAtt.Location=Pt 180 $cy; $cbAtt.AutoSize=$true; $grpCommon.Controls.Add($cbAtt)

$cy += 22
$cbRemap = New-Object System.Windows.Forms.CheckBox; $cbRemap.Text='Remap principals by name'; $cbRemap.Location=Pt 10 $cy; $cbRemap.AutoSize=$true; $grpCommon.Controls.Add($cbRemap)

$cy += 22
$cbDry = New-Object System.Windows.Forms.CheckBox; $cbDry.Text='Dry-run (simulate only)'; $cbDry.Location=Pt 10 $cy; $cbDry.AutoSize=$true; $cbDry.ForeColor=[System.Drawing.Color]::Purple; $grpCommon.Controls.Add($cbDry)

# ============ FORCE COLORS on all checkboxes/radio buttons (override Windows visual styles) ============
$applyColor = {
  param($ctrl, $color)
  $ctrl.ForeColor = $color
  $ctrl.Tag = 'KeepColor'
  $ctrl.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
  $ctrl.UseVisualStyleBackColor = $false
  $ctrl.FlatAppearance.BorderSize = 0
  $ctrl.FlatAppearance.CheckedBackColor = [System.Drawing.Color]::Transparent
  $ctrl.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::Transparent
}

$exportColor = [System.Drawing.Color]::Black
foreach($cb in @($cbExportJson,$cbExportXml,$cbExportCsv,$cbExportZip,$cbSrcHist,$cbIncremental,$cbV1ExportService,$cbExportChild,$cbExportTemplates,$cbEncryptPasswords,$cbVerboseHttp)){
  & $applyColor $cb $exportColor
}

$importColor = [System.Drawing.Color]::DarkBlue
foreach($cb in @($cbTree,$cbTypeMap,$cbOverwrite,$cbDisableInherit,$cbDecryptPasswords,$cbStopOnError,$chkSyncTemplateFields,$cbCleanupUpdated,$cbImportTemplates,$cbApplyPwdHistory)){
  & $applyColor $cb $importColor
}
$lblDup.ForeColor = $importColor
$lblDup.Tag = 'KeepColor'
foreach($rb in @($rbDupSkip,$rbDupUpdate)){
  $rb.ForeColor = $importColor
  $rb.Tag = 'KeepColor'
  $rb.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
  $rb.UseVisualStyleBackColor = $false
}

$commonColor = [System.Drawing.Color]::Chocolate
foreach($cb in @($cbFA,$cbSA,$cbSet,$cbAtt,$cbRemap)){
  & $applyColor $cb $commonColor
}

# Special-case overrides
& $applyColor $cbSkipPwdVal ([System.Drawing.Color]::DarkRed)
& $applyColor $cbDry ([System.Drawing.Color]::Purple)

# Hidden textbox for backward compatibility
$tbSrcFolderId = New-Object System.Windows.Forms.TextBox
$tbSrcFolderId.Location = (Pt 150 120)
$tbSrcFolderId.Size = (Sz 200 20)
$tbSrcFolderId.Text = [string]$Global:Config.Src.FolderId
$tbSrcFolderId.Visible = $false
$form.Controls.Add($tbSrcFolderId)

# Unused label variable for compatibility
$lblTemplateSuffix = New-Object System.Windows.Forms.Label; $lblTemplateSuffix.Text=''; $lblTemplateSuffix.Visible=$false

# --- Synopsis + Selection Details ---
$yAfterOpt = $grpOpt.Location.Y + $grpOpt.Height + 6
$panelW = 1235
$gapSide = 10
$halfW = ($panelW - $gapSide) / 2

$grpSyn = New-Object System.Windows.Forms.GroupBox; $grpSyn.Text = 'Options Synopsis'; $grpSyn.Location = Pt 10 $yAfterOpt; $grpSyn.Size = Sz $halfW 310; $settingsPanel.Controls.Add($grpSyn)
$tbHelp = New-Object System.Windows.Forms.TextBox; $tbHelp.Multiline = $true; $tbHelp.ReadOnly = $true; $tbHelp.ScrollBars = 'Both'; $tbHelp.WordWrap = $false; $tbHelp.Location = Pt 10 22; $tbHelp.Size = Sz ($halfW-20) 280; $grpSyn.Controls.Add($tbHelp)
$grpSel = New-Object System.Windows.Forms.GroupBox; $grpSel.Text = 'Selection Details'; $grpSel.Location = Pt (10 + $halfW + $gapSide) $yAfterOpt; $grpSel.Size = Sz $halfW 310; $settingsPanel.Controls.Add($grpSel)
$txtSel = New-Object System.Windows.Forms.RichTextBox; $txtSel.ReadOnly = $true; $txtSel.DetectUrls = $false; $txtSel.WordWrap = $true; $txtSel.BorderStyle = 'FixedSingle'; $txtSel.Location = Pt 10 22; $txtSel.Size = Sz ($halfW-20) 280; $grpSel.Controls.Add($txtSel)

function Add-DetailBlock([System.Windows.Forms.RichTextBox]$rtb, [string]$heading, [string]$description) {
  $rtb.SelectionStart = $rtb.TextLength
  $rtb.SelectionLength = 0
  $rtb.SelectionFont = New-Object System.Drawing.Font($rtb.Font, [System.Drawing.FontStyle]::Bold)
  $rtb.AppendText($heading + [Environment]::NewLine)

  $rtb.SelectionStart = $rtb.TextLength
  $rtb.SelectionLength = 0
  $rtb.SelectionFont = New-Object System.Drawing.Font($rtb.Font, [System.Drawing.FontStyle]::Regular)
  $rtb.AppendText($description + [Environment]::NewLine)
}

$desc = @{
  CopyFolderAcls="Export+apply folder permissions via /api/v1/folder-permissions (role names, breakInheritance)."
  CopySecretAcls="Apply secret shares: groups via BULK add-share (roleName->roleId via /roles) + users via /secret-permissions fallback."
  CopySecretSettings="Exports /api/v1/secrets/{id}/settings. PUT is 405 in this tenant, so import cannot apply (export-only)."
  Attachments="Exports file fields to disk and imports (multipart upload)."
  Remap="Implemented: remap user/group IDs by searching target /api/v1/users and /api/v1/groups."
  History="Export password history for each secret (requires View/Edit permissions on source)."
  FolderTree="Creates missing folders under Target ROOT Id using POST /api/v1/folders."
  TypeMap="Maps SecretTypeName to target template id using GET /api/v1/secret-templates."
  Overwrite="Updates existing secrets when folder-tree is OFF (same-name match in target folder)."
  DupSkip="If a secret with the same name already exists in the destination folder, the import will log a warning and SKIP it (no create/update)."
  DupUpdate="If a secret with the same name already exists in the destination folder, the import will UPDATE it (requires 'Overwrite if exists' checked)."
  Rollback="If enabled, snapshots target secret before overwrite and Cleanup restores it from DelineaMigration\\rollback\\."
  Templates="Exports templates via /secret-templates/{id}/export and imports via /secret-templates/import (best effort)."
  ImportTemplates="Imports templates from TemplateExports in JSON if they don't exist on target via /secret-templates/import."
  ExportService="Also writes CSV using POST /api/v1/secrets/export (exportedSecretsFileText). JSON export is still produced for import."
  ExportChild="When using v1 export service, include child folders in CSV export."
  DryRun="No folder creation, no ACL apply, no secret create/update; logs intended actions only."
  EncryptPasswords="Encrypts password fields using DPAPI during export (Windows machine-specific encryption)."
  DecryptPasswords="Decrypts DPAPI-encrypted password fields during import (must be on same Windows machine)."
  ExportJson="Exports secrets to JSON format (default format for import)."
  ExportXml="Generates Delinea Web Portal compatible XML export file."
  ExportCsv="Creates CSV bundle with secrets, items, permissions, settings, and attachments."
  ExportZip="Bundles all export outputs (JSON, XML, CSV, attachments) into a single timestamped ZIP archive."
  Incremental="Skips secrets that already exist in the export file to avoid re-exporting (useful for large migrations)."
  VerboseHttp="Enables DEBUG logging for every GET/POST API call showing full request URLs and response status."
  DisableInherit="Disables 'Inherit parent permissions' on imported subfolders so permissions come only from source data."
}

function Update-SelectionDetails {
  $txtSel.Clear()
  $items = @()

  # Collect all checked items
  if($cbFA.Checked){ $items += ,@('Copy Folder ACLs', $desc.CopyFolderAcls) }
  if($cbSA.Checked){ $items += ,@('Copy Secret ACLs', $desc.CopySecretAcls) }
  if($cbSet.Checked){ $items += ,@('Copy Secret Settings', $desc.CopySecretSettings) }
  if($cbAtt.Checked){ $items += ,@('Copy Attachments', $desc.Attachments) }
  if($cbRemap.Checked){ $items += ,@('Remap principals by name', $desc.Remap) }
  if($cbSrcHist.Checked){ $items += ,@('Include Password History', $desc.History) }
  if($cbTree.Checked){ $items += ,@('Folder-tree migration', $desc.FolderTree) }
  if($cbTypeMap.Checked){ $items += ,@('SecretType map by name', $desc.TypeMap) }
  if($cbOverwrite.Checked){ $items += ,@('Overwrite if exists', $desc.Overwrite) }
  if($cbDisableInherit.Checked){ $items += ,@('Disable inherit permissions on folders', $desc.DisableInherit) }
  if($rbDupSkip.Checked){ $items += ,@('Duplicate secrets: Skip', $desc.DupSkip) }
  elseif($rbDupUpdate.Checked){ $items += ,@('Duplicate secrets: Update', $desc.DupUpdate) }
  if($cbCleanupUpdated.Checked){ $items += ,@('Rollback updated secrets', $desc.Rollback) }
  if($cbExportTemplates.Checked){ $items += ,@('Template migration (export)', $desc.Templates) }
  if($cbImportTemplates.Checked){ $items += ,@('Import templates (target)', $desc.ImportTemplates) }
  if($cbV1ExportService.Checked){ $items += ,@('v1 export service (CSV)', $desc.ExportService) }
  if($cbExportChild.Checked){ $items += ,@('Export child folders (CSV)', $desc.ExportChild) }
  if($cbExportJson.Checked){ $items += ,@('Export JSON format', $desc.ExportJson) }
  if($cbExportXml.Checked){ $items += ,@('Export XML format', $desc.ExportXml) }
  if($cbExportCsv.Checked){ $items += ,@('Export CSV format', $desc.ExportCsv) }
  if($cbExportZip.Checked){ $items += ,@('Export ZIP bundle', $desc.ExportZip) }
  if($cbIncremental.Checked){ $items += ,@('Incremental export', $desc.Incremental) }
  if($cbEncryptPasswords.Checked){ $items += ,@('Encrypt passwords (DPAPI)', $desc.EncryptPasswords) }
  if($cbDecryptPasswords.Checked){ $items += ,@('Decrypt passwords (DPAPI)', $desc.DecryptPasswords) }
  if($cbVerboseHttp.Checked){ $items += ,@('Verbose HTTP logging', $desc.VerboseHttp) }
  if($cbDry.Checked){ $items += ,@('Dry-run', $desc.DryRun) }

  # Display items in reverse order (most recent at top)
  if($items.Count -gt 0){
    for($i = $items.Count - 1; $i -ge 0; $i--){
      Add-DetailBlock $txtSel $items[$i][0] $items[$i][1]
    }
  } else {
    $txtSel.SelectionFont = New-Object System.Drawing.Font($txtSel.Font, [System.Drawing.FontStyle]::Italic)
    $txtSel.AppendText("No options selected.")
  }

  $txtSel.SelectionStart = 0
  $txtSel.ScrollToCaret()
}

$cbHandlers = { Update-SelectionDetails }

# hook checkboxes
foreach($cb in @(
  $cbFA,$cbSA,$cbSet,$cbAtt,$cbRemap,$cbSrcHist,$cbDry,$cbTree,$cbTypeMap,$cbOverwrite,$cbDisableInherit,
  $cbCleanupUpdated,$cbExportTemplates,$cbImportTemplates,$cbV1ExportService,$cbExportChild,$cbExportJson,$cbExportXml,$cbExportCsv,$cbExportZip,
  $cbIncremental,$cbEncryptPasswords,$cbDecryptPasswords,$cbVerboseHttp
)){
  $cb.Add_CheckedChanged($cbHandlers)
}

# Special handler for Cleanup rollback checkbox (affects button state)
$cbCleanupUpdated.Add_CheckedChanged({
  Update-SourceTargetEnabledState
})

# hook radio buttons (ONLY ONCE)
$rbDupSkip.Add_CheckedChanged($cbHandlers)
$rbDupUpdate.Add_CheckedChanged($cbHandlers)

# --- Actions tab ---
$panelTop=New-Object System.Windows.Forms.Panel; $panelTop.Dock='Top'; $panelTop.Height=56; $tabActions.Controls.Add($panelTop)

$btnExport=New-Object System.Windows.Forms.Button; $btnExport.Name='btnExport'; $btnExport.Text='Export'; $btnExport.Location=Pt 10 10; $btnExport.Size=Sz 120 36; $panelTop.Controls.Add($btnExport)
$btnImport=New-Object System.Windows.Forms.Button; $btnImport.Name='btnImport'; $btnImport.Text='Import'; $btnImport.Location=Pt 140 10; $btnImport.Size=Sz 120 36; $panelTop.Controls.Add($btnImport)
$btnVerify=New-Object System.Windows.Forms.Button; $btnVerify.Name='btnVerify'; $btnVerify.Text='Verify'; $btnVerify.Location=Pt 270 10; $btnVerify.Size=Sz 120 36; $panelTop.Controls.Add($btnVerify)
$btnCleanup=New-Object System.Windows.Forms.Button; $btnCleanup.Name='btnCleanup'; $btnCleanup.Text='Cleanup Last Import'; $btnCleanup.Location=Pt 400 10; $btnCleanup.Size=Sz 160 36; $panelTop.Controls.Add($btnCleanup)
$btnClear=New-Object System.Windows.Forms.Button; $btnClear.Name='btnClear'; $btnClear.Text='Clear Log'; $btnClear.Location=Pt 570 10; $btnClear.Size=Sz 100 36; $panelTop.Controls.Add($btnClear)
$btnClose=New-Object System.Windows.Forms.Button; $btnClose.Name='btnClose'; $btnClose.Text='Close'; $btnClose.Location=Pt 680 10; $btnClose.Size=Sz 100 36; $panelTop.Controls.Add($btnClose)
$btnCancel=New-Object System.Windows.Forms.Button; $btnCancel.Name='btnCancel'; $btnCancel.Text='Cancel'; $btnCancel.Location=Pt 790 10; $btnCancel.Size=Sz 120 36; $btnCancel.BackColor=[System.Drawing.Color]::FromArgb(232,17,35); $btnCancel.ForeColor=[System.Drawing.Color]::White; $btnCancel.FlatStyle='Flat'; $btnCancel.Font=New-Object System.Drawing.Font("Segoe UI",9.5,[System.Drawing.FontStyle]::Bold); $btnCancel.Visible=$false; $panelTop.Controls.Add($btnCancel)
$btnCancel.Add_Click({ $script:ExportCancelled = $true; $script:ImportCancelled = $true; Write-Log "Cancel requested - will stop after current secret..." 'WARN' })

# --- Progress Bar Panel (between buttons and log) ---
$panelProgress = New-Object System.Windows.Forms.Panel
$panelProgress.Dock = 'Top'
$panelProgress.Height = 40
$panelProgress.Visible = $false
$tabActions.Controls.Add($panelProgress)

# Custom-drawn "progress bar" implemented as a Panel so we can paint the runner
# emoji directly INSIDE the bar over the green fill. Native ProgressBar does not
# support transparent child labels, so a label always paints its background over
# the green fill. Custom painting solves that.
#
# Public API (matches the original ProgressBar shape used elsewhere in the script):
#   $script:ProgressBar.Value  : 0..100 (int)   <- assignable property via Tag pct
#   $script:ProgressBar.Invalidate() to repaint
$script:ProgressBar = New-Object System.Windows.Forms.Panel
$script:ProgressBar.Location = New-Object System.Drawing.Point(10, 8)
$script:ProgressBar.Size     = New-Object System.Drawing.Size(700, 24)
$script:ProgressBar.Tag      = 0   # current percent 0..100
# Enable double buffering to eliminate flicker.
try{
  $dbProp = $script:ProgressBar.GetType().GetProperty('DoubleBuffered', `
    [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance)
  if($dbProp){ $dbProp.SetValue($script:ProgressBar, $true, $null) }
} catch {}
$panelProgress.Controls.Add($script:ProgressBar)

# Shim a write-only Value property that mirrors System.Windows.Forms.ProgressBar.Value
# so existing call sites ($script:ProgressBar.Value = $pct) keep working unchanged.
$script:ProgressBar | Add-Member -MemberType ScriptProperty -Name Value `
  -Value { [int]$this.Tag } `
  -SecondValue {
    param($v)
    $iv = 0
    try{ $iv = [int]$v } catch {}
    if($iv -lt 0){ $iv = 0 }; if($iv -gt 100){ $iv = 100 }
    $this.Tag = $iv
    $this.Invalidate()
  } -Force

# Walker emoji glyph (drawn inside the bar at the leading edge of the green fill).
# Using the walking-person glyph so the animation reads as a brisk walk, not a sprint.
$script:RunnerGlyph = [string]([char]0xD83D + [char]0xDEB6)   # 🚶 U+1F6B6
$script:RunnerFont  = New-Object System.Drawing.Font("Segoe UI Emoji", 13, [System.Drawing.FontStyle]::Regular)
$script:RunnerFrame = 0   # animation tick counter

# Fallback: text-frame spinner loaded from %USERPROFILE%\Desktop\spinners.json
# (cli-spinners format). Used only when the walking GIF couldn't be loaded.
# Tries a list of likely IconSets and picks the first one present in the file.
$script:SpinnerFrames     = $null
$script:SpinnerFrameCount = 0
$script:SpinnerInterval   = 80
try{
  $__spinPath = Join-Path $env:USERPROFILE 'Desktop\spinners.json'
  if(Test-Path -LiteralPath $__spinPath){
    $__spinJson = Get-Content -LiteralPath $__spinPath -Raw | ConvertFrom-Json
    foreach($__ic in @('runner','walker','arrow3','dots','dots2','line','bouncingBar','simpleDots')){
      try{
        $__set = $__spinJson.$__ic
        if($__set -and $__set.frames -and @($__set.frames).Count -gt 0){
          $script:SpinnerFrames     = @($__set.frames | ForEach-Object { [string]$_ })
          $script:SpinnerFrameCount = $script:SpinnerFrames.Count
          try{ $script:SpinnerInterval = [int]$__set.interval } catch {}
          if($script:SpinnerInterval -le 0){ $script:SpinnerInterval = 80 }
          break
        }
      } catch {}
    }
  }
} catch {
  $script:SpinnerFrames = $null
  $script:SpinnerFrameCount = 0
}

# Animation timer: ticks while the bar is visible so the walker shows a quick
# stride cadence even when the % value is not changing.
$script:RunnerTimer = New-Object System.Windows.Forms.Timer
# Fast-walk cadence: 4 frames per stride cycle at ~12.5 fps -> ~3 strides/sec.
# Was 200ms (slow stroll); 80ms reads as a brisk power-walk without looking jittery.
$script:RunnerTimer.Interval = 80
$script:RunnerTimer.Add_Tick({
  $script:RunnerFrame = ($script:RunnerFrame + 1) % 100000
  try{ $script:ProgressBar.Invalidate() } catch {}
  try{ if($script:ReconProgressBar -and $script:ReconProgressBar.Visible){ $script:ReconProgressBar.Invalidate() } } catch {}
})

$script:ProgressBar.Add_Paint({
  param($sender, $e)
  $g    = $e.Graphics
  $w    = $sender.ClientSize.Width
  $h    = $sender.ClientSize.Height
  $pct  = 0
  try{ $pct = [int]$sender.Tag } catch {}
  if($pct -lt 0){ $pct = 0 }; if($pct -gt 100){ $pct = 100 }

  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit

  # Background (unfilled portion)
  $bgBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(230,230,230))
  $g.FillRectangle($bgBrush, 0, 0, $w, $h)
  $bgBrush.Dispose()

  # Green fill
  $fillW = [int]([Math]::Round(($pct / 100.0) * $w))
  if($fillW -gt 0){
    $fillBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(6,176,37))
    $g.FillRectangle($fillBrush, 0, 0, $fillW, $h)
    $fillBrush.Dispose()
  }

  # Border
  $borderPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(140,140,140))
  $g.DrawRectangle($borderPen, 0, 0, $w - 1, $h - 1)
  $borderPen.Dispose()

  # Centered % text (subtle, for context)
  $pctText = ("{0}%" -f $pct)
  $fmt = New-Object System.Drawing.StringFormat
  $fmt.Alignment     = [System.Drawing.StringAlignment]::Center
  $fmt.LineAlignment = [System.Drawing.StringAlignment]::Center
  $pctFont  = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
  $pctBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(40,40,40))
  $g.DrawString($pctText, $pctFont, $pctBrush, (New-Object System.Drawing.RectangleF 0, 0, $w, $h), $fmt)
  $pctBrush.Dispose(); $pctFont.Dispose(); $fmt.Dispose()

  # Walker visual at the leading edge of the green fill, INSIDE the bar.
  # Preferred: 🚶 emoji glyph with two small alternating foot dots underneath.
  # Fallback: text-frame spinner from spinners.json when available.
  try{
    if($script:SpinnerFrames -and $script:SpinnerFrameCount -gt 0){
      # Cli-spinner style text-frame fallback (frames from spinners.json).
      # Frame index advances by wall-clock so the animation runs at the
      # IconSet's native interval regardless of paint cadence.
      $__sIdx = [int]([Math]::Abs([Environment]::TickCount / [Math]::Max(1,$script:SpinnerInterval))) % $script:SpinnerFrameCount
      $__sTxt = [string]$script:SpinnerFrames[$__sIdx]
      $__sFnt = New-Object System.Drawing.Font("Consolas", 11, [System.Drawing.FontStyle]::Bold)
      $__sSz  = $g.MeasureString($__sTxt, $__sFnt)
      $__sX = [single]($fillW - $__sSz.Width / 2.0)
      if($__sX -lt 0){ $__sX = 0 }
      if($__sX + $__sSz.Width -gt $w){ $__sX = [single]($w - $__sSz.Width) }
      $__sY = [single](($h - $__sSz.Height) / 2.0)
      $g.DrawString($__sTxt, $__sFnt, [System.Drawing.Brushes]::Black, $__sX, $__sY)
      $__sFnt.Dispose()
    } else {
      $glyphSize = $g.MeasureString($script:RunnerGlyph, $script:RunnerFont)
      $gw = [single]$glyphSize.Width
      $gh = [single]$glyphSize.Height

      # Position: center of walker sits at the leading edge of the green fill
      $rx = $fillW - [int]($gw / 2)
      if($rx -lt 0){ $rx = 0 }
      if($rx + $gw -gt $w){ $rx = $w - [int]$gw }
      $ry = [single](($h - $gh) / 2)

      # Center of glyph (for mirror pivot)
      $cx = [single]($rx + $gw / 2)
      $cy = [single]($ry + $gh / 2)

      # Draw the walker glyph: mirrored horizontally so it faces RIGHT, but with
      # zero rotation/scale jitter so the body is rock-steady.
      $state = $g.Save()
      $g.TranslateTransform($cx, $cy)
      $g.ScaleTransform(-1.0, 1.0)
      $g.DrawString($script:RunnerGlyph, $script:RunnerFont, [System.Drawing.Brushes]::Black, -($gw / 2), -($gh / 2))
      $g.Restore($state)

      # Foot animation: two small dark marks at the base of the glyph. Their fore/aft
      # offset swaps every frame, so the legs look like they are striding while the
      # body itself does not move. 4-frame cycle: left-fwd, planted, right-fwd, planted.
      $f = $script:RunnerFrame % 4
      $stride = 3.5
      switch($f){
        0 { $offA =  $stride; $offB = -$stride }   # left fwd
        1 { $offA =  0.0;     $offB =  0.0     }   # planted
        2 { $offA = -$stride; $offB =  $stride }   # right fwd
        default { $offA = 0.0; $offB = 0.0 }
      }
      $footY = [single]($ry + $gh - 4.0)
      $footW = 4.0
      $footH = 2.5
      $footBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(30,30,30))
      $g.FillEllipse($footBrush, [single]($cx - 1.0 + $offA - $footW/2), $footY, [single]$footW, [single]$footH)
      $g.FillEllipse($footBrush, [single]($cx + 1.0 + $offB - $footW/2), $footY, [single]$footW, [single]$footH)
      $footBrush.Dispose()
    }
  } catch {}
})

$script:ProgressLabel = New-Object System.Windows.Forms.Label
$script:ProgressLabel.Location = New-Object System.Drawing.Point(720, 12)
$script:ProgressLabel.Size = New-Object System.Drawing.Size(280, 20)
$script:ProgressLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$script:ProgressLabel.Text = ""
$panelProgress.Controls.Add($script:ProgressLabel)

# Create the Actions log textbox (RichTextBox so we can color lines by log level)
$tbActionsLog = New-Object System.Windows.Forms.RichTextBox
$tbActionsLog.ScrollBars = 'Both'
$tbActionsLog.ReadOnly = $true
$tbActionsLog.WordWrap = $false
$tbActionsLog.DetectUrls = $false
$tbActionsLog.HideSelection = $true
$tbActionsLog.Font = New-Object System.Drawing.Font("Consolas", 9)
$tbActionsLog.Dock = 'Fill'
$tabActions.Controls.Add($tbActionsLog)

# Fix docking z-order: Fill control must be behind Top controls
# In WinForms, controls added last dock first. We need:
#   panelTop (Top) -> panelProgress (Top) -> tbActionsLog (Fill)
# So set z-order: tbActionsLog at back, panelTop at front
$tbActionsLog.SendToBack()
$panelProgress.BringToFront()
$panelTop.BringToFront()

# Helper to show/hide/update progress bar
$script:LastDoEventsTime = [DateTime]::MinValue
function Update-ProgressBar([int]$Current, [int]$Total, [string]$StatusText){
  if($Total -le 0){ return }
  $pct = [Math]::Min(100, [int][Math]::Round(($Current / $Total) * 100))
  $script:ProgressBar.Value = $pct        # custom Panel: updates Tag and invalidates
  $script:ProgressLabel.Text = $StatusText
  if(-not $panelProgress.Visible){
    $panelProgress.Visible = $true
  }
  # Mirror progress on the Reconciliation tab (if those controls have been created)
  try{
    if($script:ReconProgressBar){
      $script:ReconProgressBar.Value = $pct
      if(-not $script:ReconProgressBar.Visible){ $script:ReconProgressBar.Visible = $true }
    }
    if($script:ReconProgressLabel){ $script:ReconProgressLabel.Text = $StatusText }
  } catch {}
  # Start the running-animation timer once when progress first appears.
  try{ if($script:RunnerTimer -and -not $script:RunnerTimer.Enabled){ $script:RunnerTimer.Start() } } catch {}
  # Throttle DoEvents to every 250ms to reduce GUI overhead
  $now = [DateTime]::Now
  if(($now - $script:LastDoEventsTime).TotalMilliseconds -ge 250){
    $script:LastDoEventsTime = $now
    [System.Windows.Forms.Application]::DoEvents()
  }
}

function Hide-ProgressBar {
  try{ if($script:RunnerTimer -and $script:RunnerTimer.Enabled){ $script:RunnerTimer.Stop() } } catch {}
  $panelProgress.Visible = $false
  $script:ProgressBar.Value = 0
  $script:ProgressLabel.Text = ""
  try{
    if($script:ReconProgressBar){ $script:ReconProgressBar.Value = 0; $script:ReconProgressBar.Visible = $false }
    if($script:ReconProgressLabel){ $script:ReconProgressLabel.Text = '' }
  } catch {}
}

# Set the script-level log textbox reference
$script:LogTextBox = $tbActionsLog


# Get # Secrets button + radio buttons for Source/Target selection
$btnGetCount=New-Object System.Windows.Forms.Button
$btnGetCount.Name='btnGetCount'
$btnGetCount.Text='Get # Secrets'
$btnGetCount.Location=Pt 790 10
$btnGetCount.Size=Sz 120 36
$panelTop.Controls.Add($btnGetCount)

# Radio buttons for Source/Target selection
$rbCountSrc = New-Object System.Windows.Forms.RadioButton
$rbCountSrc.Text = "Source"
$rbCountSrc.Location = Pt 920 2
$rbCountSrc.Size = Sz 70 34
$rbCountSrc.Checked = $true  # Default to Source
$panelTop.Controls.Add($rbCountSrc)

$rbCountTgt = New-Object System.Windows.Forms.RadioButton
$rbCountTgt.Text = "Target"
$rbCountTgt.Location = Pt 995 2
$rbCountTgt.Size = Sz 70 34
$panelTop.Controls.Add($rbCountTgt)

# One textbox used for: MaxSecrets limit (optional); Get#Secrets fills it with total count.
$lblCountHint=New-Object System.Windows.Forms.Label
$lblCountHint.Text='Total secrets / Max limit (optional):'
$lblCountHint.AutoSize=$true
$lblCountHint.Location=Pt 920 34
$panelTop.Controls.Add($lblCountHint)

$tbCount=New-Object System.Windows.Forms.TextBox
$tbCount.Location=Pt 1100 26
$tbCount.Size=Sz 120 42
$tbCount.Text=''
$panelTop.Controls.Add($tbCount)
function UpdateImportButtonState {
  # Import button requires:
  # 1. Target credentials configured
  # 2. Export file exists
  
  $hasTarget = (-not [string]::IsNullOrWhiteSpace($Global:Config.Tgt.TenantBase)) -and 
               (-not [string]::IsNullOrWhiteSpace($Global:Config.Tgt.Username))
  
  $hasExportFile = $Global:Config.ExportFile -and (Test-Path $Global:Config.ExportFile)
  
  if($btnImport){
    $btnImport.Enabled = $hasTarget
  }
}
# Update Get # Secrets button state when radio selection changes
$rbCountSrc.Add_CheckedChanged({
  # Source/Target selection should NOT affect Import button
  # Import only needs target credentials
  UpdateImportButtonState
})

$rbCountTgt.Add_CheckedChanged({
  # Source/Target selection should NOT affect Import button
  UpdateImportButtonState
})

# --- Tools tab ---
$toolsPanel = New-Object System.Windows.Forms.Panel
$toolsPanel.Dock = 'Fill'
$toolsPanel.AutoScroll = $true
$tabTools.Controls.Add($toolsPanel)

# Tools tab title
$yTools = 20
$lblToolsTitle = New-Object System.Windows.Forms.Label
$lblToolsTitle.Text = 'Update Permissions JSON from CSV Mapping'
$lblToolsTitle.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
$lblToolsTitle.Location = Pt 10 $yTools
$lblToolsTitle.AutoSize = $true
$toolsPanel.Controls.Add($lblToolsTitle)

$yTools += 40

# Map CSV file browser
$lblMapCsv = New-Object System.Windows.Forms.Label
$lblMapCsv.Text = 'Map CSV File:'
$lblMapCsv.AutoSize = $true
$lblMapCsv.Location = Pt 10 ($yTools + 4)
$toolsPanel.Controls.Add($lblMapCsv)

$tbMapCsv = New-Object System.Windows.Forms.TextBox
$tbMapCsv.Location = Pt 130 $yTools
$tbMapCsv.Size = Sz 600 24
$toolsPanel.Controls.Add($tbMapCsv)

$btnBrowseMapCsv = New-Object System.Windows.Forms.Button
$btnBrowseMapCsv.Text = 'Browse...'
$btnBrowseMapCsv.Location = Pt 740 $yTools
$btnBrowseMapCsv.Size = Sz 100 24
$toolsPanel.Controls.Add($btnBrowseMapCsv)

$btnGenSampleCsv = New-Object System.Windows.Forms.Button
$btnGenSampleCsv.Text = 'Generate Sample'
$btnGenSampleCsv.Location = Pt 850 $yTools
$btnGenSampleCsv.Size = Sz 120 24
$toolsPanel.Controls.Add($btnGenSampleCsv)

$yTools += 40

# Permissions JSON file browser
$lblPermsJson = New-Object System.Windows.Forms.Label
$lblPermsJson.Text = 'Permissions JSON:'
$lblPermsJson.AutoSize = $true
$lblPermsJson.Location = Pt 10 ($yTools + 4)
$toolsPanel.Controls.Add($lblPermsJson)

$tbPermsJson = New-Object System.Windows.Forms.TextBox
$tbPermsJson.Location = Pt 130 $yTools
$tbPermsJson.Size = Sz 600 24
$toolsPanel.Controls.Add($tbPermsJson)

$btnBrowsePermsJson = New-Object System.Windows.Forms.Button
$btnBrowsePermsJson.Text = 'Browse...'
$btnBrowsePermsJson.Location = Pt 740 $yTools
$btnBrowsePermsJson.Size = Sz 100 24
$toolsPanel.Controls.Add($btnBrowsePermsJson)

$yTools += 40

# Output JSON file browser (optional)
$lblOutJson = New-Object System.Windows.Forms.Label
$lblOutJson.Text = 'Output JSON (opt):'
$lblOutJson.AutoSize = $true
$lblOutJson.Location = Pt 10 ($yTools + 4)
$toolsPanel.Controls.Add($lblOutJson)

$tbOutJson = New-Object System.Windows.Forms.TextBox
$tbOutJson.Location = Pt 130 $yTools
$tbOutJson.Size = Sz 600 24
$toolsPanel.Controls.Add($tbOutJson)

$btnBrowseOutJson = New-Object System.Windows.Forms.Button
$btnBrowseOutJson.Text = 'Browse...'
$btnBrowseOutJson.Location = Pt 740 $yTools
$btnBrowseOutJson.Size = Sz 100 24
$toolsPanel.Controls.Add($btnBrowseOutJson)

$yTools += 40

# Dry Run checkbox
$cbToolsDryRun = New-Object System.Windows.Forms.CheckBox
$cbToolsDryRun.Text = 'Dry Run (preview changes without writing files)'
$cbToolsDryRun.Location = Pt 10 $yTools
$cbToolsDryRun.AutoSize = $true
$cbToolsDryRun.Checked = $true  # Default to dry run for safety
$toolsPanel.Controls.Add($cbToolsDryRun)

$yTools += 30

# In-Place checkbox
$cbToolsInPlace = New-Object System.Windows.Forms.CheckBox
$cbToolsInPlace.Text = 'Update In-Place (creates .bak backup)'
$cbToolsInPlace.Location = Pt 10 $yTools
$cbToolsInPlace.AutoSize = $true
$toolsPanel.Controls.Add($cbToolsInPlace)

$yTools += 30

# Verbose checkbox
$cbToolsVerbose = New-Object System.Windows.Forms.CheckBox
$cbToolsVerbose.Text = 'Verbose output (show detailed matching info)'
$cbToolsVerbose.Location = Pt 10 $yTools
$cbToolsVerbose.AutoSize = $true
$toolsPanel.Controls.Add($cbToolsVerbose)

$yTools += 40

# Run button
$btnRunTools = New-Object System.Windows.Forms.Button
$btnRunTools.Name = 'btnRunTools'
$btnRunTools.Text = 'Run Update'
$btnRunTools.Location = Pt 10 $yTools
$btnRunTools.Size = Sz 150 40
$btnRunTools.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$toolsPanel.Controls.Add($btnRunTools)

# Close button
$btnCloseTools = New-Object System.Windows.Forms.Button
$btnCloseTools.Name = 'btnCloseTools'
$btnCloseTools.Text = 'Close'
$btnCloseTools.Location = Pt 170 $yTools
$btnCloseTools.Size = Sz 100 40
$toolsPanel.Controls.Add($btnCloseTools)

# Clear Log button
$btnClearToolsLog = New-Object System.Windows.Forms.Button
$btnClearToolsLog.Name = 'btnClearToolsLog'
$btnClearToolsLog.Text = 'Clear Log'
$btnClearToolsLog.Location = Pt 280 $yTools
$btnClearToolsLog.Size = Sz 100 40
$toolsPanel.Controls.Add($btnClearToolsLog)

# Hidden legacy buttons (kept for backward compat)
$btnExportXml = New-Object System.Windows.Forms.Button
$btnExportXml.Name = 'btnExportXml'
$btnExportXml.Visible = $false
$toolsPanel.Controls.Add($btnExportXml)

$btnExportCsv = New-Object System.Windows.Forms.Button
$btnExportCsv.Name = 'btnExportCsv'
$btnExportCsv.Visible = $false
$toolsPanel.Controls.Add($btnExportCsv)

# ====================================================================
# Convert Exported JSON (GroupBox to the right of Run/Close/Clear buttons)
# ====================================================================
$grpConvert = New-Object System.Windows.Forms.GroupBox
$grpConvert.Text = 'Convert Exported JSON'
$grpConvert.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$grpConvert.Location = Pt 420 ($yTools - 10)
$grpConvert.Size = Sz 820 55
$toolsPanel.Controls.Add($grpConvert)

$lblConvertJson = New-Object System.Windows.Forms.Label
$lblConvertJson.Text = 'JSON:'
$lblConvertJson.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$lblConvertJson.AutoSize = $true
$lblConvertJson.Location = Pt 10 22
$grpConvert.Controls.Add($lblConvertJson)

$tbConvertJson = New-Object System.Windows.Forms.TextBox
$tbConvertJson.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$tbConvertJson.Location = Pt 52 19
$tbConvertJson.Size = Sz 380 24
$tbConvertJson.Text = if($Global:Config.ExportFile){ $Global:Config.ExportFile } else { '' }
$grpConvert.Controls.Add($tbConvertJson)

$btnBrowseConvertJson = New-Object System.Windows.Forms.Button
$btnBrowseConvertJson.Text = '...'
$btnBrowseConvertJson.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$btnBrowseConvertJson.Location = Pt 436 18
$btnBrowseConvertJson.Size = Sz 35 26
$grpConvert.Controls.Add($btnBrowseConvertJson)

$btnConvertXml = New-Object System.Windows.Forms.Button
$btnConvertXml.Name = 'btnConvertXml'
$btnConvertXml.Text = 'Convert to XML'
$btnConvertXml.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$btnConvertXml.Location = Pt 485 16
$btnConvertXml.Size = Sz 150 30
$grpConvert.Controls.Add($btnConvertXml)

$btnConvertCsv = New-Object System.Windows.Forms.Button
$btnConvertCsv.Name = 'btnConvertCsv'
$btnConvertCsv.Text = 'Convert to CSV'
$btnConvertCsv.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$btnConvertCsv.Location = Pt 645 16
$btnConvertCsv.Size = Sz 150 30
$grpConvert.Controls.Add($btnConvertCsv)

$lblConvertStatus = New-Object System.Windows.Forms.Label
$lblConvertStatus.Text = ''
$lblConvertStatus.Font = New-Object System.Drawing.Font('Segoe UI', 8)
$lblConvertStatus.Location = Pt 52 44
$lblConvertStatus.Size = Sz 750 14
$lblConvertStatus.ForeColor = [System.Drawing.Color]::DarkGreen
$grpConvert.Controls.Add($lblConvertStatus)

$yTools += 60

# Results/Log textbox for Tools tab
$lblToolsLog = New-Object System.Windows.Forms.Label
$lblToolsLog.Text = 'Results:'
$lblToolsLog.AutoSize = $true
$lblToolsLog.Location = Pt 10 $yTools
$toolsPanel.Controls.Add($lblToolsLog)

$yTools += 25

$tbToolsLog = New-Object System.Windows.Forms.TextBox
$tbToolsLog.Multiline = $true
$tbToolsLog.ScrollBars = 'Both'
$tbToolsLog.ReadOnly = $true
$tbToolsLog.WordWrap = $false
$tbToolsLog.Location = Pt 10 $yTools
$tbToolsLog.Size = Sz 1200 400
$toolsPanel.Controls.Add($tbToolsLog)

# ====================================================================
# Template Check Tab
# ====================================================================
$templateCheckPanel = New-Object System.Windows.Forms.Panel
$templateCheckPanel.Dock = 'Fill'
$templateCheckPanel.AutoScroll = $true
$tabTemplateCheck.Controls.Add($templateCheckPanel)

$yTemplate = 20

$lblTemplateTitle = New-Object System.Windows.Forms.Label
$lblTemplateTitle.Text = 'Secret Template Validation & Comparison'
$lblTemplateTitle.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
$lblTemplateTitle.Location = Pt 10 $yTemplate
$lblTemplateTitle.AutoSize = $true
$templateCheckPanel.Controls.Add($lblTemplateTitle)

$yTemplate += 40

$lblTemplateDesc = New-Object System.Windows.Forms.Label
$lblTemplateDesc.Text = 'Compare secret templates between Source and Target environments. Identifies missing templates, field differences, and template settings differences (checkout, session recording, approval, etc.). Generates a detailed CSV report.'
$lblTemplateDesc.Location = Pt 10 $yTemplate
$lblTemplateDesc.Size = Sz 1100 40
$templateCheckPanel.Controls.Add($lblTemplateDesc)

$yTemplate += 45

# Source/Target connection indicator
$lblConnectionStatus = New-Object System.Windows.Forms.Label
$lblConnectionStatus.Text = 'Source and Target credentials are taken from the Settings tab'
$lblConnectionStatus.ForeColor = [System.Drawing.Color]::DarkBlue
$lblConnectionStatus.Location = Pt 10 $yTemplate
$lblConnectionStatus.AutoSize = $true
$templateCheckPanel.Controls.Add($lblConnectionStatus)

$yTemplate += 35

# Output CSV file path
$lblTemplateCsv = New-Object System.Windows.Forms.Label
$lblTemplateCsv.Text = 'Output CSV:'
$lblTemplateCsv.AutoSize = $true
$lblTemplateCsv.Location = Pt 10 ($yTemplate + 4)
$templateCheckPanel.Controls.Add($lblTemplateCsv)

$tbTemplateCsv = New-Object System.Windows.Forms.TextBox
$tbTemplateCsv.Location = Pt 130 $yTemplate
$tbTemplateCsv.Size = Sz 600 24
$tbTemplateCsv.Text = (Join-Path $BaseDir "SecretTemplateComparison_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
$templateCheckPanel.Controls.Add($tbTemplateCsv)

$btnBrowseTemplateCsv = New-Object System.Windows.Forms.Button
$btnBrowseTemplateCsv.Text = 'Browse...'
$btnBrowseTemplateCsv.Location = Pt 740 $yTemplate
$btnBrowseTemplateCsv.Size = Sz 100 24
$templateCheckPanel.Controls.Add($btnBrowseTemplateCsv)

$yTemplate += 35

# Target suffix for template matching
$lblTargetSuffix = New-Object System.Windows.Forms.Label
$lblTargetSuffix.Text = 'Target Suffix:'
$lblTargetSuffix.AutoSize = $true
$lblTargetSuffix.Location = Pt 10 ($yTemplate + 4)
$templateCheckPanel.Controls.Add($lblTargetSuffix)

$tbTargetSuffix = New-Object System.Windows.Forms.TextBox
$tbTargetSuffix.Location = Pt 130 $yTemplate
$tbTargetSuffix.Size = Sz 200 24
$tbTargetSuffix.Text = ' TARGET'  # Default suffix
$templateCheckPanel.Controls.Add($tbTargetSuffix)

# Small clear (X) button at the right edge of the Target Suffix textbox.
$btnClearTargetSuffix = New-Object System.Windows.Forms.Button
$btnClearTargetSuffix.Text = 'X'
$btnClearTargetSuffix.Location = Pt 332 $yTemplate
$btnClearTargetSuffix.Size = Sz 24 24
$btnClearTargetSuffix.Font = New-Object System.Drawing.Font('Segoe UI', 8, [System.Drawing.FontStyle]::Bold)
$btnClearTargetSuffix.FlatStyle = 'Flat'
$btnClearTargetSuffix.ForeColor = [System.Drawing.Color]::FromArgb(180,40,40)
$btnClearTargetSuffix.TabStop = $false
$tt = New-Object System.Windows.Forms.ToolTip
$tt.SetToolTip($btnClearTargetSuffix,'Clear the Target Suffix')
$btnClearTargetSuffix.Add_Click({ $tbTargetSuffix.Text = ''; $tbTargetSuffix.Focus() | Out-Null })
$templateCheckPanel.Controls.Add($btnClearTargetSuffix)

$lblSuffixHint = New-Object System.Windows.Forms.Label
$lblSuffixHint.Text = '(e.g., " TARGET", " XYZ", " Prod" - used for automatic template name matching)'
$lblSuffixHint.AutoSize = $true
$lblSuffixHint.Location = Pt 365 ($yTemplate + 4)
$lblSuffixHint.ForeColor = [System.Drawing.Color]::Gray
$templateCheckPanel.Controls.Add($lblSuffixHint)

$yTemplate += 40

# Compare button
$btnCompareTemplates = New-Object System.Windows.Forms.Button
$btnCompareTemplates.Name = 'btnCompareTemplates'
$btnCompareTemplates.Text = 'Compare Templates'
$btnCompareTemplates.Location = Pt 10 $yTemplate
$btnCompareTemplates.Size = Sz 180 36
$btnCompareTemplates.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$templateCheckPanel.Controls.Add($btnCompareTemplates)

# Open CSV button
$btnOpenTemplateCsv = New-Object System.Windows.Forms.Button
$btnOpenTemplateCsv.Name = 'btnOpenTemplateCsv'
$btnOpenTemplateCsv.Text = 'Open CSV'
$btnOpenTemplateCsv.Location = Pt 200 $yTemplate
$btnOpenTemplateCsv.Size = Sz 100 36
$btnOpenTemplateCsv.Enabled = $false
$templateCheckPanel.Controls.Add($btnOpenTemplateCsv)

# Clear Log button for Template Check tab
$btnClearTemplateLog = New-Object System.Windows.Forms.Button
$btnClearTemplateLog.Name = 'btnClearTemplateLog'
$btnClearTemplateLog.Text = 'Clear Log'
$btnClearTemplateLog.Location = Pt 310 $yTemplate
$btnClearTemplateLog.Size = Sz 100 36
$templateCheckPanel.Controls.Add($btnClearTemplateLog)

# Close button for Template Check tab
$btnCloseTemplateCheck = New-Object System.Windows.Forms.Button
$btnCloseTemplateCheck.Name = 'btnCloseTemplateCheck'
$btnCloseTemplateCheck.Text = 'Close'
$btnCloseTemplateCheck.Location = Pt 420 $yTemplate
$btnCloseTemplateCheck.Size = Sz 100 36
$templateCheckPanel.Controls.Add($btnCloseTemplateCheck)

$yTemplate += 60

# Results/Log section with split view - Label
$lblTemplateLog = New-Object System.Windows.Forms.Label
$lblTemplateLog.Text = 'Results and Field Mapping:'
$lblTemplateLog.AutoSize = $true
$lblTemplateLog.Location = Pt 10 $yTemplate
$templateCheckPanel.Controls.Add($lblTemplateLog)

$yTemplate += 25

# Create SplitContainer to divide results area
$splitContainerResults = New-Object System.Windows.Forms.SplitContainer
$splitContainerResults.Location = Pt 10 $yTemplate
$splitContainerResults.Size = Sz 1220 430
$splitContainerResults.Anchor = 'Top,Left,Right'
$splitContainerResults.Orientation = 'Vertical'
$splitContainerResults.SplitterDistance = 600
$splitContainerResults.SplitterWidth = 8
$splitContainerResults.BorderStyle = 'FixedSingle'
$splitContainerResults.IsSplitterFixed = $false
$splitContainerResults.Panel1MinSize = 300
$splitContainerResults.Panel2MinSize = 400
$templateCheckPanel.Controls.Add($splitContainerResults)

# LEFT PANEL: Log TextBox
$tbTemplateLog = New-Object System.Windows.Forms.TextBox
$tbTemplateLog.Multiline = $true
$tbTemplateLog.ScrollBars = 'Both'
$tbTemplateLog.ReadOnly = $true
$tbTemplateLog.WordWrap = $false
$tbTemplateLog.Dock = 'Fill'
$splitContainerResults.Panel1.Controls.Add($tbTemplateLog)

# RIGHT PANEL: Field Mapping Interface
$mappingPanel = New-Object System.Windows.Forms.Panel
$mappingPanel.Dock = 'Fill'
$mappingPanel.AutoScroll = $true
$mappingPanel.Padding = New-Object System.Windows.Forms.Padding(5)
$splitContainerResults.Panel2.Controls.Add($mappingPanel)

# Mapping panel title
$lblMappingTitle = New-Object System.Windows.Forms.Label
$lblMappingTitle.Text = 'Template Mapping Configuration'
$lblMappingTitle.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$lblMappingTitle.Location = Pt 5 5
$lblMappingTitle.AutoSize = $true
$mappingPanel.Controls.Add($lblMappingTitle)

# Mapping instructions
$lblMappingInstructions = New-Object System.Windows.Forms.Label
$lblMappingInstructions.Text = 'Checked templates need remapping (✗). Unchecked templates match perfectly (✓). Select which mappings to export to CSV.'
$lblMappingInstructions.Location = Pt 5 30
$lblMappingInstructions.AutoSize = $true
$lblMappingInstructions.MaximumSize = Sz 2000 50
$mappingPanel.Controls.Add($lblMappingInstructions)

# Select All checkbox (positioned just below the instructions; instructions are
# AutoSize so usually one short line, leaving little wasted vertical space).
$chkSelectAllTemplates = New-Object System.Windows.Forms.CheckBox
$chkSelectAllTemplates.Text = 'Select All Templates'
$chkSelectAllTemplates.Location = Pt 5 52
$chkSelectAllTemplates.AutoSize = $true
$chkSelectAllTemplates.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$chkSelectAllTemplates.Add_CheckedChanged({
  $checked = $chkSelectAllTemplates.Checked
  for($r = 0; $r -lt $dgvFieldMappings.Rows.Count; $r++){
    $dgvFieldMappings.Rows[$r].Cells['Enabled'].Value = $checked
  }
})
$mappingPanel.Controls.Add($chkSelectAllTemplates)

# DataGridView for field mappings (anchored to all 4 sides so it grows with panel)
$dgvFieldMappings = New-Object System.Windows.Forms.DataGridView
$dgvFieldMappings.Location = Pt 5 78
$dgvFieldMappings.Size = Sz 512 230
$dgvFieldMappings.Anchor = 'Top,Bottom,Left,Right'
$dgvFieldMappings.AllowUserToAddRows = $false
$dgvFieldMappings.AllowUserToDeleteRows = $false
$dgvFieldMappings.ReadOnly = $false
$dgvFieldMappings.SelectionMode = 'FullRowSelect'
$dgvFieldMappings.MultiSelect = $false
$dgvFieldMappings.AutoSizeColumnsMode = 'None'
$dgvFieldMappings.ScrollBars = 'Both'
$dgvFieldMappings.RowHeadersVisible = $false
$dgvFieldMappings.AllowUserToResizeRows = $false
$dgvFieldMappings.AllowUserToResizeColumns = $true
$dgvFieldMappings.ColumnHeadersDefaultCellStyle.WrapMode = 'True'
$dgvFieldMappings.AutoGenerateColumns = $false
$mappingPanel.Controls.Add($dgvFieldMappings)

# Add columns to DataGridView
$colEnabled = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colEnabled.Name = 'Enabled'
$colEnabled.HeaderText = 'Sel'
$colEnabled.Width = 50
$colEnabled.MinimumWidth = 40
$colEnabled.ReadOnly = $false
$dgvFieldMappings.Columns.Add($colEnabled) | Out-Null

$colTemplate = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colTemplate.Name = 'Template'
$colTemplate.HeaderText = 'Source Template'
$colTemplate.ReadOnly = $true
$colTemplate.Width = 200
$colTemplate.MinimumWidth = 100
$colTemplate.SortMode = 'Automatic'
$dgvFieldMappings.Columns.Add($colTemplate) | Out-Null

$colSourceId = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colSourceId.Name = 'SourceId'
$colSourceId.HeaderText = 'Source ID'
$colSourceId.ReadOnly = $true
$colSourceId.Width = 80
$colSourceId.MinimumWidth = 60
$colSourceId.SortMode = 'Automatic'
$dgvFieldMappings.Columns.Add($colSourceId) | Out-Null

$colTargetTemplate = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colTargetTemplate.Name = 'TargetTemplate'
$colTargetTemplate.HeaderText = 'Target Template'
$colTargetTemplate.ReadOnly = $true
$colTargetTemplate.Width = 200
$colTargetTemplate.MinimumWidth = 100
$colTargetTemplate.SortMode = 'Automatic'
$dgvFieldMappings.Columns.Add($colTargetTemplate) | Out-Null

$colTargetId = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colTargetId.Name = 'TargetId'
$colTargetId.HeaderText = 'Target ID'
$colTargetId.ReadOnly = $true
$colTargetId.Width = 80
$colTargetId.MinimumWidth = 60
$colTargetId.SortMode = 'Automatic'
$dgvFieldMappings.Columns.Add($colTargetId) | Out-Null

$colSourceField = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colSourceField.Name = 'SourceField'
$colSourceField.HeaderText = 'Field'
$colSourceField.ReadOnly = $true
$colSourceField.Width = 120
$colSourceField.MinimumWidth = 80
$colSourceField.SortMode = 'Automatic'
$dgvFieldMappings.Columns.Add($colSourceField) | Out-Null

$colStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colStatus.Name = 'Status'
$colStatus.HeaderText = 'Match'
$colStatus.ReadOnly = $true
$colStatus.Width = 90
$colStatus.MinimumWidth = 70
$colStatus.SortMode = 'Automatic'
$colStatus.DefaultCellStyle.Alignment = 'MiddleCenter'
$dgvFieldMappings.Columns.Add($colStatus) | Out-Null

# Add CellFormatting event for color coding the Match column
$dgvFieldMappings.Add_CellFormatting({
  param($sender, $e)
  
  if ($e.ColumnIndex -eq $dgvFieldMappings.Columns['Status'].Index -and $e.RowIndex -ge 0) {
    $cellValue = $dgvFieldMappings.Rows[$e.RowIndex].Cells[$e.ColumnIndex].Value
    
    if ($cellValue -eq '✓') {
      # Green for matched
      $e.CellStyle.ForeColor = [System.Drawing.Color]::Green
      $e.CellStyle.Font = New-Object System.Drawing.Font($e.CellStyle.Font.FontFamily, 12, [System.Drawing.FontStyle]::Bold)
    } elseif ($cellValue -eq '✗') {
      # Red for not matched
      $e.CellStyle.ForeColor = [System.Drawing.Color]::Red
      $e.CellStyle.Font = New-Object System.Drawing.Font($e.CellStyle.Font.FontFamily, 12, [System.Drawing.FontStyle]::Bold)
    }
  }
})

# Buttons for field mapping operations (anchored to the bottom so they stay
# pinned below the DataGridView regardless of panel height).
$btnSaveMappings = New-Object System.Windows.Forms.Button
$btnSaveMappings.Text = 'Save to CSV'
$btnSaveMappings.Location = Pt 5 313
$btnSaveMappings.Size = Sz 130 36
$btnSaveMappings.Anchor = 'Bottom,Left'
$btnSaveMappings.Enabled = $false
$mappingPanel.Controls.Add($btnSaveMappings)

$btnLoadMappings = New-Object System.Windows.Forms.Button
$btnLoadMappings.Text = 'Load from CSV'
$btnLoadMappings.Location = Pt 145 313
$btnLoadMappings.Size = Sz 130 36
$btnLoadMappings.Anchor = 'Bottom,Left'
$mappingPanel.Controls.Add($btnLoadMappings)

$btnClearMappings = New-Object System.Windows.Forms.Button
$btnClearMappings.Text = 'Clear'
$btnClearMappings.Location = Pt 285 313
$btnClearMappings.Size = Sz 100 36
$btnClearMappings.Anchor = 'Bottom,Left'
$mappingPanel.Controls.Add($btnClearMappings)

# Label for mapping CSV path
$lblMappingCsv = New-Object System.Windows.Forms.Label
$lblMappingCsv.Text = 'Mapping CSV:'
$lblMappingCsv.Location = Pt 5 360
$lblMappingCsv.AutoSize = $true
$lblMappingCsv.Anchor = 'Bottom,Left'
$mappingPanel.Controls.Add($lblMappingCsv)

$tbMappingCsv = New-Object System.Windows.Forms.TextBox
$tbMappingCsv.Location = Pt 105 358
$tbMappingCsv.Size = Sz 332 24
$tbMappingCsv.Anchor = 'Bottom,Left,Right'
$tbMappingCsv.Text = (Join-Path $BaseDir "TemplateMappings.csv")
$mappingPanel.Controls.Add($tbMappingCsv)

$btnBrowseMappingCsv = New-Object System.Windows.Forms.Button
$btnBrowseMappingCsv.Text = 'Browse...'
$btnBrowseMappingCsv.Location = Pt 442 358
$btnBrowseMappingCsv.Size = Sz 80 24
$btnBrowseMappingCsv.Anchor = 'Bottom,Right'
$mappingPanel.Controls.Add($btnBrowseMappingCsv)

# Info label about CSV usage
$lblMappingInfo = New-Object System.Windows.Forms.Label
$lblMappingInfo.Text = '💡 This CSV can be used directly in the Template Remapping Tool section below'
$lblMappingInfo.Location = Pt 5 390
$lblMappingInfo.AutoSize = $true
$lblMappingInfo.MaximumSize = Sz 2000 40
$lblMappingInfo.Anchor = 'Bottom,Left'
$lblMappingInfo.ForeColor = [System.Drawing.Color]::DarkGreen
$mappingPanel.Controls.Add($lblMappingInfo)

# Store field mappings data globally
$Global:CurrentFieldMappings = @()

# Add event handler to resize controls when panel resizes.
# Note: $dgvFieldMappings is anchored to all 4 sides, so its size tracks the
# panel automatically. Bottom-row controls are anchored to Bottom so they
# follow the panel bottom. We only keep the wrap-width of the long label
# controls in sync with the available width.
$mappingPanel.Add_Resize({
  $panelWidth = $mappingPanel.Width - 20
  if ($panelWidth -gt 200) {
    $lblMappingInstructions.MaximumSize = Sz $panelWidth 50
    $lblMappingInfo.MaximumSize = Sz $panelWidth 40
  }
})

# Add event handler to resize controls when splitter moves
$splitContainerResults.Add_SplitterMoved({
  $panelWidth = $splitContainerResults.Panel2.Width - 20
  if ($panelWidth -gt 200) {
    $lblMappingInstructions.MaximumSize = Sz $panelWidth 50
    $lblMappingInfo.MaximumSize = Sz $panelWidth 40
    $mappingPanel.PerformLayout()
    $mappingPanel.Refresh()
  }
})

$yTemplate += 450

# ====================================================================
# Template Remapping Section
# ====================================================================
$lblRemapTitle = New-Object System.Windows.Forms.Label
$lblRemapTitle.Text = 'Template Remapping Tool'
$lblRemapTitle.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
$lblRemapTitle.Location = Pt 10 $yTemplate
$lblRemapTitle.AutoSize = $true
$templateCheckPanel.Controls.Add($lblRemapTitle)

$yTemplate += 35

$lblRemapDesc = New-Object System.Windows.Forms.Label
$lblRemapDesc.Text = 'Remap template names and IDs in your JSON export file. Use this when template names differ between Source and Target (e.g., "Active Directory Account" -> "Active Directory Account TARGET"). Requires a CSV mapping file with columns: SourceName, SourceId, TargetName, TargetId'
$lblRemapDesc.Location = Pt 10 $yTemplate
$lblRemapDesc.Size = Sz 600 35
$lblRemapDesc.Anchor = 'Top,Left,Right'
$templateCheckPanel.Controls.Add($lblRemapDesc)

$yTemplate += 45

# Capture the Y of the first Browse... row so the action buttons can be placed
# vertically alongside the Mapping CSV / Output JSON rows instead of below them.
$yBrowseStart = $yTemplate

# Template mapping CSV file
$lblRemapCsv = New-Object System.Windows.Forms.Label
$lblRemapCsv.Text = 'Mapping CSV:'
$lblRemapCsv.AutoSize = $true
$lblRemapCsv.Location = Pt 10 ($yTemplate + 4)
$templateCheckPanel.Controls.Add($lblRemapCsv)

$tbRemapCsv = New-Object System.Windows.Forms.TextBox
$tbRemapCsv.Location = Pt 130 $yTemplate
$tbRemapCsv.Size = Sz 400 24
$tbRemapCsv.Anchor = 'Top,Left,Right'
$templateCheckPanel.Controls.Add($tbRemapCsv)

$btnBrowseRemapCsv = New-Object System.Windows.Forms.Button
$btnBrowseRemapCsv.Text = 'Browse...'
$btnBrowseRemapCsv.Location = Pt 540 $yTemplate
$btnBrowseRemapCsv.Size = Sz 80 24
$btnBrowseRemapCsv.Anchor = 'Top,Right'
$templateCheckPanel.Controls.Add($btnBrowseRemapCsv)

$yTemplate += 35

# Source JSON file
$lblRemapSourceJson = New-Object System.Windows.Forms.Label
$lblRemapSourceJson.Text = 'Source JSON:'
$lblRemapSourceJson.AutoSize = $true
$lblRemapSourceJson.Location = Pt 10 ($yTemplate + 4)
$templateCheckPanel.Controls.Add($lblRemapSourceJson)

$tbRemapSourceJson = New-Object System.Windows.Forms.TextBox
$tbRemapSourceJson.Location = Pt 130 $yTemplate
$tbRemapSourceJson.Size = Sz 400 24
$tbRemapSourceJson.Anchor = 'Top,Left,Right'
$templateCheckPanel.Controls.Add($tbRemapSourceJson)

$btnBrowseRemapSourceJson = New-Object System.Windows.Forms.Button
$btnBrowseRemapSourceJson.Text = 'Browse...'
$btnBrowseRemapSourceJson.Location = Pt 540 $yTemplate
$btnBrowseRemapSourceJson.Size = Sz 80 24
$btnBrowseRemapSourceJson.Anchor = 'Top,Right'
$templateCheckPanel.Controls.Add($btnBrowseRemapSourceJson)

$yTemplate += 35

# Output JSON file
$lblRemapOutputJson = New-Object System.Windows.Forms.Label
$lblRemapOutputJson.Text = 'Output JSON:'
$lblRemapOutputJson.AutoSize = $true
$lblRemapOutputJson.Location = Pt 10 ($yTemplate + 4)
$templateCheckPanel.Controls.Add($lblRemapOutputJson)

$tbRemapOutputJson = New-Object System.Windows.Forms.TextBox
$tbRemapOutputJson.Location = Pt 130 $yTemplate
$tbRemapOutputJson.Size = Sz 400 24
$tbRemapOutputJson.Anchor = 'Top,Left,Right'
$templateCheckPanel.Controls.Add($tbRemapOutputJson)

$btnBrowseRemapOutputJson = New-Object System.Windows.Forms.Button
$btnBrowseRemapOutputJson.Text = 'Browse...'
$btnBrowseRemapOutputJson.Location = Pt 540 $yTemplate
$btnBrowseRemapOutputJson.Size = Sz 80 24
$btnBrowseRemapOutputJson.Anchor = 'Top,Right'
$templateCheckPanel.Controls.Add($btnBrowseRemapOutputJson)

$yTemplate += 45

# Remap action buttons - placed in a column to the RIGHT of the three Browse...
# buttons, vertically aligned with the Mapping CSV (top) and Output JSON
# (bottom) rows. Anchor=Top,Right keeps them pinned to the form's right edge.
$btnRemapTemplates = New-Object System.Windows.Forms.Button
$btnRemapTemplates.Name = 'btnRemapTemplates'
$btnRemapTemplates.Text = 'Remap Templates'
$btnRemapTemplates.Location = Pt 630 ($yBrowseStart - 6)
$btnRemapTemplates.Size = Sz 180 36
$btnRemapTemplates.Anchor = 'Top,Right'
$btnRemapTemplates.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$templateCheckPanel.Controls.Add($btnRemapTemplates)

# Open output JSON button (aligned with the Output JSON / 3rd browse row)
$btnOpenRemapJson = New-Object System.Windows.Forms.Button
$btnOpenRemapJson.Name = 'btnOpenRemapJson'
$btnOpenRemapJson.Text = 'Open Output'
$btnOpenRemapJson.Location = Pt 630 ($yBrowseStart + 64)
$btnOpenRemapJson.Size = Sz 180 36
$btnOpenRemapJson.Anchor = 'Top,Right'
$btnOpenRemapJson.Enabled = $false
$templateCheckPanel.Controls.Add($btnOpenRemapJson)

# Remap results log - merged into the main Results log ($tbTemplateLog) above.
# Keep $tbRemapLog and $lblRemapLog as aliases / hidden so existing append-text
# call sites continue to work without refactoring.
$lblRemapLog = New-Object System.Windows.Forms.Label
$lblRemapLog.Text = ''
$lblRemapLog.Visible = $false
$tbRemapLog = $tbTemplateLog

# Pin the Template Check panel's scrollable canvas to the actual content
# height. Without this, AutoScroll computes virtual size from anchored
# children (Top,Left,Right), which makes the scrollbar thumb shrink/jump
# and prevents scrolling all the way back to the top. We set Width=0 so
# only a vertical scrollbar is used.
$templateCheckPanel.AutoScrollMinSize = New-Object System.Drawing.Size(0, ($yTemplate + 20))
$templateCheckPanel.HorizontalScroll.Enabled = $false
$templateCheckPanel.HorizontalScroll.Visible = $false

function Populate($c){
  $tbTokenPath.Text=$c.TokenPath
  $cbStore.Checked=[bool]$c.Auth.StorePassword
  # Show the base log path (without timestamp) in the textbox
  $tbLogPath.Text=$c.LogFile -replace '_\d{8}_\d{6}\.log$','.log'
  $cbLogDateStamp.Checked=[bool]$c.LogFileDateStamp
  $tbRootFolder.Text = $script:BaseDir
  $tbCfgPath.Text = $script:ConfigPath

  $tbSrcBase.Text=$c.Src.TenantBase; $tbSrcUser.Text=$c.Src.Username; $tbSrcApi.Text=$c.Src.SSApiBase
  $tbSrcSearch.Text=$c.Src.SearchText; $tbSrcFld.Text=""
  $tbCount.Text=""  # used for MaxSecrets/total

  $tbTgtBase.Text=$c.Tgt.TenantBase; $tbTgtUser.Text=$c.Tgt.Username; $tbTgtApi.Text=$c.Tgt.SSApiBase
  $tbTgtFld.Text=[string]$c.Tgt.TargetFolderId; $tbTgtRoot.Text=[string]$c.Tgt.TargetRootFolderId

  $cbFA.Checked=[bool]$c.Tgt.CopyFolderAcls
  $cbSA.Checked=[bool]$c.Tgt.CopySecretAcls
  $cbSet.Checked=[bool]$c.Tgt.CopySecretSettings
  $cbAtt.Checked=[bool]$c.Tgt.CopyAttachments
  $cbImportTemplates.Checked=[bool]$c.Tgt.ImportTemplates
  $cbRemap.Checked=[bool]$c.Tgt.RemapPrincipals
  $cbDry.Checked=[bool]$c.Tgt.DryRun
  $cbTree.Checked=[bool]$c.Tgt.FolderTreeMigration
  $cbTypeMap.Checked=[bool]$c.Tgt.SecretTypeMapByName
  $cbSrcHist.Checked=[bool]$c.Src.IncludeHistory
  $cbOverwrite.Checked=[bool]$c.Tgt.OverwriteIfExists
  if($c.Tgt.PSObject.Properties['DisableInheritPermissions']){ $cbDisableInherit.Checked=[bool]$c.Tgt.DisableInheritPermissions }

  # Duplicate handling radios (Skip vs Update) - config -> UI only
  $dup = [string]$c.Tgt.DuplicateSecretAction
  if([string]::IsNullOrWhiteSpace($dup)){ $dup = "Skip" }
  $rbDupSkip.Checked   = ($dup -eq "Skip")
  $rbDupUpdate.Checked = ($dup -eq "Update")

  $cbExportTemplates.Checked=[bool]$c.Src.ExportTemplates
  $cbV1ExportService.Checked=[bool]$c.Src.UseV1ExportService
  $cbExportChild.Checked=[bool]$c.Src.ExportChildFolders
  
  # Load encryption/decryption options
  try {
    $cbEncryptPasswords.Checked = [bool](Get-PropValue $c.Src @('EncryptPasswords') $false)
  } catch {
    $cbEncryptPasswords.Checked = $false
  }
  try {
    $cbDecryptPasswords.Checked = [bool](Get-PropValue $c.Crypto @('DecryptPasswords') $false)
  } catch {
    $cbDecryptPasswords.Checked = $false
  }
  
  # Safe load with fallback to $false if property doesn't exist
try {
  $cbExportJson.Checked = [bool](Get-PropValue $c.Src @('ExportJson') $true)  # default true for JSON
} catch {
  $cbExportJson.Checked = $true
}
try {
  $cbExportXml.Checked = [bool](Get-PropValue $c.Src @('ExportXml') $false)
} catch {
  $cbExportXml.Checked = $false
}
try {
  $cbExportCsv.Checked = [bool](Get-PropValue $c.Src @('ExportCsv') $false)
} catch {
  $cbExportCsv.Checked = $false
}
  try {
  $cbExportZip.Checked = [bool](Get-PropValue $c.Src @('ExportZip') $false)
} catch {
  $cbExportZip.Checked = $false
  }
  
  $tbExport.Text = $c.ExportFile
  $tbExportCsv.Text = $c.ExportCsvFile

  # Template Check tab CSV paths
  if($c.TemplateCsvPath -and -not [string]::IsNullOrWhiteSpace($c.TemplateCsvPath)){
    $tbTemplateCsv.Text = $c.TemplateCsvPath
  }
  if($c.RemapCsvPath -and -not [string]::IsNullOrWhiteSpace($c.RemapCsvPath)){
    $tbRemapCsv.Text = $c.RemapCsvPath
  }
  if($c.PSObject.Properties['MappingCsvPath'] -and -not [string]::IsNullOrWhiteSpace($c.MappingCsvPath)){
    $tbMappingCsv.Text = $c.MappingCsvPath
  }

  # New V22 import options (load with sensible defaults)
  try { $tbTemplateSuffix.Text = [string](Get-PropValue $c.Tgt @('TemplateSuffix') 'MIGRATED') } catch { $tbTemplateSuffix.Text = 'MIGRATED' }
  try { $tbTargetSuffix.Text   = [string](Get-PropValue $c.Tgt @('TargetSuffix')   ' TARGET')   } catch { $tbTargetSuffix.Text   = ' TARGET' }
  # SkipPasswordValidation: always default to UNCHECKED on GUI load.
  # The target Delinea tenant often rejects POST /secrets when this body flag is present
  # (returns Invalid request (400)), so we don't persist this across sessions - the user
  # must opt in explicitly each run.
  $cbSkipPwdVal.Checked = $false
  try { $chkSyncTemplateFields.Checked = [bool](Get-PropValue $c.Tgt @('SyncTemplateFields') $false) } catch { $chkSyncTemplateFields.Checked = $false }
  try { $cbStopOnError.Checked = [bool](Get-PropValue $c.Tgt @('StopOnError') $false) } catch { $cbStopOnError.Checked = $false }
  try { $cbApplyPwdHistory.Checked = [bool](Get-PropValue $c.Tgt @('ApplyPasswordHistory') $true) } catch { $cbApplyPwdHistory.Checked = $true }
  try { $cbCleanupUpdated.Checked = [bool](Get-PropValue $c.Tgt @('CleanupRollbackUpdatedSecrets') $false) } catch { $cbCleanupUpdated.Checked = $false }
  # Enforce mutual exclusion: cbImportTemplates <-> chkSyncTemplateFields
  if($cbImportTemplates.Checked -and $chkSyncTemplateFields.Checked){ $chkSyncTemplateFields.Checked = $false }
  $tbTemplateSuffix.Enabled = $cbImportTemplates.Checked

  $tbHelp.Text=@"
Options help:

FOLDER OPERATIONS:
- Folder-tree migration: Creates missing folders under Target ROOT Id using POST /api/v1/folders.
- Copy Folder ACLs: Export+apply folder permissions via /api/v1/folder-permissions (role names, breakInheritance).

SECRET OPERATIONS:
- Copy Secret ACLs: Apply secret shares - groups via BULK add-share (roleName->roleId via /roles) + users via /secret-permissions fallback.
- Copy Secret Settings: Exports /api/v1/secrets/{id}/settings. PUT is 405 in this tenant, so import cannot apply (export-only).
- Copy Attachments: Exports file fields to disk and imports (multipart upload).
- Include Password History: Export password history for each secret (requires View/Edit permissions on source).
- SecretType map by name: Maps SecretTypeName to target template id using GET /api/v1/secret-templates.
- Overwrite if exists: Updates existing secrets when folder-tree is OFF (same-name match in target folder).
- Remap principals: Implemented. Tries (userName -> displayNameWithDomain -> displayName) for users; group name for groups.

DUPLICATE HANDLING:
- Skip: If a secret with the same name already exists in the destination folder, log warning and SKIP (no create/update).
- Update: If a secret with the same name already exists in the destination folder, UPDATE it (requires 'Overwrite if exists' checked).
- Cleanup rollback updated: If enabled, snapshots target secret before overwrite and Cleanup restores it from rollback folder.

EXPORT OPTIONS:
- Export JSON: Exports secrets to JSON format (default format for import).
- Export XML: Generates Delinea Web Portal compatible XML export file.
- Export CSV: Creates CSV bundle with secrets, items, permissions, settings, and attachments.
- Export ZIP: Bundles all export outputs (JSON, XML, CSV, attachments) into a single timestamped ZIP archive.
- Use v1 export service: Also writes CSV using POST /api/v1/secrets/export (exportedSecretsFileText). JSON export is still produced for import.
- Export child folders: When using v1 export service, include child folders in CSV export.
- Template migration: Exports templates via /secret-templates/{id}/export and imports via /secret-templates/import (best effort).
- Incremental export: Skip secrets that already exist in the export file (avoids re-exporting).
- Encrypt passwords (DPAPI): Encrypts password fields using Windows DPAPI during export (machine-specific encryption).
- Decrypt passwords (DPAPI): Decrypts DPAPI-encrypted password fields during import (must be on same Windows machine).

TESTING & LOGGING:
- Dry-run: No folder creation, no ACL apply, no secret create/update; logs intended actions only.
- Verbose HTTP: Enables DEBUG logging for every GET/POST API call with full URLs.

CLEANUP:
- Cleanup: Deletes secrets+folders created by last import run; can rollback overwritten secrets if 'Cleanup rollback updated' was enabled.
"@

  Update-SelectionDetails
}

function ReadControls {
  # --- Root Folder path rebasing ---
  $newRoot = $tbRootFolder.Text.TrimEnd('\')
  $oldRoot = $script:BaseDir.TrimEnd('\')
  if($newRoot -and $newRoot -ne $oldRoot){
    # Update the global BaseDir
    $script:BaseDir = $newRoot
    $script:AttachmentRoot = Join-Path $newRoot 'Attachments'
    if(-not (Test-Path $newRoot)){ New-Item -ItemType Directory -Path $newRoot -Force | Out-Null }
    if(-not (Test-Path $script:AttachmentRoot)){ New-Item -ItemType Directory -Path $script:AttachmentRoot -Force | Out-Null }
    
    # Rebase all file path textboxes from old root to new root
    function Rebase-Path([string]$path,[string]$from,[string]$to){
      if([string]::IsNullOrWhiteSpace($path)){ return $path }
      $fromNorm = $from.TrimEnd('\') + '\'
      if($path.StartsWith($fromNorm,[System.StringComparison]::OrdinalIgnoreCase)){
        return Join-Path $to $path.Substring($fromNorm.Length)
      }
      # If path is just a filename, put it under new root
      if(-not [System.IO.Path]::IsPathRooted($path)){ return Join-Path $to $path }
      return $path
    }
    
    # Update all UI textboxes in all tabs
    $tbLogPath.Text = Rebase-Path $tbLogPath.Text $oldRoot $newRoot
    if($tbExport){ $tbExport.Text = Rebase-Path $tbExport.Text $oldRoot $newRoot }
    if($tbExportCsv){ $tbExportCsv.Text = Rebase-Path $tbExportCsv.Text $oldRoot $newRoot }
    if($tbConvertJson){ $tbConvertJson.Text = Rebase-Path $tbConvertJson.Text $oldRoot $newRoot }
    if($tbTemplateCsv){ $tbTemplateCsv.Text = Rebase-Path $tbTemplateCsv.Text $oldRoot $newRoot }
    if($tbMappingCsv){ $tbMappingCsv.Text = Rebase-Path $tbMappingCsv.Text $oldRoot $newRoot }
    if($tbRemapCsv){ $tbRemapCsv.Text = Rebase-Path $tbRemapCsv.Text $oldRoot $newRoot }
    
    # Rebase config file paths (internal paths not shown in textboxes)
    $Global:Config.ExportFile = Rebase-Path ([string]$Global:Config.ExportFile) $oldRoot $newRoot
    $Global:Config.LogFile = Rebase-Path ([string]$Global:Config.LogFile) $oldRoot $newRoot
    $Global:Config.ExportCsvFile = Rebase-Path ([string]$Global:Config.ExportCsvFile) $oldRoot $newRoot
    $Global:Config.Tgt.RollbackDir = Rebase-Path ([string]$Global:Config.Tgt.RollbackDir) $oldRoot $newRoot
    if($Global:Config.TemplateCsvPath){ $Global:Config.TemplateCsvPath = Rebase-Path ([string]$Global:Config.TemplateCsvPath) $oldRoot $newRoot }
    if($Global:Config.RemapCsvPath){ $Global:Config.RemapCsvPath = Rebase-Path ([string]$Global:Config.RemapCsvPath) $oldRoot $newRoot }
    if($Global:Config.MappingCsvPath){ $Global:Config.MappingCsvPath = Rebase-Path ([string]$Global:Config.MappingCsvPath) $oldRoot $newRoot }
    
    # Also move the config file path itself to new root
    $script:ConfigPath = Rebase-Path $script:ConfigPath $oldRoot $newRoot
    $tbCfgPath.Text = $script:ConfigPath
    
    Write-Log ("Root folder changed: '{0}' -> '{1}'. All paths rebased." -f $oldRoot,$newRoot) 'INFO'
  }
  
  $Global:Config.TokenPath=$tbTokenPath.Text
  $Global:Config.Auth.StorePassword=[bool]$cbStore.Checked
  $Global:Config.LogFileDateStamp=[bool]$cbLogDateStamp.Checked
  # Use the already-stamped LogFile path; only re-stamp if checkbox state changed to checked
  if($cbLogDateStamp.Checked){
    # If current LogFile doesn't already have a timestamp, apply one
    if($Global:Config.LogFile -notmatch '_\d{8}_\d{6}\.log$'){
      $logBase = $tbLogPath.Text -replace '_\d{8}_\d{6}\.log$','.log'
      $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
      $Global:Config.LogFile = $logBase -replace '\.log$',("_{0}.log" -f $stamp)
    }
  } else {
    $Global:Config.LogFile=$tbLogPath.Text
  }

  if($tbCfgPath.Text){ $script:ConfigPath = $tbCfgPath.Text }

  # ---------------- Source ----------------
  $Global:Config.Src.TenantBase=$tbSrcBase.Text
  $Global:Config.Src.Username=$tbSrcUser.Text
  $Global:Config.Src.SSApiBase = Normalize-ApiBase -apiBase $tbSrcApi.Text -tenantBase $tbSrcBase.Text
  $Global:Config.Src.SearchText=$tbSrcSearch.Text
  $Global:Config.Src.FolderId=if([string]::IsNullOrWhiteSpace($tbSrcFld.Text)){$null}else{[int]$tbSrcFld.Text}

  $Global:Config.Src.MaxSecrets = Parse-NullableInt $tbCount.Text
  $Global:Config.Src.IncludeHistory=[bool]$cbSrcHist.Checked
  $Global:Config.Src.ExportTemplates=[bool]$cbExportTemplates.Checked
  $Global:Config.Src.UseV1ExportService=[bool]$cbV1ExportService.Checked
  $Global:Config.Src.ExportChildFolders=[bool]$cbExportChild.Checked
  
  # Save encryption/decryption options
  try {
    $Global:Config.Src | Add-Member -NotePropertyName EncryptPasswords -NotePropertyValue ([bool]$cbEncryptPasswords.Checked) -Force
  } catch {
    $Global:Config.Src.EncryptPasswords = [bool]$cbEncryptPasswords.Checked
  }
  
  if(-not $Global:Config.Crypto) {
    $Global:Config | Add-Member -NotePropertyName Crypto -NotePropertyValue ([ordered]@{}) -Force
  }
  try {
    $Global:Config.Crypto | Add-Member -NotePropertyName DecryptPasswords -NotePropertyValue ([bool]$cbDecryptPasswords.Checked) -Force
  } catch {
    $Global:Config.Crypto.DecryptPasswords = [bool]$cbDecryptPasswords.Checked
  }
  
  # Use direct assignment (works for both hashtables and PSCustomObject)
  $Global:Config.Src.ExportJson = [bool]$cbExportJson.Checked
  $Global:Config.Src.ExportXml  = [bool]$cbExportXml.Checked
  $Global:Config.Src.ExportCsv  = [bool]$cbExportCsv.Checked
  $Global:Config.Src.ExportZip  = [bool]$cbExportZip.Checked

  # DPAPI store Source password
  if($Global:Config.Auth.StorePassword){
    if($tbSrcPwd -and $tbSrcPwd.Text){
      try{
        $Global:Config.Src.PasswordDpapi = ProtectPwd ($tbSrcPwd.Text | ConvertTo-SecureString -AsPlainText -Force)
      } catch {
        Write-Log ("DPAPI store failed for Source password: {0}" -f $_) 'WARN'
      }
    }
  } else {
    try{ $Global:Config.Src.PasswordDpapi = "" } catch {}
  }

  # ---------------- Target ----------------
  $Global:Config.Tgt.TenantBase=$tbTgtBase.Text
  $Global:Config.Tgt.Username=$tbTgtUser.Text
  $Global:Config.Tgt.SSApiBase = Normalize-ApiBase -apiBase $tbTgtApi.Text -tenantBase $tbTgtBase.Text
  $Global:Config.Tgt.TargetFolderId=if([string]::IsNullOrWhiteSpace($tbTgtFld.Text)){0}else{[int]$tbTgtFld.Text}
  $Global:Config.Tgt.TargetRootFolderId=if([string]::IsNullOrWhiteSpace($tbTgtRoot.Text)){1}else{[int]$tbTgtRoot.Text}
  $Global:Config.Tgt.FolderTreeMigration=[bool]$cbTree.Checked
  $Global:Config.Tgt.SecretTypeMapByName=[bool]$cbTypeMap.Checked
  $Global:Config.Tgt.OverwriteIfExists=[bool]$cbOverwrite.Checked
  if(-not $Global:Config.Tgt.PSObject.Properties['DisableInheritPermissions']){
    $Global:Config.Tgt | Add-Member -NotePropertyName 'DisableInheritPermissions' -NotePropertyValue ([bool]$cbDisableInherit.Checked)
  } else {
    $Global:Config.Tgt.DisableInheritPermissions=[bool]$cbDisableInherit.Checked
  }

  $Global:Config.Tgt.CopyFolderAcls=[bool]$cbFA.Checked
  $Global:Config.Tgt.CopySecretAcls=[bool]$cbSA.Checked
  $Global:Config.Tgt.CopySecretSettings=[bool]$cbSet.Checked
  $Global:Config.Tgt.CopyAttachments=[bool]$cbAtt.Checked
  $Global:Config.Tgt.RemapPrincipals=[bool]$cbRemap.Checked
  $Global:Config.Tgt.DryRun=[bool]$cbDry.Checked
  $Global:Config.Tgt.CleanupRollbackUpdatedSecrets=[bool]$cbCleanupUpdated.Checked

  # New V22 import options - persist with Add-Member-if-missing pattern
  foreach($pair in @(
    @{Name='TemplateSuffix';            Value=[string]$tbTemplateSuffix.Text},
    @{Name='TargetSuffix';              Value=[string]$tbTargetSuffix.Text},
    @{Name='SkipPasswordValidation';    Value=[bool]$cbSkipPwdVal.Checked},
    @{Name='SyncTemplateFields';        Value=[bool]$chkSyncTemplateFields.Checked},
    @{Name='StopOnError';               Value=[bool]$cbStopOnError.Checked},
    @{Name='ApplyPasswordHistory';      Value=[bool]$cbApplyPwdHistory.Checked}
  )){
    if(-not $Global:Config.Tgt.PSObject.Properties[$pair.Name]){
      $Global:Config.Tgt | Add-Member -NotePropertyName $pair.Name -NotePropertyValue $pair.Value -Force
    } else {
      $Global:Config.Tgt.($pair.Name) = $pair.Value
    }
  }

  # DPAPI store Target password
  if($Global:Config.Auth.StorePassword){
    if($tbTgtPwd -and $tbTgtPwd.Text){
      try{
        $Global:Config.Tgt.PasswordDpapi = ProtectPwd ($tbTgtPwd.Text | ConvertTo-SecureString -AsPlainText -Force)
      } catch {
        Write-Log ("DPAPI store failed for Target password: {0}" -f $_) 'WARN'
      }
    }
  } else {
    try{ $Global:Config.Tgt.PasswordDpapi = "" } catch {}
  }

  # ---------------- Options ----------------
  $Global:Config.Tgt.DuplicateSecretAction = if($rbDupUpdate.Checked) { "Update" } else { "Skip" }

  $Global:Config.ExportFile=$tbExport.Text
  $Global:Config.ExportCsvFile=$tbExportCsv.Text

  # Template Check tab CSV paths
  try {
    $Global:Config | Add-Member -NotePropertyName TemplateCsvPath -NotePropertyValue $tbTemplateCsv.Text -Force
  } catch {
    $Global:Config.TemplateCsvPath = $tbTemplateCsv.Text
  }
  try {
    $Global:Config | Add-Member -NotePropertyName RemapCsvPath -NotePropertyValue $tbRemapCsv.Text -Force
  } catch {
    $Global:Config.RemapCsvPath = $tbRemapCsv.Text
  }
  try {
    $Global:Config | Add-Member -NotePropertyName MappingCsvPath -NotePropertyValue $tbMappingCsv.Text -Force
  } catch {
    $Global:Config.MappingCsvPath = $tbMappingCsv.Text
  }
}

# --- Config browse/save/load ---
$btnCfgBrowse.Add_Click({
  $sfd=New-Object System.Windows.Forms.SaveFileDialog
  $sfd.Filter='JSON files (*.json)|*.json|All files (*.*)|*.*'
  $sfd.FileName=$tbCfgPath.Text
  if($sfd.ShowDialog() -eq 'OK'){
    $tbCfgPath.Text=$sfd.FileName
    $script:ConfigPath=$tbCfgPath.Text
    Write-Log ("Config path set â†’ {0}" -f $script:ConfigPath) 'INFO'
  }
})

$btnSaveCfgTop.Add_Click({
  try{
    ReadControls
    
    # Show confirmation dialog
    $result = [System.Windows.Forms.MessageBox]::Show(
      "Save configuration to:`n`n$($script:ConfigPath)`n`nThis will overwrite the existing file (if any).`n`nDo you want to continue?",
      "Confirm Save Configuration",
      [System.Windows.Forms.MessageBoxButtons]::YesNo,
      [System.Windows.Forms.MessageBoxIcon]::Question
    )
    
    if($result -eq [System.Windows.Forms.DialogResult]::Yes){
      Save-Config $Global:Config
      
      # Show success message
      [System.Windows.Forms.MessageBox]::Show(
        "Configuration saved successfully to:`n`n$($script:ConfigPath)",
        "Save Successful",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
      ) | Out-Null
      
      Write-Log ("Config saved â†’ {0}" -f $script:ConfigPath) 'INFO'
    }
    else{
      Write-Log "Config save cancelled by user." 'INFO'
    }
  } 
  catch {
    # Show error message
    [System.Windows.Forms.MessageBox]::Show(
      "Failed to save configuration:`n`n$($_.Exception.Message)",
      "Save Failed",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    
    Write-Log ("Save config failed: {0}" -f $_) 'ERROR'
  }
})

$btnLoadCfgTop.Add_Click({
  try{
    # Check if file exists
    if(-not (Test-Path $script:ConfigPath)){
      [System.Windows.Forms.MessageBox]::Show(
        "Configuration file not found:`n`n$($script:ConfigPath)`n`nPlease check the path or use Browse to select a valid config file.",
        "File Not Found",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
      ) | Out-Null
      return
    }
    
    # Show confirmation dialog
    $result = [System.Windows.Forms.MessageBox]::Show(
      "Load configuration from:`n`n$($script:ConfigPath)`n`nThis will replace all current settings in the UI.`n`nDo you want to continue?",
      "Confirm Load Configuration",
      [System.Windows.Forms.MessageBoxButtons]::YesNo,
      [System.Windows.Forms.MessageBoxIcon]::Question
    )
    
    if($result -eq [System.Windows.Forms.DialogResult]::Yes){
      ReadControls  # Save any pending UI changes first
      $Global:Config = Load-Config
      Populate $Global:Config
      Apply-Theme 'Ocean'
      Update-SelectionDetails
      Update-SourceTargetEnabledState
      
      # Show success message
      [System.Windows.Forms.MessageBox]::Show(
        "Configuration loaded successfully from:`n`n$($script:ConfigPath)",
        "Load Successful",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
      ) | Out-Null
      
      Write-Log ("Config loaded â†’ {0}" -f $script:ConfigPath) 'INFO'
    }
    else{
      Write-Log "Config load cancelled by user." 'INFO'
    }
  } 
  catch {
    # Show error message
    [System.Windows.Forms.MessageBox]::Show(
      "Failed to load configuration:`n`n$($_.Exception.Message)",
      "Load Failed",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    
    Write-Log ("Load config failed: {0}" -f $_) 'ERROR'
  }
})

# --- Browse buttons for export paths ---
$btnExportBrowse.Add_Click({
  $sfd=New-Object System.Windows.Forms.SaveFileDialog
  $sfd.Filter='JSON files (*.json)|*.json|All files (*.*)|*.*'
  $sfd.FileName=$tbExport.Text
  if($sfd.ShowDialog() -eq 'OK'){
    $tbExport.Text=$sfd.FileName
    Write-Log ("Export JSON path set â†’ {0}" -f $tbExport.Text) 'INFO'
  }
})

$btnExportCsvBrowse.Add_Click({
  $sfd=New-Object System.Windows.Forms.SaveFileDialog
  $sfd.Filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'
  $sfd.FileName=$tbExportCsv.Text
  if($sfd.ShowDialog() -eq 'OK'){
    $tbExportCsv.Text=$sfd.FileName
    Write-Log ("Export CSV path set â†’ {0}" -f $tbExportCsv.Text) 'INFO'
  }
})

# --- Validation helpers (no popups except missing info) ---

# --- Tools tab browse buttons ---
$btnBrowseMapCsv.Add_Click({
  try {
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $ofd.Title = 'Select Map CSV File'
    if ($tbMapCsv.Text -and (Test-Path $tbMapCsv.Text -ErrorAction SilentlyContinue)) {
      $ofd.InitialDirectory = Split-Path -Parent $tbMapCsv.Text
      $ofd.FileName = Split-Path -Leaf $tbMapCsv.Text
    }
    if ($ofd.ShowDialog() -eq 'OK') {
      $tbMapCsv.Text = $ofd.FileName
      $tbToolsLog.AppendText("Map CSV file selected: $($ofd.FileName)`r`n")
    }
  } catch {
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  }
})

$btnGenSampleCsv.Add_Click({
  try {
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $sfd.Title = 'Save Sample Map CSV As...'
    $sfd.FileName = "MapCSV_Sample_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($tbMapCsv.Text -and (Test-Path (Split-Path -Parent $tbMapCsv.Text) -ErrorAction SilentlyContinue)) {
      $sfd.InitialDirectory = Split-Path -Parent $tbMapCsv.Text
    }
    if ($sfd.ShowDialog() -eq 'OK') {
      $sampleData = @(
        [PSCustomObject]@{ OldGroupName = 'Domain Admins'; OldKnownAs = 'Domain Admins'; OldUserName = ''; OldDomainName = 'OLDDOMAIN'; NewGroupName = 'Domain Admins'; NewKnownAs = 'Domain Admins'; NewUserName = ''; NewDomainName = 'NEWDOMAIN' }
        [PSCustomObject]@{ OldGroupName = ''; OldKnownAs = 'jsmith'; OldUserName = 'jsmith'; OldDomainName = 'OLDDOMAIN'; NewGroupName = ''; NewKnownAs = 'john.smith'; NewUserName = 'john.smith'; NewDomainName = 'NEWDOMAIN' }
        [PSCustomObject]@{ OldGroupName = 'SQL-Admins'; OldKnownAs = 'SQL-Admins'; OldUserName = ''; OldDomainName = 'OLDDOMAIN'; NewGroupName = 'SQL-Admins-New'; NewKnownAs = 'SQL-Admins-New'; NewUserName = ''; NewDomainName = 'NEWDOMAIN' }
      )
      $sampleData | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
      $tbMapCsv.Text = $sfd.FileName
      $tbToolsLog.AppendText("Sample Map CSV generated: $($sfd.FileName)`r`n")
      $tbToolsLog.AppendText("  Columns: OldGroupName, OldKnownAs, OldUserName, OldDomainName, NewGroupName, NewKnownAs, NewUserName, NewDomainName`r`n")
      $tbToolsLog.AppendText("  Edit the file to add your actual old-to-new group/account mappings.`r`n")
      [System.Windows.Forms.MessageBox]::Show(
        "Sample Map CSV file created:`n$($sfd.FileName)`n`nEdit the file to replace sample values with your actual group and account mappings.",
        "Sample Generated",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
      )
    }
  } catch {
    [System.Windows.Forms.MessageBox]::Show("Failed to generate sample CSV:`n`n$($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  }
})

$btnBrowsePermsJson.Add_Click({
  try {
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
    $ofd.Title = 'Select Permissions JSON File'
    if ($tbPermsJson.Text -and (Test-Path $tbPermsJson.Text -ErrorAction SilentlyContinue)) {
      $ofd.InitialDirectory = Split-Path -Parent $tbPermsJson.Text
      $ofd.FileName = Split-Path -Leaf $tbPermsJson.Text
    }
    if ($ofd.ShowDialog() -eq 'OK') {
      $tbPermsJson.Text = $ofd.FileName
      $tbToolsLog.AppendText("Permissions JSON file selected: $($ofd.FileName)`r`n")
    }
  } catch {
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  }
})

$btnBrowseOutJson.Add_Click({
  try {
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
    $sfd.Title = 'Save Updated JSON As...'
    if ($tbOutJson.Text) {
      $sfd.FileName = $tbOutJson.Text
    }
    if ($sfd.ShowDialog() -eq 'OK') {
      $tbOutJson.Text = $sfd.FileName
      $tbToolsLog.AppendText("Output JSON path set: $($sfd.FileName)`r`n")
    }
  } catch {
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  }
})

# --- Tools tab Run button ---
$btnRunTools.Add_Click({
  try {
    $tbToolsLog.Clear()
    $tbToolsLog.AppendText("=== Update Permissions JSON from CSV ===`r`n")
    $tbToolsLog.AppendText("Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n`r`n")
    
    # Validate inputs
    $errors = @()
    if ([string]::IsNullOrWhiteSpace($tbMapCsv.Text)) {
      $errors += "Map CSV file is required"
    } elseif (-not (Test-Path $tbMapCsv.Text)) {
      $errors += "Map CSV file not found: $($tbMapCsv.Text)"
    }
    
    if ([string]::IsNullOrWhiteSpace($tbPermsJson.Text)) {
      $errors += "Permissions JSON file is required"
    } elseif (-not (Test-Path $tbPermsJson.Text)) {
      $errors += "Permissions JSON file not found: $($tbPermsJson.Text)"
    }
    
    if ($errors.Count -gt 0) {
      $msg = "Validation errors:`r`n - " + ($errors -join "`r`n - ")
      $tbToolsLog.AppendText("ERROR: $msg`r`n")
      [System.Windows.Forms.MessageBox]::Show($msg, "Validation Error", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error)
      return
    }
    
    # Build argument display for log
    if ($cbToolsDryRun.Checked) {
      $tbToolsLog.AppendText("Mode: DRY RUN (no files will be modified)`r`n")
    } else {
      if ($cbToolsInPlace.Checked) {
        $tbToolsLog.AppendText("Mode: In-Place Update (backup will be created)`r`n")
      } elseif (-not [string]::IsNullOrWhiteSpace($tbOutJson.Text)) {
        $tbToolsLog.AppendText("Output: $($tbOutJson.Text)`r`n")
      }
    }
    
    $tbToolsLog.AppendText("Input CSV: $($tbMapCsv.Text)`r`n")
    $tbToolsLog.AppendText("Input JSON: $($tbPermsJson.Text)`r`n")
    
    # Show file size and estimated time
    $jsonFileSize = (Get-Item $tbPermsJson.Text).Length
    $jsonSizeMB = [math]::Round($jsonFileSize / 1MB, 1)
    $tbToolsLog.AppendText("JSON file size: $jsonSizeMB MB`r`n")
    # Rough estimate: ~50MB/min processing speed based on observed performance
    $estMinutes = [math]::Max(1, [math]::Round($jsonSizeMB / 50, 1))
    $tbToolsLog.AppendText("Estimated time: ~$estMinutes minute(s)`r`n")
    $tbToolsLog.AppendText("`r`nReading JSON file ($jsonSizeMB MB)...`r`n`r`n")
    
    $btnRunTools.Enabled = $false
    $btnRunTools.Text = 'Running...'
    [System.Windows.Forms.Application]::DoEvents()
    
    # --- Inline fast text-based permission update (no object parsing needed) ---
    $startTime = [DateTime]::Now
    try {
      # Step 1: Load CSV mapping
      $tbToolsLog.AppendText("Loading CSV mapping...`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      $csvRows = Import-Csv -Path $tbMapCsv.Text
      $tbToolsLog.AppendText("  Loaded $($csvRows.Count) mapping rows`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      
      # Step 2: Read JSON as raw text (fast - just file I/O)
      $tbToolsLog.AppendText("Reading JSON file ($jsonSizeMB MB) into memory...`r`n")
      $btnRunTools.Text = "Reading file..."
      [System.Windows.Forms.Application]::DoEvents()
      $jsonText = [System.IO.File]::ReadAllText($tbPermsJson.Text, [System.Text.Encoding]::UTF8)
      $elapsed = [DateTime]::Now - $startTime
      $tbToolsLog.AppendText("  File loaded in $([math]::Round($elapsed.TotalSeconds,1))s ($([math]::Round($jsonText.Length/1MB,1)) MB in memory)`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      
      # Step 3: Build and apply replacements using targeted regex per CSV row
      $tbToolsLog.AppendText("`r`nApplying replacements...`r`n")
      $totalChanges = 0
      $rowNum = 0
      
      foreach ($row in $csvRows) {
        $rowNum++
        $rowChanges = 0
        $btnRunTools.Text = "Row $rowNum/$($csvRows.Count)..."
        [System.Windows.Forms.Application]::DoEvents()
        
        # Helper: escape for regex
        $esc = { param($s) [regex]::Escape($s) }
        
        # Helper: build a search pattern from a CSV value that correctly matches JSON raw text
        # Handles: (1) CSV backslash inconsistency (some rows have \ others have \\)
        #          (2) & vs \u0026 in JSON
        $buildSearchPattern = { param($s)
          # Regex-escape the raw CSV value
          $p = [regex]::Escape($s)
          # Make all backslash sequences flexible: match 1 or 2 literal backslashes
          # After regex::Escape, \\ means "match 1 literal backslash", \\\\ means "match 2"
          # Replace any sequence of escaped backslashes with \\{1,2} to handle CSV inconsistency
          $p = [regex]::Replace($p, '(\\\\)+', '\\{1,2}')
          # Handle literal & in CSV matching \u0026 in JSON
          $p = $p -replace '&', '(?:&|\\u0026)'
          $p
        }
        
        # Helper: build a replacement value with proper JSON encoding
        $buildReplacement = { param($s)
          # Only double single backslashes, not already doubled ones
          $r = $s -replace '(?<!\\)\\(?!\\)', '\\\\'
          # Escape $ for regex replacement string
          $r = $r -replace '\$', '$$'
          return $r
        }
        
        # Read all CSV fields upfront so they're available for cross-references
        $oldGN = if ($row.OldGroupName) { $row.OldGroupName.Trim() } else { $null }
        $newGN = if ($row.NewGroupName) { $row.NewGroupName.Trim() } else { $null }
        $oldKA = if ($row.OldKnownAs) { $row.OldKnownAs.Trim() } else { $null }
        $newKA = if ($row.NewKnownAs) { $row.NewKnownAs.Trim() } else { $null }
        $oldUN = if ($row.OldUserName) { $row.OldUserName.Trim() } else { $null }
        $newUN = if ($row.NewUserName) { $row.NewUserName.Trim() } else { $null }
        $oldDN = if ($row.OldDomainName) { $row.OldDomainName.Trim() } else { $null }
        $newDN = if ($row.NewDomainName) { $row.NewDomainName.Trim() } else { $null }
        
        # Replace groupName
        if ($newGN -and $oldGN) {
          $pattern = '("groupName"\s*:\s*")' + (& $buildSearchPattern $oldGN) + '(")'
          $replace = '${1}' + (& $buildReplacement $newGN) + '${2}'
          $jsonText = [regex]::Replace($jsonText, $pattern, $replace)
        }
        
        # Replace knownAs
        if ($oldKA -and $newKA) {
          $pattern = '("knownAs"\s*:\s*")' + (& $buildSearchPattern $oldKA) + '(")'
          $replace = '${1}' + (& $buildReplacement $newKA) + '${2}'
          $jsonText = [regex]::Replace($jsonText, $pattern, $replace)
        }
        
        # Replace userName
        if ($oldUN -and $newUN) {
          $pattern = '("userName"\s*:\s*")' + (& $buildSearchPattern $oldUN) + '(")'
          $replace = '${1}' + (& $buildReplacement $newUN) + '${2}'
          $jsonText = [regex]::Replace($jsonText, $pattern, $replace)
        }
        
        # Replace domainName
        if ($oldDN -and $newDN) {
          $pattern = '("domainName"\s*:\s*")' + (& $buildSearchPattern $oldDN) + '(")'
          $replace = '${1}' + (& $buildReplacement $newDN) + '${2}'
          $jsonText = [regex]::Replace($jsonText, $pattern, $replace)
        }
        
        $elapsed = [DateTime]::Now - $startTime
        $tbToolsLog.AppendText("  Row $rowNum/$($csvRows.Count): $(if($oldGN){$oldGN}elseif($oldKA){$oldKA}else{'(domain only)'}) -> $(if($newGN){$newGN}elseif($newKA){$newKA}else{$newDN}) [$([math]::Floor($elapsed.TotalMinutes))m $($elapsed.Seconds)s elapsed]`r`n")
        [System.Windows.Forms.Application]::DoEvents()
      }
      
      $tbToolsLog.AppendText("`r`nAll $($csvRows.Count) mapping rows applied.`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      
      # Step 4: Write output
      if (-not $cbToolsDryRun.Checked) {
        $outPath = $null
        if ($cbToolsInPlace.Checked) {
          # Create backup
          $bakPath = "$($tbPermsJson.Text).bak"
          $tbToolsLog.AppendText("Creating backup: $bakPath`r`n")
          [System.IO.File]::Copy($tbPermsJson.Text, $bakPath, $true)
          $outPath = $tbPermsJson.Text
        } elseif (-not [string]::IsNullOrWhiteSpace($tbOutJson.Text)) {
          $outPath = $tbOutJson.Text
        } else {
          $outPath = $tbPermsJson.Text -replace '\.json$', '-updated.json'
        }
        
        $tbToolsLog.AppendText("Writing $([math]::Round($jsonText.Length/1MB,1)) MB to: $outPath`r`n")
        $btnRunTools.Text = "Writing file..."
        [System.Windows.Forms.Application]::DoEvents()
        
        $outDir = Split-Path -Parent $outPath
        if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
        [System.IO.File]::WriteAllText($outPath, $jsonText, [System.Text.Encoding]::UTF8)
        $tbToolsLog.AppendText("File saved successfully!`r`n")
      } else {
        $tbToolsLog.AppendText("DRY RUN - no files modified.`r`n")
      }
      
    } catch {
      $tbToolsLog.AppendText("`r`nERROR: $($_.Exception.Message)`r`n$($_.ScriptStackTrace)`r`n")
    }
    
    $totalElapsed = [DateTime]::Now - $startTime
    $btnRunTools.Enabled = $true
    $btnRunTools.Text = 'Run Update'
    
    $tbToolsLog.AppendText("`r`nCompleted in $([math]::Floor($totalElapsed.TotalMinutes))m $($totalElapsed.Seconds)s`r`n")
    
    # Show success message
    if (-not $cbToolsDryRun.Checked) {
      [System.Windows.Forms.MessageBox]::Show(
        "Update completed successfully!`n`nCheck the results log for details.",
        "Success",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
      )
    } else {
      [System.Windows.Forms.MessageBox]::Show(
        "Dry run completed!`n`nNo files were modified. Review the results log to see what would change.",
        "Dry Run Complete",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
      )
    }
    
  } catch {
    $btnRunTools.Enabled = $true
    $btnRunTools.Text = 'Run Update'
    $errorMsg = "Error executing update: $($_.Exception.Message)`r`n$($_.ScriptStackTrace)"
    $tbToolsLog.AppendText("`r`nERROR: $errorMsg`r`n")
    [System.Windows.Forms.MessageBox]::Show(
      "An error occurred:`n`n$($_.Exception.Message)",
      "Error",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    )
  }
})

# --- Tools tab button handlers ---
$btnClearToolsLog.Add_Click({ try { $tbToolsLog.Clear() } catch {} })
$btnCloseTools.Add_Click({ try { $form.Close() } catch {} })

# Export to XML button handler - reads from saved JSON, writes XML
$btnExportXml.Add_Click({
  # Legacy handler - redirects to new Convert to XML
  $btnConvertXml.PerformClick()
})

# Legacy Export to CSV button click handler
$btnExportCsv.Add_Click({
  $btnConvertCsv.PerformClick()
})

# Browse button for Convert JSON file selector
$btnBrowseConvertJson.Add_Click({
  $ofd = New-Object System.Windows.Forms.OpenFileDialog
  $ofd.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
  $ofd.Title = 'Select Exported JSON File'
  if($tbConvertJson.Text -and (Test-Path (Split-Path -Parent $tbConvertJson.Text) -ErrorAction SilentlyContinue)){
    $ofd.InitialDirectory = Split-Path -Parent $tbConvertJson.Text
  }
  if($ofd.ShowDialog() -eq 'OK'){
    $tbConvertJson.Text = $ofd.FileName
  }
})

# Convert to XML button click handler
$btnConvertXml.Add_Click({
  try {
    $lblConvertStatus.ForeColor = [System.Drawing.Color]::DarkBlue
    $lblConvertStatus.Text = 'Converting to XML...'
    [System.Windows.Forms.Application]::DoEvents()

    $tbToolsLog.Clear()
    $tbToolsLog.AppendText("=== Convert JSON to XML (Delinea Web Import) ===`r`n")
    $tbToolsLog.AppendText("Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n`r`n")

    $jsonPath = $tbConvertJson.Text
    if([string]::IsNullOrWhiteSpace($jsonPath) -or -not (Test-Path $jsonPath)){
      $msg = "JSON file not found: $jsonPath`r`nBrowse and select a valid exported JSON file."
      $tbToolsLog.AppendText("ERROR: $msg`r`n")
      $lblConvertStatus.ForeColor = [System.Drawing.Color]::Red
      $lblConvertStatus.Text = 'ERROR: JSON file not found'
      [System.Windows.Forms.MessageBox]::Show($msg, "JSON Not Found", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
      return
    }

    $xmlPath = $jsonPath -replace '\.json$', '.xml'
    $tbToolsLog.AppendText("Input JSON: $jsonPath`r`n")
    $tbToolsLog.AppendText("Output XML: $xmlPath`r`n`r`n")
    $tbToolsLog.AppendText("Processing...`r`n")
    [System.Windows.Forms.Application]::DoEvents()

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Export-SecretsJsonToDelineaImportXml -InputJsonPath $jsonPath -OutXmlPath $xmlPath -IncludeFolders -IncludePermissions
    $sw.Stop()

    $tbToolsLog.AppendText("`r`n[OK] XML conversion complete in $($sw.Elapsed.ToString('mm\:ss'))!`r`n")
    $tbToolsLog.AppendText("Output: $xmlPath`r`n")
    $lblConvertStatus.ForeColor = [System.Drawing.Color]::DarkGreen
    $lblConvertStatus.Text = "Done! XML saved: $(Split-Path $xmlPath -Leaf)"
    Write-Log ("[OK] Tools: XML convert complete: {0} ({1}s)" -f $xmlPath, [int]$sw.Elapsed.TotalSeconds) 'INFO'
  }
  catch {
    $tbToolsLog.AppendText("`r`nERROR: $($_.Exception.Message)`r`n")
    $lblConvertStatus.ForeColor = [System.Drawing.Color]::Red
    $lblConvertStatus.Text = "ERROR: $($_.Exception.Message)"
    Write-Log ("Tools XML convert failed: {0}" -f $_.Exception.Message) 'ERROR'
  }
})

# Convert to CSV button click handler
$btnConvertCsv.Add_Click({
  try {
    $lblConvertStatus.ForeColor = [System.Drawing.Color]::DarkBlue
    $lblConvertStatus.Text = 'Converting to CSV bundle...'
    [System.Windows.Forms.Application]::DoEvents()

    $tbToolsLog.Clear()
    $tbToolsLog.AppendText("=== Convert JSON to CSV Bundle ===`r`n")
    $tbToolsLog.AppendText("Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n`r`n")

    $jsonPath = $tbConvertJson.Text
    if([string]::IsNullOrWhiteSpace($jsonPath) -or -not (Test-Path $jsonPath)){
      $msg = "JSON file not found: $jsonPath`r`nBrowse and select a valid exported JSON file."
      $tbToolsLog.AppendText("ERROR: $msg`r`n")
      $lblConvertStatus.ForeColor = [System.Drawing.Color]::Red
      $lblConvertStatus.Text = 'ERROR: JSON file not found'
      [System.Windows.Forms.MessageBox]::Show($msg, "JSON Not Found", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
      return
    }

    $csvOutDir = Join-Path (Split-Path $jsonPath -Parent) "csv-bundle"
    $tbToolsLog.AppendText("Input JSON: $jsonPath`r`n")
    $tbToolsLog.AppendText("Output Dir: $csvOutDir`r`n`r`n")
    $tbToolsLog.AppendText("Processing...`r`n")
    [System.Windows.Forms.Application]::DoEvents()

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Export-SecretsJsonToCsvBundle -InputJsonPath $jsonPath -OutDir $csvOutDir
    $sw.Stop()

    $tbToolsLog.AppendText("`r`n[OK] CSV bundle complete in $($sw.Elapsed.ToString('mm\:ss'))!`r`n")
    $tbToolsLog.AppendText("Output directory: $csvOutDir`r`n")
    $tbToolsLog.AppendText("Files: secrets.csv, secret_items.csv, secret_permissions.csv, folder_permissions.csv, secret_settings.csv, attachments.csv`r`n")
    if($result.counts){
      $tbToolsLog.AppendText(("Counts: secrets={0}, items={1}, secretPerms={2}, folderPerms={3}, settings={4}, attachments={5}`r`n" -f `
        $result.counts.secrets, $result.counts.items, $result.counts.secretPermissions, $result.counts.folderPermissions, $result.counts.secretSettings, $result.counts.attachments))
    }
    $lblConvertStatus.ForeColor = [System.Drawing.Color]::DarkGreen
    $lblConvertStatus.Text = "Done! CSV bundle in: csv-bundle/"
    Write-Log ("[OK] Tools: CSV bundle complete: {0} ({1}s)" -f $csvOutDir, [int]$sw.Elapsed.TotalSeconds) 'INFO'
  }
  catch {
    $tbToolsLog.AppendText("`r`nERROR: $($_.Exception.Message)`r`n")
    $lblConvertStatus.ForeColor = [System.Drawing.Color]::Red
    $lblConvertStatus.Text = "ERROR: $($_.Exception.Message)"
    Write-Log ("Tools CSV convert failed: {0}" -f $_.Exception.Message) 'ERROR'
  }
})

# --- Template Check Tab Event Handlers ---
$btnBrowseTemplateCsv.Add_Click({
  try {
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $sfd.Title = 'Save Template Comparison CSV As...'
    $sfd.FileName = "SecretTemplateComparison_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($tbTemplateCsv.Text -and (Test-Path (Split-Path -Parent $tbTemplateCsv.Text) -ErrorAction SilentlyContinue)) {
      $sfd.InitialDirectory = Split-Path -Parent $tbTemplateCsv.Text
    }
    if ($sfd.ShowDialog() -eq 'OK') {
      $tbTemplateCsv.Text = $sfd.FileName
      $tbTemplateLog.AppendText("Output CSV path set: $($sfd.FileName)`r`n")
    }
  } catch {
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  }
})

$btnCompareTemplates.Add_Click({
  try {
    $tbTemplateLog.Clear()
    $tbTemplateLog.AppendText("=== Secret Template Comparison ===`r`n")
    $tbTemplateLog.AppendText("Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n`r`n")
    
    # Read config from UI
    ReadControls
    
    # Validate source and target credentials
    $missing = @()
    if([string]::IsNullOrWhiteSpace($Global:Config.Src.SSApiBase)){ $missing += 'Source API Base' }
    if([string]::IsNullOrWhiteSpace($Global:Config.Src.TenantBase)){ $missing += 'Source Tenant Base' }
    if([string]::IsNullOrWhiteSpace($Global:Config.Src.Username)){ $missing += 'Source Username' }
    if([string]::IsNullOrWhiteSpace($Global:Config.Tgt.SSApiBase)){ $missing += 'Target API Base' }
    if([string]::IsNullOrWhiteSpace($Global:Config.Tgt.TenantBase)){ $missing += 'Target Tenant Base' }
    if([string]::IsNullOrWhiteSpace($Global:Config.Tgt.Username)){ $missing += 'Target Username' }
    
    if ($missing.Count -gt 0) {
      $msg = "Missing required fields:`r`n - " + ($missing -join "`r`n - ")
      $tbTemplateLog.AppendText("ERROR: $msg`r`n")
      [System.Windows.Forms.MessageBox]::Show($msg, "Validation Error", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error)
      return
    }
    
    # Validate output path
    if ([string]::IsNullOrWhiteSpace($tbTemplateCsv.Text)) {
      $tbTemplateCsv.Text = (Join-Path $BaseDir "SecretTemplateComparison_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
    }
    
    $outputPath = $tbTemplateCsv.Text
    $tbTemplateLog.AppendText("Output CSV: $outputPath`r`n`r`n")
    
    # Disable buttons during processing
    $btnCompareTemplates.Enabled = $false
    $btnOpenTemplateCsv.Enabled = $false
    $templateCheckPanel.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $templateCheckPanel.UseWaitCursor = $true
    
    try {
      # Get source token
      $tbTemplateLog.AppendText("Authenticating to Source tenant...`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      $srcTok = Token 'Src' $tbSrcPwd
      if ([string]::IsNullOrWhiteSpace($srcTok)) {
        throw "Failed to authenticate to Source tenant"
      }
      $tbTemplateLog.AppendText("  ✓ Source authentication successful`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      
      # Get target token
      $tbTemplateLog.AppendText("Authenticating to Target tenant...`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      $tgtTok = Token 'Tgt' $tbTgtPwd
      if ([string]::IsNullOrWhiteSpace($tgtTok)) {
        throw "Failed to authenticate to Target tenant"
      }
      $tbTemplateLog.AppendText("  ✓ Target authentication successful`r`n`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      
      # Get source templates
      $tbTemplateLog.AppendText("Retrieving Source templates...`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      $srcTemplates = Get-AllSecretTemplatesDetailed -apiBase $Global:Config.Src.SSApiBase -tok $srcTok
      $tbTemplateLog.AppendText("  ✓ Retrieved $($srcTemplates.Count) active templates from Source`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      
      # Filter source templates to only those that have at least one secret (parallel HTTP)
      $tbTemplateLog.AppendText("Filtering templates that have secrets (parallel check)...`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      $srcTemplatesWithSecrets = @()
      
      try{
        $srcBaseUri = $Global:Config.Src.SSApiBase.TrimEnd('/')
        $hndl = New-Object System.Net.Http.HttpClientHandler
        $hndl.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
        $httpCli = New-Object System.Net.Http.HttpClient($hndl)
        $httpCli.Timeout = [TimeSpan]::FromSeconds(60)
        $httpCli.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer',$srcTok)
        $httpCli.DefaultRequestHeaders.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('application/json'))
        
        $batchSz = 15
        for($bi = 0; $bi -lt $srcTemplates.Count; $bi += $batchSz){
          $batch = $srcTemplates[$bi..([Math]::Min($bi + $batchSz - 1, $srcTemplates.Count - 1))]
          $taskList = @()
          
          foreach($tmpl in $batch){
            $tmplId = Get-PropValue $tmpl @('id','Id') $null
            if($tmplId){
              $url = "$srcBaseUri/secrets/lookup?filter.secretTemplateId=$tmplId&take=1"
              $taskList += @{ Template = $tmpl; Id = $tmplId; Task = $httpCli.GetAsync($url) }
            }
          }
          
          try{
            [System.Threading.Tasks.Task]::WaitAll(($taskList | ForEach-Object { $_.Task }), 30000) | Out-Null
          } catch {}
          
          foreach($t in $taskList){
            try{
              $resp = $t.Task.Result
              if($resp.IsSuccessStatusCode){
                $jsonStr = $resp.Content.ReadAsStringAsync().Result
                $parsed = $jsonStr | ConvertFrom-Json
                $recs = @(Get-Records $parsed)
                if($recs.Count -gt 0){
                  $srcTemplatesWithSecrets += $t.Template
                } else {
                  $tmplName = Get-PropValue $t.Template @('name','Name') 'Unknown'
                  $tbTemplateLog.AppendText("  Skipping template '$tmplName' (ID: $($t.Id)) - no secrets`r`n")
                }
              } else {
                # If check fails, include to be safe
                $srcTemplatesWithSecrets += $t.Template
              }
            } catch {
              $srcTemplatesWithSecrets += $t.Template
              $tmplName = Get-PropValue $t.Template @('name','Name') 'Unknown'
              $tbTemplateLog.AppendText("  Warning: Could not check secrets for '$tmplName' (ID: $($t.Id)), including anyway`r`n")
            }
          }
          [System.Windows.Forms.Application]::DoEvents()
        }
        
        $httpCli.Dispose()
        $hndl.Dispose()
      }
      catch{
        Write-Log ("Parallel template filter failed: {0}. Falling back to sequential." -f $_.Exception.Message) 'WARN'
        # Fallback: sequential check
        $srcTemplatesWithSecrets = @()
        foreach ($tmpl in $srcTemplates) {
          $tmplId = Get-PropValue $tmpl @('id','Id') $null
          $tmplName = Get-PropValue $tmpl @('name','Name') 'Unknown'
          if ($tmplId) {
            try {
              $q = @{ 'filter.secretTemplateId' = $tmplId; 'take' = 1 }
              $resp = SS $Global:Config.Src.SSApiBase GET 'secrets/lookup' $srcTok $null $q
              $recs = @(Get-Records $resp)
              if ($recs.Count -gt 0) {
                $srcTemplatesWithSecrets += $tmpl
              } else {
                $tbTemplateLog.AppendText("  Skipping template '$tmplName' (ID: $tmplId) - no secrets`r`n")
              }
            } catch {
              $srcTemplatesWithSecrets += $tmpl
            }
          }
          [System.Windows.Forms.Application]::DoEvents()
        }
      }
      
      $tbTemplateLog.AppendText("  ✓ $($srcTemplatesWithSecrets.Count) of $($srcTemplates.Count) templates have secrets`r`n`r`n")
      $srcTemplates = $srcTemplatesWithSecrets
      
      # Get target templates
      $tbTemplateLog.AppendText("Retrieving Target templates...`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      $tgtTemplates = Get-AllSecretTemplatesDetailed -apiBase $Global:Config.Tgt.SSApiBase -tok $tgtTok
      $tbTemplateLog.AppendText("  ✓ Retrieved $($tgtTemplates.Count) templates from Target`r`n`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      
      # Compare templates
      $tbTemplateLog.AppendText("Comparing templates...`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      $comparison = Compare-SecretTemplates -SourceTemplates $srcTemplates -TargetTemplates $tgtTemplates
      [System.Windows.Forms.Application]::DoEvents()
      
      # List all target template names for reference
      $tbTemplateLog.AppendText("`r`n--- All Target Template Names ---`r`n")
      foreach ($t in $tgtTemplates) {
        $tName = Get-PropValue $t @('name','Name') 'Unknown'
        $tId = Get-PropValue $t @('id','Id') '?'
        $tbTemplateLog.AppendText("  [$tId] $tName`r`n")
      }
      $tbTemplateLog.AppendText("--- End Target Templates ---`r`n`r`n")
      
      # Build field mappings for the mapping UI
      $tbTemplateLog.AppendText("Building field mappings...`r`n")
      [System.Windows.Forms.Application]::DoEvents()
      $targetSuffix = $tbTargetSuffix.Text
      if ([string]::IsNullOrWhiteSpace($targetSuffix)) { $targetSuffix = '' }
      $tbTemplateLog.AppendText("  Using target suffix for matching: '$targetSuffix'`r`n")
      $fieldMappings = @(Build-FieldMappingsFromComparison -ComparisonData $comparison -SourceTemplates $srcTemplates -TargetTemplates $tgtTemplates -TargetSuffix $targetSuffix)
      [System.Windows.Forms.Application]::DoEvents()
      $Global:CurrentFieldMappings = $fieldMappings
      
      # Populate DataGridView with field mappings
      $dgvFieldMappings.SuspendLayout()
      $dgvFieldMappings.Rows.Clear()
      
      foreach ($mapping in $fieldMappings) {
        $targetTemplateName = if ($mapping.TargetTemplateName) { $mapping.TargetTemplateName } else { '' }
        $targetTemplateId = if ($mapping.TargetTemplateId) { $mapping.TargetTemplateId } else { '' }
        
        # Add one row per template (simplified view for CSV export)
        $row = $dgvFieldMappings.Rows.Add()
        $dgvFieldMappings.Rows[$row].Cells['Enabled'].Value = $mapping.Enabled
        $dgvFieldMappings.Rows[$row].Cells['Template'].Value = $mapping.TemplateName
        $dgvFieldMappings.Rows[$row].Cells['SourceId'].Value = $mapping.SourceTemplateId
        $dgvFieldMappings.Rows[$row].Cells['TargetTemplate'].Value = $targetTemplateName
        $dgvFieldMappings.Rows[$row].Cells['TargetId'].Value = $targetTemplateId
        
        # Show field count as summary (safely handle arrays)
        $fieldMappingArray = @($mapping.FieldMappings)
        $fieldCount = $fieldMappingArray.Count
        $matchedCount = @($fieldMappingArray | Where-Object { $_.AutoMatched }).Count
        $dgvFieldMappings.Rows[$row].Cells['SourceField'].Value = "$matchedCount/$fieldCount fields"
        
        # Status should align with Enabled state (inverse relationship)
        # ✓ = Perfect match, no remapping needed (NOT enabled/checked)
        # ✗ = Needs remapping (IS enabled/checked)
        $dgvFieldMappings.Rows[$row].Cells['Status'].Value = if ($mapping.Enabled) { "✗" } else { "✓" }
        
        # Log mapping data for debugging
        if ([string]::IsNullOrWhiteSpace($targetTemplateName)) {
          $tbTemplateLog.AppendText("  ⚠ Row $($row): '$($mapping.TemplateName)' (Source ID: $($mapping.SourceTemplateId)) -> NO TARGET MATCH`r`n")
        } else {
          $tbTemplateLog.AppendText("  Row $($row): '$($mapping.TemplateName)' -> Target: '$targetTemplateName' (ID: $targetTemplateId)`r`n")
        }
      }
      
      # Force grid to properly commit and render all rows including the last one
      $dgvFieldMappings.CurrentCell = $null
      $dgvFieldMappings.ClearSelection()
      $dgvFieldMappings.ResumeLayout()
      $dgvFieldMappings.Refresh()
      
      # Enable save mappings button
      $btnSaveMappings.Enabled = ($fieldMappings.Count -gt 0)
      
      if ($fieldMappings.Count -gt 0) {
        $tbTemplateLog.AppendText("  ✓ Generated $($fieldMappings.Count) template mappings`r`n")
        $tbTemplateLog.AppendText("  → Use 'Save to CSV' button in the right panel to export mappings`r`n")
      }
      
      # Display summary
      $tbTemplateLog.AppendText("`r`n=== COMPARISON SUMMARY ===`r`n")
      $tbTemplateLog.AppendText("Source Templates: $($comparison.Summary.SourceTemplateCount)`r`n")
      $tbTemplateLog.AppendText("Target Templates: $($comparison.Summary.TargetTemplateCount)`r`n")
      $tbTemplateLog.AppendText("Matching by Name: $($comparison.Summary.MatchingByName)`r`n")
      $tbTemplateLog.AppendText("Missing in Target: $($comparison.Summary.MissingInTarget)`r`n")
      $tbTemplateLog.AppendText("Only in Target: $($comparison.Summary.OnlyInTarget)`r`n")
      $tbTemplateLog.AppendText("Different Settings/Fields: $($comparison.Summary.DifferentSettings)`r`n`r`n")
      
      # Show details for templates with differences
      $templatesWithIssues = $comparison.Details | Where-Object { 
        $_.Status -ne "Exists in both" -or $_.Differences.Count -gt 0 
      }
      
      if ($templatesWithIssues.Count -gt 0) {
        $tbTemplateLog.AppendText("=== TEMPLATES WITH DIFFERENCES ===`r`n")
        foreach ($tmpl in $templatesWithIssues) {
          $tbTemplateLog.AppendText("`r`nTemplate: $($tmpl.TemplateName)`r`n")
          $tbTemplateLog.AppendText("  Status: $($tmpl.Status)`r`n")
          $tbTemplateLog.AppendText("  Source ID: $($tmpl.SourceId)`r`n")
          $tbTemplateLog.AppendText("  Target ID: $($tmpl.TargetId)`r`n")
          if ($tmpl.Differences.Count -gt 0) {
            if ($tmpl.Status -eq "Missing in target") {
              $tbTemplateLog.AppendText("  Source Template Settings:`r`n")
            } elseif ($tmpl.Status -eq "Only in target") {
              $tbTemplateLog.AppendText("  Target Template Settings:`r`n")
            } else {
              $tbTemplateLog.AppendText("  Differences:`r`n")
            }
            foreach ($diff in $tmpl.Differences) {
              $tbTemplateLog.AppendText("    - $diff`r`n")
            }
          }
        }
      } else {
        $tbTemplateLog.AppendText("✓ All templates match! No differences found.`r`n")
      }
      
      # Save to CSV
      $tbTemplateLog.AppendText("`r`nSaving comparison report to CSV...`r`n")
      Export-SecretTemplateComparisonToCsv -ComparisonData $comparison -CsvPath $outputPath
      $tbTemplateLog.AppendText("  ✓ Saved to: $outputPath`r`n")
      
      # Enable Open CSV button
      $btnOpenTemplateCsv.Enabled = $true
      
      $tbTemplateLog.AppendText("`r`nCompleted: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n")
      
      # Show success message
      $summaryMsg = "Template comparison completed!`n`n"
      $summaryMsg += "Source Templates: $($comparison.Summary.SourceTemplateCount)`n"
      $summaryMsg += "Target Templates: $($comparison.Summary.TargetTemplateCount)`n"
      $summaryMsg += "Matching by Name: $($comparison.Summary.MatchingByName)`n"
      $summaryMsg += "Missing in Target: $($comparison.Summary.MissingInTarget)`n"
      $summaryMsg += "Only in Target: $($comparison.Summary.OnlyInTarget)`n"
      $summaryMsg += "Different Settings/Fields: $($comparison.Summary.DifferentSettings)`n`n"
      $summaryMsg += "Report saved to:`n$outputPath`n`n"
      if ($fieldMappings.Count -gt 0) {
        $summaryMsg += "✓ Template mappings generated! Next steps:`n"
        $summaryMsg += "  1. Review mappings in the right panel`n"
        $summaryMsg += "  2. Use checkboxes to select templates`n"
        $summaryMsg += "  3. Click 'Save to CSV' to export`n"
        $summaryMsg += "  4. Use the CSV in Template Remapping Tool below"
      }
      
      [System.Windows.Forms.MessageBox]::Show(
        $summaryMsg,
        "Comparison Complete",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
      )
      
    } finally {
      # Re-enable buttons
      $btnCompareTemplates.Enabled = $true
      $templateCheckPanel.UseWaitCursor = $false
      $templateCheckPanel.Cursor = [System.Windows.Forms.Cursors]::Default
    }
    
  } catch {
    $errorMsg = "Error during template comparison: $($_.Exception.Message)`r`n$($_.ScriptStackTrace)"
    $tbTemplateLog.AppendText("`r`nERROR: $errorMsg`r`n")
    
    # Re-enable buttons
    $btnCompareTemplates.Enabled = $true
    $templateCheckPanel.UseWaitCursor = $false
    $templateCheckPanel.Cursor = [System.Windows.Forms.Cursors]::Default
    
    [System.Windows.Forms.MessageBox]::Show(
      "An error occurred during template comparison:`n`n$($_.Exception.Message)",
      "Error",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    )
  }
})

$btnOpenTemplateCsv.Add_Click({
  try {
    $csvPath = $tbTemplateCsv.Text
    if ([string]::IsNullOrWhiteSpace($csvPath) -or -not (Test-Path $csvPath)) {
      [System.Windows.Forms.MessageBox]::Show(
        "CSV file not found. Please run the comparison first.",
        "File Not Found",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
      )
      return
    }
    
    # Open CSV file with default application
    Start-Process $csvPath
    $tbTemplateLog.AppendText("Opened CSV file: $csvPath`r`n")
    
  } catch {
    $tbTemplateLog.AppendText("Error opening CSV file: $($_.Exception.Message)`r`n")
    [System.Windows.Forms.MessageBox]::Show(
      "Failed to open CSV file:`n`n$($_.Exception.Message)",
      "Error",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    )
  }
})

$btnClearTemplateLog.Add_Click({ try { $tbTemplateLog.Clear() } catch {} })

$btnCloseTemplateCheck.Add_Click({ try { $form.Close() } catch {} })

# ====================================================================
# Field Mapping Event Handlers
# ====================================================================

$btnSaveMappings.Add_Click({
  try {
    if ($dgvFieldMappings.Rows.Count -eq 0) {
      [System.Windows.Forms.MessageBox]::Show(
        "No template mappings to save. Run Compare Templates first.",
        "No Mappings",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
      )
      return
    }
    
    # Update enabled status from DataGridView
    # Group by template name since we have multiple rows per template
    $templateEnabledMap = @{}
    for ($i = 0; $i -lt $dgvFieldMappings.Rows.Count; $i++) {
      $row = $dgvFieldMappings.Rows[$i]
      $templateName = $row.Cells['Template'].Value
      $enabled = [bool]$row.Cells['Enabled'].Value
      
      # Track if any row for this template is enabled (OR logic)
      # You could also use AND logic if you want all fields to be checked
      if (-not $templateEnabledMap.ContainsKey($templateName)) {
        $templateEnabledMap[$templateName] = $enabled
      } elseif ($enabled) {
        $templateEnabledMap[$templateName] = $true
      }
    }
    
    # Apply to mappings
    foreach ($mapping in $Global:CurrentFieldMappings) {
      if ($templateEnabledMap.ContainsKey($mapping.TemplateName)) {
        $mapping.Enabled = $templateEnabledMap[$mapping.TemplateName]
      }
    }
    
    $csvPath = $tbMappingCsv.Text
    if ([string]::IsNullOrWhiteSpace($csvPath)) {
      $csvPath = Join-Path $BaseDir "TemplateMappings_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
      $tbMappingCsv.Text = $csvPath
    }
    
    $result = Export-TemplateMappingsToCsv -FieldMappings $Global:CurrentFieldMappings -CsvPath $csvPath
    
    if ($result.Count -gt 0) {
      $tbTemplateLog.AppendText("`r`nTemplate mappings saved to CSV: $csvPath`r`n")
      $tbTemplateLog.AppendText("Total enabled mappings: $($result.Count)`r`n")
      
      # Show warning if any IDs are missing
      if ($result.MissingIds.Count -gt 0) {
        $tbTemplateLog.AppendText("`r`nWARNING: $($result.MissingIds.Count) template(s) missing Target ID:`r`n")
        foreach ($tmpl in $result.MissingIds) {
          $tbTemplateLog.AppendText("  - $tmpl`r`n")
        }
        $tbTemplateLog.AppendText("`r`nThese templates were not found in the target environment.`r`n")
      }
      
      # Auto-populate the remapping tool CSV field
      $tbRemapCsv.Text = $csvPath
      
      $successMsg = "Template mappings saved successfully to:`n$csvPath`n`nTotal: $($result.Count) templates`n`n💡 This CSV has been auto-filled in the Template Remapping Tool below."
      
      if ($result.MissingIds.Count -gt 0) {
        $successMsg += "`n`n⚠ Warning: $($result.MissingIds.Count) template(s) missing Target ID.`nCheck the log for details."
      }
      
      # Determine icon based on whether there are missing IDs
      $msgIcon = if ($result.MissingIds.Count -gt 0) { 
        [System.Windows.Forms.MessageBoxIcon]::Warning 
      } else { 
        [System.Windows.Forms.MessageBoxIcon]::Information 
      }
      
      [System.Windows.Forms.MessageBox]::Show(
        $successMsg,
        "Mappings Saved",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        $msgIcon
      )
    } else {
      [System.Windows.Forms.MessageBox]::Show(
        "No enabled template mappings to save.`n`nUse the checkboxes in the grid to enable templates.",
        "No Enabled Mappings",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
      )
    }
    
  } catch {
    $tbTemplateLog.AppendText("`r`nError saving template mappings: $($_.Exception.Message)`r`n")
    [System.Windows.Forms.MessageBox]::Show(
      "Failed to save template mappings:`n`n$($_.Exception.Message)",
      "Error",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    )
  }
})

$btnLoadMappings.Add_Click({
  try {
    $csvPath = $tbMappingCsv.Text
    if ([string]::IsNullOrWhiteSpace($csvPath) -or -not (Test-Path $csvPath)) {
      $ofd = New-Object System.Windows.Forms.OpenFileDialog
      $ofd.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
      $ofd.Title = 'Select Template Mapping CSV File'
      if ($ofd.ShowDialog() -ne 'OK') { return }
      $csvPath = $ofd.FileName
      $tbMappingCsv.Text = $csvPath
    }
    
    $mappings = Import-TemplateMappingsFromCsv -CsvPath $csvPath
    if ($mappings.Count -eq 0) {
      [System.Windows.Forms.MessageBox]::Show(
        "No template mappings found in the selected CSV file.",
        "No Mappings",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
      )
      return
    }
    
    $Global:CurrentFieldMappings = $mappings
    
    # Populate DataGridView
    $dgvFieldMappings.Rows.Clear()
    
    foreach ($mapping in $mappings) {
      $targetTemplateName = if ($mapping.TargetTemplateName) { $mapping.TargetTemplateName } else { $mapping.TemplateName }
      
      # Add one row per template (not per field)
      $row = $dgvFieldMappings.Rows.Add()
      $dgvFieldMappings.Rows[$row].Cells['Enabled'].Value = $mapping.Enabled
      $dgvFieldMappings.Rows[$row].Cells['Template'].Value = $mapping.TemplateName
      $dgvFieldMappings.Rows[$row].Cells['SourceId'].Value = $mapping.SourceTemplateId
      $dgvFieldMappings.Rows[$row].Cells['TargetTemplate'].Value = $targetTemplateName
      $dgvFieldMappings.Rows[$row].Cells['TargetId'].Value = $mapping.TargetTemplateId
      $dgvFieldMappings.Rows[$row].Cells['SourceField'].Value = "Template Mapping"
      $dgvFieldMappings.Rows[$row].Cells['Status'].Value = "✓"
    }
    
    $btnSaveMappings.Enabled = $true
    
    $tbTemplateLog.AppendText("`r`nTemplate mappings loaded from CSV: $csvPath`r`n")
    $tbTemplateLog.AppendText("Total mappings: $($mappings.Count)`r`n")
    
    [System.Windows.Forms.MessageBox]::Show(
      "Template mappings loaded successfully from:`n$csvPath`n`nTotal: $($mappings.Count) templates",
      "Mappings Loaded",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Information
    )
    
  } catch {
    $tbTemplateLog.AppendText("`r`nError loading template mappings: $($_.Exception.Message)`r`n")
    [System.Windows.Forms.MessageBox]::Show(
      "Failed to load template mappings:`n`n$($_.Exception.Message)",
      "Error",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    )
  }
})

$btnClearMappings.Add_Click({
  try {
    $dgvFieldMappings.Rows.Clear()
    $Global:CurrentFieldMappings = @()
    $btnSaveMappings.Enabled = $false
    $tbTemplateLog.AppendText("`r`nField mappings cleared.`r`n")
  } catch {}
})

$btnBrowseMappingCsv.Add_Click({
  try {
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $sfd.Title = 'Select Template Mapping CSV File'
    $sfd.DefaultExt = 'csv'
    if ($tbMappingCsv.Text -and (Test-Path (Split-Path -Parent $tbMappingCsv.Text) -ErrorAction SilentlyContinue)) {
      $sfd.InitialDirectory = Split-Path -Parent $tbMappingCsv.Text
      $sfd.FileName = Split-Path -Leaf $tbMappingCsv.Text
    }
    if ($sfd.ShowDialog() -eq 'OK') {
      $tbMappingCsv.Text = $sfd.FileName
    }
  } catch {
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  }
})

# ====================================================================
# Template Remapping Event Handlers
# ====================================================================

$btnBrowseRemapCsv.Add_Click({
  try {
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $ofd.Title = 'Select Template Mapping CSV File'
    if ($tbRemapCsv.Text -and (Test-Path (Split-Path -Parent $tbRemapCsv.Text) -ErrorAction SilentlyContinue)) {
      $ofd.InitialDirectory = Split-Path -Parent $tbRemapCsv.Text
    }
    if ($ofd.ShowDialog() -eq 'OK') {
      $tbRemapCsv.Text = $ofd.FileName
      $tbRemapLog.AppendText("Mapping CSV selected: $($ofd.FileName)`r`n")
    }
  } catch {
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  }
})

$btnBrowseRemapSourceJson.Add_Click({
  try {
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
    $ofd.Title = 'Select Source JSON Export File'
    if ($tbRemapSourceJson.Text -and (Test-Path (Split-Path -Parent $tbRemapSourceJson.Text) -ErrorAction SilentlyContinue)) {
      $ofd.InitialDirectory = Split-Path -Parent $tbRemapSourceJson.Text
    }
    if ($ofd.ShowDialog() -eq 'OK') {
      $tbRemapSourceJson.Text = $ofd.FileName
      $tbRemapLog.AppendText("Source JSON selected: $($ofd.FileName)`r`n")
      # Auto-suggest output path
      if ([string]::IsNullOrWhiteSpace($tbRemapOutputJson.Text)) {
        $dir = Split-Path -Parent $ofd.FileName
        $name = [System.IO.Path]::GetFileNameWithoutExtension($ofd.FileName)
        $tbRemapOutputJson.Text = Join-Path $dir "$name`_remapped.json"
      }
    }
  } catch {
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  }
})

$btnBrowseRemapOutputJson.Add_Click({
  try {
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
    $sfd.Title = 'Save Remapped JSON As...'
    if ($tbRemapOutputJson.Text) {
      $sfd.FileName = $tbRemapOutputJson.Text
      if (Test-Path (Split-Path -Parent $tbRemapOutputJson.Text) -ErrorAction SilentlyContinue) {
        $sfd.InitialDirectory = Split-Path -Parent $tbRemapOutputJson.Text
      }
    }
    if ($sfd.ShowDialog() -eq 'OK') {
      $tbRemapOutputJson.Text = $sfd.FileName
      $tbRemapLog.AppendText("Output JSON path set: $($sfd.FileName)`r`n")
    }
  } catch {
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  }
})

$btnOpenRemapJson.Add_Click({
  try {
    if ($tbRemapOutputJson.Text -and (Test-Path $tbRemapOutputJson.Text -ErrorAction SilentlyContinue)) {
      Start-Process "notepad.exe" -ArgumentList "`"$($tbRemapOutputJson.Text)`""
    }
  } catch {
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  }
})

$btnRemapTemplates.Add_Click({
  try {
    $tbRemapLog.Clear()
    $tbRemapLog.AppendText("=== Template Remapping ===`r`n")
    $tbRemapLog.AppendText("Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n`r`n")
    
    # Validate inputs
    $missing = @()
    if ([string]::IsNullOrWhiteSpace($tbRemapCsv.Text)) { $missing += 'Mapping CSV file' }
    if ([string]::IsNullOrWhiteSpace($tbRemapSourceJson.Text)) { $missing += 'Source JSON file' }
    if ([string]::IsNullOrWhiteSpace($tbRemapOutputJson.Text)) { $missing += 'Output JSON path' }
    
    if ($missing.Count -gt 0) {
      $msg = "Missing required fields:`r`n - " + ($missing -join "`r`n - ")
      $tbRemapLog.AppendText("ERROR: $msg`r`n")
      [System.Windows.Forms.MessageBox]::Show($msg, "Validation Error", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error)
      return
    }
    
    # Validate files exist
    if (-not (Test-Path $tbRemapCsv.Text)) {
      $msg = "Mapping CSV file not found: $($tbRemapCsv.Text)"
      $tbRemapLog.AppendText("ERROR: $msg`r`n")
      [System.Windows.Forms.MessageBox]::Show($msg, "File Not Found", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error)
      return
    }
    
    if (-not (Test-Path $tbRemapSourceJson.Text)) {
      $msg = "Source JSON file not found: $($tbRemapSourceJson.Text)"
      $tbRemapLog.AppendText("ERROR: $msg`r`n")
      [System.Windows.Forms.MessageBox]::Show($msg, "File Not Found", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error)
      return
    }
    
    # Disable button during processing
    $btnRemapTemplates.Enabled = $false
    $btnOpenRemapJson.Enabled = $false
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    
    try {
      # Read mapping CSV
      $tbRemapLog.AppendText("Reading template mapping from CSV...`r`n")
      $mapping = @(Import-Csv -Path $tbRemapCsv.Text)
      
      if ($mapping.Count -eq 0) {
        throw "No mappings found in CSV file"
      }
      
      # Validate CSV has required columns
      $firstRow = $mapping[0]
      $requiredCols = @('SourceName', 'SourceId', 'TargetName', 'TargetId')
      $alternativeCols = @('Source', 'Source ID', 'Target', 'Target ID')
      
      # Check if CSV has old format or new format
      $hasOldFormat = $true
      $hasNewFormat = $true
      
      foreach ($col in $requiredCols) {
        if (-not (Get-Member -InputObject $firstRow -Name $col -MemberType NoteProperty)) {
          $hasOldFormat = $false
          break
        }
      }
      
      foreach ($col in $alternativeCols) {
        if (-not (Get-Member -InputObject $firstRow -Name $col -MemberType NoteProperty)) {
          $hasNewFormat = $false
          break
        }
      }
      
      if (-not $hasOldFormat -and -not $hasNewFormat) {
        throw "CSV missing required columns. Expected either:`n  - Old format: SourceName, SourceId, TargetName, TargetId`n  - New format: Source, Source ID, Target, Target ID"
      }
      
      # Normalize to old format for compatibility with Update-JsonWithTemplateMapping
      if ($hasNewFormat -and -not $hasOldFormat) {
        $normalizedMapping = @()
        foreach ($row in $mapping) {
          $normalizedMapping += [PSCustomObject]@{
            SourceName = $row.'Source'
            SourceId = $row.'Source ID'
            TargetName = $row.'Target'
            TargetId = $row.'Target ID'
          }
        }
        $mapping = $normalizedMapping
      }
      
      $tbRemapLog.AppendText("  ✓ Loaded $($mapping.Count) template mapping(s)`r`n`r`n")
      
      # Display mappings
      $tbRemapLog.AppendText("Template Mappings:`r`n")
      foreach ($map in $mapping) {
        $tbRemapLog.AppendText("  $($map.SourceName) (ID: $($map.SourceId)) -> $($map.TargetName) (ID: $($map.TargetId))`r`n")
      }
      $tbRemapLog.AppendText("`r`n")
      
      # Run the remapping
      $tbRemapLog.AppendText("Processing JSON file...`r`n")
      $result = Update-JsonWithTemplateMapping `
        -SourceJsonPath $tbRemapSourceJson.Text `
        -OutputJsonPath $tbRemapOutputJson.Text `
        -TemplateMapping $mapping
      
      # Display results
      $tbRemapLog.AppendText("`r`n=== REMAPPING COMPLETE ===`r`n")
      $tbRemapLog.AppendText("Total Secrets: $($result.TotalSecrets)`r`n")
      $tbRemapLog.AppendText("Updated Secrets: $($result.UpdatedSecrets)`r`n")
      $tbRemapLog.AppendText("Skipped Secrets: $($result.SkippedSecrets)`r`n")
      $tbRemapLog.AppendText("Template Mappings Applied: $($result.TemplateMappings)`r`n")
      $tbRemapLog.AppendText("`r`nOutput saved to: $($result.OutputPath)`r`n")
      $tbRemapLog.AppendText("`r`nCompleted: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n")
      
      # Enable open button
      $btnOpenRemapJson.Enabled = $true
      
      # Show success message
      $summaryMsg = "Template remapping completed!`n`n"
      $summaryMsg += "Total Secrets: $($result.TotalSecrets)`n"
      $summaryMsg += "Updated Secrets: $($result.UpdatedSecrets)`n"
      $summaryMsg += "Skipped Secrets: $($result.SkippedSecrets)`n`n"
      $summaryMsg += "Output saved to:`n$($result.OutputPath)"
      
      [System.Windows.Forms.MessageBox]::Show(
        $summaryMsg,
        "Remapping Complete",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
      )
      
    } finally {
      # Re-enable button
      $btnRemapTemplates.Enabled = $true
      $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
    
  } catch {
    $tbRemapLog.AppendText("`r`nERROR: $($_.Exception.Message)`r`n")
    $tbRemapLog.AppendText("$($_.ScriptStackTrace)`r`n")
    [System.Windows.Forms.MessageBox]::Show(
      "Template remapping failed:`n`n$($_.Exception.Message)",
      "Error",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    )
  }
})

function Validate-ImportUI {
  $missing=@()
  if([string]::IsNullOrWhiteSpace($tbTgtBase.Text)){ $missing+='Target Tenant Base' }
  if([string]::IsNullOrWhiteSpace($tbTgtUser.Text)){ $missing+='Target Username' }
  if([string]::IsNullOrWhiteSpace($tbTgtApi.Text)){  $missing+='Target SS API Base' }
  if([string]::IsNullOrWhiteSpace($tbExport.Text)){  $missing+='Export JSON path (input to import)' }
  if((-not $cbTree.Checked) -and [string]::IsNullOrWhiteSpace($tbTgtFld.Text)){ $missing+='Target FolderId (required when tree OFF)' }
  if($cbTree.Checked -and [string]::IsNullOrWhiteSpace($tbTgtRoot.Text)){ $missing+='Target ROOT Id (required when tree ON)' }

  if($missing.Count){
    [System.Windows.Forms.MessageBox]::Show(("Missing:`n - {0}" -f ($missing -join "`n - "))) | Out-Null
    return $false
  }
  return $true
}

function Validate-ExportUI {
  $missing=@()

  if([string]::IsNullOrWhiteSpace($tbSrcBase.Text)){ $missing+='Source Tenant Base' }
  if([string]::IsNullOrWhiteSpace($tbSrcUser.Text)){ $missing+='Source Username' }
  if([string]::IsNullOrWhiteSpace($tbSrcApi.Text)){  $missing+='Source SS API Base' }
  if([string]::IsNullOrWhiteSpace($tbExport.Text)){  $missing+='Export JSON path' }

  # Allow CSV export for ALL secrets when FolderId is blank.
  # Only require FolderId when user requests "Export child folders".
if($cbV1ExportService.Checked -and [string]::IsNullOrWhiteSpace($tbSrcFld.Text)){
  # prevent the "missing FolderId" popup by forcing this off
  $cbExportChild.Checked = $false
}

  if($missing.Count){
    [System.Windows.Forms.MessageBox]::Show(("Missing:`n - {0}" -f ($missing -join "`n - "))) | Out-Null
    return $false
  }
  return $true
}
# --- Events ---
$btnClear.Add_Click({ try { $tbActionsLog.Clear() } catch {} })
$btnClose.Add_Click({ try { $form.Close() } catch {} })

$btnGetCount.Add_Click({
  $started = Get-Date
  try{
    ReadControls
    
    # Determine which tenant to count based on radio button selection
    $isSource = $rbCountSrc.Checked
    $tenantName = if($isSource) { "Source" } else { "Target" }
    $side = if($isSource) { 'Src' } else { 'Tgt' }
    
    # Get the correct config and API base FIRST
    $cfg = if($isSource) { $Global:Config.Src } else { $Global:Config.Tgt }
    $apiBase = [string]$cfg.SSApiBase
    $search = if($isSource) { [string]$Global:Config.Src.SearchText } else { '*' }
    if([string]::IsNullOrWhiteSpace($search)){ $search = '*' }
    
    Write-Log ("COUNT ({0}): started at {1}" -f $tenantName,$started.ToString("yyyy-MM-ddTHH:mm:ssK")) 'INFO'
    Write-Log ("COUNT ({0}): API Base = {1}" -f $tenantName,$apiBase) 'DEBUG'
    
    # Validate API Base URL AFTER setting $apiBase
    $urlCheck = Validate-ApiBaseUrl $apiBase
    if(-not $urlCheck.Valid){
      Write-Log ("COUNT ({0}): {1}" -f $tenantName,$urlCheck.Message) 'ERROR'
      [System.Windows.Forms.MessageBox]::Show(
        $urlCheck.Message,
        "Invalid API URL - $tenantName",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
      ) | Out-Null
      return
    }
    
    # Validation for required fields
    $missing = @()
    if([string]::IsNullOrWhiteSpace($cfg.SSApiBase)){ $missing += "$tenantName API Base" }
    if([string]::IsNullOrWhiteSpace($cfg.TenantBase)){ $missing += "$tenantName Tenant Base" }
    if([string]::IsNullOrWhiteSpace($cfg.Username)){ $missing += "$tenantName Username" }
    
    if($missing.Count -gt 0){
      $errMsg = "Missing required fields for $tenantName tenant:`n - " + ($missing -join "`n - ")
      Write-Log $errMsg 'ERROR'
      [System.Windows.Forms.MessageBox]::Show($errMsg, "Missing Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
      return
    }

    # Get token - pass the correct password textbox
    $pwdTextBox = if($isSource) { $tbSrcPwd } else { $tbTgtPwd }
    
    Write-Log ("COUNT ({0}): Attempting to get token for user '{1}'" -f $tenantName,$cfg.Username) 'DEBUG'
    
    # Check if password is available
    $hasPwdInTextbox = ($pwdTextBox -and -not [string]::IsNullOrWhiteSpace($pwdTextBox.Text))
    $hasPwdInConfig = $false
    try{
      $dpapi = [string](Get-PropValue $cfg @('PasswordDpapi') $null)
      $hasPwdInConfig = (-not [string]::IsNullOrWhiteSpace($dpapi))
    } catch {}
    
    if(-not $hasPwdInTextbox -and -not $hasPwdInConfig){
      $errMsg = "$tenantName password is required. Please enter it in the password field or enable DPAPI store."
      Write-Log $errMsg 'ERROR'
      [System.Windows.Forms.MessageBox]::Show($errMsg, "Password Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
      return
    }
    
    $tok = $null
    try{
      $tok = Token $side $pwdTextBox
    }
    catch{
      $errMsg = "Failed to authenticate to $tenantName tenant: $($_.Exception.Message)"
      Write-Log $errMsg 'ERROR'
      [System.Windows.Forms.MessageBox]::Show($errMsg, "Authentication Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
      return
    }
    
    if([string]::IsNullOrWhiteSpace($tok)){
      $errMsg = "$tenantName token is empty after authentication. Check credentials."
      Write-Log $errMsg 'ERROR'
      [System.Windows.Forms.MessageBox]::Show($errMsg, "Authentication Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
      return
    }
    
    Write-Log ("COUNT ({0}): Token obtained successfully" -f $tenantName) 'DEBUG'
    
    # Test API reachability
    if(-not (Test-ApiBaseReachable -apiBase $apiBase -tok $tok)){
      $errMsg = "Cannot reach API Base '$apiBase'. Check your SS API Base URL."
      Write-Log $errMsg 'ERROR'
      [System.Windows.Forms.MessageBox]::Show($errMsg, "API Unreachable", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
      return
    }

    # ==========================================================================
    # Count secrets using parallel /secrets endpoint
    # ==========================================================================
    
    Write-Log ("COUNT ({0}): Enumerating secrets via parallel /secrets endpoint..." -f $tenantName) 'INFO'
    
    $countTenantName = $tenantName
    $allRecs = Get-AllSecretsPaged-Parallel -ApiBase $apiBase -Token $tok -SearchText $search -PageSize 500 -ConcurrentPages 5 -OnProgress {
      param($pg,$pgCount,$totalSoFar,$apiTotal)
      $pctEst = if($apiTotal -gt 0){ [int][Math]::Min(95, [Math]::Round(($totalSoFar / $apiTotal) * 100)) } else { 50 }
      try{ Update-ProgressBar -Current $pctEst -Total 100 -StatusText ("Counting ({0}): {1} secrets fetched..." -f $countTenantName,$totalSoFar) }catch{}
    }
    
    # Deduplicate by secret ID
    $secretIdsSeen = New-Object 'System.Collections.Generic.HashSet[int]'
    $folderNamePairs = New-Object 'System.Collections.Generic.HashSet[string]'
    $dupPairs = 0
    foreach($rec in $allRecs){
      $sid = $null
      try{ $sid = [int](Get-PropValue $rec @('id','Id','secretId','SecretId') $null) } catch {}
      if($sid -ne $null -and $sid -gt 0){
        [void]$secretIdsSeen.Add($sid)
      }
      $fid2 = 0; $nm2 = $null
      try{ $fid2 = [int](Get-PropValue $rec @('folderId','FolderId') 0) } catch {}
      try{ $nm2  = [string](Get-PropValue $rec @('name','Name','secretName','SecretName') $null) } catch {}
      if(-not [string]::IsNullOrWhiteSpace($nm2)){
        $pairKey = ("{0}|{1}" -f $fid2,$nm2.ToLowerInvariant())
        if(-not $folderNamePairs.Add($pairKey)){ $dupPairs++ }
      }
    }
    try{ Update-ProgressBar -Current 100 -Total 100 -StatusText ("Count complete: {0} secrets" -f $secretIdsSeen.Count) }catch{}
    
    $total = $secretIdsSeen.Count
    
    # Show total in textbox
    $tbCount.Text = [string]$total
    if($isSource){ $Global:Config.Src.MaxSecrets = $total }

    Write-Log ("COUNT ({0}): Complete. Total unique secrets: {1}" -f $tenantName,$total) 'INFO'
    Write-Log ("COUNT ({0}): Duplicate (same folder + same name) pairs: {1}" -f $tenantName,$dupPairs) 'INFO'
    
    $summaryMsg = "Secrets counted in $tenantName tenant:`n`n"
    $summaryMsg += "Total secrets: $total`n"
    $summaryMsg += "Records fetched: $($allRecs.Count)`n"
    $summaryMsg += "Duplicate (same folder + name): $dupPairs`n"
    if($search -and $search -ne '*'){ $summaryMsg += "Search filter: '$search'`n" }
    $summaryMsg += "`nResult stored in count textbox."
    if($isSource){ $summaryMsg += "`n(Also available as MaxSecrets limit for export)" }

    [System.Windows.Forms.MessageBox]::Show(
      $summaryMsg,
      "Secret Count - $tenantName",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null

  } catch {
    $tenantName = if($rbCountSrc.Checked) { "Source" } else { "Target" }
    $errMsg = "Get # Secrets failed ($tenantName): $($_.Exception.Message)"
    Write-Log $errMsg 'ERROR'
    [System.Windows.Forms.MessageBox]::Show(
      $errMsg,
      "Count Failed",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
  } finally {
    try{ Hide-ProgressBar }catch{}
    $elapsed = New-TimeSpan -Start $started -End (Get-Date)
    $tenantName = if($rbCountSrc.Checked) { "Source" } else { "Target" }
    Write-Log ("COUNT ({0}): task completed. Elapsed={1:c}" -f $tenantName,$elapsed) 'INFO'
    $tabs.SelectedTab = $tabActions
  }
})

$btnCleanup.Add_Click({
  $started = Get-Date
  try{
    ReadControls
    
    $secretCount = $script:ImportRunCreatedSecretIds.Count
    $folderCount = $script:ImportRunCreatedFolderIds.Count
    
    if($secretCount -eq 0 -and $folderCount -eq 0){
      [System.Windows.Forms.MessageBox]::Show(
        "No objects from last import run to clean up.",
        "Nothing to Clean",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
      ) | Out-Null
      return
    }
    
    $confirmMsg = "This will delete:`n- $secretCount secrets`n- $folderCount folders`n`nCreated during the last import.`n`nContinue?"
    $confirm = [System.Windows.Forms.MessageBox]::Show(
      $confirmMsg,
      "Confirm Cleanup",
      [System.Windows.Forms.MessageBoxButtons]::YesNo,
      [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    
    if($confirm -ne [System.Windows.Forms.DialogResult]::Yes){ return }
    
    Write-Log "CLEANUP: starting cleanup of last import run objects..." 'INFO'
    
    $tok = Token Tgt $tbTgtPwd
    $apiBase = $Global:Config.Tgt.SSApiBase
    
    $secretsDeleted = 0
    $secretsFailed = 0
    $foldersDeleted = 0
    $foldersFailed = 0
    
    # Delete secrets first (reverse order)
    if($secretCount -gt 0){
      Write-Log ("CLEANUP: deleting {0} created secrets..." -f $secretCount) 'INFO'
      
      $reversedSecrets = @($script:ImportRunCreatedSecretIds)
      [Array]::Reverse($reversedSecrets)
      
      foreach($sid in $reversedSecrets){
        try{
          $info = $script:ImportRunCreatedSecretsById[[string]$sid]
          $sname = if($info){ $info.name } else { "unknown" }
          
          SS $apiBase DELETE ("secrets/{0}" -f $sid) $tok $null $null | Out-Null
          Write-Log ("CLEANUP: deleted secret id={0} name='{1}'" -f $sid,$sname) 'INFO'
          $secretsDeleted++
        }
        catch{
          Write-Log ("CLEANUP: failed to delete secret id={0}: {1}" -f $sid,$_.Exception.Message) 'WARN'
          $secretsFailed++
        }
      }
    }
    
    # Delete folders (reverse order - children first)
    if($folderCount -gt 0){
      Write-Log ("CLEANUP: deleting {0} created folders..." -f $folderCount) 'INFO'
      
      $reversedFolders = @($script:ImportRunCreatedFolderIds)
      [Array]::Reverse($reversedFolders)
      
      foreach($fid in $reversedFolders){
        try{
          $info = $script:ImportRunCreatedFoldersById[[string]$fid]
          $fname = if($info){ $info.name } else { "unknown" }
          
          SS $apiBase DELETE ("folders/{0}" -f $fid) $tok $null $null | Out-Null
          Write-Log ("CLEANUP: deleted folder id={0} name='{1}'" -f $fid,$fname) 'INFO'
          $foldersDeleted++
        }
        catch{
          Write-Log ("CLEANUP: failed to delete folder id={0}: {1}" -f $fid,$_.Exception.Message) 'WARN'
          $foldersFailed++
        }
      }
    }
    else{
      Write-Log "CLEANUP: no created folders recorded for last import run." 'INFO'
    }
    
    # Reset tracking
    Reset-ImportTracking
    # Reset folder path cache for this import run
    $script:CreatedFolderCache = @{}
    Write-Log ("CLEANUP: completed. Secrets: {0} deleted, {1} failed. Folders: {2} deleted, {3} failed." -f $secretsDeleted,$secretsFailed,$foldersDeleted,$foldersFailed) 'INFO'
    
    [System.Windows.Forms.MessageBox]::Show(
      "Cleanup complete.`n`nSecrets: $secretsDeleted deleted, $secretsFailed failed`nFolders: $foldersDeleted deleted, $foldersFailed failed",
      "Cleanup Complete",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    
  } catch {
    Write-Log ("CLEANUP ERROR: {0}" -f ($_ | Out-String)) 'ERROR'
    [System.Windows.Forms.MessageBox]::Show(
      "Cleanup failed: $($_.Exception.Message)",
      "Cleanup Error",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
  } finally {
    $elapsed = New-TimeSpan -Start $started -End (Get-Date)
    Write-Log ("CLEANUP: task completed. Elapsed={0:c}" -f $elapsed) 'INFO'
  }
})

$btnVerify.Add_Click({
  $started = Get-Date
  try{
    ReadControls
    
    # Determine which tenant to verify based on radio button
    $isSource = $rbCountSrc.Checked
    $tenantName = if($isSource) { "Source" } else { "Target" }
    
    # Get config and API base FIRST
    $cfg = if($isSource) { $Global:Config.Src } else { $Global:Config.Tgt }
    $apiBase = [string]$cfg.SSApiBase
    $tenantBase = [string]$cfg.TenantBase
    
    Write-Log ("VERIFY ({0}): started at {1}" -f $tenantName,$started.ToString("yyyy-MM-ddTHH:mm:ssK")) 'INFO'
    Write-Log ("VERIFY ({0}): API Base = {1}" -f $tenantName,$apiBase) 'DEBUG'
    
    # Validate API Base URL
    $urlCheck = Validate-ApiBaseUrl $apiBase
    if(-not $urlCheck.Valid){
      Write-Log ("VERIFY ({0}): {1}" -f $tenantName,$urlCheck.Message) 'ERROR'
      [System.Windows.Forms.MessageBox]::Show(
        $urlCheck.Message,
        "Invalid API URL",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
      ) | Out-Null
      return
    }
    
    # Get folder ID from appropriate textbox (OPTIONAL - not required)
    $rootFolderId = $null
    if($isSource){
      if(-not [string]::IsNullOrWhiteSpace($tbSrcFld.Text)){
        try{ 
          $parsed = [int]$tbSrcFld.Text.Trim()
          if($parsed -gt 0){ $rootFolderId = $parsed }
        } catch {}
      }
    } else {
      if(-not [string]::IsNullOrWhiteSpace($tbTgtRoot.Text)){
        try{ 
          $parsed = [int]$tbTgtRoot.Text.Trim()
          if($parsed -gt 0){ $rootFolderId = $parsed }
        } catch {}
      }
    }

    # Fallback: if textbox empty/invalid, use the root folder ID from saved settings.
    # Source uses Src.FolderId; Target uses Tgt.TargetRootFolderId.
    if($rootFolderId -eq $null -or $rootFolderId -le 0){
      try{
        $cfgRoot = if($isSource){ $Global:Config.Src.FolderId } else { $Global:Config.Tgt.TargetRootFolderId }
        if($cfgRoot -ne $null -and [int]$cfgRoot -gt 0){
          $rootFolderId = [int]$cfgRoot
          Write-Log ("VERIFY ({0}): No folder ID in textbox; using rootFolderId={1} from settings" -f $tenantName,$rootFolderId) 'INFO'
        }
      } catch {}
    }
    
    # Get token
    $pwdTextBox = if($isSource) { $tbSrcPwd } else { $tbTgtPwd }
    $side = if($isSource) { 'Src' } else { 'Tgt' }
    
    $tok = $null
    try{
      $tok = Token $side $pwdTextBox
    }
    catch{
      $errMsg = "Failed to authenticate: $($_.Exception.Message)"
      Write-Log $errMsg 'ERROR'
      [System.Windows.Forms.MessageBox]::Show($errMsg, "Authentication Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
      return
    }
    
    if([string]::IsNullOrWhiteSpace($tok)){
      $errMsg = "$tenantName token is empty. Check credentials."
      Write-Log $errMsg 'ERROR'
      [System.Windows.Forms.MessageBox]::Show($errMsg, "Authentication Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
      return
    }
    
    Write-Log ("VERIFY ({0}): Token obtained successfully" -f $tenantName) 'DEBUG'
    
    # Test API connectivity first
    Write-Log ("VERIFY ({0}): Testing API connectivity to {1}" -f $tenantName,$apiBase) 'INFO'
    
    $apiOk = $false
    try{
      $testResp = SS $apiBase GET 'users/current' $tok $null $null
      $apiOk = $true
      Write-Log ("VERIFY ({0}): API connectivity OK" -f $tenantName) 'INFO'
    }
    catch{
      $errMsg = "Cannot connect to API: $($_.Exception.Message)`n`nAPI Base: $apiBase"
      Write-Log $errMsg 'ERROR'
      [System.Windows.Forms.MessageBox]::Show($errMsg, "API Connection Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
      return
    }
    
    # ========================================================================
    # STEP 1: Get all folders
    # ========================================================================
    $folderIds = @()
    
    if($rootFolderId -ne $null -and $rootFolderId -gt 0){
      Write-Log ("VERIFY ({0}): Scanning from rootFolderId={1}" -f $tenantName,$rootFolderId) 'INFO'
      
      try{
        $folderIds = @(Get-DescendantFolderIds -ApiBase $apiBase -Tok $tok -RootFolderId $rootFolderId)
      } catch {
        Write-Log ("VERIFY ({0}): Folder enumeration failed: {1}" -f $tenantName,$_.Exception.Message) 'WARN'
        $folderIds = @($rootFolderId)
      }
    }
    else{
      Write-Log ("VERIFY ({0}): No folder ID specified - scanning ALL accessible folders" -f $tenantName) 'INFO'
      
      try{
        $folderIds = @(Get-AllFoldersRecursive-BFS -ApiBase $apiBase -Tok $tok)
      }
      catch{
        Write-Log ("VERIFY ({0}): BFS folder enumeration failed: {1}" -f $tenantName,$_.Exception.Message) 'WARN'
        
        # Fallback: try simple folder listing
        try{
          $accessible = @(Get-AccessibleFolders -apiBase $apiBase -tok $tok)
          $folderIds = @($accessible | ForEach-Object { $_.Id } | Where-Object { $_ -gt 0 })
        }
        catch{
          Write-Log ("VERIFY ({0}): Fallback folder listing also failed" -f $tenantName) 'ERROR'
          $folderIds = @()
        }
      }
    }
    
    Write-Log ("VERIFY ({0}): Found {1} folders" -f $tenantName,$folderIds.Count) 'INFO'
    
    # ========================================================================
    # STEP 2: Count secrets using parallel /secrets endpoint
    # This is more reliable than per-folder lookup
    # ========================================================================

    $totalSecrets = 0
    $secretIdsSeen = New-Object 'System.Collections.Generic.HashSet[int]'
    $secretsByFolder = @{}  # folderId -> count
    $verifyFolderNamePairs = New-Object 'System.Collections.Generic.HashSet[string]'
    $verifyDupPairs = 0

    # NOTE: We intentionally do NOT filter the secret list against the enumerated
    # folder set. The /folders BFS may under-report descendants (Delinea API can
    # restrict deep enumeration even when child secrets are visible), which would
    # discard real secrets and produce a falsely-low total. Instead we count every
    # accessible secret returned by the parallel pager - matching the behaviour of
    # the Get#Secrets button which is known-correct.
    $verifyTenantName = $tenantName
    $allRecs = Get-AllSecretsPaged-Parallel -ApiBase $apiBase -Token $tok -SearchText '*' -PageSize 500 -ConcurrentPages 5 -OnProgress {
      param($pg,$pgCount,$totalSoFar,$apiTotal)
      $pctEst = if($apiTotal -gt 0){ [int][Math]::Min(95, [Math]::Round(($totalSoFar / $apiTotal) * 100)) } else { 50 }
      try{ Update-ProgressBar -Current $pctEst -Total 100 -StatusText ("Verify ({0}): {1} secrets fetched..." -f $verifyTenantName,$totalSoFar) }catch{}
    }

    foreach($rec in $allRecs){
      $sid = $null
      $fid = $null
      $vnm = $null
      try{ $sid = [int](Get-PropValue $rec @('id','Id','secretId','SecretId') $null) } catch {}
      try{ $fid = [int](Get-PropValue $rec @('folderId','FolderId') 0) } catch {}
      try{ $vnm = [string](Get-PropValue $rec @('name','Name','secretName','SecretName') $null) } catch {}

      if($sid -ne $null -and $sid -gt 0){
        if($secretIdsSeen.Add($sid)){
          $totalSecrets++
          if($fid -gt 0){
            if(-not $secretsByFolder.ContainsKey($fid)){ $secretsByFolder[$fid] = 0 }
            $secretsByFolder[$fid]++
          }
        }
      }
      if(-not [string]::IsNullOrWhiteSpace($vnm)){
        $pairKey = ("{0}|{1}" -f $fid,$vnm.ToLowerInvariant())
        if(-not $verifyFolderNamePairs.Add($pairKey)){ $verifyDupPairs++ }
      }
    }
    try{ Update-ProgressBar -Current 100 -Total 100 -StatusText ("Verify complete: {0} secrets" -f $totalSecrets) }catch{}
    Write-Log ("VERIFY ({0}): Duplicate (same folder + same name) pairs: {1}" -f $tenantName,$verifyDupPairs) 'INFO'

    # Count folders that actually contain secrets (from the secret list, not enumeration)
    $foldersWithSecrets = $secretsByFolder.Keys.Count

    # ======================================================================
    # PER-FOLDER BREAKDOWN: folder name + secret count for each folder (and
    # all of its subfolders) under the specified root. Reuses the folder
    # map populated by Get-AllFoldersRecursive-BFS ($script:LastFolderDetailsMap)
    # which already returned reliable {Id, Name, Path} entries. Subtree scope
    # is determined by folder-path prefix matching (no parent-chain walking).
    # ======================================================================
    try{
      # Build name/path lookup from BFS map (always run BFS to ensure populated)
      try{
        $null = Get-AllFoldersRecursive-BFS -ApiBase $apiBase -Tok $tok
      } catch {}
      $folderLookup = @{}    # folderId -> @{ Name; FolderPath }
      if($script:LastFolderDetailsMap){
        foreach($kv in $script:LastFolderDetailsMap.GetEnumerator()){
          $folderLookup[[int]$kv.Key] = @{
            Name       = [string]$kv.Value.Name
            FolderPath = [string]$kv.Value.Path
          }
        }
      }

      # Determine in-scope folder IDs by folder-path prefix from rootFolderId
      $inScope = $null
      if($rootFolderId -ne $null -and $rootFolderId -gt 0 -and $folderLookup.Count -gt 0){
        $inScope = New-Object 'System.Collections.Generic.HashSet[int]'
        [void]$inScope.Add([int]$rootFolderId)
        $rootInfo = $folderLookup[[int]$rootFolderId]
        $rootPath = if($rootInfo){ [string]$rootInfo.FolderPath } else { '' }
        if(-not [string]::IsNullOrWhiteSpace($rootPath)){
          # NOTE: single-quoted '\\' is a literal TWO-backslash string in PowerShell.
          # We need ONE backslash, so use '\' (one literal backslash).
          $rpTrim = $rootPath.TrimEnd('\').TrimEnd('/')
          $prefix1 = $rpTrim + '\'
          $prefix2 = $rpTrim + '/'
          foreach($kv in $folderLookup.GetEnumerator()){
            $fp = [string]$kv.Value.FolderPath
            if([string]::IsNullOrWhiteSpace($fp)){ continue }
            if($fp.StartsWith($prefix1,[System.StringComparison]::OrdinalIgnoreCase) -or `
               $fp.StartsWith($prefix2,[System.StringComparison]::OrdinalIgnoreCase) -or `
               $fp.Equals($rootPath,[System.StringComparison]::OrdinalIgnoreCase)){
              [void]$inScope.Add([int]$kv.Key)
            }
          }
        }
        Write-Log ("VERIFY ({0}): Subtree under rootFolderId={1} contains {2} folders" -f $tenantName,$rootFolderId,$inScope.Count) 'INFO'
      }

      # Build breakdown rows from $secretsByFolder, filtered to scope
      $breakdown = New-Object System.Collections.ArrayList
      $scopedSecrets = 0
      foreach($kv in $secretsByFolder.GetEnumerator()){
        $fid = [int]$kv.Key
        $cnt = [int]$kv.Value
        if($inScope -ne $null -and -not $inScope.Contains($fid)){ continue }
        $info = $folderLookup[$fid]
        $fname = if($info){ [string]$info.Name } else { "Folder $fid (unknown)" }
        $fpath = if($info -and $info.FolderPath){ [string]$info.FolderPath } else { '' }
        [void]$breakdown.Add([pscustomobject]@{ Id=$fid; Name=$fname; Path=$fpath; Count=$cnt })
        $scopedSecrets += $cnt
      }
      $breakdown = @($breakdown | Sort-Object -Property @{Expression='Count';Descending=$true},@{Expression='Path';Descending=$false})

      Write-Log ("VERIFY ({0}): Per-folder breakdown - {1} folders, {2} secrets in scope" -f $tenantName,$breakdown.Count,$scopedSecrets) 'INFO'
      foreach($row in $breakdown){
        $label = if($row.Path){ $row.Path } else { $row.Name }
        Write-Log ("    {0,6} | {1}  (id={2})" -f $row.Count,$label,$row.Id) 'INFO'
      }

      # Add top-N to popup summary
      $topN = 25
      $script:VerifyBreakdownTop = @($breakdown | Select-Object -First $topN)
      $script:VerifyBreakdownScopedSecrets = $scopedSecrets
      $script:VerifyBreakdownScopedFolders = $breakdown.Count
    } catch {
      Write-Log ("VERIFY ({0}): Per-folder breakdown failed: {1}" -f $tenantName,$_.Exception.Message) 'WARN'
      $script:VerifyBreakdownTop = @()
      $script:VerifyBreakdownScopedSecrets = 0
      $script:VerifyBreakdownScopedFolders = 0
    }
    
    $summaryMsg = "Verify Complete ($tenantName)`n`n"
    if($rootFolderId -ne $null -and $rootFolderId -gt 0){
      $summaryMsg += "Root Folder ID: $rootFolderId`n"
      $summaryMsg += "Folders in Subtree: $($script:VerifyBreakdownScopedFolders)`n"
      $summaryMsg += "Secrets in Subtree: $($script:VerifyBreakdownScopedSecrets)`n"
    } else {
      $summaryMsg += "Scope: All Accessible`n"
    }
    $summaryMsg += "Total Folders (tenant): $($folderIds.Count)`n"
    $summaryMsg += "Folders with Secrets (tenant): $foldersWithSecrets`n"
    $summaryMsg += "Total Secrets (tenant): $totalSecrets`n"
    $summaryMsg += "Duplicate (same folder + name): $verifyDupPairs`n"

    if($script:VerifyBreakdownTop -and $script:VerifyBreakdownTop.Count -gt 0){
      $summaryMsg += "`nPer-Folder Breakdown (top $($script:VerifyBreakdownTop.Count)):`n"
      foreach($row in $script:VerifyBreakdownTop){
        $label = if($row.Path){ $row.Path } else { $row.Name }
        $summaryMsg += ("  {0,6} | {1}`n" -f $row.Count,$label)
      }
      $summaryMsg += "`n(full list available in log file)"
    }
    
    [System.Windows.Forms.MessageBox]::Show(
      $summaryMsg,
      "Verify Results - $tenantName",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    
  } catch {
    $tenantName = if($rbCountSrc.Checked) { "Source" } else { "Target" }
    $errMsg = "Verify failed ($tenantName): $($_.Exception.Message)"
    Write-Log $errMsg 'ERROR'
    [System.Windows.Forms.MessageBox]::Show(
      $errMsg,
      "Verify Failed",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
  } finally {
    try{ Hide-ProgressBar }catch{}
    $elapsed = New-TimeSpan -Start $started -End (Get-Date)
    $tenantName = if($rbCountSrc.Checked) { "Source" } else { "Target" }
    Write-Log ("VERIFY ({0}): task completed. Elapsed={1:c}" -f $tenantName,$elapsed) 'INFO'
    $tabs.SelectedTab = $tabActions
  }
})
# IMPORTANT: Keep ONLY THIS Export handler (delete any earlier $btnExport.Add_Click blocks)
function Read-ControlsToConfig {
  # Source tenant settings
  try {
    if($tbSrcTenant -and $tbSrcTenant.Text){ 
      $Global:Config.Src.TenantBase = $tbSrcTenant.Text.Trim() 
    }
  } catch {}
  
  try {
    if($tbSrcUser -and $tbSrcUser.Text){ 
      $Global:Config.Src.Username = $tbSrcUser.Text.Trim() 
    }
  } catch {}
  
  try {
    if($tbSrcApi -and $tbSrcApi.Text){ 
      $Global:Config.Src.SSApiBase = $tbSrcApi.Text.Trim() 
    }
  } catch {}
  
  try {
    if($tbSrcSearch -and $tbSrcSearch.Text){ 
      $Global:Config.Src.SearchText = $tbSrcSearch.Text.Trim() 
    }
  } catch {}
  
  try {
    if($tbSrcFolderId -and -not [string]::IsNullOrWhiteSpace($tbSrcFolderId.Text)){ 
      $Global:Config.Src.FolderId = Parse-NullableInt $tbSrcFolderId.Text 
    } else {
      $Global:Config.Src.FolderId = $null
    }
  } catch {}
  
  try {
    if($tbMaxSecrets -and -not [string]::IsNullOrWhiteSpace($tbMaxSecrets.Text)){ 
      $Global:Config.Src.MaxSecrets = Parse-NullableInt $tbMaxSecrets.Text 
    } else {
      $Global:Config.Src.MaxSecrets = $null
    }
  } catch {}
  
  # Target tenant settings
  try {
    if($tbTgtTenant -and $tbTgtTenant.Text){ 
      $Global:Config.Tgt.TenantBase = $tbTgtTenant.Text.Trim() 
    }
  } catch {}
  
  try {
    if($tbTgtUser -and $tbTgtUser.Text){ 
      $Global:Config.Tgt.Username = $tbTgtUser.Text.Trim() 
    }
  } catch {}
  
  try {
    if($tbTgtApi -and $tbTgtApi.Text){ 
      $Global:Config.Tgt.SSApiBase = $tbTgtApi.Text.Trim() 
    }
  } catch {}
  
  try {
    if($tbTgtFolderId -and -not [string]::IsNullOrWhiteSpace($tbTgtFolderId.Text)){ 
      $Global:Config.Tgt.TargetFolderId = Parse-NullableInt $tbTgtFolderId.Text 
      if($Global:Config.Tgt.TargetFolderId -eq $null){ $Global:Config.Tgt.TargetFolderId = 0 }
    }
  } catch {}
  
  try {
    if($tbTgtRootFolderId -and -not [string]::IsNullOrWhiteSpace($tbTgtRootFolderId.Text)){ 
      $Global:Config.Tgt.TargetRootFolderId = Parse-NullableInt $tbTgtRootFolderId.Text 
      if($Global:Config.Tgt.TargetRootFolderId -eq $null){ $Global:Config.Tgt.TargetRootFolderId = 1 }
    }
  } catch {}
  
  # Checkboxes - Export options
  try {
    if($cbCopyFolderAcls){ $Global:Config.Tgt.CopyFolderAcls = [bool]$cbCopyFolderAcls.Checked }
  } catch {}
  
  try {
    if($cbCopySecretAcls){ $Global:Config.Tgt.CopySecretAcls = [bool]$cbCopySecretAcls.Checked }
  } catch {}
  
  try {
    if($cbCopySettings){ $Global:Config.Tgt.CopySecretSettings = [bool]$cbCopySettings.Checked }
  } catch {}
  
  try {
    if($cbCopyAttachments){ $Global:Config.Tgt.CopyAttachments = [bool]$cbCopyAttachments.Checked }
  } catch {}
  
  try {
    if($cbRemapPrincipals){ $Global:Config.Tgt.RemapPrincipals = [bool]$cbRemapPrincipals.Checked }
  } catch {}
  
  try {
    if($cbFolderTree){ $Global:Config.Tgt.FolderTreeMigration = [bool]$cbFolderTree.Checked }
  } catch {}
  
  try {
    if($cbDryRun){ $Global:Config.Tgt.DryRun = [bool]$cbDryRun.Checked }
  } catch {}
  
  try {
    if($cbExportTemplates){ $Global:Config.Src.ExportTemplates = [bool]$cbExportTemplates.Checked }
  } catch {}
  
  # Export format options
  try {
    if($cbExportJson){ 
      $Global:Config.Src | Add-Member -NotePropertyName ExportJson -NotePropertyValue ([bool]$cbExportJson.Checked) -Force 
    }
  } catch {}
  
  try {
    if($cbExportXml){ 
      $Global:Config.Src | Add-Member -NotePropertyName ExportXml -NotePropertyValue ([bool]$cbExportXml.Checked) -Force 
    }
  } catch {}
  
  try {
    if($cbExportCsv){ 
      $Global:Config.Src | Add-Member -NotePropertyName ExportCsv -NotePropertyValue ([bool]$cbExportCsv.Checked) -Force 
    }
  } catch {}
  
  try {
    if($cbExportZip){ 
      $Global:Config.Src | Add-Member -NotePropertyName ExportZip -NotePropertyValue ([bool]$cbExportZip.Checked) -Force 
    }
  } catch {}
  
  # Template mapping
  try {
    if($cbMapTemplateByName){ $Global:Config.Tgt.SecretTypeMapByName = [bool]$cbMapTemplateByName.Checked }
  } catch {}
  
  # Duplicate action combo
  try {
    if($cmbDuplicateAction -and $cmbDuplicateAction.SelectedItem){ 
      $Global:Config.Tgt.DuplicateSecretAction = [string]$cmbDuplicateAction.SelectedItem 
    }
  } catch {}
  
  Write-Log "Config updated from UI controls" 'DEBUG'
}
$btnExport.Add_Click({
  try{
    $btnExport.Enabled = $false
    $sw = [Diagnostics.Stopwatch]::StartNew()
    
    ReadControls
    
    # CHECK FOR DRY-RUN MODE
    $isDryRun = [bool]$Global:Config.Tgt.DryRun
    
    if($isDryRun){
      Write-Log "========================================" 'INFO'
      Write-Log "DRY-RUN MODE: Export will simulate only" 'INFO'
      Write-Log "========================================" 'INFO'
    }
    
    # Read MaxSecrets from the UI textbox
    $maxSecretsLimit = $null
    $tbCountValue = $tbCount.Text.Trim()
    
    if(-not [string]::IsNullOrWhiteSpace($tbCountValue)){
      try{
        $parsed = [int]$tbCountValue
        if($parsed -gt 0){
          $maxSecretsLimit = $parsed
          Write-Log ("EXPORT: MaxSecrets limit set from UI: {0}" -f $maxSecretsLimit) 'INFO'
        }
      } catch {
        Write-Log ("EXPORT: Could not parse MaxSecrets value '{0}'" -f $tbCountValue) 'WARN'
      }
    }
    
    if($maxSecretsLimit -eq $null){
      Write-Log "EXPORT: No MaxSecrets limit - will export ALL secrets" 'INFO'
    }
    
    # Read folder filter
    $effectiveFolderId = $null
    if(-not [string]::IsNullOrWhiteSpace($tbSrcFld.Text)){
      try{
        $effectiveFolderId = [int]$tbSrcFld.Text.Trim()
        if($effectiveFolderId -le 0){ $effectiveFolderId = $null }
      } catch {
        $effectiveFolderId = $null
      }
    }
    
    Log-ConfigSummary 'EXPORT-START'

    # DRY-RUN: Only enumerate secrets, don't write files
    if($isDryRun){
      Write-Log "[DRY-RUN] Would export secrets with these settings:" 'INFO'
      Write-Log ("  - API Base: {0}" -f $Global:Config.Src.SSApiBase) 'INFO'
      Write-Log ("  - Search: {0}" -f $Global:Config.Src.SearchText) 'INFO'
      Write-Log ("  - FolderId: {0}" -f $(if($effectiveFolderId){"$effectiveFolderId"}else{"(all)"})) 'INFO'
      Write-Log ("  - MaxSecrets: {0}" -f $(if($maxSecretsLimit){"$maxSecretsLimit"}else{"(all)"})) 'INFO'
      Write-Log ("  - Output JSON: {0}" -f $Global:Config.ExportFile) 'INFO'
      Write-Log ("  - Copy Attachments: {0}" -f $Global:Config.Tgt.CopyAttachments) 'INFO'
      Write-Log ("  - Copy Folder ACLs: {0}" -f $Global:Config.Tgt.CopyFolderAcls) 'INFO'
      Write-Log ("  - Copy Secret ACLs: {0}" -f $Global:Config.Tgt.CopySecretAcls) 'INFO'
      Write-Log ("  - Copy Settings: {0}" -f $Global:Config.Tgt.CopySecretSettings) 'INFO'
      Write-Log ("  - Export JSON: {0}" -f $Global:Config.Src.ExportJson) 'INFO'
      Write-Log ("  - Export XML: {0}" -f $Global:Config.Src.ExportXml) 'INFO'
      Write-Log ("  - Export CSV: {0}" -f $Global:Config.Src.ExportCsv) 'INFO'
      Write-Log ("  - Export ZIP: {0}" -f $Global:Config.Src.ExportZip) 'INFO'
      
      # Count how many secrets would be exported
      $tok = Token Src $tbSrcPwd
      $apiBase = $Global:Config.Src.SSApiBase
      
      $secretCount = 0
      $page = 1
      $pageSize = 500
      
      while($page -le 100){
        $params = @{
          'filter.searchText' = $Global:Config.Src.SearchText
          'filter.page'       = $page
          'filter.pageSize'   = $pageSize
        }
        
        if($effectiveFolderId -ne $null -and $effectiveFolderId -gt 0){
          $params['filter.folderId'] = $effectiveFolderId
        }
        
        try{
          $resp = SS $apiBase GET 'secrets' $tok $null $params
          $recs = @(Get-Records $resp)
          $secretCount += $recs.Count
          
          if($maxSecretsLimit -ne $null -and $secretCount -ge $maxSecretsLimit){
            $secretCount = $maxSecretsLimit
            break
          }
          
          if($recs.Count -lt $pageSize){ break }
          $page++
        }
        catch{
          Write-Log ("[DRY-RUN] Error counting secrets: {0}" -f $_.Exception.Message) 'WARN'
          break
        }
      }
      
      Write-Log "[DRY-RUN] Would export approximately $secretCount secrets" 'INFO'
      
      $sw.Stop()
      Write-Log ("[DRY-RUN] Export simulation completed. Elapsed={0}" -f $sw.Elapsed) 'INFO'
      
      [System.Windows.Forms.MessageBox]::Show(
        "DRY-RUN: Export simulation completed.`n`nWould export: ~$secretCount secrets`n`nNo files were written.`n`nUncheck 'Dry-run' to perform actual export.",
        "Dry-Run Complete",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
      ) | Out-Null
      
      return
    }

    # ACTUAL EXPORT (not dry-run)
    $script:ExportCancelled = $false
    $btnGetCount.Visible = $false
    $btnCancel.Visible = $true
    $btnExport.Enabled = $false
    # Auto-check incremental if resuming
    if($btnExport.Text -eq "Resume Export"){ $cbIncremental.Checked = $true }
    [System.Windows.Forms.Application]::DoEvents()
    try{
    $cnt = Export-SS `
      -ApiBase $Global:Config.Src.SSApiBase `
      -Token (Token Src $tbSrcPwd) `
      -OutPath $Global:Config.ExportFile `
      -Search $Global:Config.Src.SearchText `
      -FolderId $effectiveFolderId `
      -MaxSecrets $maxSecretsLimit `
      -IncludeHistory ([bool]$Global:Config.Src.IncludeHistory) `
      -ExportTemplates ([bool]$Global:Config.Src.ExportTemplates) `
      -CopyFolderAcls ([bool]$Global:Config.Tgt.CopyFolderAcls) `
      -CopySecretAcls ([bool]$Global:Config.Tgt.CopySecretAcls) `
      -CopySecretSettings ([bool]$Global:Config.Tgt.CopySecretSettings) `
      -CopyAttachments ([bool]$Global:Config.Tgt.CopyAttachments) `
      -Incremental ([bool]$cbIncremental.Checked) `
      -EncryptPasswords ([bool]$cbEncryptPasswords.Checked)
    }finally{
      $btnCancel.Visible = $false
      $btnGetCount.Visible = $true
      $btnExport.Enabled = $true
      try{ Hide-ProgressBar }catch{}
      try{ Update-ResumeButtonState }catch{}
      [System.Windows.Forms.Application]::DoEvents()
    }

    # Skip post-processing if export was cancelled
    if($script:ExportCancelled){
      $sw.Stop()
      Write-Log ("EXPORT: Cancelled after {0}. Use Resume Export to continue." -f $sw.Elapsed) 'WARN'
      return
    }

    # Re-read checkbox state for post-processing (in case user changed during long export)
    $Global:Config.Src.ExportXml = [bool]$cbExportXml.Checked
    $Global:Config.Src.ExportCsv = [bool]$cbExportCsv.Checked
    $Global:Config.Src.ExportZip = [bool]$cbExportZip.Checked
    Write-Log ("EXPORT: Post-processing flags - XML={0}, CSV={1}, ZIP={2}" -f $Global:Config.Src.ExportXml,$Global:Config.Src.ExportCsv,$Global:Config.Src.ExportZip) 'INFO'

    # Generate XML if ExportXml is checked
    if([bool]$Global:Config.Src.ExportXml){
      Write-Log "EXPORT: Generating XML file..." 'INFO'
      
      $xmlPath = $Global:Config.ExportFile -replace '\.json$', '.xml'
      if($xmlPath -eq $Global:Config.ExportFile){
        $xmlPath = $Global:Config.ExportFile + '.xml'
      }
      
      try{
        Export-SecretsJsonToDelineaImportXml `
          -InputJsonPath $Global:Config.ExportFile `
          -OutXmlPath $xmlPath `
          -IncludeFolders `
          -IncludePermissions
        
        Write-Log ("EXPORT: XML file created: {0}" -f $xmlPath) 'INFO'
      }
      catch{
        Write-Log ("EXPORT: XML generation failed: {0}" -f $_.Exception.Message) 'ERROR'
      }
    }
    
    # Generate CSV bundle if ExportCsv is checked
    if([bool]$Global:Config.Src.ExportCsv){
      Write-Log "EXPORT: Generating CSV bundle..." 'INFO'
      
      $csvDir = Join-Path (Split-Path -Parent $Global:Config.ExportFile) 'csv-bundle'
      
      try{
        $csvResult = Export-SecretsJsonToCsvBundle `
          -InputJsonPath $Global:Config.ExportFile `
          -OutDir $csvDir
        
        Write-Log ("EXPORT: CSV bundle created in: {0}" -f $csvDir) 'INFO'
      }
      catch{
        Write-Log ("EXPORT: CSV bundle generation failed: {0}" -f $_.Exception.Message) 'ERROR'
      }

      # Generate Templates CSV (with secrets count, fields, launchers, mappings)
      try{
        Write-Log "EXPORT: Generating templates CSV..." 'INFO'
        $tmplCsvResult = Export-TemplateSummaryToCsv `
          -ApiBase $Global:Config.Src.SSApiBase `
          -Tok (Token Src $tbSrcPwd) `
          -InputJsonPath $Global:Config.ExportFile `
          -OutDir $csvDir
        Write-Log ("EXPORT: Templates CSV done - {0} templates, {1} fields" -f $tmplCsvResult.Templates,$tmplCsvResult.Fields) 'INFO'
      }
      catch{
        Write-Log ("EXPORT: Templates CSV generation failed: {0}" -f $_.Exception.Message) 'ERROR'
      }

      # Generate Secret Policies CSV
      try{
        Write-Log "EXPORT: Generating secret policies CSV..." 'INFO'
        $polCsvResult = Export-SecretPoliciesToCsv `
          -ApiBase $Global:Config.Src.SSApiBase `
          -Tok (Token Src $tbSrcPwd) `
          -OutDir $csvDir
        Write-Log ("EXPORT: Policies CSV done - {0} policies, {1} policy items" -f $polCsvResult.Policies,$polCsvResult.PolicyItems) 'INFO'
      }
      catch{
        Write-Log ("EXPORT: Secret policies CSV generation failed: {0}" -f $_.Exception.Message) 'ERROR'
      }
    }

    # Generate ZIP if ExportZip is checked
    if([bool]$Global:Config.Src.ExportZip){
      Write-Log "EXPORT: Creating ZIP bundle..." 'INFO'
      
      $exportDir = Split-Path -Parent $Global:Config.ExportFile
      $zipPath = Create-ExportZip -SourceDir $exportDir -ZipOutDir $exportDir
      
      if($zipPath){
        Write-Log ("EXPORT: ZIP bundle created: {0}" -f $zipPath) 'INFO'
      }
    }

    $sw.Stop()
    Write-Log ("EXPORT: Completed. Exported {0} secrets. Elapsed={1}" -f $cnt,$sw.Elapsed) 'INFO'
    
    $successMsg = "Export completed!`n`nSecrets exported: $cnt`nElapsed: $($sw.Elapsed)"
    
    $additionalFiles = @()
    if([bool]$Global:Config.Src.ExportXml){
      $additionalFiles += "XML file"
    }
    if([bool]$Global:Config.Src.ExportCsv){
      $additionalFiles += "CSV bundle"
    }
    if([bool]$Global:Config.Src.ExportZip){
      $additionalFiles += "ZIP archive"
    }
    
    if($additionalFiles.Count -gt 0){
      $successMsg += "`n`nAdditional files generated:`n"
      foreach($file in $additionalFiles){
        $successMsg += "- $file`n"
      }
    }
    
    [System.Windows.Forms.MessageBox]::Show(
      $successMsg,
      "Export Complete",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
  }
  catch{
    Write-Log ("EXPORT ERROR: {0}" -f ($_ | Out-String)) 'ERROR'
    [System.Windows.Forms.MessageBox]::Show(
      "Export failed: $($_.Exception.Message)",
      "Export Error",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
  }
  finally{
    $btnExport.Enabled = $true
    $tabs.SelectedTab = $tabActions
  }
})

$btnImport.Add_Click({
  $started = Get-Date
  try{
    $btnImport.Enabled = $false
    
    ReadControls
    
    # Validation
    if(-not (Validate-ImportUI)){ return }
    
    # Check if export file exists
    if(-not (Test-Path $Global:Config.ExportFile)){
      [System.Windows.Forms.MessageBox]::Show(
        "Export file not found:`n$($Global:Config.ExportFile)`n`nPlease run Export first or select a valid export JSON file.",
        "Import Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
      ) | Out-Null
      return
    }
    
    $isDryRun = [bool]$Global:Config.Tgt.DryRun
    
    if($isDryRun){
      Write-Log "========================================" 'INFO'
      Write-Log "DRY-RUN MODE: Import will simulate only" 'INFO'
      Write-Log "========================================" 'INFO'
    }
    
    Log-ConfigSummary 'IMPORT-START'
    
    Write-Log ("IMPORT: Starting import from {0}" -f $Global:Config.ExportFile) 'INFO'
    Write-Log ("IMPORT: Target API: {0}" -f $Global:Config.Tgt.SSApiBase) 'INFO'
    Write-Log ("IMPORT: Folder Tree Migration: {0}" -f $Global:Config.Tgt.FolderTreeMigration) 'INFO'
    Write-Log ("IMPORT: Target Folder ID: {0}" -f $Global:Config.Tgt.TargetFolderId) 'INFO'
    Write-Log ("IMPORT: Target Root Folder ID: {0}" -f $Global:Config.Tgt.TargetRootFolderId) 'INFO'
    Write-Log ("IMPORT: Dry Run: {0}" -f $isDryRun) 'INFO'
    
    # Get tokens - CRITICAL: Get both tokens before calling Import-SS
    $srcTok = $null
    $tgtTok = $null
    
    try{
      Write-Log "IMPORT: Obtaining Source token..." 'DEBUG'
      $srcTok = Token Src $tbSrcPwd
      Write-Log "IMPORT: Source token obtained successfully" 'DEBUG'
    }
    catch{
      Write-Log ("IMPORT: Source token failed (may be OK if not needed): {0}" -f $_.Exception.Message) 'WARN'
      # Source token may not be needed for import if we're just reading from JSON
      $srcTok = "DUMMY_TOKEN_NOT_USED"
    }
    
    try{
      Write-Log "IMPORT: Obtaining Target token..." 'DEBUG'
      $tgtTok = Token Tgt $tbTgtPwd
      Write-Log "IMPORT: Target token obtained successfully" 'DEBUG'
    }
    catch{
      $errMsg = "Failed to authenticate to Target tenant: $($_.Exception.Message)"
      Write-Log $errMsg 'ERROR'
      [System.Windows.Forms.MessageBox]::Show(
        $errMsg,
        "Authentication Failed",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
      ) | Out-Null
      return
    }
    
    if([string]::IsNullOrWhiteSpace($tgtTok)){
      $errMsg = "Target token is empty. Check Target credentials."
      Write-Log $errMsg 'ERROR'
      [System.Windows.Forms.MessageBox]::Show($errMsg, "Authentication Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
      return
    }
    
    # Validate target folder exists (if not using folder tree)
    $targetFolderId = [int]$Global:Config.Tgt.TargetFolderId
    $targetRootId = [int]$Global:Config.Tgt.TargetRootFolderId
    $useFolderTree = [bool]$Global:Config.Tgt.FolderTreeMigration
    
    if($useFolderTree){
      if($targetRootId -le 0){ $targetRootId = 1 }
      Write-Log ("IMPORT: Using folder tree mode with root folder ID: {0}" -f $targetRootId) 'INFO'
    }
    else{
      if($targetFolderId -le 0){
        $errMsg = "Target Folder ID is required when Folder Tree Migration is disabled."
        Write-Log $errMsg 'ERROR'
        [System.Windows.Forms.MessageBox]::Show($errMsg, "Configuration Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return
      }
      Write-Log ("IMPORT: Using flat mode with target folder ID: {0}" -f $targetFolderId) 'INFO'
    }
    
    # Reset tracking for this import run
    Reset-ImportTracking
    
    # Call Import-SS with all parameters
    $script:ImportCancelled = $false
    $btnGetCount.Visible = $false
    $btnCancel.Visible = $true
    $btnImport.Enabled = $false
    [System.Windows.Forms.Application]::DoEvents()
    try{
    $result = Import-SS `
      -SrcApiBase $Global:Config.Src.SSApiBase `
      -SrcToken $srcTok `
      -TgtApiBase $Global:Config.Tgt.SSApiBase `
      -TgtToken $tgtTok `
      -InputPath $Global:Config.ExportFile `
      -TargetFolderId $targetFolderId `
      -UseFolderTree $useFolderTree `
      -TargetRootFolderId $targetRootId `
      -OverwriteIfExists ([bool]$Global:Config.Tgt.OverwriteIfExists) `
      -SecretTypeMapByName ([bool]$Global:Config.Tgt.SecretTypeMapByName) `
      -CopyFolderAcls ([bool]$Global:Config.Tgt.CopyFolderAcls) `
      -CopySecretAcls ([bool]$Global:Config.Tgt.CopySecretAcls) `
      -CopySecretSettings ([bool]$Global:Config.Tgt.CopySecretSettings) `
      -CopyAttachments ([bool]$Global:Config.Tgt.CopyAttachments) `
      -RemapPrincipals ([bool]$Global:Config.Tgt.RemapPrincipals) `
      -DryRun $isDryRun `
      -DecryptPasswords ([bool]$cbDecryptPasswords.Checked) `
      -DisableInheritPermissions ([bool]$cbDisableInherit.Checked) `
      -ImportTemplates ([bool]$cbImportTemplates.Checked) `
      -TemplateSuffix ([string]$tbTemplateSuffix.Text) `
      -SyncTemplateFields ([bool]$chkSyncTemplateFields.Checked) `
      -SkipPasswordValidation ([bool]$cbSkipPwdVal.Checked) `
      -StopOnError ([bool]$cbStopOnError.Checked)
    }finally{
      $btnCancel.Visible = $false
      $btnGetCount.Visible = $true
      $btnImport.Enabled = $true
      try{ Hide-ProgressBar }catch{}
      try{ Update-ResumeButtonState }catch{}
      [System.Windows.Forms.Application]::DoEvents()
    }
    
    $elapsed = New-TimeSpan -Start $started -End (Get-Date)
    
    # Check if permission error occurred (returned error instead of throwing)
    $errorMsg = $null
    if($result.PSObject.Properties.Name -contains 'Error'){ $errorMsg = $result.Error }
    if(-not [string]::IsNullOrWhiteSpace($errorMsg)){
      [System.Windows.Forms.MessageBox]::Show(
        $errorMsg,
        "Import Blocked",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
      ) | Out-Null
      return
    }
    
    $summaryMsg = if($isDryRun){
      "DRY-RUN Import simulation completed.`n`n"
    } else {
      "Import completed.`n`n"
    }
    
    $summaryMsg += "Created: $($result.Created)`n"
    $summaryMsg += "Updated: $($result.Updated)`n"
    $summaryMsg += "Skipped: $($result.Skipped)`n"
    
    # Show permission counts if copying ACLs
    $secretACLs = if($result.PSObject.Properties.Name -contains 'SecretACLs'){ $result.SecretACLs } else { 0 }
    $folderACLs = if($result.PSObject.Properties.Name -contains 'FolderACLs'){ $result.FolderACLs } else { 0 }
    
    if($cbSA.Checked -or $cbFA.Checked){
      $summaryMsg += "`nPermissions that would be applied:`n"
      if($cbSA.Checked){
        $summaryMsg += "- Secret ACLs: $secretACLs`n"
      }
      if($cbFA.Checked){
        $summaryMsg += "- Folder ACLs: $folderACLs`n"
      }
    }
    
    $summaryMsg += "`nElapsed: $($elapsed.ToString('hh\:mm\:ss'))"
    
    if($isDryRun){
      $summaryMsg += "`n`nNo changes were made to the target tenant."
    }
    else{
      $summaryMsg += "`n`nTracked for cleanup:`n"
      $summaryMsg += "- Folders: $($script:ImportRunCreatedFolderIds.Count)`n"
      $summaryMsg += "- Secrets: $($script:ImportRunCreatedSecretIds.Count)`n"
      $summaryMsg += "- Permissions: $($script:ImportRunAppliedFolderPermissions.Count + $script:ImportRunAppliedSecretPermissions.Count)"
    }
    
    Write-Log ("IMPORT: Complete. Created={0}, Updated={1}, Skipped={2}, Elapsed={3}" -f $result.Created,$result.Updated,$result.Skipped,$elapsed) 'INFO'
    
    [System.Windows.Forms.MessageBox]::Show(
      $summaryMsg,
      $(if($isDryRun){"Dry-Run Complete"}else{"Import Complete"}),
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    
  }
  catch{
    $errMsg = $_.Exception.Message
    Write-Log ("IMPORT ERROR: {0}" -f $errMsg) 'ERROR'
    [System.Windows.Forms.MessageBox]::Show(
      "Import failed: $errMsg",
      "Import Error",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
  }
  finally{
    $btnImport.Enabled = $true
    $elapsed = New-TimeSpan -Start $started -End (Get-Date)
    Write-Log ("IMPORT: Task completed. Total elapsed={0:c}" -f $elapsed) 'INFO'
    $tabs.SelectedTab = $tabActions
  }
})
Populate $Global:Config
if([string]::IsNullOrWhiteSpace($tbTokenPath.Text)){ $tbTokenPath.Text='/oauth2/token' }

Apply-Theme 'Ocean'
Update-SelectionDetails
# Initialize enabled state on startup
Update-SourceTargetEnabledState
# Validate critical objects before showing form
if(-not $script:LogTextBox){
  throw "CRITICAL: LogTextBox not initialized. Script cannot continue."
}

if(-not $Global:Config){
  throw "CRITICAL: Config not loaded. Script cannot continue."
}

Write-Log "Delinea Migration Tool started successfully." 'INFO'
# =========================
# FINAL OVERRIDES (KEEP LAST)
# These ensure Import uses the correct payload shape.
# =========================

function Resolve-TargetTemplateId([string]$tgtApiBase,[string]$tgtTok,$exportSecret,[bool]$MapByName){
  $srcId = Get-PropValue $exportSecret @('SecretTypeId','secretTypeId') $null
  $srcName = Get-PropValue $exportSecret @('SecretTypeName','secretTypeName') $null

  if($MapByName -and -not [string]::IsNullOrWhiteSpace([string]$srcName)){
    $idx = Get-TemplateNameIndex -apiBase $tgtApiBase -tok $tgtTok
    if($idx.ContainsKey($srcName.ToLowerInvariant())){
      return [int]$idx[$srcName.ToLowerInvariant()]
    }
  }

  return $srcId
}

function New-SSItemObject([int]$fieldId,[string]$value){
  @{
    secretTemplateFieldId = $fieldId
    itemValue             = $value
  }
}

# Function to check for resumable export/import and update button labels
function Update-ResumeButtonState {
  # Check for partial export (auto-resume)
  # NOTE: Only read first 4KB of file to check _ExportInProgress flag (avoids parsing 300MB+ JSON)
  try{
    $exportFile = $Global:Config.ExportFile
    if($exportFile -and (Test-Path $exportFile)){
      $inProgress = $false
      $fs = [System.IO.File]::OpenRead($exportFile)
      try{
        $buf = New-Object byte[] 4096
        $bytesRead = $fs.Read($buf, 0, $buf.Length)
        $header = [System.Text.Encoding]::UTF8.GetString($buf, 0, $bytesRead)
        $inProgress = $header -match '"_ExportInProgress"\s*:\s*true'
      }finally{ $fs.Close() }
      if($inProgress){
        $btnExport.Text = "Resume Export"
        $btnExport.BackColor = [System.Drawing.Color]::FromArgb(218, 128, 0)
        $btnExport.ForeColor = [System.Drawing.Color]::White
        $btnExport.FlatStyle = 'Flat'
      } else {
        $btnExport.Text = "Export"
        $btnExport.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
        $btnExport.ForeColor = [System.Drawing.Color]::White
        $btnExport.FlatStyle = 'Flat'
      }
    }
  }catch{}

  # Check for partial import
  try{
    $exportFile = $Global:Config.ExportFile
    if($exportFile){
      $importProgressFile = $exportFile -replace '\.json$', '-import-progress.json'
      if(Test-Path $importProgressFile){
        $btnImport.Text = "Resume Import"
        $btnImport.BackColor = [System.Drawing.Color]::FromArgb(218, 128, 0)
        $btnImport.ForeColor = [System.Drawing.Color]::White
        $btnImport.FlatStyle = 'Flat'
      } else {
        $btnImport.Text = "Import"
        $btnImport.BackColor = [System.Drawing.Color]::FromArgb(0, 153, 188)
        $btnImport.ForeColor = [System.Drawing.Color]::White
        $btnImport.FlatStyle = 'Flat'
      }
    }
  }catch{}
}

# Check resume state on form load
$form.Add_Shown({ Update-ResumeButtonState })

# ============================================================================
# RECONCILIATION TAB
# ----------------------------------------------------------------------------
# Fact-based comparison + delta migration.
#  - Source scope: $Global:Config.Src.FolderId + $Global:Config.Src.SearchText
#  - Target scope: $Global:Config.Tgt.TargetRootFolderId
#  - Match key: lowercase("{FolderPath}|{SecretName}")
#  - Two flows:
#       1) Reconcile Missing Secrets   (creates missing source secrets on target,
#                                       attachments come along via CopyAttachments)
#       2) Reconcile Attachments Only  (for already-matched secrets, uploads any
#                                       file-field whose target side is empty)
# Reuses existing helpers: Get-AllFoldersRecursive-BFS, Get-AllSecretsPaged-Parallel,
# SS-GetFieldBytes, Test-SecretFileFieldHasContent, Upload-SecretFieldFile-MultipartPS51,
# Export-SS-DirectToXml, Import-SS.
# ============================================================================

function Reconcile-BuildFolderPathMap([string]$apiBase,[string]$tok){
  $null = Get-AllFoldersRecursive-BFS -ApiBase $apiBase -Tok $tok
  $map = @{}
  if($script:LastFolderDetailsMap){
    foreach($kv in $script:LastFolderDetailsMap.GetEnumerator()){
      $map[[int]$kv.Key] = [string]$kv.Value.Path
    }
  }
  return $map
}

function Reconcile-GetSubtreeFolderIds([hashtable]$folderPathMap,[int]$rootFolderId){
  $set = New-Object 'System.Collections.Generic.HashSet[int]'
  if($rootFolderId -le 0){
    foreach($k in $folderPathMap.Keys){ [void]$set.Add([int]$k) }
    return $set
  }
  [void]$set.Add([int]$rootFolderId)
  $rootPath = [string]$folderPathMap[[int]$rootFolderId]
  if([string]::IsNullOrWhiteSpace($rootPath)){ return $set }
  $p1 = $rootPath.TrimEnd('\').TrimEnd('/') + '\'
  $p2 = $rootPath.TrimEnd('\').TrimEnd('/') + '/'
  foreach($kv in $folderPathMap.GetEnumerator()){
    $fp = [string]$kv.Value
    if([string]::IsNullOrWhiteSpace($fp)){ continue }
    if($fp.Equals($rootPath,[System.StringComparison]::OrdinalIgnoreCase) -or `
       $fp.StartsWith($p1,[System.StringComparison]::OrdinalIgnoreCase) -or `
       $fp.StartsWith($p2,[System.StringComparison]::OrdinalIgnoreCase)){
      [void]$set.Add([int]$kv.Key)
    }
  }
  return $set
}

function Reconcile-NormalizeKey([string]$folderPath,[string]$secretName){
  $fp = if($folderPath){ ($folderPath -replace '/','\').Trim().TrimStart('\').TrimEnd('\').ToLowerInvariant() } else { '' }
  $nm = if($secretName){ $secretName.Trim().ToLowerInvariant() } else { '' }
  return "$fp|$nm"
}

function Reconcile-BuildTenantIndex([string]$apiBase,[string]$tok,[int]$rootFolderId,[string]$searchText,[string]$label,[string]$keyPrefix=''){
  Write-Log ("RECONCILE ({0}): building folder path map..." -f $label) 'INFO'
  try{ Recon-AppendLog ("[{0}] building folder path map (lists all folders the API user can see)..." -f $label) } catch {}
  try{ [System.Windows.Forms.Application]::DoEvents() } catch {}
  $__swFolderMap = [System.Diagnostics.Stopwatch]::StartNew()
  $folderPathMap = Reconcile-BuildFolderPathMap -apiBase $apiBase -tok $tok
  $__swFolderMap.Stop()
  Write-Log ("RECONCILE ({0}): folder map has {1} entries" -f $label,$folderPathMap.Count) 'INFO'
  try{ Recon-AppendLog ("[{0}] folder map built: {1} folders in {2:N1}s" -f $label,$folderPathMap.Count,$__swFolderMap.Elapsed.TotalSeconds) } catch {}

  $inScope = Reconcile-GetSubtreeFolderIds -folderPathMap $folderPathMap -rootFolderId $rootFolderId
  Write-Log ("RECONCILE ({0}): subtree under rootFolderId={1} = {2} folders" -f $label,$rootFolderId,$inScope.Count) 'INFO'
  try{ Recon-AppendLog ("[{0}] subtree under rootFolderId={1}: {2} folders in scope" -f $label,$rootFolderId,$inScope.Count) } catch {}

  # Root folder absolute path - used to compute folder paths RELATIVE to the configured root.
  # This way source key (\Migration Test\Foo) matches target key (\TargetRoot\Migration Test\Foo)
  # because both reduce to "\Migration Test\Foo" after stripping their respective root prefix.
  $rootPath = ''
  if($rootFolderId -gt 0 -and $folderPathMap.ContainsKey($rootFolderId)){
    $rootPath = [string]$folderPathMap[$rootFolderId]
  }
  if($rootPath){ Write-Log ("RECONCILE ({0}): rootPath='{1}' will be stripped from match keys" -f $label,$rootPath) 'INFO' }

  $st = if([string]::IsNullOrWhiteSpace($searchText)){ '*' } else { $searchText }
  Write-Log ("RECONCILE ({0}): fetching secrets (searchText='{1}')..." -f $label,$st) 'INFO'
  try{ Recon-AppendLog ("[{0}] fetching secrets from API (this may take a while for large tenants)..." -f $label) } catch {}

  $__reconLastHeartbeat = [System.Diagnostics.Stopwatch]::StartNew()
  $__reconLabel = $label
  $progressCb = {
    param($pg,$pgCount,$totalSoFar,$apiTotal)
    $pct = if($apiTotal -gt 0){ [int][Math]::Min(95,[Math]::Round(($totalSoFar / $apiTotal) * 100)) } else { 50 }
    $msg = if($apiTotal -gt 0){
      ("Reconcile ({0}): {1}/{2} secrets fetched (page {3})..." -f $__reconLabel,$totalSoFar,$apiTotal,$pg)
    } else {
      ("Reconcile ({0}): {1} secrets fetched (page {2})..." -f $__reconLabel,$totalSoFar,$pg)
    }
    try{ Update-ProgressBar -Current $pct -Total 100 -StatusText $msg }catch{}
    if($__reconLastHeartbeat.Elapsed.TotalSeconds -ge 3){
      try{ Recon-AppendLog ("  [{0}] page {1} done. running total = {2}{3}" -f $__reconLabel,$pg,$totalSoFar,$(if($apiTotal -gt 0){ " / $apiTotal" } else { '' })) } catch {}
      $__reconLastHeartbeat.Restart()
    }
    try{ [System.Windows.Forms.Application]::DoEvents() } catch {}
  }.GetNewClosure()
  $allRecs = Get-AllSecretsPaged-Parallel -ApiBase $apiBase -Token $tok -SearchText $st -PageSize 500 -ConcurrentPages 5 -OnProgress $progressCb
  try{ Recon-AppendLog ("[{0}] secret fetch complete: {1} total records returned by API." -f $label,@($allRecs).Count) } catch {}

  $idx = @{}
  $dupsList = New-Object System.Collections.ArrayList   # records that share a key with an already-indexed record
  $rootPathNorm = if($rootPath){ ($rootPath -replace '/','\').TrimEnd('\') } else { '' }
  $rawInScope = 0
  $dupCollapsed = 0
  foreach($rec in $allRecs){
    $sid = 0; $fid = 0; $nm = $null
    try{ $sid = [int](Get-PropValue $rec @('id','Id','secretId','SecretId') 0) } catch {}
    try{ $fid = [int](Get-PropValue $rec @('folderId','FolderId') 0) } catch {}
    try{ $nm  = [string](Get-PropValue $rec @('name','Name','secretName','SecretName') $null) } catch {}
    if($sid -le 0 -or [string]::IsNullOrWhiteSpace($nm)){ continue }
    if($rootFolderId -gt 0 -and -not $inScope.Contains($fid)){ continue }
    $rawInScope++
    $fp = if($folderPathMap.ContainsKey($fid)){ [string]$folderPathMap[$fid] } else { '' }
    # Compute relative path (strip root prefix) for match key; keep absolute for display.
    $fpNorm = ($fp -replace '/','\').TrimEnd('\')
    $relFp  = $fpNorm
    if($rootPathNorm -and $fpNorm.Equals($rootPathNorm,[System.StringComparison]::OrdinalIgnoreCase)){
      $relFp = ''
    } elseif($rootPathNorm -and $fpNorm.StartsWith($rootPathNorm + '\',[System.StringComparison]::OrdinalIgnoreCase)){
      $relFp = $fpNorm.Substring($rootPathNorm.Length)
    }
    # Optional key prefix: prepended to RelFolderPath BEFORE keying so that a
    # source tree imported under a wrapper folder on target (e.g. '\Abcd\...')
    # can be matched without requiring TargetRootFolderId to point at the
    # wrapper. The prefix is only joined into the match key, not stored in
    # FolderPath/RelFolderPath so display still shows the real folder path.
    $keyRelFp = $relFp
    if(-not [string]::IsNullOrWhiteSpace($keyPrefix)){
      $kp = $keyPrefix.Trim().Trim('\').Trim('/')
      if($kp){
        $rel = $relFp.TrimStart('\').TrimStart('/')
        if([string]::IsNullOrWhiteSpace($rel)){ $keyRelFp = '\' + $kp }
        else { $keyRelFp = '\' + $kp + '\' + $rel }
      }
    }
    $key = Reconcile-NormalizeKey $keyRelFp $nm
    if(-not $idx.ContainsKey($key)){
      $idx[$key] = [pscustomobject]@{
        Id = $sid; Name = $nm; FolderId = $fid; FolderPath = $fp; RelFolderPath = $relFp
      }
    } else {
      $dupCollapsed++
      $first = $idx[$key]
      [void]$dupsList.Add([pscustomobject]@{
        Key=$key; RelFolderPath=$relFp; FolderPath=$fp; Name=$nm
        FirstId=$first.Id; FirstFolderId=$first.FolderId
        DuplicateId=$sid; DuplicateFolderId=$fid
      })
    }
  }
  Write-Log ("RECONCILE ({0}): raw secrets in scope = {1}, unique by (relFolderPath|name) = {2}, duplicates collapsed = {3}" -f $label,$rawInScope,$idx.Count,$dupCollapsed) 'INFO'
  # Surface duplicates list to caller via script-scope variable keyed by label
  $dupArr = @($dupsList)
  if($label -ieq 'Source'){ $script:ReconLastDuplicates_Source = $dupArr }
  elseif($label -ieq 'Target'){ $script:ReconLastDuplicates_Target = $dupArr }
  try{ Set-Variable -Name ("ReconLastDuplicates_{0}" -f $label) -Value $dupArr -Scope Script } catch {}
  Write-Log ("RECONCILE ({0}): duplicate records captured = {1}" -f $label,$dupArr.Count) 'INFO'
  return $idx
}

function Reconcile-ReconcileAttachmentsForPair([string]$srcApi,[string]$srcTok,[string]$tgtApi,[string]$tgtTok,[int]$srcSid,[int]$tgtSid){
  $uploaded = 0
  $errors   = 0
  try{
    $secret = SS $srcApi GET ("secrets/{0}" -f $srcSid) $srcTok $null $null
    $items  = @(Get-PropValue $secret @('items','Items','fields','Fields') @())
    foreach($it in $items){
      $isFile = $false
      try{ $isFile = [bool](Get-PropValue $it @('isFile','IsFile') $false) } catch {}
      if(-not $isFile){ continue }
      $slug = [string](Get-PropValue $it @('slug','Slug','fieldSlugName','FieldSlugName') $null)
      if([string]::IsNullOrWhiteSpace($slug)){ continue }

      if(-not (Test-SecretFileFieldHasContent -apiBase $srcApi -tok $srcTok -secretId $srcSid -slug $slug)){
        continue
      }
      if(Test-SecretFileFieldHasContent -apiBase $tgtApi -tok $tgtTok -secretId $tgtSid -slug $slug){
        Write-Log ("RECONCILE ATTACH: skip srcSid={0} tgtSid={1} slug='{2}' (target already has content)" -f $srcSid,$tgtSid,$slug) 'DEBUG'
        continue
      }
      $bytes = $null
      try{
        $bytes = SS-GetFieldBytes -apiBase $srcApi -tok $srcTok -secretId $srcSid -slug $slug
      } catch {
        Write-Log ("RECONCILE ATTACH: download failed srcSid={0} slug='{1}': {2}" -f $srcSid,$slug,$_.Exception.Message) 'WARN'
        $errors++; continue
      }
      if(-not $bytes -or $bytes.Length -le 0){
        Write-Log ("RECONCILE ATTACH: no bytes for srcSid={0} slug='{1}'; skipping" -f $srcSid,$slug) 'WARN'
        continue
      }
      $fn = [string](Get-PropValue $it @('filename','fileName','FileName') $null)
      if([string]::IsNullOrWhiteSpace($fn)){ $fn = "$slug.bin" }
      # Stage reconcile attachment temp files under <BaseDir>\Reconciliation\tmp
      # (BaseDir follows Settings root folder).
      $__reconTmpDir = Join-Path (Join-Path $script:BaseDir 'Reconciliation') 'tmp'
      try{ if(-not (Test-Path $__reconTmpDir)){ New-Item -ItemType Directory -Path $__reconTmpDir -Force | Out-Null } } catch {}
      $tmp = Join-Path $__reconTmpDir ("recon-attach-" + [guid]::NewGuid().ToString('n') + "-" + $fn)
      try{
        [IO.File]::WriteAllBytes($tmp,$bytes)
        Upload-SecretFieldFile-MultipartPS51 -apiBase $tgtApi -tok $tgtTok -secretId $tgtSid -fieldSlug $slug -filePath $tmp
        Write-Log ("RECONCILE ATTACH: uploaded {0} bytes srcSid={1} -> tgtSid={2} slug='{3}'" -f $bytes.Length,$srcSid,$tgtSid,$slug) 'INFO'
        $uploaded++
      } catch {
        Write-Log ("RECONCILE ATTACH: upload failed tgtSid={0} slug='{1}': {2}" -f $tgtSid,$slug,$_.Exception.Message) 'ERROR'
        $errors++
      } finally {
        try{ if(Test-Path $tmp){ Remove-Item $tmp -Force -ErrorAction SilentlyContinue } } catch {}
      }
    }
  } catch {
    Write-Log ("RECONCILE ATTACH: failed for srcSid={0} tgtSid={1}: {2}" -f $srcSid,$tgtSid,$_.Exception.Message) 'WARN'
  }
  return [pscustomobject]@{ Uploaded=$uploaded; Errors=$errors }
}

# ---------- Reconciliation Tab UI ----------
$tabReconcile = New-Object System.Windows.Forms.TabPage
$tabReconcile.Text = 'Reconciliation'
$tabs.Controls.Add($tabReconcile)

$reconPanel = New-Object System.Windows.Forms.Panel
$reconPanel.Dock = 'Fill'
$reconPanel.AutoScroll = $true
$tabReconcile.Controls.Add($reconPanel)

$yR = 20
$lblReconTitle = New-Object System.Windows.Forms.Label
$lblReconTitle.Text = 'Source >>> Target Reconciliation'
$lblReconTitle.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
$lblReconTitle.Location = Pt 10 $yR
$lblReconTitle.AutoSize = $true
$reconPanel.Controls.Add($lblReconTitle)
$yR += 40

$lblReconDesc = New-Object System.Windows.Forms.Label
$lblReconDesc.Text = 'Compares Source (Src.FolderId + Src.SearchText from Settings) vs Target (Tgt.TargetRootFolderId). Match key = FolderPath + SecretName (case-insensitive). Two actions: import missing secrets (with their attachments), or upload missing attachments for already-migrated secrets.'
$lblReconDesc.Location = Pt 10 $yR
$lblReconDesc.Size = Sz 1180 50
$reconPanel.Controls.Add($lblReconDesc)
$yR += 56

$grpScope = New-Object System.Windows.Forms.GroupBox
$grpScope.Text = 'Scope (from Settings)'
$grpScope.Location = Pt 10 $yR
$grpScope.Size = Sz 1180 60
$reconPanel.Controls.Add($grpScope)

# Single-row layout: Src Root | Src Search (narrow) | Tgt Root | Refresh
$lblReconSrcRoot = New-Object System.Windows.Forms.Label
$lblReconSrcRoot.Text = 'Source Root Folder ID:'
$lblReconSrcRoot.Location = Pt 10 28
$lblReconSrcRoot.AutoSize = $true
$grpScope.Controls.Add($lblReconSrcRoot)
$tbReconSrcRoot = New-Object System.Windows.Forms.TextBox
$tbReconSrcRoot.Location = Pt 140 25
$tbReconSrcRoot.Size = Sz 70 22
$tbReconSrcRoot.ReadOnly = $true
$grpScope.Controls.Add($tbReconSrcRoot)

$lblReconSrcSearch = New-Object System.Windows.Forms.Label
$lblReconSrcSearch.Text = 'Source Search:'
$lblReconSrcSearch.Location = Pt 225 28
$lblReconSrcSearch.AutoSize = $true
$grpScope.Controls.Add($lblReconSrcSearch)
$tbReconSrcSearch = New-Object System.Windows.Forms.TextBox
$tbReconSrcSearch.Location = Pt 320 25
$tbReconSrcSearch.Size = Sz 170 22
$tbReconSrcSearch.ReadOnly = $true
$grpScope.Controls.Add($tbReconSrcSearch)

$lblReconTgtRoot = New-Object System.Windows.Forms.Label
$lblReconTgtRoot.Text = 'Target Root Folder ID:'
$lblReconTgtRoot.Location = Pt 500 28
$lblReconTgtRoot.AutoSize = $true
$grpScope.Controls.Add($lblReconTgtRoot)
$tbReconTgtRoot = New-Object System.Windows.Forms.TextBox
$tbReconTgtRoot.Location = Pt 640 25
$tbReconTgtRoot.Size = Sz 70 22
$tbReconTgtRoot.ReadOnly = $true
$grpScope.Controls.Add($tbReconTgtRoot)

$btnReconRefresh = New-Object System.Windows.Forms.Button
$btnReconRefresh.Text = 'Refresh from Settings'
$btnReconRefresh.Location = Pt 730 23
$btnReconRefresh.Size = Sz 170 28
$grpScope.Controls.Add($btnReconRefresh)

$yR += 70

$btnReconPreview = New-Object System.Windows.Forms.Button
$btnReconPreview.Text = '1. Preview Differences'
$btnReconPreview.Location = Pt 10 $yR
$btnReconPreview.Size = Sz 175 36
$btnReconPreview.BackColor = [System.Drawing.Color]::FromArgb(0,153,188)
$btnReconPreview.ForeColor = [System.Drawing.Color]::White
$btnReconPreview.FlatStyle = 'Flat'
$btnReconPreview.Tag = 'KeepColor'
$reconPanel.Controls.Add($btnReconPreview)

$btnReconMissing = New-Object System.Windows.Forms.Button
$btnReconMissing.Text = '2. Missing Secrets'
$btnReconMissing.Location = Pt 190 $yR
$btnReconMissing.Size = Sz 175 36
$btnReconMissing.BackColor = [System.Drawing.Color]::FromArgb(6,176,37)
$btnReconMissing.ForeColor = [System.Drawing.Color]::White
$btnReconMissing.FlatStyle = 'Flat'
$btnReconMissing.Tag = 'KeepColor'
$btnReconMissing.Enabled = $false
$reconPanel.Controls.Add($btnReconMissing)

$btnReconAttach = New-Object System.Windows.Forms.Button
$btnReconAttach.Text = '3. Missing Attachments'
$btnReconAttach.Location = Pt 370 $yR
$btnReconAttach.Size = Sz 175 36
$btnReconAttach.BackColor = [System.Drawing.Color]::FromArgb(218,128,0)
$btnReconAttach.ForeColor = [System.Drawing.Color]::White
$btnReconAttach.FlatStyle = 'Flat'
$btnReconAttach.Tag = 'KeepColor'
$btnReconAttach.Enabled = $false
$reconPanel.Controls.Add($btnReconAttach)

# 4. Reconcile Missing Permissions: re-applies SecretPermissions / FolderPermissions
# from the big-bang export JSON (Settings -> Export File) to ALREADY-IMPORTED
# secrets on the target. Uses Import-SS-Recon with DuplicateSecretAction=Skip so
# no secret create/update happens; only ACLs are pushed onto existing matches.
$btnReconPerms = New-Object System.Windows.Forms.Button
$btnReconPerms.Text = '4. Missing Permissions'
$btnReconPerms.Location = Pt 550 $yR
$btnReconPerms.Size = Sz 175 36
$btnReconPerms.BackColor = [System.Drawing.Color]::FromArgb(120,80,180)
$btnReconPerms.ForeColor = [System.Drawing.Color]::White
$btnReconPerms.FlatStyle = 'Flat'
$btnReconPerms.Tag = 'KeepColor'
$reconPanel.Controls.Add($btnReconPerms)

# Cancel button - cancels the currently running Reconcile action (Preview / Missing / Attach / Perms).
# Sets cooperative cancellation flags that are checked at safe points in the loops.
$btnReconCancel = New-Object System.Windows.Forms.Button
$btnReconCancel.Text = 'Cancel'
$btnReconCancel.Location = Pt 740 $yR
$btnReconCancel.Size = Sz 90 36
$btnReconCancel.BackColor = [System.Drawing.Color]::FromArgb(180,40,40)
$btnReconCancel.ForeColor = [System.Drawing.Color]::White
$btnReconCancel.FlatStyle = 'Flat'
$btnReconCancel.Tag = 'KeepColor'
$btnReconCancel.Enabled = $false
$reconPanel.Controls.Add($btnReconCancel)

$btnReconClearLog = New-Object System.Windows.Forms.Button
$btnReconClearLog.Text = 'Clear Log'
$btnReconClearLog.Location = Pt 835 $yR
$btnReconClearLog.Size = Sz 90 36
$btnReconClearLog.BackColor = [System.Drawing.Color]::FromArgb(100,100,100)
$btnReconClearLog.ForeColor = [System.Drawing.Color]::White
$btnReconClearLog.FlatStyle = 'Flat'
$btnReconClearLog.Tag = 'KeepColor'
$reconPanel.Controls.Add($btnReconClearLog)

$btnReconClose = New-Object System.Windows.Forms.Button
$btnReconClose.Text = 'Close'
$btnReconClose.Location = Pt 930 $yR
$btnReconClose.Size = Sz 90 36
$btnReconClose.BackColor = [System.Drawing.Color]::FromArgb(180,40,40)
$btnReconClose.ForeColor = [System.Drawing.Color]::White
$btnReconClose.FlatStyle = 'Flat'
$btnReconClose.Tag = 'KeepColor'
$reconPanel.Controls.Add($btnReconClose)

$btnReconClearLog.Add_Click({
  try{ $tbReconLog.Clear() } catch {}
  try{ $lblReconStatus.Text = 'Log cleared.' } catch {}
})

$btnReconClose.Add_Click({
  try{ $form.Close() } catch {}
})

# Cooperative-cancel flag for reconcile loops (preview pagination, attach loop).
$script:ReconCancelled = $false

function Recon-BeginAction([string]$name){
  $script:ReconCancelled    = $false
  $script:ImportCancelled   = $false
  $script:ExportCancelled   = $false
  try{ $btnReconCancel.Enabled  = $true }  catch {}
  try{ $btnReconPreview.Enabled = $false } catch {}
  try{ $btnReconMissing.Enabled = $false } catch {}
  try{ $btnReconAttach.Enabled  = $false } catch {}
  try{ $btnReconPerms.Enabled   = $false } catch {}
  try{ $tbReconTplSfx.Enabled   = $false } catch {}
  Recon-AppendLog ("--- {0} started (click 'Cancel' to stop at next safe checkpoint) ---" -f $name)
}

function Recon-EndAction(){
  try{ $btnReconCancel.Enabled  = $false } catch {}
  try{ $btnReconPreview.Enabled = $true }  catch {}
  try{ $btnReconPerms.Enabled   = $true }  catch {}
  # Missing/Attach buttons follow whatever the last preview decided.
  try{
    if($script:ReconLastMissing -and $script:ReconLastMissing.Count -gt 0){
      $btnReconMissing.Enabled = $true
      $tbReconTplSfx.Enabled   = $true
    }
  } catch {}
  try{
    if($script:ReconLastMatched -and $script:ReconLastMatched.Count -gt 0){ $btnReconAttach.Enabled = $true }
  } catch {}
}

$btnReconCancel.Add_Click({
  $script:ReconCancelled  = $true
  $script:ImportCancelled = $true
  $script:ExportCancelled = $true
  Recon-AppendLog "*** CANCEL requested - reconcile will stop at next safe checkpoint ***"
  try{ $lblReconStatus.Text = 'Cancel requested - waiting for current step to finish...' } catch {}
  try{ $btnReconCancel.Enabled = $false } catch {}
})

# Resume state for Reconcile Missing Permissions (preserved across cancel/resume click).
$script:ReconPermsResume = $null

function Recon-Perms-SetResumeButton(){
  try{
    $btnReconPerms.Text      = '4. Resume Permissions'
    $btnReconPerms.BackColor = [System.Drawing.Color]::FromArgb(60,160,80)
  } catch {}
}
function Recon-Perms-ResetButton(){
  try{
    $btnReconPerms.Text      = '4. Missing Permissions'
    $btnReconPerms.BackColor = [System.Drawing.Color]::FromArgb(120,80,180)
  } catch {}
}

$yR += 46

# Template Suffix: appended to source template names to resolve target match (e.g. 'Windows Account' -> 'Windows Account ABCD'); blank if same.
$lblReconTplSfx = New-Object System.Windows.Forms.Label
$lblReconTplSfx.Text = 'Target Template Suffix:'
$lblReconTplSfx.Location = Pt 10 ($yR + 4)
$lblReconTplSfx.Size = Sz 150 20
$lblReconTplSfx.Font = New-Object System.Drawing.Font('Segoe UI',9)
$reconPanel.Controls.Add($lblReconTplSfx)

$tbReconTplSfx = New-Object System.Windows.Forms.TextBox
$tbReconTplSfx.Location = Pt 165 $yR
$tbReconTplSfx.Size = Sz 160 22
# Disabled until Preview finds missing secrets.
$tbReconTplSfx.Enabled = $false
# Pre-seed from the Import-tab textbox so users who already configured it once don't retype.
try{
  $__seed = [string]$tbTemplateSuffix.Text
  if(-not [string]::IsNullOrWhiteSpace($__seed) -and $__seed -ne 'MIGRATED'){ $tbReconTplSfx.Text = $__seed }
} catch {}
$reconPanel.Controls.Add($tbReconTplSfx)

$lblReconTplSfxHint = New-Object System.Windows.Forms.Label
$lblReconTplSfxHint.Text = "e.g. 'ABCD' -> matches target 'Windows Account ABCD'. Leave blank if target template names match source exactly."
$lblReconTplSfxHint.Location = Pt 335 ($yR + 4)
$lblReconTplSfxHint.Size = Sz 860 20
$lblReconTplSfxHint.Font = New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Italic)
$lblReconTplSfxHint.ForeColor = [System.Drawing.Color]::DimGray
$reconPanel.Controls.Add($lblReconTplSfxHint)

$yR += 28

# Group Mapping CSV: optional; rewrites group/user principals in delta JSON before Import-SS-Recon.
$lblReconGroupMap = New-Object System.Windows.Forms.Label
$lblReconGroupMap.Text = 'Group Mapping CSV:'
$lblReconGroupMap.Location = Pt 10 ($yR + 4)
$lblReconGroupMap.Size = Sz 150 20
$lblReconGroupMap.Font = New-Object System.Drawing.Font('Segoe UI',9)
$reconPanel.Controls.Add($lblReconGroupMap)

$tbReconGroupMap = New-Object System.Windows.Forms.TextBox
$tbReconGroupMap.Location = Pt 165 $yR
$tbReconGroupMap.Size = Sz 600 22
# Default-seed from <BaseDir>\groupsmap.csv if it exists.
try{
  $__gmDefault = Join-Path $script:BaseDir 'groupsmap.csv'
  if(Test-Path $__gmDefault){ $tbReconGroupMap.Text = $__gmDefault }
} catch {}
$reconPanel.Controls.Add($tbReconGroupMap)

$btnBrowseReconGroupMap = New-Object System.Windows.Forms.Button
$btnBrowseReconGroupMap.Text = 'Browse...'
$btnBrowseReconGroupMap.Location = Pt 775 $yR
$btnBrowseReconGroupMap.Size = Sz 90 22
$btnBrowseReconGroupMap.Add_Click({
  $ofd = New-Object System.Windows.Forms.OpenFileDialog
  $ofd.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
  $ofd.Title  = 'Select Group Mapping CSV'
  if($tbReconGroupMap.Text -and (Test-Path $tbReconGroupMap.Text -ErrorAction SilentlyContinue)){
    $ofd.InitialDirectory = Split-Path -Parent $tbReconGroupMap.Text
    $ofd.FileName         = Split-Path -Leaf   $tbReconGroupMap.Text
  } elseif($script:BaseDir -and (Test-Path $script:BaseDir)){
    $ofd.InitialDirectory = $script:BaseDir
  }
  if($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){
    $tbReconGroupMap.Text = $ofd.FileName
  }
})
$reconPanel.Controls.Add($btnBrowseReconGroupMap)

$lblReconGroupMapHint = New-Object System.Windows.Forms.Label
$lblReconGroupMapHint.Text = 'Optional. Update delta JSON before import. Leave blank to skip.'
$lblReconGroupMapHint.Location = Pt 875 ($yR + 4)
$lblReconGroupMapHint.Size = Sz 320 20
$lblReconGroupMapHint.Font = New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Italic)
$lblReconGroupMapHint.ForeColor = [System.Drawing.Color]::DimGray
$reconPanel.Controls.Add($lblReconGroupMapHint)

$yR += 32

# Target Folder Path Prefix: prepended to source FolderPath when walking target hierarchy (e.g. wrapper folder).
$lblReconPathPfx = New-Object System.Windows.Forms.Label
$lblReconPathPfx.Text = 'Target Folder Prefix:'
$lblReconPathPfx.Location = Pt 10 ($yR + 4)
$lblReconPathPfx.Size = Sz 150 20
$lblReconPathPfx.Font = New-Object System.Drawing.Font('Segoe UI',9)
$reconPanel.Controls.Add($lblReconPathPfx)

$tbReconPathPrefix = New-Object System.Windows.Forms.TextBox
$tbReconPathPrefix.Location = Pt 165 $yR
$tbReconPathPrefix.Size = Sz 320 22
$reconPanel.Controls.Add($tbReconPathPrefix)

$lblReconPathPfxHint = New-Object System.Windows.Forms.Label
$lblReconPathPfxHint.Text = "e.g. 'Abcd' -> source '\Foo\Bar' resolves as '\Abcd\Foo\Bar' on target. Leave blank if tree was imported flat at the root."
$lblReconPathPfxHint.Location = Pt 495 ($yR + 4)
$lblReconPathPfxHint.Size = Sz 700 20
$lblReconPathPfxHint.Font = New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Italic)
$lblReconPathPfxHint.ForeColor = [System.Drawing.Color]::DimGray
$reconPanel.Controls.Add($lblReconPathPfxHint)

$yR += 28

# Skip Password Validation: opt-in; adds validatePasswordRequirements=false to CREATE body.
$cbReconSkipPwd = New-Object System.Windows.Forms.CheckBox
$cbReconSkipPwd.Text = 'Skip Password Validation (2.Missing Secrets)'
$cbReconSkipPwd.Location = Pt 165 $yR
$cbReconSkipPwd.Size = Sz 280 22
$cbReconSkipPwd.Checked = $false
$reconPanel.Controls.Add($cbReconSkipPwd)

$lblReconSkipPwdHint = New-Object System.Windows.Forms.Label
$lblReconSkipPwdHint.Text = 'Bypasses target password complexity. Use when source passwords are shorter than target policy (e.g. < 12 chars).'
$lblReconSkipPwdHint.Location = Pt 450 ($yR + 4)
$lblReconSkipPwdHint.Size = Sz 750 20
$lblReconSkipPwdHint.Font = New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Italic)
$lblReconSkipPwdHint.ForeColor = [System.Drawing.Color]::DimGray
$reconPanel.Controls.Add($lblReconSkipPwdHint)

$yR += 28

# Import JSON Path: source for 'Reconcile Missing Permissions' (defaults to Settings -> Export File).
$lblReconPermJson = New-Object System.Windows.Forms.Label
$lblReconPermJson.Text = 'Import JSON Path:'
$lblReconPermJson.Location = Pt 10 ($yR + 4)
$lblReconPermJson.Size = Sz 150 20
$lblReconPermJson.Font = New-Object System.Drawing.Font('Segoe UI',9)
$reconPanel.Controls.Add($lblReconPermJson)

$tbReconPermJson = New-Object System.Windows.Forms.TextBox
$tbReconPermJson.Location = Pt 165 $yR
$tbReconPermJson.Size = Sz 600 22
# Default-seed from $Global:Config.ExportFile (the big-bang import path).
try{
  if($Global:Config -and $Global:Config.ExportFile){ $tbReconPermJson.Text = [string]$Global:Config.ExportFile }
} catch {}
$reconPanel.Controls.Add($tbReconPermJson)

$btnBrowseReconPermJson = New-Object System.Windows.Forms.Button
$btnBrowseReconPermJson.Text = 'Browse...'
$btnBrowseReconPermJson.Location = Pt 775 $yR
$btnBrowseReconPermJson.Size = Sz 90 22
$btnBrowseReconPermJson.Add_Click({
  $ofd = New-Object System.Windows.Forms.OpenFileDialog
  $ofd.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
  $ofd.Title  = 'Select big-bang export JSON for Reconcile Missing Permissions'
  if($tbReconPermJson.Text -and (Test-Path $tbReconPermJson.Text -ErrorAction SilentlyContinue)){
    $ofd.InitialDirectory = Split-Path -Parent $tbReconPermJson.Text
    $ofd.FileName         = Split-Path -Leaf   $tbReconPermJson.Text
  } elseif($script:BaseDir -and (Test-Path $script:BaseDir)){
    $ofd.InitialDirectory = $script:BaseDir
  }
  if($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){
    $tbReconPermJson.Text = $ofd.FileName
  }
})
$reconPanel.Controls.Add($btnBrowseReconPermJson)

$lblReconPermJsonHint = New-Object System.Windows.Forms.Label
$lblReconPermJsonHint.Text = '4. Missing Permissions''. Defaults to Settings -> Export File.'
$lblReconPermJsonHint.Location = Pt 875 ($yR + 4)
$lblReconPermJsonHint.Size = Sz 320 20
$lblReconPermJsonHint.Font = New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Italic)
$lblReconPermJsonHint.ForeColor = [System.Drawing.Color]::DimGray
$reconPanel.Controls.Add($lblReconPermJsonHint)

$yR += 28

$lblReconStatus = New-Object System.Windows.Forms.Label
$lblReconStatus.Text = 'Idle. Click "Preview Differences" to start.'
$lblReconStatus.Location = Pt 10 $yR
$lblReconStatus.Size = Sz 1180 22
$lblReconStatus.Font = New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Italic)
$reconPanel.Controls.Add($lblReconStatus)
$yR += 26

# Mirror of global Update-ProgressBar so user sees progress without switching tabs.
$script:ReconProgressBar = New-Object System.Windows.Forms.Panel
$script:ReconProgressBar.Location = Pt 10 $yR
$script:ReconProgressBar.Size = Sz 1180 24
$script:ReconProgressBar.Tag = 0   # current percent 0..100
$script:ReconProgressBar.Visible = $false
# Enable double buffering to eliminate flicker.
try{
  $__dbP = $script:ReconProgressBar.GetType().GetProperty('DoubleBuffered', `
    [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance)
  if($__dbP){ $__dbP.SetValue($script:ReconProgressBar, $true, $null) }
} catch {}
$reconPanel.Controls.Add($script:ReconProgressBar)

# Shim a Value property so $script:ReconProgressBar.Value = $pct keeps working.
$script:ReconProgressBar | Add-Member -MemberType ScriptProperty -Name Value `
  -Value { [int]$this.Tag } `
  -SecondValue {
    param($v)
    $iv = 0
    try{ $iv = [int]$v } catch {}
    if($iv -lt 0){ $iv = 0 }; if($iv -gt 100){ $iv = 100 }
    $this.Tag = $iv
    $this.Invalidate()
  } -Force

# Paint handler: same look-and-feel as the Actions tab progress bar.
$script:ReconProgressBar.Add_Paint({
  param($sender, $e)
  $g    = $e.Graphics
  $w    = $sender.ClientSize.Width
  $h    = $sender.ClientSize.Height
  $pct  = 0
  try{ $pct = [int]$sender.Tag } catch {}
  if($pct -lt 0){ $pct = 0 }; if($pct -gt 100){ $pct = 100 }

  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit

  # Background (unfilled portion)
  $bgBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(230,230,230))
  $g.FillRectangle($bgBrush, 0, 0, $w, $h)
  $bgBrush.Dispose()

  # Green fill
  $fillW = [int]([Math]::Round(($pct / 100.0) * $w))
  if($fillW -gt 0){
    $fillBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(6,176,37))
    $g.FillRectangle($fillBrush, 0, 0, $fillW, $h)
    $fillBrush.Dispose()
  }

  # Border
  $borderPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(140,140,140))
  $g.DrawRectangle($borderPen, 0, 0, $w - 1, $h - 1)
  $borderPen.Dispose()

  # Centered % text (subtle, for context)
  $pctText = ("{0}%" -f $pct)
  $fmt = New-Object System.Drawing.StringFormat
  $fmt.Alignment     = [System.Drawing.StringAlignment]::Center
  $fmt.LineAlignment = [System.Drawing.StringAlignment]::Center
  $pctFont  = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
  $pctBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(40,40,40))
  $g.DrawString($pctText, $pctFont, $pctBrush, (New-Object System.Drawing.RectangleF 0, 0, $w, $h), $fmt)
  $pctBrush.Dispose(); $pctFont.Dispose(); $fmt.Dispose()

  # Walker visual at the leading edge of the green fill, INSIDE the bar.
  # Preferred: 🚶 emoji with alternating foot dots so the body never jumps.
  # Fallback: text-frame spinner from spinners.json when available.
  try{
    if($script:SpinnerFrames -and $script:SpinnerFrameCount -gt 0){
      $__sIdx = [int]([Math]::Abs([Environment]::TickCount / [Math]::Max(1,$script:SpinnerInterval))) % $script:SpinnerFrameCount
      $__sTxt = [string]$script:SpinnerFrames[$__sIdx]
      $__sFnt = New-Object System.Drawing.Font("Consolas", 11, [System.Drawing.FontStyle]::Bold)
      $__sSz  = $g.MeasureString($__sTxt, $__sFnt)
      $__sX = [single]($fillW - $__sSz.Width / 2.0)
      if($__sX -lt 0){ $__sX = 0 }
      if($__sX + $__sSz.Width -gt $w){ $__sX = [single]($w - $__sSz.Width) }
      $__sY = [single](($h - $__sSz.Height) / 2.0)
      $g.DrawString($__sTxt, $__sFnt, [System.Drawing.Brushes]::Black, $__sX, $__sY)
      $__sFnt.Dispose()
    } elseif($script:RunnerGlyph -and $script:RunnerFont){
      $glyphSize = $g.MeasureString($script:RunnerGlyph, $script:RunnerFont)
      $gw = [single]$glyphSize.Width
      $gh = [single]$glyphSize.Height

      $rx = $fillW - [int]($gw / 2)
      if($rx -lt 0){ $rx = 0 }
      if($rx + $gw -gt $w){ $rx = $w - [int]$gw }
      $ry = [single](($h - $gh) / 2)

      # Body stays still; mirror horizontally so walker faces right.
      $cx = [single]($rx + $gw / 2)
      $cy = [single]($ry + $gh / 2)
      $state = $g.Save()
      $g.TranslateTransform($cx, $cy)
      $g.ScaleTransform(-1.0, 1.0)
      $g.DrawString($script:RunnerGlyph, $script:RunnerFont, [System.Drawing.Brushes]::Black, -($gw / 2), -($gh / 2))
      $g.Restore($state)

      # Alternating foot dots (4-frame cycle).
      $f = $script:RunnerFrame % 4
      $stride = 3.5
      switch($f){
        0 { $offA =  $stride; $offB = -$stride }
        1 { $offA =  0.0;     $offB =  0.0     }
        2 { $offA = -$stride; $offB =  $stride }
        default { $offA = 0.0; $offB = 0.0 }
      }
      $footY = [single]($ry + $gh - 4.0)
      $footW = 4.0
      $footH = 2.5
      $footBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(30,30,30))
      $g.FillEllipse($footBrush, [single]($cx - 1.0 + $offA - $footW/2), $footY, [single]$footW, [single]$footH)
      $g.FillEllipse($footBrush, [single]($cx + 1.0 + $offB - $footW/2), $footY, [single]$footW, [single]$footH)
      $footBrush.Dispose()
    }
  } catch {}
})
$yR += 22

$script:ReconProgressLabel = New-Object System.Windows.Forms.Label
$script:ReconProgressLabel.Location = Pt 10 $yR
$script:ReconProgressLabel.Size = Sz 1180 18
$script:ReconProgressLabel.Text = ''
$script:ReconProgressLabel.Font = New-Object System.Drawing.Font('Segoe UI',9)
$reconPanel.Controls.Add($script:ReconProgressLabel)
$yR += 22

$tbReconLog = New-Object System.Windows.Forms.RichTextBox
$tbReconLog.Multiline = $true
$tbReconLog.ScrollBars = 'Both'
$tbReconLog.ReadOnly = $true
$tbReconLog.WordWrap = $false
$tbReconLog.Font = New-Object System.Drawing.Font('Consolas',9)
$tbReconLog.Location = Pt 10 $yR
$tbReconLog.Size = Sz 1180 380
$reconPanel.Controls.Add($tbReconLog)

$script:ReconLastSrcIdx = $null
$script:ReconLastTgtIdx = $null
$script:ReconLastMissing = @()
$script:ReconLastMatched = @()

# Group/user translation tables populated by Load-GroupMapTranslations.
$script:GroupMapTranslations_Group   = @{}
$script:GroupMapTranslations_User    = @{}
$script:GroupMapTranslations_KnownAs = @{}
$script:GroupMapTranslations_LoadedFrom = $null
$script:TemplateMapBySrcId   = @{}
$script:TemplateMapBySrcName = @{}
$script:TemplateMapLoadedFrom = $null

# Duplicate-record arrays populated by Reconcile-BuildTenantIndex (initialized for StrictMode).
$script:ReconLastDuplicates_Source = @()
$script:ReconLastDuplicates_Target = @()

function Recon-AppendLog([string]$msg){
  try{
    $line = "{0}  {1}" -f (Get-Date -Format 'HH:mm:ss'),$msg
    if($tbReconLog -is [System.Windows.Forms.RichTextBox]){
      # Infer level from message content (ERROR/FAIL red, WARN orange, completion green).
      $defC = $tbReconLog.ForeColor
      $c = $defC
      if($msg -match '(?i)\b(error|failed|fail|exception)\b' -or $msg -match '^\s*ERR\b'){
        $c = [System.Drawing.Color]::FromArgb(220,40,40)
      } elseif($msg -match '(?i)\b(warn|warning|cancel(led)?|skip(ped)?)\b'){
        $c = [System.Drawing.Color]::FromArgb(210,120,0)
      } elseif($msg -match '(?i)\b(done|complete|completed|applied|success|succeeded|created|imported|exported|restored)\b'){
        $c = [System.Drawing.Color]::FromArgb(0,140,0)
      }
      $s = $tbReconLog.TextLength
      $tbReconLog.AppendText($line + "`r`n")
      $tbReconLog.Select($s, ($tbReconLog.TextLength - $s))
      $tbReconLog.SelectionColor = $c
      $tbReconLog.Select($tbReconLog.TextLength, 0)
      $tbReconLog.SelectionColor = $defC
      $tbReconLog.ScrollToCaret()
    } else {
      $tbReconLog.AppendText($line + "`r`n")
    }
  } catch {}
}

function Recon-RefreshScope(){
  try{
    $tbReconSrcRoot.Text   = [string]$Global:Config.Src.FolderId
    $tbReconSrcSearch.Text = [string]$Global:Config.Src.SearchText
    $tbReconTgtRoot.Text   = [string]$Global:Config.Tgt.TargetRootFolderId
  } catch {}
}

$btnReconRefresh.Add_Click({ try{ ReadControls } catch {}; Recon-RefreshScope; Recon-AppendLog "Scope refreshed from Settings." })

$btnReconPreview.Add_Click({
  try{
    ReadControls
    Recon-RefreshScope
    $tbReconLog.Clear()
    $lblReconStatus.Text = 'Preview running...'
    Recon-BeginAction 'Preview Differences'
    Recon-AppendLog "=== PREVIEW: Source vs Target ==="

    $srcApi = [string]$Global:Config.Src.SSApiBase
    $tgtApi = [string]$Global:Config.Tgt.SSApiBase
    $srcRoot = 0; try{ $srcRoot = [int]$Global:Config.Src.FolderId } catch {}
    $tgtRoot = 0; try{ $tgtRoot = [int]$Global:Config.Tgt.TargetRootFolderId } catch {}
    $srcSearch = [string]$Global:Config.Src.SearchText

    $srcTok = $null; $tgtTok = $null
    try{ $srcTok = Token Src $tbSrcPwd } catch { throw "Source authentication failed: $($_.Exception.Message)" }
    try{ $tgtTok = Token Tgt $tbTgtPwd } catch { throw "Target authentication failed: $($_.Exception.Message)" }

    try{ Update-ProgressBar -Current 5 -Total 100 -StatusText "Reconcile: building source index..." } catch {}
    $__srcKeyPrefix = ''
    try{ $__srcKeyPrefix = [string]$tbReconPathPrefix.Text } catch {}
    $__srcKeyPrefix = $__srcKeyPrefix.Trim().Trim('\').Trim('/')
    if(-not [string]::IsNullOrWhiteSpace($__srcKeyPrefix)){
      Recon-AppendLog ("Preview: source RelFolderPath match keys will be prefixed with '\{0}\' to align with target tree." -f $__srcKeyPrefix)
    }
    $srcIdx = Reconcile-BuildTenantIndex -apiBase $srcApi -tok $srcTok -rootFolderId $srcRoot -searchText $srcSearch -label 'Source' -keyPrefix $__srcKeyPrefix
    if($script:ReconCancelled){ Recon-AppendLog "Preview cancelled by user after Source index build."; $lblReconStatus.Text = 'Preview cancelled.'; return }

    try{ Update-ProgressBar -Current 50 -Total 100 -StatusText "Reconcile: building target index..." } catch {}
    $tgtIdx = Reconcile-BuildTenantIndex -apiBase $tgtApi -tok $tgtTok -rootFolderId $tgtRoot -searchText '*' -label 'Target'
    if($script:ReconCancelled){ Recon-AppendLog "Preview cancelled by user after Target index build."; $lblReconStatus.Text = 'Preview cancelled.'; return }

    $missing = New-Object System.Collections.ArrayList
    $matched = New-Object System.Collections.ArrayList
    $tgtOnly = New-Object System.Collections.ArrayList
    foreach($kv in $srcIdx.GetEnumerator()){
      if($tgtIdx.ContainsKey($kv.Key)){
        [void]$matched.Add([pscustomobject]@{
          Key=$kv.Key; SrcId=$kv.Value.Id; TgtId=$tgtIdx[$kv.Key].Id
          Name=$kv.Value.Name; FolderPath=$kv.Value.FolderPath
        })
      } else {
        [void]$missing.Add($kv.Value)
      }
    }

    # Compute target-only set (secrets target has but source doesn't)
    foreach($kv in $tgtIdx.GetEnumerator()){
      if(-not $srcIdx.ContainsKey($kv.Key)){
        [void]$tgtOnly.Add($kv.Value)
      }
    }

    $script:ReconLastSrcIdx  = $srcIdx
    $script:ReconLastTgtIdx  = $tgtIdx
    $script:ReconLastMissing = @($missing)
    $script:ReconLastMatched = @($matched)
    $script:ReconLastTgtOnly = @($tgtOnly)

    # --- Write full CSV reports for offline review ---
    $reportDir = $null
    $missingCsv = $null; $tgtOnlyCsv = $null; $matchedCsv = $null
    try{
      $baseDir = if($script:BaseDir){ [string]$script:BaseDir } else { [System.IO.Path]::GetTempPath() }
      $reportDir = Join-Path $baseDir 'Reconciliation'
      if(-not (Test-Path $reportDir)){ New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
      $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
      $missingCsv = Join-Path $reportDir ("missing_on_target_{0}.csv" -f $stamp)
      $tgtOnlyCsv = Join-Path $reportDir ("target_only_{0}.csv"        -f $stamp)
      $matchedCsv = Join-Path $reportDir ("matched_pairs_{0}.csv"      -f $stamp)
      if($missing.Count -gt 0){
        $missing | Select-Object @{n='RelFolderPath';e={$_.RelFolderPath}},@{n='FolderPath';e={$_.FolderPath}},Name,@{n='SrcId';e={$_.Id}},@{n='SrcFolderId';e={$_.FolderId}} | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $missingCsv
      }
      if($tgtOnly.Count -gt 0){
        $tgtOnly | Select-Object @{n='RelFolderPath';e={$_.RelFolderPath}},@{n='FolderPath';e={$_.FolderPath}},Name,@{n='TgtId';e={$_.Id}},@{n='TgtFolderId';e={$_.FolderId}} | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $tgtOnlyCsv
      }
      if($matched.Count -gt 0){
        $matched | Select-Object Key,Name,FolderPath,SrcId,TgtId | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $matchedCsv
      }
      # Source / Target duplicates (same folder + same name on the same side)
      $srcDupCsv = Join-Path $reportDir ("source_duplicates_{0}.csv" -f $stamp)
      $tgtDupCsv = Join-Path $reportDir ("target_duplicates_{0}.csv" -f $stamp)
      try{
        $srcDups = @($script:ReconLastDuplicates_Source) | Where-Object { $_ -ne $null }
        Recon-AppendLog ("Source duplicate records available for CSV: {0}" -f $srcDups.Count)
        if($srcDups.Count -gt 0){
          $srcDups | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $srcDupCsv
          Recon-AppendLog ("Source has {0} duplicate entries (same RelFolderPath + Name) -> {1}" -f $srcDups.Count,$srcDupCsv)
        }
      } catch { Recon-AppendLog ("WARN: source duplicates CSV failed: {0}" -f $_.Exception.Message) }
      try{
        $tgtDups = @($script:ReconLastDuplicates_Target) | Where-Object { $_ -ne $null }
        Recon-AppendLog ("Target duplicate records available for CSV: {0}" -f $tgtDups.Count)
        if($tgtDups.Count -gt 0){
          $tgtDups | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $tgtDupCsv
          Recon-AppendLog ("Target has {0} duplicate entries (same RelFolderPath + Name) -> {1}" -f $tgtDups.Count,$tgtDupCsv)
        }
      } catch { Recon-AppendLog ("WARN: target duplicates CSV failed: {0}" -f $_.Exception.Message) }
      Recon-AppendLog ("CSV reports written under: {0}" -f $reportDir)

      # Persist preview state so Missing-Secrets / Attachments stay enabled across GUI restarts.
      try{
        $stateJson = Join-Path $reportDir ("recon-preview-state-{0}.json" -f $stamp)
        $statePayload = [ordered]@{
          savedAt    = (Get-Date).ToString('o')
          srcApi     = [string]$Global:Config.Src.SSApiBase
          tgtApi     = [string]$Global:Config.Tgt.SSApiBase
          missing    = @($missing)
          matched    = @($matched)
          tgtOnly    = @($tgtOnly)
          srcCount   = $srcIdx.Count
          tgtCount   = $tgtIdx.Count
        }
        $statePayload | ConvertTo-Json -Depth 8 | Set-Content -Path $stateJson -Encoding UTF8
        Recon-AppendLog ("Preview state saved: {0}" -f $stateJson)
      } catch {
        Recon-AppendLog ("WARN: failed to save preview state JSON: {0}" -f $_.Exception.Message)
      }
    } catch {
      Recon-AppendLog ("WARN: failed to write CSV reports: {0}" -f $_.Exception.Message)
    }

    Recon-AppendLog ("Source secrets in scope (unique): {0}" -f $srcIdx.Count)
    Recon-AppendLog ("Target secrets in scope (unique): {0}" -f $tgtIdx.Count)
    Recon-AppendLog ("Missing on target:                {0}" -f $missing.Count)
    Recon-AppendLog ("Matched (existing both):          {0}" -f $matched.Count)
    Recon-AppendLog ("Target-only (extra on target):    {0}" -f $tgtOnly.Count)
    Recon-AppendLog "NOTE: counts are UNIQUE by (relative folder path | secret name). Duplicates in same folder collapse into 1 entry. Raw counts are in the main log (RECONCILE: raw secrets in scope = N)."
    Recon-AppendLog ""

    # Cap to first 200 lines for GUI responsiveness; CSV report has the complete list.
    if($missing.Count -gt 0){
      $__missCap = 200
      $__missHdr = if($missing.Count -gt $__missCap){
        ("--- First {0} of {1} MISSING secrets on target (path RELATIVE to root). Full list in CSV: {2} ---" -f $__missCap,$missing.Count,$missingCsv)
      } else {
        ("--- ALL {0} MISSING secrets on target (path RELATIVE to root) ---" -f $missing.Count)
      }
      Recon-AppendLog $__missHdr
      $__missShown = 0
      foreach($m in $missing){
        if($__missShown -ge $__missCap){ break }
        $rp = if($m.PSObject.Properties.Match('RelFolderPath').Count -gt 0){ [string]$m.RelFolderPath } else { [string]$m.FolderPath }
        Recon-AppendLog ("  [MISSING] {0}\{1}  (srcId={2}, srcFolderId={3})" -f $rp,$m.Name,$m.Id,$m.FolderId)
        $__missShown++
      }
      if($missing.Count -gt $__missCap){
        Recon-AppendLog ("  ... {0} additional MISSING entries truncated from log; see CSV: {1}" -f ($missing.Count - $__missCap),$missingCsv)
      }
      Recon-AppendLog ""
    }

    # Full list of target-only entries - capped the same way.
    if($tgtOnly.Count -gt 0){
      $__tOnlyCap = 200
      $__tOnlyHdr = if($tgtOnly.Count -gt $__tOnlyCap){
        ("--- First {0} of {1} TARGET-ONLY secrets (exist on target, not in source scope). Full list in CSV: {2} ---" -f $__tOnlyCap,$tgtOnly.Count,$tgtOnlyCsv)
      } else {
        ("--- ALL {0} TARGET-ONLY secrets (exist on target, not in source scope) ---" -f $tgtOnly.Count)
      }
      Recon-AppendLog $__tOnlyHdr
      $__tOnlyShown = 0
      foreach($t in $tgtOnly){
        if($__tOnlyShown -ge $__tOnlyCap){ break }
        $rp = if($t.PSObject.Properties.Match('RelFolderPath').Count -gt 0){ [string]$t.RelFolderPath } else { [string]$t.FolderPath }
        Recon-AppendLog ("  [TGT-ONLY] {0}\{1}  (tgtId={2}, tgtFolderId={3})" -f $rp,$t.Name,$t.Id,$t.FolderId)
        $__tOnlyShown++
      }
      if($tgtOnly.Count -gt $__tOnlyCap){
        Recon-AppendLog ("  ... {0} additional TGT-ONLY entries truncated from log; see CSV: {1}" -f ($tgtOnly.Count - $__tOnlyCap),$tgtOnlyCsv)
      }
      Recon-AppendLog ""
    }

    try{ Update-ProgressBar -Current 100 -Total 100 -StatusText "Reconcile preview complete" } catch {}
    $btnReconMissing.Enabled = ($missing.Count -gt 0)
    try{ $tbReconTplSfx.Enabled = ($missing.Count -gt 0) } catch {}
    $btnReconAttach.Enabled  = ($matched.Count -gt 0)
    $lblReconStatus.Text = "Preview complete. Missing={0}  Matched={1}  TargetOnly={2}" -f $missing.Count,$matched.Count,$tgtOnly.Count

    $popupMsg = ("Preview Complete`r`n`r`nSource in scope (unique): {0}`r`nTarget in scope (unique): {1}`r`nMissing on target:        {2}`r`nMatched (existing both):  {3}`r`nTarget-only (extra):      {4}`r`n`r`nCSV reports:`r`n  {5}`r`n`r`nEnable buttons:`r`n - Reconcile Missing Secrets ({2})`r`n - Reconcile Attachments Only ({3})" -f $srcIdx.Count,$tgtIdx.Count,$missing.Count,$matched.Count,$tgtOnly.Count,$reportDir)
    [System.Windows.Forms.MessageBox]::Show(
      $popupMsg,
      "Reconciliation Preview",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
  } catch {
    $err = "Preview failed: $($_.Exception.Message)"
    Recon-AppendLog $err
    $lblReconStatus.Text = $err
    [System.Windows.Forms.MessageBox]::Show($err,"Reconciliation Preview Failed",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  } finally {
    try{ Hide-ProgressBar } catch {}
    Recon-EndAction
  }
})

$btnReconMissing.Add_Click({
  try{
    if(-not $script:ReconLastMissing -or $script:ReconLastMissing.Count -le 0){
      [System.Windows.Forms.MessageBox]::Show("Nothing to reconcile. Run Preview first.","Reconciliation",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
      return
    }
    $missing = $script:ReconLastMissing
    $confirm = [System.Windows.Forms.MessageBox]::Show(
      ("Import {0} missing secrets to Target (with attachments)?`r`n`r`nThis will run a delta export of just those source secrets and then Import-SS." -f $missing.Count),
      "Confirm Reconcile Missing Secrets",
      [System.Windows.Forms.MessageBoxButtons]::YesNo,
      [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if($confirm -ne [System.Windows.Forms.DialogResult]::Yes){ return }

    Recon-BeginAction 'Reconcile Missing Secrets'
    $lblReconStatus.Text = "Exporting delta XML for missing secrets..."
    Recon-AppendLog ("=== RECONCILE MISSING SECRETS: {0} items ===" -f $missing.Count)

    $srcApi = [string]$Global:Config.Src.SSApiBase
    $tgtApi = [string]$Global:Config.Tgt.SSApiBase
    $tgtRoot = 1; try{ $tgtRoot = [int]$Global:Config.Tgt.TargetRootFolderId } catch {}

    $srcTok = Token Src $tbSrcPwd
    $tgtTok = Token Tgt $tbTgtPwd

    # Save reconcile delta export under <BaseDir>\Reconciliation (next to recon CSV reports).
    $reconOutDir = Join-Path $script:BaseDir 'Reconciliation'
    try{ if(-not (Test-Path $reconOutDir)){ New-Item -ItemType Directory -Path $reconOutDir -Force | Out-Null } } catch {}
    $tmpDeltaXml = Join-Path $reconOutDir ("recon-export-delta-" + (Get-Date -Format 'yyyyMMddHHmmss') + ".json")

    # Build list of just the missing source secret IDs to export directly.
    $missingIds = @()
    foreach($m in $missing){
      try{
        $mid = [int]$m.Id
        if($mid -gt 0){ $missingIds += $mid }
      } catch {}
    }
    if($missingIds.Count -le 0){
      Recon-AppendLog "No valid source IDs in missing list. Aborting."
      $lblReconStatus.Text = "No valid source IDs in missing list."
      return
    }

    Recon-AppendLog ("Running targeted source export for {0} missing secret IDs (this includes attachments)..." -f $missingIds.Count)
    # Mirror Write-Log to the Reconcile tab log box for the entire export+import flow.
    $script:LogMirrorTextBox = $tbReconLog
    $expCount = Export-SS -ApiBase $srcApi -Token $srcTok -OutPath $tmpDeltaXml `
                          -CopyAttachments $true -CopyFolderAcls $true -CopySecretAcls $true -CopySecretSettings $true `
                          -OnlySecretIds $missingIds
    Recon-AppendLog ("Exported {0} source secrets directly to {1}" -f $expCount,$tmpDeltaXml)

    if($expCount -le 0){
      $lblReconStatus.Text = "Nothing to import: export produced 0 secrets."
      Recon-AppendLog "Targeted export produced 0 secrets. Aborting."
      return
    }
    $kept = $expCount

    # ---- Group Mapping CSV (optional): rewrite group/user principals in delta JSON pre-import.
    try{
      $__gmCsv = ''
      try{ $__gmCsv = [string]$tbReconGroupMap.Text } catch {}
      if(-not [string]::IsNullOrWhiteSpace($__gmCsv)){
        if(Test-Path $__gmCsv){
          Recon-AppendLog ("Applying Group Mapping CSV to delta JSON: {0}" -f $__gmCsv)
          $__gmCount = Apply-GroupMapCsvToJson -CsvPath $__gmCsv -JsonPath $tmpDeltaXml -InPlace
          Recon-AppendLog ("Group Mapping CSV applied: {0} total replacements in {1}" -f $__gmCount,$tmpDeltaXml)
        } else {
          Recon-AppendLog ("WARN: Group Mapping CSV not found, skipping remap: {0}" -f $__gmCsv)
        }
      }
    } catch {
      Recon-AppendLog ("WARN: Group Mapping CSV step failed: {0}" -f $_.Exception.Message)
    }

    # ---- Template Mappings CSV: auto-refresh via Compare+Save on Template Check tab, then mirror into Reconciliation folder for Import-SS-Recon override.
    try{
      Recon-AppendLog "Refreshing TemplateMappings.csv (Compare Templates + Save to CSV) before import..."
      $btnCompareTemplates.PerformClick()
      [System.Windows.Forms.Application]::DoEvents()
      $btnSaveMappings.PerformClick()
      [System.Windows.Forms.Application]::DoEvents()
      $__tmCsv = ''
      try{ $__tmCsv = [string]$tbMappingCsv.Text } catch {}
      if(-not [string]::IsNullOrWhiteSpace($__tmCsv) -and (Test-Path $__tmCsv)){
        $__tmReconCsv = Join-Path $reconOutDir 'TemplateMappings.csv'
        Copy-Item -Path $__tmCsv -Destination $__tmReconCsv -Force
        Recon-AppendLog ("Template mapping CSV copied to Reconciliation folder: {0}" -f $__tmReconCsv)
      } else {
        Recon-AppendLog "WARN: Template mapping CSV not produced (check Template Check tab); Import-SS-Recon will fall back to name/suffix matching."
      }
    } catch {
      Recon-AppendLog ("WARN: Template mapping refresh failed: {0}. Continuing with name/suffix matching." -f $_.Exception.Message)
    }

    # Skip Password Validation: opt-in; adds validatePasswordRequirements=false so short passwords migrate verbatim.
    $optSkipPwd  = $false; try{ $optSkipPwd  = [bool]$cbReconSkipPwd.Checked } catch {}
    $optSyncTpl  = $false; try{ $optSyncTpl  = [bool]$chkSyncTemplateFields.Checked } catch {}
    $optStopErr  = $false; try{ $optStopErr  = [bool]$cbStopOnError.Checked } catch {}
    $optTplSfx   = '';     try{ $optTplSfx   = [string]$tbReconTplSfx.Text } catch {}
    if([string]::IsNullOrWhiteSpace($optTplSfx)){
      # Fall back to the Import-tab suffix if the Reconciliation tab textbox is empty
      try{ $optTplSfx = [string]$tbTemplateSuffix.Text } catch {}
    }

    # Honor Import-tab ACL / settings / remap toggles for reconciliation
    $optCopyFolderAcls    = $false; try{ $optCopyFolderAcls    = [bool]$Global:Config.Tgt.CopyFolderAcls    } catch {}
    $optCopySecretAcls    = $false; try{ $optCopySecretAcls    = [bool]$Global:Config.Tgt.CopySecretAcls    } catch {}
    $optCopySecretSettings= $false; try{ $optCopySecretSettings= [bool]$Global:Config.Tgt.CopySecretSettings } catch {}
    $optRemapPrincipals   = $false; try{ $optRemapPrincipals   = [bool]$Global:Config.Tgt.RemapPrincipals   } catch {}

    Recon-AppendLog ("Calling Import-SS-Recon on delta JSON (TemplateSuffix='{0}', SkipPasswordValidation={1}, CopyAttachments=True, CopyFolderAcls={2}, CopySecretAcls={3}, CopySecretSettings={4}, RemapPrincipals={5})..." -f `
        $optTplSfx,$optSkipPwd,$optCopyFolderAcls,$optCopySecretAcls,$optCopySecretSettings,$optRemapPrincipals)
    # Mirror Write-Log into Reconcile tab log box.
    $script:LogMirrorTextBox = $tbReconLog
    try{
      # Use Import-SS-Recon (V13 verbatim Import-SS body) with TemplateSuffix + opt-in SkipPasswordValidation.
      Import-SS-Recon -SrcApiBase $srcApi -SrcToken $srcTok -TgtApiBase $tgtApi -TgtToken $tgtTok `
                -InputPath $tmpDeltaXml -TargetFolderId 0 -UseFolderTree $true -TargetRootFolderId $tgtRoot `
                -OverwriteIfExists $false -SecretTypeMapByName $true -ImportTemplates $false `
                -TemplateSuffix $optTplSfx -SkipPasswordValidation $optSkipPwd `
                -CopyFolderAcls $optCopyFolderAcls -CopySecretAcls $optCopySecretAcls -CopySecretSettings $optCopySecretSettings `
                -CopyAttachments $true -RemapPrincipals $optRemapPrincipals -DryRun $false
      Recon-AppendLog "Import-SS-Recon completed."
      $lblReconStatus.Text = "Reconcile Missing Secrets: complete ($kept imported)"
    } catch {
      Recon-AppendLog ("Import-SS-Recon failed: {0}" -f $_.Exception.Message)
      $lblReconStatus.Text = "Import-SS-Recon failed: $($_.Exception.Message)"
    } finally {
      # Restore template-level password-validation flags (only those originally true); runs regardless of import success.
      try{
        if((Test-Path variable:script:__reconPwdPolicyOriginals) -and $script:__reconPwdPolicyOriginals -and $script:__reconPwdPolicyOriginals.Count -gt 0){
          Recon-AppendLog ("PWDPOLICY: restoring password-validation flags on {0} target template(s)..." -f $script:__reconPwdPolicyOriginals.Count)
          foreach($__tid in @($script:__reconPwdPolicyOriginals.Keys)){
            $__orig = $script:__reconPwdPolicyOriginals[$__tid]
            if(-not ($__orig.create -or $__orig.edit)){ continue }
            try{
              $__base = [string]$__orig.apiBase
              if([string]::IsNullOrWhiteSpace($__base)){ $__base = $tgtApi }
              # SS Cloud has no working REST endpoint to flip these flags; warn for manual UI re-enable.
              Recon-AppendLog ("PWDPOLICY: REMINDER - re-enable Validate-on-Create={2} and Validate-on-Edit={3} on target template id={0} name='{1}' in the SS UI now that the import has finished." -f $__tid,$__orig.name,$__orig.create,$__orig.edit)
            } catch {
              Recon-AppendLog ("PWDPOLICY: FAILED to restore template id={0} name='{1}': {2} - restore manually if needed." -f $__tid,$__orig.name,$_.Exception.Message)
            }
          }
          $script:__reconPwdPolicyOriginals = @{}
        }
      } catch {
        Recon-AppendLog ("PWDPOLICY: restore block error: {0}" -f $_.Exception.Message)
      }
      $script:LogMirrorTextBox = $null
    }
  } catch {
    $err = "Reconcile failed: $($_.Exception.Message)"
    Recon-AppendLog $err
    $lblReconStatus.Text = $err
    [System.Windows.Forms.MessageBox]::Show($err,"Reconcile Failed",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  } finally {
    try{ Hide-ProgressBar } catch {}
    $script:LogMirrorTextBox = $null
    if($script:ReconCancelled){
      Recon-AppendLog 'Reconcile Missing Secrets: CANCELLED by user.'
      try{ $lblReconStatus.Text = 'Reconcile Missing Secrets: cancelled.' } catch {}
    }
    Recon-EndAction
  }
})

$btnReconAttach.Add_Click({
  try{
    if(-not $script:ReconLastMatched -or $script:ReconLastMatched.Count -le 0){
      [System.Windows.Forms.MessageBox]::Show("No matched pairs. Run Preview first.","Reconciliation",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
      return
    }
    $pairs = $script:ReconLastMatched
    $confirm = [System.Windows.Forms.MessageBox]::Show(
      ("Scan {0} matched secrets and upload any attachments that exist on source but are empty on target?" -f $pairs.Count),
      "Confirm Reconcile Attachments Only",
      [System.Windows.Forms.MessageBoxButtons]::YesNo,
      [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if($confirm -ne [System.Windows.Forms.DialogResult]::Yes){ return }

    Recon-BeginAction 'Reconcile Attachments Only'
    # Mirror Write-Log output to the Reconcile tab so the user can watch progress here.
    $script:LogMirrorTextBox = $tbReconLog

    $srcApi = [string]$Global:Config.Src.SSApiBase
    $tgtApi = [string]$Global:Config.Tgt.SSApiBase
    $srcTok = Token Src $tbSrcPwd
    $tgtTok = Token Tgt $tbTgtPwd

    $totUp = 0; $totErr = 0; $i = 0; $totScanned = 0
    $__pauseUntil = [DateTime]::MinValue
    foreach($pair in $pairs){
      if($script:ReconCancelled){
        Recon-AppendLog ("Cancelled by user at pair {0}/{1}." -f $i,$pairs.Count)
        break
      }
      $i++
      $pct = [int][Math]::Round(($i / $pairs.Count) * 100)
      try{ Update-ProgressBar -Current $pct -Total 100 -StatusText ("Reconcile Attachments: {0}/{1}" -f $i,$pairs.Count) } catch {}

      # If a prior refresh failed and we're in cooldown, idle here until the
      # cooldown elapses (token endpoint rate-limit recovery window).
      while([DateTime]::UtcNow -lt $__pauseUntil){
        if($script:ReconCancelled){ break }
        try{ [System.Windows.Forms.Application]::DoEvents() } catch {}
        Start-Sleep -Milliseconds 1000
      }
      if($script:ReconCancelled){
        Recon-AppendLog ("Cancelled by user during token cooldown at pair {0}/{1}." -f $i,$pairs.Count)
        break
      }

      # Sync local token from global cache every pair: if the SS wrapper
      # auto-refreshed (it updates $Global:TokenCache), pick up the new value
      # for the raw HttpWebRequest helpers used inside Reconcile-ReconcileAttachmentsForPair.
      try{
        if($Global:TokenCache.Src -and $Global:TokenCache.Src.access_token){ $srcTok = $Global:TokenCache.Src.access_token }
        if($Global:TokenCache.Tgt -and $Global:TokenCache.Tgt.access_token){ $tgtTok = $Global:TokenCache.Tgt.access_token }
      } catch {}

      # Preemptive token refresh every 50 pairs (no-op if still valid, refreshes
      # 5 min before actual expiry per GetTokenObj buffer).
      if(($i % 50) -eq 0){
        try{
          Update-MigrationTokens -SrcRef ([ref]$srcTok) -TgtRef ([ref]$tgtTok) -Reason 'recon-attach periodic'
        } catch {
          # Refresh failed (likely SS Cloud token rate limit). Cool down for 60s
          # before continuing - much better than failing every subsequent pair.
          $__pauseUntil = [DateTime]::UtcNow.AddSeconds(60)
          Recon-AppendLog ("  WARN: token refresh failed at pair {0}: {1}" -f $i,$_.Exception.Message)
          Recon-AppendLog ("  -> cooling down for 60s before resuming. If this repeats, the SS Cloud token endpoint is rate-limiting; consider pausing the run.")
        }
      }

      # Per-pair 401 detect-and-retry (raw HttpWebRequest paths inside
      # SS-GetFieldBytes / Upload-SecretFieldFile-MultipartPS51 do NOT
      # auto-refresh, so we wrap the call here).
      $r = $null
      try{
        $r = Invoke-WithTokenRetry -Context ("recon-attach pair {0}/{1} '{2}'" -f $i,$pairs.Count,$pair.Name) `
              -SrcRef ([ref]$srcTok) -TgtRef ([ref]$tgtTok) `
              -Action { Reconcile-ReconcileAttachmentsForPair -srcApi $srcApi -srcTok $srcTok -tgtApi $tgtApi -tgtTok $tgtTok -srcSid $pair.SrcId -tgtSid $pair.TgtId }
      } catch {
        $__emsg = [string]$_.Exception.Message
        Recon-AppendLog ("  [{0}/{1}] ERROR '{2}': {3}" -f $i,$pairs.Count,$pair.Name,$__emsg)
        $r = [pscustomobject]@{ Uploaded = 0; Errors = 1 }
        # If the error was an auth failure (refresh-during-retry threw), enter
        # cooldown so we don't hammer the token endpoint pair after pair.
        if(Test-IsTokenAuthError $__emsg -or $__emsg -match 'Authentication failed'){
          $__pauseUntil = [DateTime]::UtcNow.AddSeconds(60)
          Recon-AppendLog ("  -> auth failure detected, cooling down for 60s.")
        }
      }

      if($r.Uploaded -gt 0 -or $r.Errors -gt 0){
        Recon-AppendLog ("  [{0}/{1}] {2}: uploaded={3} errors={4}" -f $i,$pairs.Count,$pair.Name,$r.Uploaded,$r.Errors)
      }
      $totUp  += $r.Uploaded
      $totErr += $r.Errors
      $totScanned++
      # Heartbeat: log progress every 25 pairs (and the very first one) so the
      # user can see the loop is alive even when most pairs have nothing to do.
      if($i -eq 1 -or ($i % 25) -eq 0 -or $i -eq $pairs.Count){
        Recon-AppendLog ("  [{0}/{1}] scanned (running totals: uploaded={2} errors={3}) - current: '{4}'" -f $i,$pairs.Count,$totUp,$totErr,$pair.Name)
      }
      # Pump GUI events so the Cancel button click can be processed mid-loop.
      try{ [System.Windows.Forms.Application]::DoEvents() } catch {}
    }
    Recon-AppendLog ("=== ATTACHMENT RECONCILE DONE: scanned={0}  uploaded={1}  errors={2} ===" -f $totScanned,$totUp,$totErr)
    $lblReconStatus.Text = "Attachments uploaded=$totUp  errors=$totErr"
    [System.Windows.Forms.MessageBox]::Show(
      ("Attachment reconciliation complete.`r`nUploaded: {0}`r`nErrors:   {1}" -f $totUp,$totErr),
      "Reconcile Attachments",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
  } catch {
    $err = "Attachment reconcile failed: $($_.Exception.Message)"
    Recon-AppendLog $err
    $lblReconStatus.Text = $err
    [System.Windows.Forms.MessageBox]::Show($err,"Reconcile Attachments Failed",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  } finally {
    try{ Hide-ProgressBar } catch {}
    $script:LogMirrorTextBox = $null
    Recon-EndAction
  }
})

$form.Add_Shown({ try{ Recon-RefreshScope } catch {} })

# ---- Reconcile Missing Permissions handler: per secret -> resolve folder, find by name, Apply-SecretShares only. Optional Group Mapping CSV applied first.
$btnReconPerms.Add_Click({
  try{
    $jsonPath = ''
    try{ $jsonPath = [string]$tbReconPermJson.Text } catch {}
    if([string]::IsNullOrWhiteSpace($jsonPath)){
      try{ $jsonPath = [string]$Global:Config.ExportFile } catch {}
    }
    if([string]::IsNullOrWhiteSpace($jsonPath) -or -not (Test-Path $jsonPath)){
      [System.Windows.Forms.MessageBox]::Show(
        "Import JSON path is empty or file not found:`r`n`r`n$jsonPath`r`n`r`nSet 'Import JSON Path' on the Reconciliation tab (or Settings -> Export File) and try again.",
        "Reconcile Missing Permissions",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
      return
    }

    # Detect Resume: if prior run cancelled and JSON path matches, skip prompt and continue counters.
    $isResume     = $false
    $resumeStart  = 0
    $resumeMatched=0; $resumeApplied=0; $resumeNoperms=0; $resumeMissing=0; $resumeErrors=0
    if($script:ReconPermsResume -ne $null){
      try{
        $prevJson = [string]$script:ReconPermsResume.JsonPath
        if($prevJson -and ($prevJson -ieq $jsonPath)){
          $isResume      = $true
          $resumeStart   = [int]$script:ReconPermsResume.StartIdx
          $resumeMatched = [int]$script:ReconPermsResume.Matched
          $resumeApplied = [int]$script:ReconPermsResume.Applied
          $resumeNoperms = [int]$script:ReconPermsResume.NoPerms
          $resumeMissing = [int]$script:ReconPermsResume.Missing
          $resumeErrors  = [int]$script:ReconPermsResume.Errors
        }
      } catch {}
    }

    if(-not $isResume){
      $confirm = [System.Windows.Forms.MessageBox]::Show(
        ("Re-apply SecretPermissions from`r`n  {0}`r`nto already-imported target secrets?`r`n`r`nNo secrets will be created or updated - only ACLs." -f $jsonPath),
        "Confirm Reconcile Missing Permissions",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
      )
      if($confirm -ne [System.Windows.Forms.DialogResult]::Yes){ return }
    }

    Recon-BeginAction $(if($isResume){ 'Resume Missing Permissions' } else { 'Reconcile Missing Permissions' })
    if($isResume){
      Recon-AppendLog ("=== RESUMING from secret index {0} (prior counts: matched={1} applied={2} missing={3} noperms={4} errors={5}) ===" -f $resumeStart,$resumeMatched,$resumeApplied,$resumeMissing,$resumeNoperms,$resumeErrors)
    }
    $script:LogMirrorTextBox = $tbReconLog
    Recon-AppendLog ("=== RECONCILE MISSING PERMISSIONS: source JSON = {0} ===" -f $jsonPath)

    $tgtApi = [string]$Global:Config.Tgt.SSApiBase
    $tgtRoot = 1; try{ $tgtRoot = [int]$Global:Config.Tgt.TargetRootFolderId } catch {}
    $tgtTok = Token Tgt $tbTgtPwd

    # ---- Optional Group Mapping CSV: rewrite principals BEFORE ACLs (work on a copy of JSON).
    $workJson = $jsonPath
    try{
      $__gmCsv = ''
      try{ $__gmCsv = [string]$tbReconGroupMap.Text } catch {}
      if(-not [string]::IsNullOrWhiteSpace($__gmCsv)){
        if(Test-Path $__gmCsv){
          $reconOutDir = Join-Path $script:BaseDir 'Reconciliation'
          try{ if(-not (Test-Path $reconOutDir)){ New-Item -ItemType Directory -Path $reconOutDir -Force | Out-Null } } catch {}
          $workJson = Join-Path $reconOutDir ("recon-perms-mapped-" + (Get-Date -Format 'yyyyMMddHHmmss') + ".json")
          Copy-Item -LiteralPath $jsonPath -Destination $workJson -Force
          Recon-AppendLog ("Applying Group Mapping CSV to working JSON copy: {0}" -f $__gmCsv)
          $__gmCount = Apply-GroupMapCsvToJson -CsvPath $__gmCsv -JsonPath $workJson -InPlace
          Recon-AppendLog ("Group Mapping CSV applied: {0} total replacements in {1}" -f $__gmCount,$workJson)
        } else {
          Recon-AppendLog ("WARN: Group Mapping CSV not found, skipping remap: {0}" -f $__gmCsv)
        }
      }
    } catch {
      Recon-AppendLog ("WARN: Group Mapping CSV step failed: {0}" -f $_.Exception.Message)
    }

    $__jsonSizeMB = 0.0
    try{ $__jsonSizeMB = [math]::Round((Get-Item -LiteralPath $workJson).Length / 1MB, 1) } catch {}
    Recon-AppendLog ("Reading JSON: {0} ({1} MB) using fast JavaScriptSerializer path..." -f $workJson,$__jsonSizeMB)
    try{ [System.Windows.Forms.Application]::DoEvents() } catch {}
    $__swJson = [System.Diagnostics.Stopwatch]::StartNew()
    $inObj = Read-LargeJsonAsPSObject -Path $workJson
    $__swJson.Stop()
    Recon-AppendLog ("JSON deserialized in {0:N1}s." -f $__swJson.Elapsed.TotalSeconds)
    $secrets = @()
    try{
      if($inObj.PSObject.Properties.Name -contains 'Secrets'){ $secrets = @($inObj.Secrets) }
      elseif($inObj.PSObject.Properties.Name -contains 'secrets'){ $secrets = @($inObj.secrets) }
      elseif($inObj -is [System.Collections.IEnumerable]){ $secrets = @($inObj) }
    } catch {}
    Recon-AppendLog ("Loaded {0} secret entries from JSON. Beginning per-secret reconcile (each secret requires target folder lookup + name index build; first occurrences in each folder are slower due to API calls)." -f $secrets.Count)
    try{
      $__pfxLog = ''
      try{ $__pfxLog = [string]$tbReconPathPrefix.Text } catch {}
      $__pfxLog = $__pfxLog.Trim().Trim('\').Trim('/')
      if(-not [string]::IsNullOrWhiteSpace($__pfxLog)){
        Recon-AppendLog ("Target folder prefix: '{0}' - will be prepended to every source FolderPath before walking the target tree (walk root = TargetRootFolderId={1})." -f $__pfxLog,$tgtRoot)
      } else {
        Recon-AppendLog ("No target folder prefix set. Walking from TargetRootFolderId={0}." -f $tgtRoot)
      }
    } catch {}
    try{ [System.Windows.Forms.Application]::DoEvents() } catch {}

    # PERF: bulk pre-load tenant-wide secret name->id index; rebuilt if prior preload did not finish cleanly.
    if(-not (Get-Variable -Name 'ReconGlobalSecretNameCache' -Scope Script -ErrorAction SilentlyContinue)){
      $script:ReconGlobalSecretNameCache = @{}
    }
    if(-not (Get-Variable -Name 'ReconGlobalSecretFolderCache' -Scope Script -ErrorAction SilentlyContinue)){
      $script:ReconGlobalSecretFolderCache = @{}
    }
    if(-not (Get-Variable -Name 'ReconGlobalSecretNameCacheComplete' -Scope Script -ErrorAction SilentlyContinue)){
      $script:ReconGlobalSecretNameCacheComplete = $false
    }
    # Reuse cache only when prior preload finished cleanly; else nuke and reload.
    $__reuseCache = ($script:ReconGlobalSecretNameCacheComplete -and $script:ReconGlobalSecretNameCache.Count -ge 100)
    if(-not $__reuseCache){
      if($script:ReconGlobalSecretNameCache.Count -gt 0){
        Recon-AppendLog ("Discarding incomplete target secret name cache ({0} entries) and rebuilding..." -f $script:ReconGlobalSecretNameCache.Count)
        $script:ReconGlobalSecretNameCache = @{}
        $script:ReconGlobalSecretFolderCache = @{}
      }
      $script:ReconGlobalSecretNameCacheComplete = $false
      Recon-AppendLog "Pre-loading target tenant secret name->id index (one bulk sweep, parallel paged)..."
      try{ [System.Windows.Forms.Application]::DoEvents() } catch {}
      $__swBulk = [System.Diagnostics.Stopwatch]::StartNew()
      $__bulkRecs = @()
      $__bulkOk = $false
      try{
        # OnlyActive=$false so cache mirrors what tenant-wide search finds.
        $__bulkRecs = @(Get-AllSecretsPaged-Parallel `
          -ApiBase $tgtApi -Token $tgtTok `
          -SearchText '' -PageSize 500 -MaxPages 500 -ConcurrentPages 5 -OnlyActive $false `
          -OnProgress {
            param($p,$pc,$ac,$tot)
            if(($p % 5) -eq 0 -or $p -eq 1){
              Recon-AppendLog ("  bulk-load: page {0} (+{1} recs, total so far {2}/{3})" -f $p,$pc,$ac,$tot)
              try{ [System.Windows.Forms.Application]::DoEvents() } catch {}
            }
          })
        $__bulkOk = $true
      } catch {
        Recon-AppendLog ("WARN: bulk pre-load failed ({0}); falling back to per-secret tenant-wide lookups." -f $_.Exception.Message)
      }
      $__swBulk.Stop()
      $__ambig = @{}
      foreach($__bs in $__bulkRecs){
        $__bn = $null
        foreach($__nk in @('name','Name','secretName','SecretName')){
          if($__bs.PSObject.Properties.Name -contains $__nk){ $__bn = [string]$__bs.$__nk; if($__bn){ break } }
        }
        $__bid = 0
        foreach($__ik in @('id','Id','secretId','SecretId')){
          if($__bs.PSObject.Properties.Name -contains $__ik){ try{ $__bid = [int]$__bs.$__ik } catch {}; if($__bid -gt 0){ break } }
        }
        $__bfid = 0
        foreach($__fk in @('folderId','FolderId')){
          if($__bs.PSObject.Properties.Name -contains $__fk){ try{ $__bfid = [int]$__bs.$__fk } catch {}; break }
        }
        if($__bid -le 0 -or [string]::IsNullOrWhiteSpace($__bn)){ continue }
        $__k = $__bn.Trim().ToLowerInvariant()
        if($__ambig.ContainsKey($__k)){
          # Duplicate name on target - mark ambiguous (=0) so per-secret falls back to folder-aware search.
          $script:ReconGlobalSecretNameCache[$__k] = 0
        } else {
          $__ambig[$__k] = $true
          $script:ReconGlobalSecretNameCache[$__k] = $__bid
          $script:ReconGlobalSecretFolderCache[$__k] = $__bfid
        }
      }
      Recon-AppendLog ("Pre-loaded {0} target secret records into name cache ({1} unique names, {2} ambiguous) in {3:N1}s." -f `
          $__bulkRecs.Count,$script:ReconGlobalSecretNameCache.Count,(@($script:ReconGlobalSecretNameCache.Values | Where-Object { $_ -eq 0 }).Count),$__swBulk.Elapsed.TotalSeconds)
      # Mark complete only on clean finish (no exception, no cancel, >0 recs).
      if($__bulkOk -and -not $script:ReconCancelled -and $__bulkRecs.Count -gt 0){
        $script:ReconGlobalSecretNameCacheComplete = $true
      } else {
        Recon-AppendLog "  cache marked INCOMPLETE - will rebuild on next reconcile click."
      }
      try{ [System.Windows.Forms.Application]::DoEvents() } catch {}
    } else {
      Recon-AppendLog ("Reusing pre-loaded target secret name cache ({0} entries, marked complete) from previous run." -f $script:ReconGlobalSecretNameCache.Count)
    }

    # Per-folder caches: folder path -> target folder id; folder id -> name->id index.
    $folderPathToId    = @{}
    $folderSecretIndex = @{}

    $total   = $secrets.Count
    $matched = $resumeMatched
    $missing = $resumeMissing
    $applied = $resumeApplied
    $noperms = $resumeNoperms
    $errors  = $resumeErrors
    $skipped = 0
    $idx = 0

    # Parallel apply batching: queue per-secret work items and dispatch their
    # bulk-share POSTs concurrently. Cuts wall-clock from ~one HTTP round-trip
    # per secret to ~one round-trip per batch of $batchSize.
    $pendingBatch  = New-Object 'System.Collections.Generic.List[hashtable]'
    $batchSize     = 8
    $flushBatch = {
      if($pendingBatch.Count -eq 0){ return }
      try{
        $batchResults = Apply-SecretShares-Batch-Parallel $tgtApi $tgtTok $pendingBatch.ToArray() ([ref]$tgtTok)
        for($__bi=0; $__bi -lt $batchResults.Count; $__bi++){
          $__itm = $pendingBatch[$__bi]
          $__r   = $batchResults[$__bi]
          if($__r.Ok){
            $script:__applied = ($script:__applied + 1)
            if($script:__applied -le 25 -or ($script:__applied % 50) -eq 0){
              Recon-AppendLog ("  [{0}/{1}] applied {2}/{3} perms to secretId={4} ('{5}')" -f $__itm.Idx,$total,$__itm.TodoCount,$__itm.OrigCount,$__itm.SecretId,$__itm.SecName)
            }
          } else {
            $script:__errors = ($script:__errors + 1)
            Recon-AppendLog ("  [{0}/{1}] ERR secretId={2} ('{3}'): {4}" -f $__itm.Idx,$total,$__itm.SecretId,$__itm.SecName,$__r.Error)
          }
        }
      } catch {
        foreach($__itm in $pendingBatch){
          $script:__errors = ($script:__errors + 1)
          Recon-AppendLog ("  [{0}/{1}] ERR secretId={2} ('{3}'): batch failed: {4}" -f $__itm.Idx,$total,$__itm.SecretId,$__itm.SecName,$_.Exception.Message)
        }
      }
      $pendingBatch.Clear()
      # Mirror script-scope counters used by flush back to the local loop variables.
      $script:__applied_out = $script:__applied
      $script:__errors_out  = $script:__errors
    }
    # The flush scriptblock runs in script scope; bridge counters via $script:__applied/$script:__errors.
    $script:__applied = $applied
    $script:__errors  = $errors

    foreach($sec in $secrets){
      if($script:ReconCancelled){
        # Flush any pending work so 'applied' counts only finished items.
        try{ & $flushBatch } catch {}
        $applied = $script:__applied
        $errors  = $script:__errors
        Recon-AppendLog ("Cancelled by user at {0}/{1}. Click 'Resume Permissions' to continue from here." -f $idx,$total)
        $script:ReconPermsResume = @{
          JsonPath = $jsonPath
          StartIdx = $idx
          Total    = $total
          Matched  = $matched
          Applied  = $applied
          NoPerms  = $noperms
          Missing  = $missing
          Errors   = $errors
        }
        Recon-Perms-SetResumeButton
        break
      }
      $idx++
      # Skip already-processed secrets when resuming.
      if($idx -le $resumeStart){ continue }
      if(($idx % 5) -eq 0 -or $idx -eq $total -or $idx -eq 1){
        $pct = [int][Math]::Round(($idx / [double][Math]::Max(1,$total)) * 100)
        try{ Update-ProgressBar -Current $pct -Total 100 -StatusText ("Reconcile Missing Permissions: {0}/{1}" -f $idx,$total) } catch {}
        try{ [System.Windows.Forms.Application]::DoEvents() } catch {}
      }

      # Preemptive token refresh every 100 secrets (no-op if still valid). The
      # parallel batch dispatcher also handles 401 reactively via [ref]$tgtTok,
      # but a preemptive refresh keeps that retry path cold.
      if(($idx % 100) -eq 0){
        try{ Update-MigrationTokens -TgtRef ([ref]$tgtTok) -Reason 'recon-perms periodic' } catch {
          Recon-AppendLog ("  WARN: periodic target token refresh failed at idx {0}: {1}" -f $idx,$_.Exception.Message)
        }
      }

      $secName = [string](Get-PropValue $sec @('Name','name','SecretName','secretName') $null)
      if([string]::IsNullOrWhiteSpace($secName)){ continue }
      $srcFolderPath = [string](Get-PropValue $sec @('FolderPath','folderPath') '')

      # Optional UI-supplied target folder prefix (e.g. 'Abcd' wrapper folder).
      $pathPrefix = ''
      try{ $pathPrefix = [string]$tbReconPathPrefix.Text } catch {}
      $pathPrefix = $pathPrefix.Trim().Trim('\').Trim('/')

      # Candidate paths to try: (A) prefix+source, (B) source as-is, (C) source with prefix stripped.
      $srcRaw = $srcFolderPath.Trim().Trim('\').Trim('/')
      $candidatePaths = New-Object System.Collections.ArrayList
      if(-not [string]::IsNullOrWhiteSpace($pathPrefix)){
        $withPfx = if([string]::IsNullOrWhiteSpace($srcRaw)){ $pathPrefix } else { ($pathPrefix + '\' + $srcRaw) }
        [void]$candidatePaths.Add($withPfx)
      }
      [void]$candidatePaths.Add($srcRaw)
      if(-not [string]::IsNullOrWhiteSpace($pathPrefix) -and -not [string]::IsNullOrWhiteSpace($srcRaw)){
        $pfxLead = ($pathPrefix + '\').ToLowerInvariant()
        if($srcRaw.ToLowerInvariant().StartsWith($pfxLead)){
          $stripped = $srcRaw.Substring($pfxLead.Length)
          if(-not [string]::IsNullOrWhiteSpace($stripped)){ [void]$candidatePaths.Add($stripped) }
        }
      }

      # Resolve target folder id (no creation). Empty/blank path -> root.
      $tgtFolderId = 0
      $resolvedPath = ''
      foreach($candPath in $candidatePaths){
        $folderKey = $candPath.Trim().Trim('\').Trim('/').ToLowerInvariant()
        if(-not $folderPathToId.ContainsKey($folderKey)){
          $resolvedId = 0
          if([string]::IsNullOrWhiteSpace($folderKey)){
            $resolvedId = $tgtRoot
          } else {
            $cur = $tgtRoot
            $segs = $folderKey.Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)
            $ok = $true
            foreach($seg in $segs){
              try{
                $found = Find-FolderByNameUnderParent -TgtApiBase $tgtApi -TgtTok $tgtTok -ParentFolderId $cur -FolderName $seg
              } catch { $found = 0 }
              if(-not $found -or $found -le 0){ $ok = $false; break }
              $cur = [int]$found
            }
            if($ok){ $resolvedId = $cur }
          }
          $folderPathToId[$folderKey] = $resolvedId
        }
        $tryId = [int]$folderPathToId[$folderKey]
        if($tryId -gt 0){ $tgtFolderId = $tryId; $resolvedPath = $candPath; break }
      }

      # Skip folder-scoped step if source folder did not resolve; tenant-wide name match still runs below.
      $haveFolder = ($tgtFolderId -gt 0)
      if(-not $haveFolder){
        if($idx -le 5 -or ($idx % 100) -eq 0){
          Recon-AppendLog ("  [{0}/{1}] folder not on target for '{2}' (tried: {3}); will try tenant-wide name lookup" -f $idx,$total,$secName,(@($candidatePaths) -join ' | '))
        }
      }

      # Build / reuse the secret-name index for this folder.
      $nameIdx = @{}

      $tgtSecretId = 0
      $cacheKey = $secName.Trim().ToLowerInvariant()

      # FAST PATH: global name cache hit = 0 API calls; ambiguous (=0) falls through to folder-scoped index.
      if($script:ReconGlobalSecretNameCache.ContainsKey($cacheKey)){
        $__cached = [int]$script:ReconGlobalSecretNameCache[$cacheKey]
        if($__cached -gt 0){ $tgtSecretId = $__cached }
      }

      # Folder-scoped lookup: only when global cache missed or returned ambiguous=0.
      if($tgtSecretId -le 0 -and $haveFolder){
        $fkey = [string]$tgtFolderId
        if(-not $folderSecretIndex.ContainsKey($fkey)){
          try{
            $folderSecretIndex[$fkey] = Get-SecretNameIndexForFolder -apiBase $tgtApi -tok $tgtTok -folderId $tgtFolderId
          } catch {
            Recon-AppendLog ("  [{0}/{1}] WARN folder {2}: index build failed: {3}" -f $idx,$total,$tgtFolderId,$_.Exception.Message)
            $folderSecretIndex[$fkey] = @{}
          }
        }
        $nameIdx = $folderSecretIndex[$fkey]
        foreach($nv in @($cacheKey, $secName.ToLowerInvariant())){
          if($nameIdx.ContainsKey($nv)){ $tgtSecretId = [int]$nameIdx[$nv]; break }
        }
      }

      # Fallback: tenant-wide name search when both global cache and folder-scoped lookup missed.
      if($tgtSecretId -le 0){
        $needle = $secName.Trim()
        if(-not (Get-Variable -Name 'ReconGlobalSecretNameCache' -Scope Script -ErrorAction SilentlyContinue)){
          $script:ReconGlobalSecretNameCache = @{}
        }
        $globalMatchId = 0
        if($script:ReconGlobalSecretNameCache.ContainsKey($cacheKey)){
          $globalMatchId = [int]$script:ReconGlobalSecretNameCache[$cacheKey]
        } else {
          try{
            $gResp = SS $tgtApi GET 'secrets' $tgtTok $null @{
              'filter.searchText' = $needle
              'filter.pageSize'   = 200
              'filter.page'       = 1
            }
            $gRecs = @(Get-Records $gResp)
            $exactMatches = @()
            foreach($gx in $gRecs){
              $gname = $null
              foreach($nk in @('name','Name','secretName','SecretName')){
                if($gx.PSObject.Properties.Name -contains $nk){ $gname = [string]$gx.$nk; break }
              }
              $gid = 0
              foreach($ik in @('id','Id','secretId','SecretId')){
                if($gx.PSObject.Properties.Name -contains $ik){ try{ $gid = [int]$gx.$ik } catch {}; if($gid -gt 0){ break } }
              }
              if($gid -gt 0 -and $gname -and ($gname.Trim().ToLowerInvariant() -eq $cacheKey)){
                $gfid = 0
                foreach($fk in @('folderId','FolderId')){
                  if($gx.PSObject.Properties.Name -contains $fk){ try{ $gfid = [int]$gx.$fk } catch {}; break }
                }
                $exactMatches += [PSCustomObject]@{ id=$gid; folderId=$gfid }
              }
            }
            if($exactMatches.Count -eq 1){
              $globalMatchId = [int]$exactMatches[0].id
            }
            elseif($exactMatches.Count -gt 1){
              # Multiple matches: prefer same-folder candidate, else leave ambiguous.
              $preferred = $exactMatches | Where-Object { $_.folderId -eq $tgtFolderId } | Select-Object -First 1
              if($preferred){ $globalMatchId = [int]$preferred.id }
              else {
                Recon-AppendLog ("  [{0}/{1}] AMBIGUOUS (multiple targets named '{2}'): ids={3}" -f $idx,$total,$secName,(($exactMatches | ForEach-Object { $_.id }) -join ','))
              }
            }
          } catch {
            Recon-AppendLog ("  [{0}/{1}] global name search failed for '{2}': {3}" -f $idx,$total,$secName,$_.Exception.Message)
          }
          $script:ReconGlobalSecretNameCache[$cacheKey] = $globalMatchId
        }
        if($globalMatchId -gt 0){
          $tgtSecretId = $globalMatchId
          Recon-AppendLog ("  [{0}/{1}] matched '{2}' by tenant-wide name lookup -> secretId={3} (folder-scoped lookup in {4} missed)" -f $idx,$total,$secName,$tgtSecretId,$tgtFolderId)
        }
      }

      if($tgtSecretId -le 0){
        $missing++
        if($missing -le 25 -or ($missing % 50) -eq 0){
          Recon-AppendLog ("  [{0}/{1}] SKIP (no matching target secret): '{2}' in folder {3}" -f $idx,$total,$secName,$tgtFolderId)
        }
        continue
      }
      $matched++

      $secPerms = @(Get-PropValue $sec @('SecretPermissions','secretPermissions') @())
      if($secPerms.Count -le 0){
        $noperms++
        continue
      }

      # Skip-if-already-applied: only on RESUME runs do we fetch existing target
      # shares and filter out perms whose (principal,roleName) tuple is already
      $existingKeys = @{}
      if($isResume){
        try{
          $epResp = SS $tgtApi GET 'secret-permissions' $tgtTok $null @{
            'filter.secretId' = $tgtSecretId
            'filter.page'     = 1
            'filter.pageSize' = 200
          }
          foreach($ep in @(Get-Records $epResp)){
            $epGid = Get-PropValue $ep @('groupId','GroupId') $null
            $epUid = Get-PropValue $ep @('userId','UserId') $null
            $epRn  = [string](Get-PropValue $ep @('secretAccessRoleName','SecretAccessRoleName') '')
            $epRn  = $epRn.Trim().ToLowerInvariant()
            if($epGid -ne $null -and [int]$epGid -gt 0){ $existingKeys[("g{0}:{1}" -f [int]$epGid,$epRn)] = $true }
            elseif($epUid -ne $null -and [int]$epUid -gt 0){ $existingKeys[("u{0}:{1}" -f [int]$epUid,$epRn)] = $true }
          }
        } catch {}
      }

      $todoPerms = @()
      foreach($sp in $secPerms){
        if($existingKeys.Count -eq 0){
          # Fresh run: send every perm, server-side dedupe / Apply-SecretShares handles already-present rows.
          $todoPerms += $sp
          continue
        }
        $spGid = Get-PropValue $sp @('groupId','GroupId') 0
        $spUid = Get-PropValue $sp @('userId','UserId') 0
        $spRn  = [string](Get-PropValue $sp @('secretAccessRoleName','SecretAccessRoleName') '')
        $spRn  = $spRn.Trim().ToLowerInvariant()
        $k = $null
        if([int]$spGid -gt 0){ $k = "g{0}:{1}" -f [int]$spGid,$spRn }
        elseif([int]$spUid -gt 0){ $k = "u{0}:{1}" -f [int]$spUid,$spRn }
        if($k -and -not $existingKeys.ContainsKey($k)){ $todoPerms += $sp }
      }

      if($todoPerms.Count -le 0){
        $skipped++
        if($skipped -le 25 -or ($skipped % 50) -eq 0){
          Recon-AppendLog ("  [{0}/{1}] SKIP (all {2} perms already applied): secretId={3} ('{4}')" -f $idx,$total,$secPerms.Count,$tgtSecretId,$secName)
        }
        continue
      }

      # Queue this secret's apply work; flush when the batch fills up. The flush
      # scriptblock updates $script:__applied / $script:__errors which we mirror
      # back here so cancel/resume captures accurate counts.
      [void]$pendingBatch.Add(@{
        SecretId  = [int]$tgtSecretId
        Perms     = $todoPerms
        SecName   = $secName
        Idx       = $idx
        TodoCount = $todoPerms.Count
        OrigCount = $secPerms.Count
      })
      if($pendingBatch.Count -ge $batchSize){
        & $flushBatch
        $applied = $script:__applied
        $errors  = $script:__errors
      }
    }

    # Drain any remaining queued items after the loop exits normally.
    if($pendingBatch.Count -gt 0 -and -not $script:ReconCancelled){
      & $flushBatch
      $applied = $script:__applied
      $errors  = $script:__errors
    }

    # Only treat as 'done' (clearing resume state + button) when we weren't cancelled.
    if(-not $script:ReconCancelled){
      $script:ReconPermsResume = $null
      Recon-Perms-ResetButton
    }
    $__wasCancelled = [bool]$script:ReconCancelled
    $__headline = if($__wasCancelled){ 'PERMISSIONS RECONCILE PAUSED' } else { 'PERMISSIONS RECONCILE DONE' }
    Recon-AppendLog ("=== {0}: total={1} matched={2} applied={3} skipped-already-applied={4} no-perms-in-json={5} missing-on-target={6} errors={7} ===" -f `
        $__headline,$total,$matched,$applied,$skipped,$noperms,$missing,$errors)
    if($__wasCancelled){
      $lblReconStatus.Text = "Permissions PAUSED at $idx/$total - applied=$applied  errors=$errors  (click 'Resume Permissions' to continue)"
    } else {
      $lblReconStatus.Text = "Missing Permissions: applied=$applied  errors=$errors  missing=$missing"
    }
    $__boxTitle = if($__wasCancelled){ 'Reconcile Missing Permissions - Paused' } else { 'Reconcile Missing Permissions' }
    $__boxBody  = if($__wasCancelled){
      ("Permissions reconcile PAUSED at {0}/{1}.`r`n`r`nMatched so far:        {2}`r`nPermissions applied:   {3}`r`nAlready applied (skip):{4}`r`nNo perms in JSON:      {5}`r`nMissing on target:     {6}`r`nErrors:                {7}`r`n`r`nClick the green 'Resume Permissions' button to continue from where you left off." -f $idx,$total,$matched,$applied,$skipped,$noperms,$missing,$errors)
    } else {
      ("Permissions reconcile complete.`r`n`r`nTotal secrets in JSON: {0}`r`nMatched on target:     {1}`r`nPermissions applied:   {2}`r`nAlready applied (skip):{3}`r`nNo perms in JSON:      {4}`r`nMissing on target:     {5}`r`nErrors:                {6}" -f `
          $total,$matched,$applied,$skipped,$noperms,$missing,$errors)
    }
    [System.Windows.Forms.MessageBox]::Show($__boxBody,$__boxTitle,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
  } catch {
    $err = "Reconcile Missing Permissions failed: $($_.Exception.Message)"
    Recon-AppendLog $err
    $lblReconStatus.Text = $err
    [System.Windows.Forms.MessageBox]::Show($err,"Reconcile Missing Permissions Failed",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
  } finally {
    try{ Hide-ProgressBar } catch {}
    $script:LogMirrorTextBox = $null
    Recon-EndAction
  }
})

[System.Windows.Forms.Application]::EnableVisualStyles()

# Global WinForms exception trap: under StrictMode + $ErrorActionPreference='Stop',
# an undefined-property access inside any Add_Click handler will otherwise tear
# the message-loop down (which looks like "the form closes when I click"). Log
# the failure to a file and show a MessageBox instead of crashing the GUI.
try{
  [System.Windows.Forms.Application]::SetUnhandledExceptionMode([System.Windows.Forms.UnhandledExceptionMode]::CatchException)
  [System.Windows.Forms.Application]::add_ThreadException({
    param($s,$e)
    try{
      $msg = "{0}`n`n{1}" -f $e.Exception.Message,$e.Exception.StackTrace
      $logPath = Join-Path $PSScriptRoot 'gui-error.log'
      ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$msg) | Out-File $logPath -Append -Encoding utf8
      [System.Windows.Forms.MessageBox]::Show($msg,'Handler error',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    } catch {}
  })
} catch {}

# Re-apply theme now that the Reconciliation tab has been fully constructed.
# The initial Apply-Theme call happens earlier (before this tab exists), so
# without this second pass the Reconciliation tab keeps the default WinForms
# light-gray panel and looks inconsistent with the other tabs. Buttons on the
# Recon tab are tagged 'KeepColor' so their custom backgrounds survive.
try{ Apply-Theme 'Ocean' } catch {}

# Restore the most recent recon preview state (if any) so Missing Secrets /
# Attachments / Permissions buttons come up active without forcing the user
# to re-run Preview Differences after every relaunch.
try{
  $__reconDir = $null
  try{ if($script:BaseDir){ $__reconDir = Join-Path ([string]$script:BaseDir) 'Reconciliation' } } catch {}
  if($__reconDir -and (Test-Path $__reconDir)){
    $__stateFile = Get-ChildItem -Path $__reconDir -Filter 'recon-preview-state-*.json' -File -ErrorAction SilentlyContinue |
                     Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if($__stateFile){
      $__state = Get-Content -Raw -Path $__stateFile.FullName | ConvertFrom-Json
      $script:ReconLastMissing = @($__state.missing)
      $script:ReconLastMatched = @($__state.matched)
      $script:ReconLastTgtOnly = @($__state.tgtOnly)
      try{ $btnReconMissing.Enabled = ($script:ReconLastMissing.Count -gt 0) } catch {}
      try{ $tbReconTplSfx.Enabled   = ($script:ReconLastMissing.Count -gt 0) } catch {}
      try{ $btnReconAttach.Enabled  = ($script:ReconLastMatched.Count -gt 0) } catch {}
      try{
        $lblReconStatus.Text = ("Loaded previous preview from {0:yyyy-MM-dd HH:mm} - Missing={1}  Matched={2}  TargetOnly={3}" -f $__stateFile.LastWriteTime,$script:ReconLastMissing.Count,$script:ReconLastMatched.Count,$script:ReconLastTgtOnly.Count)
      } catch {}
      try{ Recon-AppendLog ("Restored preview state from {0} (Missing={1}, Matched={2}, TargetOnly={3})" -f $__stateFile.Name,$script:ReconLastMissing.Count,$script:ReconLastMatched.Count,$script:ReconLastTgtOnly.Count) } catch {}
    }
  }
} catch {
  try{ Recon-AppendLog ("WARN: could not restore previous preview state: {0}" -f $_.Exception.Message) } catch {}
}

[void]$form.ShowDialog()

