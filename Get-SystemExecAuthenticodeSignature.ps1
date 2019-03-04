<#
.SYNOPSIS
Checks the system32 and SysWOW64 directories for their digital signature status.
.PARAMETER Status
An optional parameter; defines what statuses to report on. Can be NotSigned (default), UnknownError, Valid or All.
.PARAMETER OutputFilePath
An optional parameter; defines where to write the results. Default is "C:\temp\"
.EXAMPLE
Get-SystemExecAuthenticodeSignature.ps1 -Status NotSigned -OutputFilePath "C:\temp\"
.NOTES
.DESCRIPTION
Get-SystemExecAuthenticodeSignature is used to check the digital signature of binaries in the
C:\Windows\system32\ and C:\Windows\SysWOW64\ directories. Unsigned binaries in these folders
could be an indication of file transfers to the "admin$" share, which is used by adversaries
for lateral movement between machines. Results are saved by default in "C:\temp\"

Author: Chris Miller
Date Created: 20190228
.EXAMPLE
#>

Param(
    [string]$Status = "NotSigned",
    [string]$OutputFilePath = "C:\temp\"
)

$sys32 = Get-ChildItem "C:\Windows\system32\"
$sys64 = Get-ChildItem "C:\Windows\SysWOW64\"

$SystemDirectories = @($sys32, $sys64)

function CheckExecutableStatus($ExecutableToCheck, $SignatureResult)
{
    $md5 = Get-FileHash -Algorithm MD5 $ExecutableToCheck.FullName
    $sha256 = Get-FileHash -Algorithm SHA256 $ExecutableToCheck.FullName
    $HashedResults = $SignatureResult | Select-Object *, @{n="FileHashMd5"; e={$md5.Hash}}, @{n="FileHashSha256"; e={$sha256.Hash}}
    $JsonifyResults = $HashedResults | ConvertTo-Json -Depth 4
    $JsonifyResults | Out-File -Append $OutputFilePath"\SystemExecSignatureStatus.json"
}

function CheckSignature($directory)
{
    ForEach($ExecutableToCheck in $directory)
    {
        if ((Get-Item $ExecutableToCheck.Fullname) -is [System.IO.DirectoryInfo]){
            continue
        }else{
            $SignatureResult = Get-AuthenticodeSignature $ExecutableToCheck.FullName -ErrorAction SilentlyContinue | Select *
            if ("All" -in $Status){
                CheckExecutableStatus $ExecutableToCheck $SignatureResult
            } elseif ($Status -in $SignatureResult.Status) {
                CheckExecutableStatus $ExecutableToCheck $SignatureResult
            }
        }
    }    
}

function main()
{
    ForEach($directory in $SystemDirectories){
        CheckSignature($directory)
    }
}

main