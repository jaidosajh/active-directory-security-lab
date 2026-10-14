[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $OutputPath = (Join-Path -Path (Get-Location) -ChildPath 'identity-posture.json')
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domain = Get-ADDomain
$forest = Get-ADForest
$forestRoot = Get-ADDomain -Identity $forest.RootDomain
$passwordPolicy = Get-ADDefaultDomainPasswordPolicy

$groupsToReview = @(
    [pscustomobject]@{ Name = 'Domain Admins'; Sid = "$($domain.DomainSID.Value)-512" },
    [pscustomobject]@{ Name = 'Enterprise Admins'; Sid = "$($forestRoot.DomainSID.Value)-519" },
    [pscustomobject]@{ Name = 'Schema Admins'; Sid = "$($forestRoot.DomainSID.Value)-518" }
)

$groupMembership = foreach ($groupRef in $groupsToReview) {
    try {
        $group = Get-ADGroup -Identity $groupRef.Sid
        $members = @(Get-ADGroupMember -Identity $group -Recursive | Select-Object Name, SamAccountName, ObjectClass)
        [pscustomobject]@{
            GroupName = $group.Name
            GroupSid = $group.SID.Value
            DirectAndNestedMembers = $members
            MemberCount = $members.Count
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        [pscustomobject]@{
            GroupName = $groupRef.Name
            GroupSid = $groupRef.Sid
            DirectAndNestedMembers = @()
            MemberCount = 0
            Note = 'Group not found in the queried domain or forest root.'
        }
    }
}

$domainControllers = @(Get-ADDomainController -Filter * | Select-Object HostName, IPv4Address, Site, IsGlobalCatalog)
$report = [ordered]@{
    GeneratedAtUtc = [DateTime]::UtcNow.ToString('o')
    Scope = 'Read-only inventory of the connected AD domain and forest root.'
    Domain = [ordered]@{
        DnsRoot = $domain.DNSRoot
        DomainMode = [string]$domain.DomainMode
        DistinguishedName = $domain.DistinguishedName
        DomainControllerCount = $domainControllers.Count
        DomainControllers = $domainControllers
    }
    Forest = [ordered]@{
        Name = $forest.Name
        RootDomain = $forest.RootDomain
        ForestMode = [string]$forest.ForestMode
    }
    DefaultPasswordPolicy = [ordered]@{
        ComplexityEnabled = $passwordPolicy.ComplexityEnabled
        MinPasswordLength = $passwordPolicy.MinPasswordLength
        MinPasswordAge = [string]$passwordPolicy.MinPasswordAge
        MaxPasswordAge = [string]$passwordPolicy.MaxPasswordAge
        LockoutThreshold = $passwordPolicy.LockoutThreshold
        LockoutDuration = [string]$passwordPolicy.LockoutDuration
        LockoutObservationWindow = [string]$passwordPolicy.LockoutObservationWindow
        ReversibleEncryptionEnabled = $passwordPolicy.ReversibleEncryptionEnabled
    }
    PrivilegedGroupsForReview = @($groupMembership)
}

$parentPath = Split-Path -Parent $OutputPath
if ($parentPath -and -not (Test-Path -LiteralPath $parentPath)) {
    throw "Output directory does not exist: $parentPath"
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Host "Read-only identity posture report written to $OutputPath"
