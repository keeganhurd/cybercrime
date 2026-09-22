$ErrorActionPreference = 'Stop'

$repoRoot = 'C:\Users\thoma\Documents\Codex\2026-06-03\files-mentioned-by-the-user-pasted\cybercrime'
$transferRoot = Join-Path $repoRoot 'forensic-project-transfer'

function Copy-TreeFiltered {
    param(
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Destination,
        [string[]] $ExcludedNames = @()
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        Write-Warning "Missing source: $Source"
        return
    }

    Get-ChildItem -LiteralPath $Source -File -Recurse | ForEach-Object {
        if ($ExcludedNames -contains $_.Name) { return }
        $relative = $_.FullName.Substring($Source.Length).TrimStart('\')
        $target = Join-Path $Destination $relative
        $targetDirectory = Split-Path -Parent $target
        New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
        Copy-Item -LiteralPath $_.FullName -Destination $target -Force
    }
}

Copy-TreeFiltered `
    -Source 'C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs' `
    -Destination (Join-Path $transferRoot 'reports') `
    -ExcludedNames @('MBOX_Relevant_Hits.csv', 'media.zip')

Copy-TreeFiltered `
    -Source 'C:\Users\thoma\Documents\Cyber Crimes Tools\POPD Final Supplemental Packet' `
    -Destination (Join-Path $transferRoot 'popd-final-packet')

Copy-TreeFiltered `
    -Source 'C:\Users\thoma\Documents\Cyber Crimes Tools\Final Reopen Packet POPD SA' `
    -Destination (Join-Path $transferRoot 'handoff')

Copy-TreeFiltered `
    -Source 'C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Access Audit April 2024\Triage' `
    -Destination (Join-Path $transferRoot 'triage')

$scriptDestination = Join-Path $transferRoot 'scripts'
New-Item -ItemType Directory -Path $scriptDestination -Force | Out-Null
Get-ChildItem -LiteralPath 'C:\Users\thoma\Documents\Cyber Crimes Tools' -File -Filter '*.py' | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $scriptDestination $_.Name) -Force
}

$workspaceScripts = 'C:\Users\thoma\Documents\Codex\2026-06-03\files-mentioned-by-the-user-pasted\work'
if (Test-Path -LiteralPath $workspaceScripts) {
    $workspaceDestination = Join-Path $scriptDestination 'workspace-builders'
    New-Item -ItemType Directory -Path $workspaceDestination -Force | Out-Null
    Get-ChildItem -LiteralPath $workspaceScripts -File | Where-Object { $_.Extension -in @('.py', '.ps1', '.js') } | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $workspaceDestination $_.Name) -Force
    }
}

$files = Get-ChildItem -LiteralPath $transferRoot -File -Recurse
$totalBytes = ($files | Measure-Object -Property Length -Sum).Sum
Write-Output ("Transfer files: {0}" -f $files.Count)
Write-Output ("Transfer size MB: {0:N2}" -f ($totalBytes / 1MB))
Write-Output ("Largest files:")
$files | Sort-Object Length -Descending | Select-Object -First 15 FullName, Length
