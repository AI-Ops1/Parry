# =============================================================================
# Parry - Windows D:\Parry Zero-C-Drive-Bloat Environment Setup (PowerShell)
# =============================================================================

$ParryRoot = "D:\Parry"
$CacheRoot = "$ParryRoot\.cache"

New-Item -ItemType Directory -Force -Path "$CacheRoot\cargo" | Out-Null
New-Item -ItemType Directory -Force -Path "$CacheRoot\rustup" | Out-Null
New-Item -ItemType Directory -Force -Path "$CacheRoot\target" | Out-Null
New-Item -ItemType Directory -Force -Path "$CacheRoot\npm" | Out-Null
New-Item -ItemType Directory -Force -Path "$CacheRoot\pip" | Out-Null
New-Item -ItemType Directory -Force -Path "$CacheRoot\uv" | Out-Null
New-Item -ItemType Directory -Force -Path "$CacheRoot\temp" | Out-Null

$EnvMap = @{
    "PARRY_HOME"        = $ParryRoot
    "CARGO_HOME"        = "$CacheRoot\cargo"
    "RUSTUP_HOME"       = "$CacheRoot\rustup"
    "CARGO_TARGET_DIR"  = "$CacheRoot\target"
    "NPM_CONFIG_CACHE"  = "$CacheRoot\npm"
    "PIP_CACHE_DIR"     = "$CacheRoot\pip"
    "UV_CACHE_DIR"      = "$CacheRoot\uv"
    "TMP"               = "$CacheRoot\temp"
    "TEMP"              = "$CacheRoot\temp"
}

foreach ($key in $EnvMap.Keys) {
    $val = $EnvMap[$key]
    Set-Item -Path "Env:$key" -Value $val
    [System.Environment]::SetEnvironmentVariable($key, $val, [System.EnvironmentVariableTarget]::User)
}

Write-Host "[OK] Parry D:\ Drive Isolation Active! Zero bytes will be written to C:\ for caches." -ForegroundColor Green
Write-Host "  Root Folder:      $ParryRoot"
Write-Host "  Cargo Target Dir: $CacheRoot\target"
Write-Host "  Run Benchmark:    python .\parry.py bench"
