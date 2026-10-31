# =============================================================================
# Parry - 1-Step GitHub Repository Initializer & Pusher (PowerShell)
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\push_to_github.ps1 -RepoUrl "https://github.com/YOUR_USERNAME/parry.git"
# =============================================================================
param(
    [Parameter(Mandatory=$false)]
    [string]$RepoUrl = ""
)

if (-not (Test-Path ".git")) {
    git init
    git branch -M main
}

git add .
git commit -m "feat: initial release of Parry v0.1.0 + 25-case Evil AI Benchmark + MCP/Gemini/Claude/Codex connectors"

if (Get-Command gh -ErrorAction SilentlyContinue) {
    if ([string]::IsNullOrWhiteSpace($RepoUrl)) {
        Write-Host "[INFO] Creating public GitHub repository 'parry' via GitHub CLI..." -ForegroundColor Cyan
        gh repo create parry --public --source=. --remote=origin --push
        exit 0
    }
}

if (-not [string]::IsNullOrWhiteSpace($RepoUrl)) {
    git remote remove origin 2>$null
    git remote add origin $RepoUrl
    git push -u origin main
    Write-Host "[OK] Pushed Parry repository to $RepoUrl" -ForegroundColor Green
} else {
    Write-Host "[READY] Local git commit created! Create an empty public repo at https://github.com/new named 'parry', then run:" -ForegroundColor Yellow
    Write-Host "  git remote add origin https://github.com/<YOUR_USERNAME>/parry.git"
    Write-Host "  git push -u origin main"
}
