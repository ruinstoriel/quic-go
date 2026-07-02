<#
.SYNOPSIS
Rename the Go module path between upstream quic-go and the apernet fork.

.DESCRIPTION
    .\module_rename.ps1        upstream -> fork
    .\module_rename.ps1 -r     fork -> upstream

The module directive of the root go.mod is changed with the canonical
`go mod edit -module`. Everything else (import paths, docs, scripts and
nested go.mod require/replace directives) is rewritten textually.
Hidden directories (.git, .github, .clusterfuzzlite, ...) are skipped.
#>

param (
    [Alias("r")]
    [switch]$Reverse
)

# 相当于 Bash 的 set -e，遇到错误立即停止
$ErrorActionPreference = "Stop"

$upstream = "github.com/quic-go/quic-go"
$fork = "github.com/ruinstoriel/quic-go"

if ($Reverse) {
    $from = $fork
    $to = $upstream
} else {
    $from = $upstream
    $to = $fork
}

# 转义点号，以便在正则替换时进行字面量匹配 (相当于 sed 's/\./\\./g')
$from_re = [regex]::Escape($from)

Write-Host "Renaming module from $from to $to..." -ForegroundColor Cyan

# 1. Root module directive: use the canonical tool.
go mod edit -module="$to"

# 2. References everywhere else: imports, docs, scripts and nested go.mod
#    require/replace directives.
$scriptName = $MyInvocation.MyCommand.Name
$extensions = @('.go', '.md', '.sh', '.mod', '.ps1')

# 获取当前目录下所有文件
$files = Get-ChildItem -Path . -Recurse -File | Where-Object {
    # 匹配目标扩展名
    ($extensions -contains $_.Extension) -and
    # 排除隐藏目录 (如 .git, .github) -> 匹配路径中包含 "/." 或 "\." 的文件夹层级
    ($_.FullName -notmatch '[\\/]\.[^\\/]+[\\/]') -and
    # 排除当前脚本自身
    ($_.Name -ne $scriptName)
}

# Go 项目统一使用 UTF-8 无 BOM 编码
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

foreach ($file in $files) {
    # 使用 .NET 底层方法一次性读取，保留原有的换行符(LF/CRLF)格式
    $content = [System.IO.File]::ReadAllText($file.FullName)

    # 如果文件内容中包含需要替换的路径
    if ($content -match $from_re) {
        # PowerShell 的 -replace 默认就是全局替换 (相当于 sed 的 g 标志)
        $newContent = $content -replace $from_re, $to

        # 写回文件
        [System.IO.File]::WriteAllText($file.FullName, $newContent, $utf8NoBom)
        Write-Host "Updated: $($file.FullName)" -ForegroundColor Green
    }
}

Write-Host "Done!" -ForegroundColor Cyan