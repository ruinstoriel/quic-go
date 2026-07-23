<#
.SYNOPSIS
    在 upstream quic-go 与 fork 模块路径之间切换重命名。

.EXAMPLE
    .\module_rename.ps1             # upstream -> fork
    .\module_rename.ps1 -Reverse    # fork -> upstream
#>
[CmdletBinding()]
param (
    [Alias("r")]
    [Switch]$Reverse
)

$ErrorActionPreference = "Stop"

$upstream = "crypto/tls"
$fork     = "github.com/metacubex/jls-tls"

$from = $upstream
$to   = $fork

if ($Reverse) {
    $from = $fork
    $to   = $upstream
}

# 1. 根目录的 go.mod 依然使用标准工具更新
go mod edit -module="$to"

# 2. 获取目标文件，自动跳过隐藏文件夹（如 .git, .github 等）以及脚本自身
$targetExtensions = @('.go', '.md', '.sh', '.mod')
$myFilename = $MyInvocation.MyCommand.Name

$files = Get-ChildItem -Path . -Recurse -File | Where-Object {
    # 过滤 1: 跳过任何隐藏文件夹中的文件 (以 . 开头的目录)
    $inHiddenDir = $_.FullName.Split([System.IO.Path]::DirectorySeparatorChar) | Where-Object { $_.StartsWith(".") }
    if ($inHiddenDir) { return $false }

    # 过滤 2: 匹配指定的后缀
    if ($targetExtensions -notcontains $_.Extension) { return $false }

    # 过滤 3: 排除脚本自身
    if ($_.Name -eq $myFilename) { return $false }

    return $true
}

# 3. 逐个文件执行字符串替换（区分文本编码，默认保持原样写回）
foreach ($file in $files) {
    $content = Get-Content -Path $file.FullName -Raw
    if ($content -match [regex]::Escape($from)) {
        $updatedContent = $content -replace [regex]::Escape($from), $to
        Set-Content -Path $file.FullName -Value $updatedContent -NoNewline -Encoding UTF8
    }
}