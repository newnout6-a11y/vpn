# Compatibility shim: the old PowerShell CLI moved into vpnte-proxy.exe next to this file.
& "$PSScriptRoot\vpnte-proxy.exe" @args
exit $LASTEXITCODE
