# Rebuild the local herdr claude agent with magpie settings (run after herdr server restart)
$ws = & "C:\Users\84915\bin\herdr\herdr.exe" workspace create --cwd "C:\Users\84915\herdr-local" --label local-agent 2>$null | ConvertFrom-Json
$pane = $ws.result.root_pane.pane_id
Start-Sleep 2
& "C:\Users\84915\bin\herdr\herdr.exe" agent start local-claude --kind claude --pane $pane -- --settings "C:\Users\84915\bin\herdr-agent-bin\magpie-settings.json"
