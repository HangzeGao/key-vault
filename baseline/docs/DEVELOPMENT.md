# Development

On Windows use `npm.cmd`, because PowerShell execution policy may block `npm.ps1`. Run frontend checks with `npm.cmd test` and `npm.cmd run build`.

Vite/esbuild may be unable to traverse dependency paths in a restricted sandbox. If the TypeScript phase passes but Vite reports access denied outside the workspace, repeat the build outside the sandbox.

For Go, keep cache writes in the workspace:

```powershell
$env:GOCACHE=(Resolve-Path .gocache).Path
Set-Location baseline
go test ./...
```

`.gocache` is disposable; stop Go processes and remove only the repository-local directory when cleanup is needed.
