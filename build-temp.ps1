$ErrorActionPreference = "Stop"
$tempDir = "$env:TEMP\event-viewer-build"
Write-Host "Creating temp build dir: $tempDir"
if (Test-Path $tempDir) {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $tempDir | Out-Null

Write-Host "Copying files to bypass # in path..."
$items = @("package.json", "tsconfig.json", "tsconfig.app.json", "tsconfig.node.json", "vite.config.ts", "index.html", "src", "node_modules", "server.ts", "postcss.config.js", "tailwind.config.js")
foreach ($item in $items) {
    if (Test-Path $item) {
        Copy-Item -Recurse -Force $item -Destination $tempDir
    }
}

Write-Host "Building in temp dir..."
Set-Location $tempDir
# Run vite build only, esbuild can run anywhere
npx vite build

Write-Host "Copying dist back..."
Set-Location "C:\Users\SASA\Documents\##PROJECTDUIT\event-viewer-analyzer\event-viewer-analyzer"
if (Test-Path "dist") {
    Remove-Item -Recurse -Force "dist"
}
Copy-Item -Recurse -Force "$tempDir\dist" -Destination ".\dist"

Write-Host "Running esbuild for server..."
npx esbuild server.ts --bundle --platform=node --format=cjs --packages=external --sourcemap --outfile=dist/server.cjs

Write-Host "Packaging with pkg..."
npx pkg . --target node18-win-x64 --output dist/EventAnalyzer.exe

Write-Host "Build Complete!"
