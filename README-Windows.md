# miqrochain v1.7.8 â€” Windows Build

**Requirements**
- Visual Studio 2022 Build Tools (C++), x64 Native Tools command prompt
- CMake 3.20+
- Windows 10/11 SDK (for sockets)

**Build (daemon only)**
```powershell
Set-Location C:\miqrochain_v0.1
if (Test-Path .\build) { Remove-Item -Recurse -Force .\build }
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --target miqrod --parallel
.\build\Release\miqrod.exe
```

**Optional tests**
```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DMIQ_BUILD_TESTS=ON
cmake --build build --config Release --target test_crypto
```

Ports: P2P 9833, RPC 9834.
