# Miqrochain Qt GUI


### Prereqs
- **Qt 6.4+** (Widgets, Network)
- **CMake 3.22+**
- A working `miqrod` binary


### Build (Windows, x64 MSVC)
1. Install Qt 6 (e.g., via Qt Online Installer). Note the kit path.
2. Open **x64 Native Tools Command Prompt for VS**.
3. Configure & build:
```bat
cd miqro-gui
cmake -B build -S . -DCMAKE_PREFIX_PATH="C:/Qt/6.6.2/msvc2019_64"
cmake --build build --config Release
