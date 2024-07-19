# direw

WIP C++ cross-platform 3D game engine (macOS/Metal-first)

### how to compile
- `brew install moltenvk`
- have vcpkg installed and `VCPKG_ROOT` env var set, check dependencies in `CMakeLists.txt`
- run `mkdir build && cd build && cmake .. --preset debug && cd debug && cmake --build .`
