# Hash2077

Hash2077 is a highly optimized tool for brute-forcing the names of symbols used in Cyberpunk2077, using the Adler-32 and SHA-256 hashes found in `cyberpunk2077_addresses.json`.

Potential matches are found using a meet-in-the-middle attack on the Adler-32 hashes, before being validated using the SHA-256 hashes.

## Setup
Compilation requires VS2022 and CMake.
```
git clone https://github.com/0x1F9F1/Hash2077.git
cd Hash2077
mkdir build
cd build
cmake ..
cmake --build . --config Release
```
The compiled DLL can be found in `build\bin\Release\hash2077.dll`.

## Usage
Your CPU must support the AVX2 and SHA instruction set extensions. \
For optimal performance it is recommended to have at least 16GB of RAM. If you have less, you may need to reduce `suffix_size` to avoid running out of memory. \
Copy `cyberpunk2077_addresses.json` to the `python` folder. \
For example usage, see `collide.py`.