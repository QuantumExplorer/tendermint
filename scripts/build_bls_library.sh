rm -rf github.com/quantumexplorer/bls-signatures
mkdir -pv github.com/quantumexplorer/
git clone https://github.com/quantumexplorer/bls-signatures.git github.com/quantumexplorer/bls-signatures
cd github.com/quantumexplorer/bls-signatures
git submodule update --init --recursive
mkdir build
cd build
cmake ../
cmake --build . -- -j 6
cd bls-signatures/go-bindings
make
