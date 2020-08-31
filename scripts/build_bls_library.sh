rm -rf src/github.com/quantumexplorer/bls-signatures
mkdir -pv src/github.com/quantumexplorer/
git clone https://github.com/quantumexplorer/bls-signatures.git src/github.com/quantumexplorer/bls-signatures
cd src/github.com/quantumexplorer/bls-signatures
git submodule update --init --recursive
mkdir build
cd build
cmake ../
cmake --build . -- -j 6
cd bls-signatures/go-bindings
make
