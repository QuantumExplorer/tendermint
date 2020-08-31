rm -rf "${GOPATH}"/src/github.com/quantumexplorer/bls-signatures
mkdir -pv "${GOPATH}"/src/github.com/quantumexplorer/
git clone https://github.com/quantumexplorer/bls-signatures.git "${GOPATH}"/src/github.com/quantumexplorer/bls-signatures
cd "${GOPATH}"/src/github.com/quantumexplorer/bls-signatures
git submodule update --init --recursive
mkdir build
cd build
cmake ../
cmake --build . -- -j 6
cd "${GOPATH}"/src/bls-signatures/go-bindings
make
