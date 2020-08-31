BLS_REPO_PATH="${GOPATH}"/github.com/quantumexplorer/bls-signatures

rm -rf "${BLS_REPO_PATH}"

mkdir -pv "${GOPATH}"/github.com/quantumexplorer/

git clone https://github.com/quantumexplorer/bls-signatures.git "$BLS_REPO_PATH"
cd "$BLS_REPO_PATH"
git submodule update --init --recursive
mkdir build
cd build
cmake ../
cmake --build . -- -j 6
cd "${BLS_REPO_PATH}"/go-bindings
make
