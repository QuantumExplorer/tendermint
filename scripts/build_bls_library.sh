PACKAGES_PATH=$(go env GOPATH)
BLS_REPO_PATH="${PACKAGES_PATH}"/src/github.com/quantumexplorer/bls-signatures

echo "PACKAGES_PATH: ${PACKAGES_PATH}"
echo "PWD: ${PWD}"

# Cleaning previous build
rm -rf "${BLS_REPO_PATH}"
mkdir -pv "${PACKAGES_PATH}"/github.com/quantumexplorer/

# Cloning bls repo and fetching dependencies
git clone https://github.com/quantumexplorer/bls-signatures.git "$BLS_REPO_PATH"
cd "$BLS_REPO_PATH"
git submodule update --init --recursive

# Build the bindings
mkdir build
cd build
cmake ../
cmake --build . -- -j 6
cd "${BLS_REPO_PATH}"/go-bindings
make
