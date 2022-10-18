# have a stricter check later
if [ -f "$GOROOT/bin/go" ]; then
	echo "Go runtime is already installed"
	exit 0
fi
pushd $MAIN_HOME/prerequisite/go > /dev/null
wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
tar -xf go1.14.2.linux-amd64.tar.gz
mv go $GOROOT
mkdir $GOPATH
rm go1.14.2.linux-amd64.tar.gz