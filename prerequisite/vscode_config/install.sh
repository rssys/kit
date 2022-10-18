#!/bin/sh
# Refer to git contrib/vscode/init.sh

die () {
        echo "$*" >&2
        exit 1
}

CUR_DIR=$(readlink -f $(dirname $BASH_SOURCE))
source $CUR_DIR/../../script/common.sh

cd $MAIN_HOME
mkdir -p .vscode
# General settings
echo 
cat <<EOF >.vscode/settings.json
{
        "go.goroot": "$GOROOT",
        "go.gopath": "$GOPATH",
        "terminal.integrated.env.linux": {
                "PATH": "$PATH"
        },
}
EOF