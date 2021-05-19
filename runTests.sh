#!/bin/bash
set -e

# https://stackoverflow.com/questions/59895/get-the-source-directory-of-a-bash-script-from-within-the-script-itself
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd $DIR
for i in `ls tests/test*.py`
do
    echo "Running File ${i}"
    /usr/bin/env python -m unittest $i "$@"
done
