#!/bin/bash

echo "HOST_DIR=$HOST_DIR"
PWD=`pwd`
echo "nsign dir=${PWD}"
if [ ! -d build ]; then
    mkdir build
fi
cd build
${HOST_DIR}/bin/cmake ..
make -j8
cd ../
if [ -f ./build/src/nsign ];then
    echo "copy nsign......."
    cp ./build/src/nsign ./
else
   echo "nsign not exist."
fi

