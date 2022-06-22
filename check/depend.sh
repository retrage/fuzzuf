#!/bin/bash

DIR=${1}
LIB=${2}

if [ ! -e ${DIR}/CMakeLists.txt ]
then
  exit 1
fi
if grep -E "^\s*${LIB}\s*$" ${DIR}/CMakeLists.txt
then
  exit 0
else
  exit 1
fi

