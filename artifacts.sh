#!/bin/bash

for i in ./artifacts/* 
do
    if [ -d "$i" ]
    then
        cp LICENSE* "$i"
        cp README.md "$i"
        # tar czf "${i}.tar.gz" -C "${i}"
        tar -cvpzf "${i}.tar.gz" --directory=${i} .
    fi
done