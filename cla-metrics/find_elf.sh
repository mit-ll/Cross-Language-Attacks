#!/bin/bash

# Used to collect a list of file names from a directory (recursively) that are elfs

# Input is the path to the search directory
path=$1

echo "Finding ELFs..."

# Count the number of / in path to strip files later
char="/"
stripped=${path//[^$char]/}
num=${#stripped}

if [ -f input/files.txt ]
then
  echo "Cleaning up input/files.txt"
  rm input/files.txt
  echo "Cleaning up input/elfs/"
  rm input/elfs/*
  echo "Cleaning up input/objdumps/"
  rm input/objdumps/*
fi

shopt -s globstar

count=0
for f in $path**/*
do
  if file -L $f | grep -qi elf  
  then
    # Skip certain files
    if [[ $f =~ "Test" ]]
    then
      printf "Skipping $f\n"
      continue 
    fi

    if [[ $f == *.jsm ]]
    then
      printf "Skipping $f\n"
      continue 
    fi

    if [[ $f == *.objdump ]]
    then
      printf "Skipping $f\n"
      continue 
    fi

    # holds binary name
    b=$f

    # strip path from binary name
    for i in $(eval echo {1..$num})
    do
        b="${b#*/}"
    done

    # count remaining paths for this file
    strippedb=${b//[^$char]/}
    numb=${#strippedb}

    # strip rest of path from binary name
    for i in $(eval echo {1..$numb})
    do
        b="${b#*/}"
    done

    ((count+=1))
    printf "File #$count: $b\n"
    objdump -d $f > input/objdumps/$b.objdump
    cp $f input/elfs/$b.elf
    echo $b >> input/files.txt
  fi
done
