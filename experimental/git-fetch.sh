#!/bin/bash
if [ ! -e "./gitsource" ]; then
  mkdir gitsource;
  cd gitsource;
  git clone https://github.com/kessnerch/WalletGenerator.net.git .
else
  cd gitsource;
fi
echo "setting git config"
git config --local user.name "Automatic WalletGenerator.net Generator"
git config --local user.email "kesserch+awgng@gmail.com"
echo "reset git (hard)"
git reset HEAD^ --hard
git pull