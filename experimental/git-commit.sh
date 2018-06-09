#!/bin/bash
cd gitsource;
echo "copy new currency"
cp ../janin.currency.js.new src/janin.currency.js
echo "install NPM module for grunt"
npm install grunt-cli grunt --no-save 2>/dev/null
echo "grunt-ing"
grunt
echo "adding git changes"
git add index.html
git add src/janin.currency.js
git status
echo "commiting changes"
git commit -m 'reordered coins alphabetically'
git push 
