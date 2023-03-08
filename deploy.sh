#!/bin/bash
rm -rf $1.zip
zip -r $1.zip $1
aws lambda update-function-code --function-name $1 --zip-file fileb://$1.zip