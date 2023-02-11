#!/usr/bin/env bash

rm -f data/exploit.class
rm -f data/exploittemplate.class
javac exploit.java

# Moving to "template" file so we can inject on the fly
mv exploit.class data/exploittemplate.class