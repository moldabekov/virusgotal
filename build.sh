#!/bin/bash

PACKAGE=virusgotal
DIR=./release
SRC=.
LDFLAGS="-s -w"

if [ ! -d "$DIR" ]; then
	mkdir $DIR
fi

function compress {
    cd $DIR
    upx -9 $PACKAGE-$GOOS-$GOARCH
    zip -9 -v -D $PACKAGE-$GOOS-$GOARCH.zip $PACKAGE-$GOOS-$GOARCH
    cd ..
}

function compress_win {
    cd $DIR
    upx -9 $PACKAGE-$GOOS-$GOARCH.exe
    zip -9 -v -D $PACKAGE-$GOOS-$GOARCH.zip $PACKAGE-$GOOS-$GOARCH.exe
    cd ..
}

# Linux
export GOOS=linux GOARCH=amd64 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress
export GOOS=linux GOARCH=386 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress
export GOOS=linux GOARCH=arm && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress
export GOOS=linux GOARCH=arm64 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress
export GOOS=linux GOARCH=mips && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress
export GOOS=linux GOARCH=mips64 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress

# macOS
export GOOS=darwin GOARCH=amd64 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress
export GOOS=darwin GOARCH=386 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress

# Windows
export GOOS=windows GOARCH=amd64 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH.exe $SRC && compress_win
export GOOS=windows GOARCH=386 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH.exe $SRC && compress_win

# Android [!] Needs cross compiler!
# export GOOS=android GOARCH=arm && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress

# FreeBSD
export GOOS=freebsd GOARCH=amd64 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress
export GOOS=freebsd GOARCH=386 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress

# NetBSD
export GOOS=netbsd GOARCH=amd64 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress
export GOOS=netbsd GOARCH=386 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress

# OpenBSD
export GOOS=openbsd GOARCH=amd64 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress
export GOOS=openbsd GOARCH=386 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress

# Plan9
# export GOOS=plan9 GOARCH=amd64 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress
# export GOOS=plan9 GOARCH=386 && go build -ldflags="-s -w" -o $DIR/$PACKAGE-$GOOS-$GOARCH $SRC && compress
