#!/bin/bash

# darwin arm64
fyne package -appID com.notebrew -os darwin -release -src ./notebrewgui -name Notebrew

# darwin amd64
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -ldflags '-s -w' -trimpath -o notebrewgui-darwin-arm64 ./notebrewgui
cp -r Notebrew.app NotebrewIntel.app
mv notebrewgui-darwin-arm64 NotebrewIntel.app/Contents/MacOS/notebrewgui
