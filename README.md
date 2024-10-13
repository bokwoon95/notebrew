# Notebrew

Notebrew is a self-hostable static site CMS in a single binary.

## Installation

1. Install Git.

2. Install Go.

3. ```shell
   go install -tags fts5 github.com/bokwoon95/notebrew/notebrew@latest
   ```

4. ```shell
   notebrew # or "$(go env GOPATH)/bin/notebrew" if you have not added $GOPATH/bin into your $PATH.
   ```
