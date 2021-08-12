# ARMO Golang Utilities Repository

This is ARMO Golang repository for common data structures, functions and etc.

**Please keep everything organized**

Guideline: If you KNOW a datastructure/function will appear in two components or more this is where it belongs!


Each subfolder contains it's own readme

### Clone `capacketsgo` to you repository

```
git submodule add git@github.com:armosec/capacketsgo.git ./vendor/github.com/armosec/capacketsgo
```

Update your project `go.mod`:
```
replace github.com/armosec/capacketsgo => ./vendor/github.com/armosec/capacketsgo

require (
	github.com/armosec/capacketsgo v0.0.0
)
```

When vendor is angry on u run build with the following command:
```
go build -mod=mod .
```
every project must do:

git config --global url."ssh://git@github.com/armosec/".insteadOf "https://github.com/armosec/"
go env -w GOPRIVATE=github.com/armosec
