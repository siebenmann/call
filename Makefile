SRC=call.go tlsnames.go ciphername.go ciphername_old.go

call: $(SRC)
	go build -o call

all: call call.static call32 call64 call.fbsd32 call.fbsd call.solaris

call.static: $(SRC)
	CGO_ENABLED=0 go build -tags netgo -o $@

call32: $(SRC)
	GOARCH=386 go build -o $@

call64: $(SRC)
	GOARCH=amd64 go build -o $@

call.fbsd32: $(SRC)
	GOOS=freebsd GOARCH=386 go build -o $@

call.fbsd: $(SRC)
	GOOS=freebsd GOARCH=amd64 go build -o $@

call.solaris: $(SRC)
	GOOS=solaris GOARCH=amd64 go build -o $@

# yes yes I know, 'go clean' or something. I'm old fashioned.
clean:
	rm -f call call32 call64 call.static call.fbsd call.fbsd32 call.solaris
