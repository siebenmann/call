SRC=call.go tlsnames.go

call: $(SRC)
	go build -o call

all: call call32 call64 call.fbsd call.solaris

call32: $(SRC)
	GOARCH=386 go build -o call32

call64: $(SRC)
	GOARCH=amd64 go build -o call64

call.fbsd: $(SRC)
	GOOS=freebsd GOARCH=386 go build -o call.fbsd

call.solaris: $(SRC)
	GOOS=solaris GOARCH=amd64 go build -o call.solaris

# yes yes I know, 'go clean' or something. I'm old fashioned.
clean:
	rm -f call call32 call64 call.fbsd call.solaris
