call: call.go
	go build -o call

all: call call32 call64 call.fbsd call.solaris

call32: call.go
	GOARCH=386 go build -o call32

call64: call.go
	GOARCH=amd64 go build -o call64

call.fbsd: call.go
	GOOS=freebsd GOARCH=386 go build -o call.fbsd

call.solaris: call.go
	GOOS=solaris GOARCH=amd64 go build -o call.solaris

# yes yes I know, 'go clean' or something. I'm old fashioned.
clean:
	rm -f call call32 call64 call.fbsd call.solaris
