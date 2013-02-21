call: call.go
	go build call.go

all: call call32 call64

call32: call.go
	GOARCH=386 go build -o call32 call.go

call64: call.go
	GOARCH=amd64 go build -o call64 call.go

#call.fbsd: call.go
#	CGO_ENABLED=0 GOOS=freebsd GOARCH=386 go build -o call.fbsd call.go

# yes yes I know, 'go clean' or something. I'm old fashioned.
clean:
	rm -f call call32 call64
