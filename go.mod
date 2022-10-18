module github.com/rss/kit

go 1.14

require (
	github.com/google/syzkaller v0.0.0 // version is useless
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b // indirect
	golang.org/x/sys v0.0.0-20210925032602-92d5a993a665
	google.golang.org/protobuf v1.26.0 // indirect
)

replace github.com/google/syzkaller => ./syzkaller
