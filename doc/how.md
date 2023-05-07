# how

size:

- https://api.github.com/repos/4cq2/tls
- https://docs.github.com/search-github/searching-on-github/searching-for-repositories

enable flexible external configuration:

https://github.com/refraction-networking/utls/tree/112951f6

before the first commit, lets remove large items:

~~~
handshake_client_test.go
handshake_server_test.go
testdata
~~~

now create `go.mod`:

~~~
go mod init 2a.pages.dev/tls
~~~

create `go.sum`:

~~~
go mod tidy
~~~

then export:

~~~
gofmt -w -r 'pointFormatUncompressed -> PointFormatUncompressed' .
~~~

Now we want to clean up `go.mod`. First remove:

~~~
cpu\cpu_test.go
examples\examples.go
tls_test.go
~~~

commit:

https://github.com/refraction-networking/utls/commit/1552a980

remove:

~~~
.travis.yml
CONTRIBUTING.md
CONTRIBUTORS_GUIDE.md
cpu
example_test.go

generate_cert.go
handshake_messages_test.go
handshake_test.go
prf_test.go
testenv
~~~
