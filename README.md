# identity-oidc-gin

An example Login.gov client application which authenticates users via OpenID Connect (OIDC). Written in [Go](https://golang.org/). Uses the [Gin](https://gin-gonic.github.io/gin/) web framework.

## Installation

Install Go (version 1.9.4).

Install the source code:

```sh
go get github.com/s2t2/identity-oidc-gin
cd $GOPATH/src/github.com/s2t2/identity-oidc-gin
```

## Configuration

Configure environment variables using a `.env` file. At a minimum, set the `SESSION_SECRET` variable. For an example, see the `.env.example` file.

### Choose a Login.gov Environment

#### Development Environment (Local Server)

Set the `PROVIDER_URL` environment variable to http://localhost:3000.

Run a [Login.gov (identity-idp) instance](https://github.com/18F/identity-idp/) locally on port 3000:

```sh
cd path/to/identity-idp
make run
```

#### Sandbox Environment

Set the `PROVIDER_URL` environment variable to to one of the sandbox urls:

  + `https://idp.dev.identitysandbox.gov`
  + `https://idp.int.identitysandbox.gov`

> NOTE: this application's credentials have not yet been deployed to the sandbox environments. this note will be removed when the credentials have been deployed and this application has been tested against these sandbox environments.

## Usage

Run the app:

```sh
go run app.go
```

Then view in browser at localhost:8080.
