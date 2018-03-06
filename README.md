# identity-oidc-gin

An example [Login.gov](https://login.gov/) client application which authenticates users via OpenID Connect (OIDC). Written in [Go](https://golang.org/). Uses the [Gin](https://gin-gonic.github.io/gin/) web framework and the [Goth](https://github.com/markbates/goth) authentication package. Disclaimer: Goth is not (yet) a certified OpenID Relaying Party.

Demo:

![a screencast of a user navigating this application: logging in using LOA1 by clicking a button on the homepage, then getting redirected to a profile page showing the user's email address, then logging out and demonstrating inability to access the profile page again. then repeating the process using LOA3 to log-in produces the same results, except it displays more user information on the profile page.](demo.gif)

## Installation

Install Go (version 1.9.4).

Install the source code:

```sh
go get github.com/18F/identity-oidc-gin
cd $GOPATH/src/github.com/18F/identity-oidc-gin
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

## [License](/LICENSE.md)
