// Package integration holds end-to-end tests that run real lumi-server
// processes against a real Postgres. They are behind the `integration`
// build tag:
//
//	make test-integration        # go test -tags=integration ./...
//
// Postgres: set LUMI_TEST_DATABASE_URL to a superuser URL (test databases
// are created and dropped in it); otherwise the harness starts a throwaway
// postgres:16.16-alpine3.24 container via the docker CLI (honours
// DOCKER_HOST / DOCKER_CONFIG) bound to 127.0.0.1 and removes it after.
package integration
