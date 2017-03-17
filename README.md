# identity-openidconnect-sinatra

An example of a Relying Party for OpenID Connect written as a simple Sinatra app in Ruby.

## Running locally

These instructions assume [`identity-idp`](https://github.com/18F/identity-idp) is also running locally at `http://localhost:3000`. This sample sp is configured to run on `http://localhost:9292`.

1. Set up the environment with:

  ```
  $ make setup
  ```

2. And run the app server:

  ```
  $ make run
  ```

3. To run specs:

  ```
  $ make test
  ```

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for additional information.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.
