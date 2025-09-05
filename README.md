# NimbleTOTP

This library allows developers to implement Time-based One-Time Passwords (TOTP)
for their applications as one of the mechanisms for Two-factor authentication (2FA).

It provides functions to:

  * Generate secrets composed of random bytes.
  * Generate URIs to be encoded in a QR Code.
  * Generate Time-Based One-Time Passwords for a secret.

Documentation can be found at https://hexdocs.pm/nimble_totp.

## Installation

You can install `nimble_totp` by adding it to your list of
dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:nimble_totp, "~> 1.0"}
  ]
end
```

## Usage

Generating a secret composed of random bytes:

```elixir
secret = NimbleTOTP.secret()
#=> <<63, 24, 42, 30, 95, 116, 80, 121, 106, 102>>
```

Generating a URI to be encoded in a QR Code:

```elixir
NimbleTOTP.otpauth_uri("Acme:alice", secret, issuer: "Acme")
#=> "otpauth://totp/Acme:alice?secret=MFRGGZA&issuer=Acme"
```

Generating a Time-Based One-Time Password for a secret and validating it:

```elixir
NimbleTOTP.verification_code(secret)
#=> "569777"

NimbleTOTP.valid?(secret, "569777")
#=> true
```

## Nimble*

All nimble libraries by Dashbit:

  * [NimbleCSV](https://github.com/dashbitco/nimble_csv) - simple and fast CSV parsing
  * [NimbleOptions](https://github.com/dashbitco/nimble_options) - tiny library for validating and documenting high-level options
  * [NimbleOwnership](https://github.com/dashbitco/nimble_ownership) - resource ownership tracking
  * [NimbleParsec](https://github.com/dashbitco/nimble_parsec) - simple and fast parser combinators
  * [NimblePool](https://github.com/dashbitco/nimble_pool) - tiny resource-pool implementation
  * [NimblePublisher](https://github.com/dashbitco/nimble_publisher) - a minimal filesystem-based publishing engine with Markdown support and code highlighting
  * [NimbleTOTP](https://github.com/dashbitco/nimble_totp) - tiny library for generating time-based one time passwords (TOTP)

## License

Copyright 2020 Dashbit

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
