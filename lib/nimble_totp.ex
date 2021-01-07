defmodule NimbleTOTP do
  @moduledoc ~S"""
  NimbleTOTP is a tiny library for Two-factor authentication (2FA) that
  allows developers to implement Time-Based One-Time Passwords (TOTP)
  for their applications.

  ## Two-factor authentication (2FA)

  The concept of 2FA is quite simple. It's an extra layer of security
  that demands a user to provide two pieces of evidence (factors) to
  the authentication system before access can be granted.

  One way to implement 2FA is to generate a random secret for the user
  and whenever the system needs to perform a critical action it will
  ask the user to enter a validation code. This validation code is a
  Time-Based One-Time Password (TOTP) based on the user's secret and can be
  provided by an authentication app like Google Authenticator or Authy, which
  should be previously installed and configured on a compatible device, e.g.
  a smartphone.

  > **Note:** A critical action can mean different things depending on
  the application. For instance, while in a banking system the login itself
  is already considered a critical action, in other systems a user may
  be allowed to log in using just the password and only when trying to
  update critical data (e.g. its profile) 2FA will be required.

  ## Using NimbleTOTP

  In order to allow developers to implement 2FA, NimbleTOTP provides functions to:

    * Generate secrets composed of random bytes.
    * Generate URIs to be encoded in a QR Code.
    * Generate Time-Based One-Time Passwords based on a secret.

  ### Generating the secret

  The first step to set up 2FA for a user is to generate (and later persist) its random
  secret. You can achieve that using `NimbleTOTP.secret/1`.

  Example:

      secret = NimbleTOTP.secret()
      #=> <<63, 24, 42, 30, 95, 116, 80, 121, 106, 102>>

  By default, a binary with 10 random bytes is generated.

  ### Generating URIs for QR Code

  Before persisting the secret, you need to make sure the user has already
  configured the authentication app in a compatible device. The most common
  way to do that is to generate a QR Code that can be read by the app.

  You can use `NimbleTOTP.otpauth_uri/3` along with
  [eqrcode](https://github.com/SiliconJungles/eqrcode) to generate the QR
  code as **SVG**.

  Example:

      uri = NimbleTOTP.otpauth_uri("Acme:alice", secret, issuer: "Acme")
      #=> "otpauth://totp/Acme:alice?secret=MFRGGZA&issuer=Acme"
      uri |> EQRCode.encode() |> EQRCode.svg()
      #=> "<?xml version=\\"1.0\\" standalone=\\"yes\\"?>\\n<svg version=\\"1.1\\" ...

  ### Generating a Time-Based One-Time Password

  After successfully reading the QR Code, the app will start generating a
  different 6 digit code every `30s`. You can compute the verification code
  with:

      NimbleTOTP.verification_code(secret)
      #=> "569777"

  The code can be validated using the `valid?/3` function. Example:

      NimbleTOTP.valid?(secret, "569777")
      #=> true

      NimbleTOTP.valid?(secret, "012345")
      #=> false

  After validating the code, you can finally persist the user's secret so you use
  it later whenever you need to authorize any critical action using 2FA.
  """

  import Bitwise
  @totp_size 6
  @default_totp_period 30

  @doc """
  Generate the uri to be encoded in the QR code.

  ## Examples

      iex> NimbleTOTP.otpauth_uri("Acme:alice", "abcd", issuer: "Acme")
      "otpauth://totp/Acme:alice?secret=MFRGGZA&issuer=Acme"

  """
  def otpauth_uri(label, secret, uri_params \\ []) do
    key = Base.encode32(secret, padding: false)
    params = [{:secret, key} | uri_params]
    query = URI.encode_query(params)
    "otpauth://totp/#{URI.encode(label)}?#{query}"
  end

  @doc """
  Generate a binary composed of random bytes.

  The number of bytes is defined by the `size` argument. Default is `10`.

  ## Examples

      NimbleTOTP.secret()
      #=> <<63, 24, 42, 30, 95, 116, 80, 121, 106, 102>>

  """
  def secret(size \\ 10) do
    :crypto.strong_rand_bytes(size)
  end

  @doc """
  Generate Time-Based One-Time Password.

  ## Options

    * :time - The time in unix format to be used. Default is `System.os_time(:second)`
    * :period - The period (in seconds) in which the code is valid. Default is `30`.

  ## Examples

      NimbleTOTP.verification_code(secret)
      #=> "569777"

  """
  def verification_code(secret, opts \\ []) do
    time = Keyword.get(opts, :time, System.os_time(:second))
    period = Keyword.get(opts, :period, @default_totp_period)

    secret
    |> hmac(time, period)
    |> hmac_truncate()
    |> rem(1_000_000)
    |> to_string()
    |> String.pad_leading(@totp_size, "0")
  end

  defp hmac(secret, time, period) do
    moving_factor = <<Integer.floor_div(time, period)::64>>
    hmac_sha(secret, moving_factor)
  end

  # TODO: Remove me when we require OTP 22.1
  if Code.ensure_loaded?(:crypto) and function_exported?(:crypto, :mac, 4) do
    defp hmac_sha(key, data), do: :crypto.mac(:hmac, :sha, key, data)
  else
    defp hmac_sha(key, data), do: :crypto.hmac(:sha, key, data)
  end

  defp hmac_truncate(hmac) do
    <<_::19-binary, _::4, offset::4>> = hmac
    <<_::size(offset)-binary, p::4-binary, _::binary>> = hmac
    <<_::1, bits::31>> = p
    bits
  end

  @doc """
  Checks if the given `otp` code matches the secret.

  It accepts the same options as `verification_code/2`.
  """
  def valid?(secret, otp, opts \\ [])

  def valid?(secret, <<a1, a2, a3, a4, a5, a6>>, opts) do
    <<e1, e2, e3, e4, e5, e6>> = verification_code(secret, opts)
    (e1 ^^^ a1 ||| e2 ^^^ a2 ||| e3 ^^^ a3 ||| e4 ^^^ a4 ||| e5 ^^^ a5 ||| e6 ^^^ a6) === 0
  end

  def valid?(_secret, _otp, _opts), do: false
end
