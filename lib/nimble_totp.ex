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
      #=> <<178, 117, 46, 7, 172, 202, 108, 127, 186, 180, ...>>

  By default, a binary with 20 random bytes is generated per the
  [HOTP RFC](https://tools.ietf.org/html/rfc4226#section-4).

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

  ## Preventing codes from being reused

  The [TOTP RFC](https://tools.ietf.org/html/rfc6238#section-5.2) requires that a
  code can only be used once. This is a security feature that prevents codes from
  being reused. To ensure codes are only considered valid if they have not been
  used, you need to keep track of the last time the user entered a TOTP code.

      NimbleTOTP.valid?(user.totp_secret, code, since: user.last_totp_at)

  Assuming the code itself is valid for the given secret, if `since` is `nil`,
  the code will be considered valid. If since is given, it will not allow
  codes in the same time period (30 seconds by default) to be reused. The user
  will have to wait for the next code to be generated.
  """

  import Bitwise
  @totp_size 6
  @default_totp_period 30

  @typedoc "Unix time in seconds, `t:DateTime.t()` or `t:NaiveDateTime.t()`."
  @type time() :: DateTime.t() | NaiveDateTime.t() | integer()

  @typedoc "Options for `verification_code/2` and `valid?/3`."
  @type option() :: {:time, time()} | {:period, pos_integer()}

  @typedoc "Options for `valid?/3`."
  @type validate_option() :: {:since, time() | nil}

  @doc """
  Generate the uri to be encoded in the QR code.

  ## Examples

      iex> NimbleTOTP.otpauth_uri("Acme:alice", "abcd", issuer: "Acme")
      "otpauth://totp/Acme:alice?secret=MFRGGZA&issuer=Acme"

  """
  @spec otpauth_uri(String.t(), String.t(), keyword()) :: String.t()
  def otpauth_uri(label, secret, uri_params \\ []) do
    key = Base.encode32(secret, padding: false)
    params = [{:secret, key} | uri_params]
    query = URI.encode_query(params)
    "otpauth://totp/#{URI.encode(label)}?#{query}"
  end

  @doc """
  Generate a binary composed of random bytes.

  The number of bytes is defined by the `size` argument. Default is `20` per the
  [HOTP RFC](https://tools.ietf.org/html/rfc4226#section-4).

  ## Examples

      NimbleTOTP.secret()
      #=> <<178, 117, 46, 7, 172, 202, 108, 127, 186, 180, ...>>

  """
  @spec secret(non_neg_integer()) :: binary()
  def secret(size \\ 20) do
    :crypto.strong_rand_bytes(size)
  end

  @doc """
  Generate Time-Based One-Time Password.

  ## Options

    * :time - The time (either `%NaiveDateTime{}`, `%DateTime{}` or unix format) to
      be used. Default is `System.os_time(:second)`
    * :period - The period (in seconds) in which the code is valid. Default is `30`.

  ## Examples

      NimbleTOTP.verification_code(secret)
      #=> "569777"

  """
  @spec verification_code(binary(), [option()]) :: binary()
  def verification_code(secret, opts \\ []) do
    time = opts |> Keyword.get(:time, System.os_time(:second)) |> to_unix()
    period = Keyword.get(opts, :period, @default_totp_period)

    verification_code(secret, time, period)
  end

  @spec verification_code(binary(), integer(), pos_integer()) :: binary()
  defp verification_code(secret, time, period) do
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

  ## Options

    * :time - The time (either `%NaiveDateTime{}`, `%DateTime{}` or unix format) to
      be used. Default is `System.os_time(:second)`
    * :since - The last time the secret was used, see "Preventing TOTP code reuse" next
    * :period - The period (in seconds) in which the code is valid. Default is `30`.

  ## Preventing TOTP code reuse

  The `:since` option can be used to prevent TOTP codes from being reused. When set
  to the time when the last code was entered, only codes generated after that will
  be considered valid. This means a user may have to wait for the duration of the
  `:period` before they can enter a valid code again. This implementation meets the
  [TOTP RFC](https://datatracker.ietf.org/doc/html/rfc6238#section-5.2) requirements.

  Note that the TOTP codes regenerate every :period from unix epoch, so if you test
  for validity with :since you must consider when the TOTP code would have regenerated,
  as this would not be considered reused.

  ## Grace period

  In some cases it is preferable to allow the user more time to validate the code than
  the initial period (mostly 30 seconds), the so-called grace period. Although this library
  does not support this out of the box, you can achieve the same functionality by using
  the `:time` option.

      def valid_code?(secret, otp) do
        time = System.os_time(:second)

        NimbleTOTP.valid?(secret, otp, time: time) or NimbleTOTP.valid?(secret, otp, time: time - 30)
      end

  In this example by validating first against the current time, but also against 30 seconds
  ago, we allow the _previous_ code, to be still valid.
  """
  @spec valid?(binary(), [option() | validate_option()]) :: boolean()
  def valid?(secret, otp, opts \\ [])

  def valid?(secret, <<a1, a2, a3, a4, a5, a6>>, opts) do
    time = opts |> Keyword.get(:time, System.os_time(:second)) |> to_unix()
    period = Keyword.get(opts, :period, @default_totp_period)

    <<e1, e2, e3, e4, e5, e6>> = verification_code(secret, time, period)

    (bxor(e1, a1) ||| bxor(e2, a2) ||| bxor(e3, a3) ||| bxor(e4, a4) ||| bxor(e5, a5) |||
       bxor(e6, a6)) === 0 and not reused?(time, period, opts)
  end

  def valid?(_secret, _otp, _opts), do: false

  @spec reused?(integer(), pos_integer(), [option() | validate_option()]) :: boolean()
  defp reused?(time, period, opts) do
    if since = Keyword.get(opts, :since) do
      Integer.floor_div(time, period) <= Integer.floor_div(to_unix(since), period)
    else
      false
    end
  end

  @spec to_unix(NaiveDateTime.t()) :: integer()
  defp to_unix(%NaiveDateTime{} = naive_date_time),
    do: NaiveDateTime.diff(naive_date_time, ~N[1970-01-01 00:00:00])

  @spec to_unix(DateTime.t()) :: integer()
  defp to_unix(%DateTime{} = date_time), do: DateTime.to_unix(date_time)

  @spec to_unix(integer()) :: integer()
  defp to_unix(epoch) when is_integer(epoch), do: epoch
end
