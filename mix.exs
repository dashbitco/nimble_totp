defmodule NimbleTOTP.MixProject do
  use Mix.Project

  @version "0.1.0"
  @repo_url "https://github.com/dashbitco/nimble_totp"

  def project do
    [
      app: :nimble_totp,
      version: @version,
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Hex
      package: package(),
      description: "A tiny library for Two-factor authentication (2FA)",

      # Docs
      name: "NimbleTOTP",
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, ">= 0.19.0", only: :docs}
    ]
  end

  defp package do
    [
      licenses: ["Apache 2.0"],
      links: %{"GitHub" => @repo_url}
    ]
  end

  defp docs do
    [
      main: "NimbleTOTP",
      source_ref: "v#{@version}",
      source_url: @repo_url
    ]
  end
end
