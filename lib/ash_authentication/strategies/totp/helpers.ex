# SPDX-FileCopyrightText: 2025 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.Helpers do
  @moduledoc false

  @doc """
  Converts a DateTime, nil, or unix timestamp to unix timestamp.

  Used to normalise `last_totp_at` values for NimbleTOTP's `since` option.
  """
  @spec datetime_to_unix(DateTime.t() | nil | integer) :: integer
  def datetime_to_unix(nil), do: 0
  def datetime_to_unix(%DateTime{} = dt), do: DateTime.to_unix(dt)
  def datetime_to_unix(unix) when is_integer(unix), do: unix

  @doc """
  Converts time values (with optional units) to seconds.

  Note: The TOTP transformer already converts time values from DSL config to
  seconds, so integers are already in seconds when they reach action code.

  Accepts:
  - Integer (already in seconds from transformer)
  - `{value, :seconds}` - value in seconds
  - `{value, :minutes}` - value in minutes
  - `{value, :hours}` - value in hours
  - `{value, :days}` - value in days
  """
  @spec time_to_seconds(integer | {pos_integer, :seconds | :minutes | :hours | :days}) ::
          pos_integer
  def time_to_seconds(seconds) when is_integer(seconds), do: seconds
  def time_to_seconds({value, :days}), do: value * 86_400
  def time_to_seconds({value, :hours}), do: value * 3600
  def time_to_seconds({value, :minutes}), do: value * 60
  def time_to_seconds({value, :seconds}), do: value

  @doc """
  Validates that a TOTP code is exactly 6 digits.

  Returns `:ok` if valid, `{:error, :invalid_format}` otherwise.
  """
  @spec validate_totp_code(any) :: :ok | {:error, :invalid_format}
  def validate_totp_code(code) when is_binary(code) do
    if Regex.match?(~r/^\d{6}$/, code), do: :ok, else: {:error, :invalid_format}
  end

  def validate_totp_code(_), do: {:error, :invalid_format}

  @doc """
  Validates a TOTP code against a secret, respecting the strategy's grace period.

  When `grace_period` is nil, calls `NimbleTOTP.valid?/3` directly.
  When set to `n`, also accepts codes from the previous `n` time periods.
  """
  @spec valid_totp?(binary, binary, AshAuthentication.Strategy.Totp.t(), keyword) :: boolean
  def valid_totp?(secret, code, strategy, opts \\ []) do
    base_opts = [period: strategy.period] ++ opts

    if strategy.grace_period do
      time = System.os_time(:second)

      Enum.any?(0..strategy.grace_period, fn i ->
        NimbleTOTP.valid?(secret, code, [{:time, time - i * strategy.period} | base_opts])
      end)
    else
      NimbleTOTP.valid?(secret, code, base_opts)
    end
  end
end
