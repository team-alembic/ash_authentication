# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.Resettable do
  @moduledoc """
  The entity used to store password reset information.
  """

  defstruct token_lifetime: nil,
            request_password_reset_action_name: nil,
            password_reset_action_name: nil,
            sender: nil,
            __spark_metadata__: nil

  @type t :: %__MODULE__{
          token_lifetime: hours :: pos_integer,
          request_password_reset_action_name: atom,
          password_reset_action_name: atom,
          sender: {module, keyword},
          __spark_metadata__: Spark.Dsl.Entity.spark_meta()
        }
end
