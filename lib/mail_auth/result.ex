defmodule MailAuth.Result do
  @moduledoc """
  The result of `MailAuth.authenticate/2`.

  Fields:

    * `:from_domain`: the domain of the `From:` address, or `nil` when there
      is not exactly one
    * `:dkim`: one `MailAuth.DKIM.Result` per signature
    * `:spf`: the `MailAuth.SPF.Result`. Without a client IP it is `:none`,
      reason `:no_client_ip`
    * `:dmarc`: the `MailAuth.DMARC.Result`, or `nil` with `dmarc: false`
    * `:warnings`: the warnings of all the checks, without repeats
  """

  @type t :: %__MODULE__{
          from_domain: String.t() | nil,
          dkim: [MailAuth.DKIM.Result.t()],
          spf: MailAuth.SPF.Result.t() | nil,
          dmarc: MailAuth.DMARC.Result.t() | nil,
          warnings: [atom()]
        }

  defstruct from_domain: nil, dkim: [], spf: nil, dmarc: nil, warnings: []

  @doc """
  True only when DMARC passed: a DKIM signature or the SPF check that passed
  belongs to the `From:` domain.

  This is the one call most callers need.
  """
  @spec dmarc_pass?(t()) :: boolean()
  def dmarc_pass?(%__MODULE__{dmarc: %MailAuth.DMARC.Result{result: :pass}}), do: true
  def dmarc_pass?(%__MODULE__{}), do: false
end
