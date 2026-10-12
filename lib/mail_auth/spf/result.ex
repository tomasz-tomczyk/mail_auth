defmodule MailAuth.SPF.Result do
  @moduledoc """
  The result of an SPF check (RFC 7208).

  Fields:

    * `:result`: `:pass`, `:fail`, `:softfail`, `:neutral`, `:none`,
      `:temperror` or `:permerror`
    * `:reason`: why, when no mechanism decided it. See the README
    * `:domain`: the domain whose record was checked: the `MAIL FROM`
      domain, or the HELO name for a bounce
    * `:mail_from`: the sender checked, `postmaster@<helo>` for a bounce
    * `:helo`: the HELO name
    * `:identity`: `:mailfrom`, or `:helo` when `MAIL FROM` was empty
    * `:ip`: the client IP, as a string
    * `:mechanism`: the term that decided the result, such as `"-all"` or
      `"include:_spf.example.com"`
    * `:explanation`: the `exp=` text, on a fail
    * `:trace`: each `{domain, record}` evaluated, in order, through
      `include` and `redirect`
    * `:warnings`: such as `:ptr_used`
  """

  @type t :: %__MODULE__{
          result: :pass | :fail | :softfail | :neutral | :none | :temperror | :permerror,
          reason: atom() | nil,
          domain: String.t() | nil,
          mail_from: String.t() | nil,
          helo: String.t() | nil,
          identity: :mailfrom | :helo | nil,
          ip: String.t() | nil,
          mechanism: String.t() | nil,
          explanation: String.t() | nil,
          trace: [{String.t(), String.t()}],
          warnings: [atom()]
        }

  defstruct result: :none,
            reason: nil,
            domain: nil,
            mail_from: nil,
            helo: nil,
            identity: nil,
            ip: nil,
            mechanism: nil,
            explanation: nil,
            trace: [],
            warnings: []
end
