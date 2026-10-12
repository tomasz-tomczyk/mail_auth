defmodule MailAuth.AuthenticationResults.Method do
  @moduledoc """
  One method's result in an `Authentication-Results:` header, such as
  `dkim=pass header.d=example.com`.

  Fields:

    * `:method`: the method name, lowercase, such as `"dkim"`, `"spf"` or
      `"dmarc"`. Unknown methods are kept
    * `:version`: the method version, when written (`dkim/1=pass`)
    * `:result`: `:pass`, `:fail`, `:softfail`, `:neutral`, `:none`,
      `:temperror`, `:permerror`, `:policy` or `:hardfail`, or the text as
      written when it is none of these
    * `:reason`: the `reason=` text
    * `:properties`: the other properties, such as
      `%{"header.d" => "example.com"}`, with lowercase names
  """

  @type t :: %__MODULE__{
          method: String.t(),
          version: String.t() | nil,
          result: atom() | String.t(),
          reason: String.t() | nil,
          properties: %{String.t() => String.t()}
        }

  defstruct method: nil, version: nil, result: nil, reason: nil, properties: %{}

  @results %{
    "pass" => :pass,
    "fail" => :fail,
    "softfail" => :softfail,
    "neutral" => :neutral,
    "none" => :none,
    "temperror" => :temperror,
    "permerror" => :permerror,
    "policy" => :policy,
    "hardfail" => :hardfail
  }

  @doc false
  def result_value(text), do: Map.get(@results, String.downcase(text), text)
end
