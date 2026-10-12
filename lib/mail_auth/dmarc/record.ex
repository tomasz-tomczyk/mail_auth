defmodule MailAuth.DMARC.Record do
  @moduledoc """
  A DMARC policy record (RFC 9989).

  Fields:

    * `:domain`: where the record was found, without the `_dmarc.` prefix
    * `:p`, `:sp`, `:np`: the policies, `:none`, `:quarantine` or `:reject`,
      or `nil` when the tag is missing or not valid
    * `:adkim`, `:aspf`: `:relaxed` (the default) or `:strict`
    * `:psd`: `:yes`, `:no` or `:unknown` (the default)
    * `:testing?`: true for `t=y`
    * `:rua`, `:ruf`: report addresses, as written
    * `:fo`: the failure reporting options, as written
    * `:warnings`: problems found while parsing, such as `:missing_policy`

  Unknown tags, and the `pct`, `rf` and `ri` tags that RFC 9989 removed, are
  ignored. A record without a valid `p` tag, or with an `sp` or `np` tag that
  is not valid, is read as `p=none` when it has a `rua` address, and does not
  apply otherwise, as RFC 9989 section 4.10.1 says.
  """

  alias MailAuth.Tags

  @type policy :: :none | :quarantine | :reject

  @type t :: %__MODULE__{
          domain: String.t() | nil,
          p: policy() | nil,
          sp: policy() | nil,
          np: policy() | nil,
          adkim: :relaxed | :strict,
          aspf: :relaxed | :strict,
          psd: :yes | :no | :unknown,
          testing?: boolean(),
          rua: [String.t()],
          ruf: [String.t()],
          fo: String.t() | nil,
          warnings: [atom()]
        }

  defstruct domain: nil,
            p: nil,
            sp: nil,
            np: nil,
            adkim: :relaxed,
            aspf: :relaxed,
            psd: :unknown,
            testing?: false,
            rua: [],
            ruf: [],
            fo: nil,
            warnings: []

  @doc """
  Parses a TXT record. Returns `:error` unless its first tag is `v=DMARC1`.
  """
  @spec parse(binary(), String.t() | nil) :: {:ok, t()} | :error
  def parse(txt, domain \\ nil) when is_binary(txt) do
    case Tags.parse(txt) do
      {:ok, [{"v", "DMARC1"} | tags]} -> {:ok, build(tags, domain)}
      {:error, :duplicate} -> :error
      {:error, :malformed} -> lenient(txt, domain)
      _ -> :error
    end
  end

  # A broken tag after v=DMARC1 does not throw the record away; the tags that
  # can be read are kept.
  defp lenient(txt, domain) do
    tags =
      txt
      |> :binary.split(";", [:global])
      |> Enum.flat_map(fn segment ->
        case :binary.split(segment, "=") do
          [name, value] -> [{Tags.trim(name), Tags.trim(value)}]
          _ -> []
        end
      end)

    case tags do
      [{"v", "DMARC1"} | tags] -> {:ok, build(tags, domain)}
      _ -> :error
    end
  end

  defp build(tags, domain) do
    tags = Enum.map(tags, fn {k, v} -> {String.downcase(k), v} end)
    get = fn name -> List.keyfind(tags, name, 0) |> then(&(&1 && elem(&1, 1))) end
    p = get.("p")

    %__MODULE__{
      domain: domain,
      p: policy(p),
      sp: policy(get.("sp")),
      np: policy(get.("np")),
      adkim: alignment(get.("adkim")),
      aspf: alignment(get.("aspf")),
      psd: psd(get.("psd")),
      testing?: flag(get.("t")),
      rua: uris(get.("rua")),
      ruf: uris(get.("ruf")),
      fo: get.("fo"),
      warnings:
        cond do
          is_nil(p) -> [:missing_policy]
          is_nil(policy(p)) -> [:invalid_policy]
          invalid?(get.("sp")) or invalid?(get.("np")) -> [:invalid_policy]
          true -> []
        end
    }
  end

  defp policy(nil), do: nil

  defp policy(value) do
    case String.downcase(value) do
      "none" -> :none
      "quarantine" -> :quarantine
      "reject" -> :reject
      _ -> nil
    end
  end

  defp invalid?(value), do: value != nil and policy(value) == nil

  @doc """
  True when the record has a `p` tag and valid `sp` and `np` tags, if any.
  RFC 9989 reads a record without them as `p=none` only when it has a
  report address; otherwise DMARC does not apply.
  """
  @spec valid_policy?(t()) :: boolean()
  def valid_policy?(%__MODULE__{warnings: warnings}),
    do: :missing_policy not in warnings and :invalid_policy not in warnings

  defp alignment(value) do
    if value && String.downcase(value) == "s", do: :strict, else: :relaxed
  end

  defp psd(nil), do: :unknown

  defp psd(value) do
    case String.downcase(value) do
      "y" -> :yes
      "n" -> :no
      _ -> :unknown
    end
  end

  defp flag(value), do: value != nil and String.downcase(value) == "y"

  defp uris(nil), do: []

  defp uris(value) do
    value |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
  end
end
