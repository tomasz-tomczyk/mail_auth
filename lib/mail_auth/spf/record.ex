defmodule MailAuth.SPF.Record do
  @moduledoc false

  # SPF records, RFC 7208 sections 4.5, 4.6 and 5.

  alias MailAuth.SPF.Macro

  defstruct directives: [], redirect: nil, exp: nil, has_all?: false

  @type qualifier :: :pass | :fail | :softfail | :neutral
  @type mechanism ::
          :all
          | {:include, Macro.t()}
          | {:a, Macro.t() | nil, 0..32, 0..128}
          | {:mx, Macro.t() | nil, 0..32, 0..128}
          | {:ptr, Macro.t() | nil}
          | {:ip4, :inet.ip4_address(), 0..32}
          | {:ip6, :inet.ip6_address(), 0..128}
          | {:exists, Macro.t()}
  @type t :: %__MODULE__{
          directives: [{qualifier(), mechanism(), String.t()}],
          redirect: Macro.t() | nil,
          exp: Macro.t() | nil,
          has_all?: boolean()
        }

  @doc "True when a TXT record is an SPF record: `v=spf1` and then a space or the end."
  @spec spf?(binary()) :: boolean()
  def spf?(txt), do: Regex.match?(~r/\Av=spf1( |\z)/i, txt)

  @doc "Parses an SPF record. Any syntax error makes the whole record invalid."
  @spec parse(binary()) :: {:ok, t()} | :error
  def parse(txt) do
    with true <- spf?(txt),
         true <- ascii?(txt) do
      txt
      |> binary_part(6, byte_size(txt) - 6)
      |> String.split(" ", trim: true)
      |> Enum.reduce_while(%__MODULE__{}, fn term, acc ->
        case term(term, acc) do
          {:ok, acc} -> {:cont, acc}
          :error -> {:halt, :error}
        end
      end)
      |> case do
        :error -> :error
        record -> {:ok, %{record | directives: Enum.reverse(record.directives)}}
      end
    else
      _ -> :error
    end
  end

  defp ascii?(txt), do: txt |> :binary.bin_to_list() |> Enum.all?(&(&1 in 0x20..0x7E))

  defp term(term, acc) do
    case Regex.run(~r/\A([a-z][a-z0-9\-_.]*)=(.*)\z/is, term) do
      [_, name, value] -> modifier(String.downcase(name), value, acc)
      nil -> directive(term, acc)
    end
  end

  defp modifier("redirect", value, %{redirect: nil} = acc) do
    with {:ok, spec} <- domain_spec(value), do: {:ok, %{acc | redirect: spec}}
  end

  defp modifier("exp", value, %{exp: nil} = acc) do
    with {:ok, spec} <- domain_spec(value), do: {:ok, %{acc | exp: spec}}
  end

  defp modifier(name, _value, _acc) when name in ["redirect", "exp"], do: :error

  defp modifier(_unknown, value, acc) do
    case Macro.parse(value) do
      {:ok, _} -> {:ok, acc}
      :error -> :error
    end
  end

  defp directive(term, acc) do
    {qualifier, rest} = qualifier(term)

    {name, arg} =
      case Regex.run(~r/\A([a-z0-9]+)(.*)\z/is, rest) do
        [_, name, arg] -> {String.downcase(name), arg}
        nil -> {nil, rest}
      end

    with {:ok, mechanism} <- mechanism(name, arg) do
      directive = {qualifier, mechanism, term}

      {:ok,
       %{
         acc
         | directives: [directive | acc.directives],
           has_all?: acc.has_all? or mechanism == :all
       }}
    end
  end

  defp qualifier(<<"+", rest::binary>>), do: {:pass, rest}
  defp qualifier(<<"-", rest::binary>>), do: {:fail, rest}
  defp qualifier(<<"~", rest::binary>>), do: {:softfail, rest}
  defp qualifier(<<"?", rest::binary>>), do: {:neutral, rest}
  defp qualifier(rest), do: {:pass, rest}

  defp mechanism("all", ""), do: {:ok, :all}

  defp mechanism(name, <<":", spec::binary>>) when name in ["include", "exists"] do
    with {:ok, spec} <- domain_spec(spec),
         do: {:ok, {if(name == "include", do: :include, else: :exists), spec}}
  end

  defp mechanism(name, arg) when name in ["a", "mx"] do
    type = if name == "a", do: :a, else: :mx

    with {:ok, spec, cidr} <- spec_and_cidr(arg),
         {:ok, v4, v6} <- dual_cidr(cidr) do
      {:ok, {type, spec, v4, v6}}
    end
  end

  defp mechanism("ptr", ""), do: {:ok, {:ptr, nil}}

  defp mechanism("ptr", <<":", spec::binary>>) do
    with {:ok, spec} <- domain_spec(spec), do: {:ok, {:ptr, spec}}
  end

  defp mechanism("ip4", <<":", value::binary>>) do
    with [addr | cidr] <- String.split(value, "/", parts: 2),
         {:ok, ip} <- ip4(addr),
         {:ok, len} <- cidr(cidr, 32) do
      {:ok, {:ip4, ip, len}}
    else
      _ -> :error
    end
  end

  defp mechanism("ip6", <<":", value::binary>>) do
    with [addr | cidr] <- String.split(value, "/", parts: 2),
         {:ok, ip} <- :inet.parse_ipv6strict_address(String.to_charlist(addr)),
         {:ok, len} <- cidr(cidr, 128) do
      {:ok, {:ip6, ip, len}}
    else
      _ -> :error
    end
  end

  defp mechanism(_name, _arg), do: :error

  defp ip4(addr) do
    if Regex.match?(~r/\A(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}\z/, addr),
      do: :inet.parse_ipv4strict_address(String.to_charlist(addr)),
      else: :error
  end

  defp cidr([], max), do: {:ok, max}

  defp cidr([len], max) do
    if Regex.match?(~r/\A(0|[1-9][0-9]{0,2})\z/, len) and String.to_integer(len) <= max,
      do: {:ok, String.to_integer(len)},
      else: :error
  end

  # "a", "a:example.com", "a/24", "a:example.com/24//64"
  defp spec_and_cidr(""), do: {:ok, nil, ""}
  defp spec_and_cidr(<<"/", _::binary>> = cidr), do: {:ok, nil, cidr}

  defp spec_and_cidr(<<":", rest::binary>>) do
    {spec, cidr} =
      case Regex.run(~r/\A(.*?)((?:\/[0-9]+)?(?:\/\/[0-9]+)?)\z/s, rest) do
        [_, spec, cidr] -> {spec, cidr}
      end

    with {:ok, spec} <- domain_spec(spec), do: {:ok, spec, cidr}
  end

  defp spec_and_cidr(_), do: :error

  defp dual_cidr(cidr) do
    case Regex.run(~r/\A(?:\/([0-9]+))?(?:\/\/([0-9]+))?\z/, cidr) do
      nil ->
        :error

      parts ->
        [v4, v6] = parts |> tl() |> Enum.concat(["", ""]) |> Enum.take(2)

        with {:ok, v4} <- cidr(non_empty(v4), 32),
             {:ok, v6} <- cidr(non_empty(v6), 128) do
          {:ok, v4, v6}
        end
    end
  end

  defp non_empty(""), do: []
  defp non_empty(s), do: [s]

  defp domain_spec(""), do: :error

  defp domain_spec(spec) do
    with {:ok, parts} <- Macro.parse(spec),
         true <- Macro.valid_domain_end?(parts) do
      {:ok, parts}
    else
      _ -> :error
    end
  end
end
