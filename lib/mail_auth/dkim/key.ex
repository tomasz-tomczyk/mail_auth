defmodule MailAuth.DKIM.Key do
  @moduledoc false

  # DKIM key records (RFC 6376 section 3.6.1) and private keys.

  alias MailAuth.Tags

  @max_rsa_bits 4096
  @ed25519_oid {1, 3, 101, 112}

  defstruct [:type, :key, :bits, hashes: nil, services: nil, flags: []]

  @type t :: %__MODULE__{
          type: :rsa | :ed25519,
          key: term(),
          bits: pos_integer(),
          hashes: [String.t()] | nil,
          services: [String.t()] | nil,
          flags: [String.t()]
        }

  @doc "Parses the TXT record of a DKIM public key."
  @spec parse(binary()) :: {:ok, t()} | {:error, atom()}
  def parse(txt) do
    with {:ok, tags} <- tags(txt),
         map = Map.new(tags),
         :ok <- check_version(tags),
         {:ok, p} <- fetch_p(map),
         {:ok, type} <- key_type(map),
         {:ok, der} <- decode(p),
         {:ok, key, bits} <- decode_key(type, der) do
      {:ok,
       %__MODULE__{
         type: type,
         key: key,
         bits: bits,
         hashes: list(map, "h"),
         services: list(map, "s"),
         flags: list(map, "t") || []
       }}
    end
  end

  defp tags(txt) do
    case Tags.parse(txt) do
      {:ok, tags} -> {:ok, tags}
      {:error, _} -> {:error, :malformed_key}
    end
  end

  # v= is optional, but when present it must be first and DKIM1.
  defp check_version(tags) do
    case List.keyfind(tags, "v", 0) do
      nil -> :ok
      {"v", "DKIM1"} -> if hd(tags) == {"v", "DKIM1"}, do: :ok, else: {:error, :malformed_key}
      _ -> {:error, :malformed_key}
    end
  end

  defp fetch_p(map) do
    case Map.fetch(map, "p") do
      {:ok, p} -> if Tags.strip_whitespace(p) == "", do: {:error, :key_revoked}, else: {:ok, p}
      :error -> {:error, :malformed_key}
    end
  end

  defp key_type(map) do
    case map |> Map.get("k", "rsa") |> String.downcase() do
      "rsa" -> {:ok, :rsa}
      "ed25519" -> {:ok, :ed25519}
      _ -> {:error, :unsupported_key_type}
    end
  end

  defp decode(p) do
    case Tags.decode64(p) do
      {:ok, der} -> {:ok, der}
      :error -> {:error, :malformed_key}
    end
  end

  defp decode_key(:ed25519, <<key::binary-size(32)>>), do: {:ok, key, 256}
  defp decode_key(:ed25519, _), do: {:error, :malformed_key}

  defp decode_key(:rsa, der) do
    # RFC 6376 says SubjectPublicKeyInfo, but some publish a bare
    # RSAPublicKey (erratum 3017), so accept both.
    with :error <-
           try_decode(fn ->
             :public_key.pem_entry_decode({:SubjectPublicKeyInfo, der, :not_encrypted})
           end),
         :error <- try_decode(fn -> :public_key.der_decode(:RSAPublicKey, der) end) do
      {:error, :malformed_key}
    else
      {:ok, {:RSAPublicKey, n, _e} = key} ->
        bits = bit_length(n)
        if bits > @max_rsa_bits, do: {:error, :key_too_large}, else: {:ok, key, bits}

      {:ok, _other} ->
        {:error, :malformed_key}
    end
  end

  defp try_decode(fun) do
    {:ok, fun.()}
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  defp bit_length(n) when is_integer(n) and n > 0, do: length(Integer.digits(n, 2))
  defp bit_length(_), do: 0

  defp list(map, tag) do
    case Map.fetch(map, tag) do
      {:ok, value} -> value |> Tags.colon_list() |> Enum.map(&String.downcase/1)
      :error -> nil
    end
  end

  @doc """
  Reads a private key: PEM, a decoded `:public_key` record, or
  `{:ed25519, seed}` with the 32-byte seed.
  """
  @spec private_key(term()) :: {:ok, {:rsa, tuple()} | {:ed25519, binary()}} | {:error, atom()}
  def private_key(pem) when is_binary(pem) do
    case try_decode(fn -> :public_key.pem_decode(pem) end) do
      {:ok, [entry | _]} ->
        case try_decode(fn -> :public_key.pem_entry_decode(entry) end) do
          {:ok, key} -> private_key(key)
          :error -> {:error, :invalid_private_key}
        end

      _ ->
        {:error, :invalid_private_key}
    end
  end

  def private_key({:ed25519, <<seed::binary-size(32)>>}), do: {:ok, {:ed25519, seed}}

  def private_key(key) when is_tuple(key) and elem(key, 0) == :RSAPrivateKey,
    do: {:ok, {:rsa, key}}

  def private_key({:ECPrivateKey, _, seed, {:namedCurve, @ed25519_oid}, _, _})
      when byte_size(seed) == 32,
      do: {:ok, {:ed25519, seed}}

  def private_key(_), do: {:error, :invalid_private_key}

  @doc "Generates a key pair and the TXT record for its public key."
  @spec generate(:rsa | :ed25519, keyword()) :: %{private_key: String.t(), dns_record: String.t()}
  def generate(:rsa, opts) do
    bits = Keyword.get(opts, :bits, 2048)
    key = :public_key.generate_key({:rsa, bits, 65_537})
    {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} = key
    pem = :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, key)])

    {:SubjectPublicKeyInfo, der, _} =
      :public_key.pem_entry_encode(:SubjectPublicKeyInfo, {:RSAPublicKey, n, e})

    %{private_key: pem, dns_record: "v=DKIM1; k=rsa; p=" <> Base.encode64(der)}
  end

  def generate(:ed25519, _opts) do
    {pub, seed} = :crypto.generate_key(:eddsa, :ed25519)
    record = {:ECPrivateKey, 1, seed, {:namedCurve, @ed25519_oid}, pub, :asn1_NOVALUE}
    pem = :public_key.pem_encode([:public_key.pem_entry_encode(:PrivateKeyInfo, record)])
    %{private_key: pem, dns_record: "v=DKIM1; k=ed25519; p=" <> Base.encode64(pub)}
  end
end
