defmodule MailAuth.Domain do
  @moduledoc false

  # Domain name helpers. Names are compared and queried in lowercase A-labels
  # (RFC 8616). Only labels with non-ASCII characters go through IDNA, since
  # ASCII labels such as "_dmarc" or "_domainkey" are not valid IDNA labels.

  @doc """
  Converts a domain to lowercase A-labels and drops a trailing dot.
  """
  @spec to_ascii(String.t()) :: {:ok, String.t()} | {:error, :invalid_domain}
  def to_ascii(domain) when is_binary(domain) do
    domain = domain |> String.trim() |> String.trim_trailing(".")

    if ascii?(domain) do
      {:ok, String.downcase(domain)}
    else
      domain
      |> String.split(".")
      |> Enum.reduce_while([], fn label, acc ->
        case label_to_ascii(label) do
          {:ok, label} -> {:cont, [label | acc]}
          :error -> {:halt, :error}
        end
      end)
      |> case do
        :error -> {:error, :invalid_domain}
        labels -> {:ok, labels |> Enum.reverse() |> Enum.join(".")}
      end
    end
  end

  @doc "Like `to_ascii/1`, but returns the input lowercased when it can't be converted."
  @spec to_ascii!(String.t()) :: String.t()
  def to_ascii!(domain) do
    case to_ascii(domain) do
      {:ok, ascii} -> ascii
      {:error, _} -> domain |> String.trim_trailing(".") |> String.downcase()
    end
  end

  defp label_to_ascii(label) do
    if ascii?(label) do
      {:ok, String.downcase(label)}
    else
      if String.valid?(label) do
        try do
          {:ok,
           label |> String.downcase() |> String.to_charlist() |> :idna.encode() |> to_string()}
        rescue
          _ -> :error
        catch
          _, _ -> :error
        end
      else
        :error
      end
    end
  end

  defp ascii?(s), do: s |> :binary.bin_to_list() |> Enum.all?(&(&1 < 128))

  @doc "Splits a domain into labels."
  @spec labels(String.t()) :: [String.t()]
  def labels(domain), do: String.split(domain, ".", trim: true)

  @doc "True when `domain` is `parent` or a subdomain of it."
  @spec subdomain_of?(String.t(), String.t()) :: boolean()
  def subdomain_of?(domain, parent),
    do: domain == parent or String.ends_with?(domain, "." <> parent)
end
