defmodule MailAuth do
  @moduledoc """
  Checks whether an email really came from who it says.

  `authenticate/2` runs every check it can:

    * DKIM, always (`MailAuth.DKIM`)
    * SPF, when the client IP is given with `:ip` (`MailAuth.SPF`). Without it,
      as for mail read over IMAP, SPF is `:none`, reason `:no_client_ip`
    * DMARC, from the DKIM and SPF results, unless `dmarc: false`
      (`MailAuth.DMARC`)

  ```elixir
  result = MailAuth.authenticate(raw)

  if MailAuth.Result.dmarc_pass?(result) do
    # The From: domain sent this message.
  end
  ```

  `raw` is the message exactly as stored, headers and body. Lines end in
  CRLF; a message with bare LF line endings is read as if each LF were CRLF.

  ## Options for every call

    * `:resolver`: a module implementing `MailAuth.Resolver`. Default
      `MailAuth.Resolver.Inet`
    * `:deadline`: milliseconds for the whole call. Default 15000. A check
      still waiting on DNS at the deadline is `:temperror`, reason `:deadline`
    * `:timeout`: milliseconds per DNS query. Default 5000
    * `:now`: the time to check signatures against, in Unix seconds or a
      `DateTime`. Default: now

  ## Options for `authenticate/2`

    * `:ip`: the client IP, a tuple or a string, to run SPF
    * `:mail_from`: the `MAIL FROM` address. Empty for a bounce
    * `:helo`: the HELO name
    * `:dmarc`: `false` to skip DMARC

  and the options of `MailAuth.DKIM.verify/2`, `MailAuth.SPF.check/4` and
  `MailAuth.DMARC.evaluate/3`.
  """

  alias MailAuth.{DKIM, DMARC, DNS, Message, Result, SPF}

  @doc "Runs DKIM, SPF (with `:ip`) and DMARC on a message."
  @spec authenticate(binary(), keyword()) :: Result.t()
  def authenticate(raw, opts \\ []) when is_binary(raw) do
    opts = DNS.start(opts)

    :telemetry.span([:mail_auth, :authenticate], %{}, fn ->
      result = do_authenticate(raw, opts)

      {result,
       %{
         dkim: Enum.map(result.dkim, & &1.result),
         spf: result.spf && result.spf.result,
         dmarc: result.dmarc && result.dmarc.result
       }}
    end)
  end

  defp do_authenticate(raw, opts) do
    parsed = Message.parse(raw)
    dkim = DKIM.verify(raw, opts)
    spf = spf(opts)

    dmarc =
      cond do
        Keyword.get(opts, :dmarc, true) == false ->
          nil

        match?({:error, _}, parsed) ->
          %DMARC.Result{result: :permerror, reason: elem(parsed, 1)}

        true ->
          DMARC.evaluate_message(elem(parsed, 1), dkim, Keyword.put(opts, :spf, spf))
      end

    from_domain =
      case parsed do
        {:ok, msg} ->
          case DMARC.from_domain(msg) do
            {:ok, domain} -> domain
            {:error, _} -> nil
          end

        _ ->
          nil
      end

    warnings =
      (Enum.flat_map(dkim, & &1.warnings) ++
         ((spf && spf.warnings) || []) ++ ((dmarc && dmarc.warnings) || []))
      |> Enum.uniq()

    %Result{from_domain: from_domain, dkim: dkim, spf: spf, dmarc: dmarc, warnings: warnings}
  end

  defp spf(opts) do
    case Keyword.get(opts, :ip) do
      nil ->
        %SPF.Result{result: :none, reason: :no_client_ip}

      ip ->
        SPF.check(ip, Keyword.get(opts, :mail_from), Keyword.get(opts, :helo), opts)
    end
  end
end
