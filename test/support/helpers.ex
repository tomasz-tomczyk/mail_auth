defmodule MailAuth.Test.Helpers do
  @moduledoc false

  alias MailAuth.Test.DKIMFixtures

  @message "From: Joe <joe@example.com>\r\n" <>
             "To: Suzie <suzie@example.net>\r\n" <>
             "Subject: Is dinner ready?\r\n" <>
             "Date: Fri, 11 Jul 2003 21:00:37 -0700\r\n" <>
             "Message-ID: <1@example.com>\r\n" <>
             "\r\n" <>
             "Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n"

  def message, do: @message

  def message(from), do: String.replace(@message, "joe@example.com", from)

  @doc "Signs with the 1024-bit test key, published at `selector._domainkey.domain`."
  def sign(raw, domain, opts \\ []) do
    selector = Keyword.get(opts, :selector, "s1")

    {:ok, signed} =
      MailAuth.DKIM.sign(
        raw,
        Keyword.merge(
          [domain: domain, selector: selector, private_key: DKIMFixtures.rsa_private_key_pem()],
          opts
        )
      )

    signed
  end

  def key_record(domain, selector \\ "s1"),
    do: %{"#{selector}._domainkey.#{domain}" => [txt: DKIMFixtures.dns_public_key()]}

  def static(records, opts \\ []),
    do: Keyword.merge([resolver: MailAuth.Resolver.Static, records: records], opts)

  @doc "Runs `fun` and returns its result with the names queried, in order."
  def capture_queries(fun) do
    ref = make_ref()
    parent = self()
    id = {__MODULE__, ref}

    :telemetry.attach(
      id,
      [:mail_auth, :dns, :lookup, :start],
      # Handlers are global; count only this process's queries.
      fn _event, _measure, meta, _ ->
        if self() == parent, do: send(parent, {ref, meta.name, meta.type})
      end,
      nil
    )

    try do
      result = fun.()
      {result, collect(ref, [])}
    after
      :telemetry.detach(id)
    end
  end

  defp collect(ref, acc) do
    receive do
      {^ref, name, type} -> collect(ref, [{name, type} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end
