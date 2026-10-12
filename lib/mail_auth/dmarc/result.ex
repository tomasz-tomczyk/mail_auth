defmodule MailAuth.DMARC.Result do
  @moduledoc """
  The result of a DMARC check (RFC 9989).

  Fields:

    * `:result`: `:pass`, `:fail`, `:none`, `:temperror` or `:permerror`
    * `:reason`: why it did not pass, as an atom. See the README
    * `:from_domain`: the domain of the `From:` address, in A-labels
    * `:organizational_domain`: the From domain's organizational domain
    * `:record_domain`: where the record that applies was found
    * `:record`: the `MailAuth.DMARC.Record` that applies
    * `:policy`: the policy that applies to this domain: `p`, `sp` or `np`
    * `:testing?`: true when the record has `t=y`
    * `:disposition`: what the domain asks a receiver to do with this
      message: `:none` on a pass, otherwise the policy, one step lower when
      `testing?`. The library reports it and never acts on it
    * `:aligned_by`: which checks aligned with the From domain, `:dkim` and `:spf`
    * `:dkim_domain`: the `d=` of the aligned DKIM signature, or of the first
      that passed
    * `:spf_domain`: the domain SPF checked
    * `:warnings`: such as `:missing_policy`
  """

  @type t :: %__MODULE__{
          result: :pass | :fail | :none | :temperror | :permerror,
          reason: atom() | nil,
          from_domain: String.t() | nil,
          organizational_domain: String.t() | nil,
          record_domain: String.t() | nil,
          record: MailAuth.DMARC.Record.t() | nil,
          policy: MailAuth.DMARC.Record.policy() | nil,
          testing?: boolean(),
          disposition: MailAuth.DMARC.Record.policy(),
          aligned_by: [:dkim | :spf],
          dkim_domain: String.t() | nil,
          spf_domain: String.t() | nil,
          warnings: [atom()]
        }

  defstruct result: :none,
            reason: nil,
            from_domain: nil,
            organizational_domain: nil,
            record_domain: nil,
            record: nil,
            policy: nil,
            testing?: false,
            disposition: :none,
            aligned_by: [],
            dkim_domain: nil,
            spf_domain: nil,
            warnings: []
end
