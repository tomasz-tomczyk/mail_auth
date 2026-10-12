defmodule MailAuth.DKIM.Result do
  @moduledoc """
  The result of checking one `DKIM-Signature` header.

  Fields:

    * `:result`: `:pass`, `:fail`, `:neutral`, `:none`, `:temperror` or `:permerror`
    * `:reason`: why it did not pass, as an atom. `nil` on a pass. See the
      README for every reason
    * `:domain`: the signing domain (`d=`), lowercase, in A-labels
    * `:selector`: the selector (`s=`)
    * `:identity`: the agent or user identifier (`i=`), or `"@"` and the domain
    * `:algorithm`: `:rsa_sha256`, `:ed25519_sha256` or `:rsa_sha1`
    * `:key_bits`: the size of the RSA key, or 256 for Ed25519, once the key was read
    * `:canonicalization`: `{header, body}`, each `:simple` or `:relaxed`
    * `:signed_headers`: the names in `h=`, lowercase, in order
    * `:signed_at`, `:expires_at`: the `t=` and `x=` times
    * `:body_length`: the `l=` value, when set
    * `:testing?`: true when the key has the `t=y` flag. The result is as
      computed; a caller may choose not to trust it
    * `:warnings`: things that pass but look wrong, such as `:from_not_oversigned`
  """

  @type result :: :pass | :fail | :neutral | :none | :temperror | :permerror
  @type algorithm :: :rsa_sha256 | :ed25519_sha256 | :rsa_sha1

  @type t :: %__MODULE__{
          result: result(),
          reason: atom() | nil,
          domain: String.t() | nil,
          selector: String.t() | nil,
          identity: String.t() | nil,
          algorithm: algorithm() | nil,
          key_bits: pos_integer() | nil,
          canonicalization: {:simple | :relaxed, :simple | :relaxed} | nil,
          signed_headers: [String.t()],
          signed_at: DateTime.t() | nil,
          expires_at: DateTime.t() | nil,
          body_length: non_neg_integer() | nil,
          testing?: boolean(),
          warnings: [atom()]
        }

  defstruct result: :none,
            reason: nil,
            domain: nil,
            selector: nil,
            identity: nil,
            algorithm: nil,
            key_bits: nil,
            canonicalization: nil,
            signed_headers: [],
            signed_at: nil,
            expires_at: nil,
            body_length: nil,
            testing?: false,
            warnings: []
end
