defmodule MailAuth.Test.DKIMFixtures do
  @moduledoc false
  # Signed messages and keys: the RFC 6376 and RFC 8463 examples, and others
  # signed with the same keys. Messages are written with LF and turned into
  # CRLF.

  def unsigned_mail_string,
    do:
      crlf("""
      From: Joe SixPack <joe@football.example.com>
      To: Suzie Q <suzie@shopping.example.net>
      Subject: Is dinner ready?
      Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
      Message-ID: <20030712040037.46341.5F8J@football.example.com>

      Hi.

      We lost the game. Are you hungry yet?

      Joe.
      """)

  def verified_mail_string,
    do:
      crlf("""
      DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
            c=simple/simple; q=dns/txt; i=joe@football.example.com;
            h=Received : From : To : Subject : Date : Message-ID;
            bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
            b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
            4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
            KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
            4bmp/YzhwvcubU4=;
      Received: from client1.football.example.com  [192.0.2.1]
            by submitserver.example.com with SUBMISSION;
            Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
      From: Joe SixPack <joe@football.example.com>
      To: Suzie Q <suzie@shopping.example.net>
      Subject: Is dinner ready?
      Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
      Message-ID: <20030712040037.46341.5F8J@football.example.com>

      Hi.

      We lost the game. Are you hungry yet?

      Joe.
      """)

  def verified_raw_rsa_mail_string,
    do:
      crlf("""
      DKIM-Signature: a=rsa-sha256; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
       c=simple/simple; d=example.com;
       h=Received:From:To:Subject:Date:Message-ID; i=joe@football.example.com;
       s=newengland; t=1615825284; v=1;
       b=Xh4Ujb2wv5x54gXtulCiy4C0e+plRm6pZ4owF+kICpYzs/8WkTVIDBrzhJP0DAYCpnL62T0G
       k+0OH8pi/yqETVjKtKk+peMnNvKkut0GeWZMTze0bfq3/JUK3Ln3jTzzpXxrgVnvBxeY9EZIL4g
       s4wwFRRKz/1bksZGSjD8uuSU=
      Received: from client1.football.example.com  [192.0.2.1]
            by submitserver.example.com with SUBMISSION;
            Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
      From: Joe SixPack <joe@football.example.com>
      To: Suzie Q <suzie@shopping.example.net>
      Subject: Is dinner ready?
      Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
      Message-ID: <20030712040037.46341.5F8J@football.example.com>

      Hi.

      We lost the game. Are you hungry yet?

      Joe.
      """)

  def verified_ed25519_mail_string,
    do:
      crlf(
        String.trim_trailing(
          """
          DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
           d=football.example.com; i=@football.example.com;
           q=dns/txt; s=brisbane; t=1528637909; h=from : to :
           subject : date : message-id : from : subject : date;
           bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
           b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
           Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
          DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
           d=football.example.com; i=@football.example.com;
           q=dns/txt; s=test; t=1528637909; h=from : to : subject :
           date : message-id : from : subject : date;
           bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
           b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3
           DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz
           dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=
          From: Joe SixPack <joe@football.example.com>
          To: Suzie Q <suzie@shopping.example.net>
          Subject: Is dinner ready?
          Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
          Message-ID: <20030712040037.46341.5F8J@football.example.com>

          Hi.

          We lost the game.  Are you hungry yet?

          Joe.
          """,
          "\n"
        )
      )

  def too_many_signatures_mail_string,
    do:
      crlf("""
      DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
            c=simple/simple; q=dns/txt; i=joe@football.example.com;
            h=Received : From : To : Subject : Date : Message-ID;
            bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
            b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
            4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
            KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
            4bmp/YzhwvcubU4=;
      DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
            c=simple/simple; q=dns/txt; i=joe@football.example.com;
            h=Received : From : To : Subject : Date : Message-ID;
            bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
            b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
            4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
            KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
            4bmp/YzhwvcubU4=;
      DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
            c=simple/simple; q=dns/txt; i=joe@football.example.com;
            h=Received : From : To : Subject : Date : Message-ID;
            bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
            b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
            4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
            KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
            4bmp/YzhwvcubU4=;
      Received: from client1.football.example.com  [192.0.2.1]
            by submitserver.example.com with SUBMISSION;
            Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
      From: Joe SixPack <joe@football.example.com>
      To: Suzie Q <suzie@shopping.example.net>
      Subject: Is dinner ready?
      Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
      Message-ID: <20030712040037.46341.5F8J@football.example.com>

      Hi.

      We lost the game. Are you hungry yet?

      Joe.
      """)

  def rsa_private_key_pem,
    do: """
    -----BEGIN RSA PRIVATE KEY-----
    MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
    jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
    to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
    AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
    /1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
    gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
    n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
    3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
    eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
    7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
    qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
    eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
    GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
    -----END RSA PRIVATE KEY-----
    """

  def ed25519_seed, do: Base.decode64!("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")

  def dns_raw_rsa_public_key,
    do:
      "v=DKIM1; p=MIGJAoGBALVI635dLK4cJJAH3Lx6upo3X/Lm1tQz3mezcWTA3BUBnyIsdnRf57aD5BtNmhPrYYDlWlzw3UgnKisIxktkk5+iMQMlFtAS10JB8L3YadXNJY+JBcbeSi5TgJe4WFzNgW95FWDAuSTRXSWZfA/8xjflbTLDx0euFZOM7C4T0GwLAgMBAAE="

  def dns_public_key,
    do:
      "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB"

  def dns_ed25519_public_key,
    do: "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

  def rfc8463_rsa_public_key do
    "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR" <>
      "iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC" <>
      "DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3" <>
      "Ip3G+2kryOTIKT+l/K4w3QIDAQAB"
  end

  def records do
    %{
      "brisbane._domainkey.example.com" => [txt: dns_public_key()],
      "brisbane._domainkey.example.org" => [txt: dns_public_key()],
      "test._domainkey.football.example.com" => [txt: rfc8463_rsa_public_key()],
      "newengland._domainkey.example.com" => [txt: dns_raw_rsa_public_key()],
      "brisbane._domainkey.football.example.com" => [txt: dns_ed25519_public_key()]
    }
  end

  defp crlf(s), do: String.replace(s, "\n", "\r\n")
end
