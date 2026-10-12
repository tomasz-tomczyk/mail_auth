defmodule MailAuth.ReadmeTest do
  use ExUnit.Case, async: true

  @readme File.read!("README.md")

  test "the dependency line matches the version in mix.exs" do
    version = Version.parse!(Mix.Project.config()[:version])
    assert @readme =~ ~s({:mail_auth, "~> #{version.major}.#{version.minor}"})
  end

  test "every reason and warning in the README has a test" do
    tests =
      "test/**/*_test.exs"
      |> Path.wildcard()
      |> Enum.reject(&(&1 == "test/readme_test.exs"))
      |> Enum.map_join(&File.read!/1)

    atoms =
      ~r/^\| [A-Za-z-]+ \| (`:[a-z_]+`(?:, `:[a-z_]+`)*) \|/m
      |> Regex.scan(@readme, capture: :all_but_first)
      |> List.flatten()
      |> Enum.flat_map(&Regex.scan(~r/:[a-z_]+/, &1))
      |> List.flatten()
      |> Enum.uniq()

    assert length(atoms) > 50
    untested = Enum.reject(atoms, &String.contains?(tests, &1))
    assert untested == []
  end
end
