# STREAM_DATA_MAX_RUNS raises the number of runs of each property, as the
# weekly property workflow does.
if runs = System.get_env("STREAM_DATA_MAX_RUNS") do
  Application.put_env(:stream_data, :max_runs, String.to_integer(runs))
end

ExUnit.start(exclude: [:network])
