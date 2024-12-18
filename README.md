# Nginx to Go Replay
This is a script that allows for the conversion of Nginx Access logs to [GoReplay](https://github.com/buger/goreplay) `.gor` file format.
This allows for the replay of Nginx access logs using GoReplay.

## Installation
This project requires poetry to manage dependencies. To install poetry, run the following command: (Making sure you have pipx installed first)
```bash
pipx install poetry
```

To install the dependencies, run the following command:
```bash
poetry install
```

## Usage

To the the script, run the following command:
```bash
poetry run python main.py [ARGS]
```

The full help is as follows:
```bash
Usage: main.py [OPTIONS] LOG_FILE_NAMES

Options:
  --sample-length-secs INTEGER    The number of seconds of log entries that
                                  should be parsed  [default: 3600]
  --sample-offset-secs INTEGER    How far into the log files to start parsing
                                  [default: 0]
  --sample-amplification-factor INTEGER
                                  The number of logs to duplicate by
                                  [default: 1]
  --output-gor-file TEXT          The name of the output file
  --output-log-file TEXT          The name of the output log file
  --host TEXT                     The host that the log entries should be sent
                                  to  [default: localhost]
  --exclude-non-200               Exclude log entries do not have a 200 status
                                  code
  --header TEXT                   Set key value pairs as headers
  --help                          Show this message and exit.
```

## Example
```bash
python main.py logs/\* --host="localhost:8081" --sample-length-secs=3600 --sample-amplification-factor=1 --exclude-non-200 --header "Foo: baz" --header "Var: Bar" --output-gor-file export.gor --output-log-file example.log
```

Then to use with GoReplay, run the following command:
```bash
gor --input-file "example.gor" --output-http "http://localhost:8080" --stats --output-http-track-response
```

## Utility Scripts
In the `scripts` directory, there are some utility scripts that can be used to help collecting logs.
These scripts are:
- `gather-aws-logs.sh`: This script will collect logs from a passed aws log group and copy them to the `logs` directory.