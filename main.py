
try:
    import re2 as re # type: ignore
except ImportError:
    import re
from tqdm import tqdm
from datetime import datetime
import itertools
import math
import random
from typing import List, Dict, TypedDict, Literal, cast
import glob
import click
import os

LOG_REGEX = re.compile(r""".*(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<dateandtime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(?P<method>GET|POST) )(?P<url>.+)(http\/1\.1")) (?P<statuscode>\d{3}) (?P<bytessent>\d+) (?P<refferer>-|"([^"]+)") (["](?P<useragent>[^"]+)["])""", re.IGNORECASE)
DATE_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# Yup that's the line separator format https://github.com/buger/goreplay/wiki/Saving-and-Replaying-from-file#file-format
GOR_LINE_SEPARATOR = "\n🐵🙈🙉\n"


###############
# Typed Dicts #
###############
class LogEntry(TypedDict):
    ipaddress: str
    datetime: float
    url: str
    statuscode: str
    bytessent: str
    refferer: str
    useragent: str
    method: Literal["GET", "POST"]

class LogCollection:
    def __init__(self, log_file_names) -> None:
        self.log_files = [LogFile(log_file_name) for log_file_name in log_file_names]
        self.combined_log = None
    
    def parse_log_files(self):
        for log_file in self.log_files:
            log_file.parse_log_file()
            log_file.filter_log_entries()
    
    # Pulls the earliest log entry from each log file and returns the oldest one
    def get_oldest_initial_log_entry(self) -> LogEntry:
        return max(
            filter(
                lambda y: y is not None,
                [log_file.get_earliest_log_entry() for log_file in self.log_files]
            ),
            key=lambda x: x["datetime"]
        )

    def combine_logs(self):
        print("Aggregrating log files...")
        flattened_entries = list(itertools.chain(*[log_file.log_entries for log_file in self.log_files]))
        self.combined_log = LogFile.from_entries("combined_logs", flattened_entries)
        self.combined_log.sort_log_entries()
    
    def get_log_file_from_timerange(self, start_time, end_time):
        filtered_logs = list(filter(lambda x: x["datetime"] >= start_time and x["datetime"] <= end_time, self.combined_log.log_entries))
        return LogFile.from_entries("", filtered_logs)

class LogFile:
    log_entries: List[LogEntry]
    def __init__(self, log_file_name) -> None:
        self.log_file_name = log_file_name
        self.log_entries = []
        self.valid_log_entries = 0
        self.invalid_log_entries = 0
    
    def parse_log_file(self):
        with open(self.log_file_name) as f:
            progress_bar = tqdm(f.readlines())
            progress_bar.set_description(f"Parsing log file: {self.log_file_name}")
            for line in progress_bar:
                parsed_line = self.parse_log_file_line(line)
                if not parsed_line:
                    self.invalid_log_entries += 1
                    continue

                self.log_entries.append(parsed_line)
                self.valid_log_entries += 1
        
        print(f"Log file parsing complete. Valid entries: {self.valid_log_entries}, Invalid entries: {self.invalid_log_entries}")
        
        if len(self.log_entries) > 0:
            print("Sample log entry:", self.log_entries[0])

    
    def parse_log_file_line(self, line: str)-> LogEntry|None:
        result = re.search(LOG_REGEX, line)
        if result:
            return LogEntry(
                ipaddress=result.group("ipaddress"),
                datetime=datetime.strptime(result.group("dateandtime"), DATE_TIME_FORMAT).timestamp(),
                url=result.group("url"),
                statuscode=result.group("statuscode"),
                bytessent=result.group("bytessent"),
                refferer=result.group("refferer"),
                useragent=result.group("useragent"),
                method=cast(Literal["GET", "POST"], result.group("method"))
            )
        
        return None

    def sort_log_entries(self):
        print(f"Sorting log entries for {self.log_file_name}...")
        self.log_entries.sort(key=lambda x: x["datetime"])
    
    def get_earliest_log_entry(self):
        if len(self.log_entries) == 0:
            return None
        return self.log_entries[0]

    def filter_log_entries(self, exclude_non_200=False):
        before = len(self.log_entries)
        print(f"Sorting log entries for {self.log_file_name}. Starting with {before} entries.")
        
        def filter_log_entry(log_entry):
            if exclude_non_200 and log_entry["statuscode"] != "200":
                return False

            if log_entry["method"] == "POST":
                return False
            return True
        
        self.log_entries = list(filter(filter_log_entry, self.log_entries))
        print(f"Removed {before-len(self.log_entries)} entries.")
    
    def __iter__(self):
        return iter(self.log_entries) 
    
    # A function that takes a number and amplifies the number log by that number. If the number is a float it will be randomized
    def amplify_log(self, amplification_factor):
        print(f"Amplifying logs by {amplification_factor}")
        if amplification_factor == 1:
            return

        duplicated_log_entries = self.log_entries * math.floor(amplification_factor)
        remaining_amplification = amplification_factor - math.floor(amplification_factor)
        if remaining_amplification != 0:
            duplicated_log_entries += [log_entry for log_entry in self.log_entries if random.random() > remaining_amplification]
        self.log_entries = duplicated_log_entries
        self.sort_log_entries()

    @classmethod
    def from_entries(cls, filename , entries):
        log_file = cls(filename)
        log_file.log_entries = entries
        return log_file

class LogFileWriter():
    host: str
    headers: Dict[str, str]
    
    def __init__(self, host: str, headers: Dict[str, str]) -> None:
        self.host = host
        self.headers = headers
    
    def save_as_gor(self, log_file: LogFile, output_file: str):
        progress_bar = tqdm(log_file.log_entries)
        progress_bar.set_description(f"Writing to output file {output_file}")
        with open(output_file, "w") as f:
            f.write(GOR_LINE_SEPARATOR)
            for log_entry in progress_bar:
                f.write(self._get_gor_entry(log_entry))
                f.write(GOR_LINE_SEPARATOR)
    
    def save_as_log(self, log_file: LogFile, output_file: str):
        with open(output_file, "w") as f:
            for log_entry in log_file:
                f.write(self._get_log_entry(log_entry))
                f.write("\n")
               
    def _get_gor_entry(self, log_entry: LogEntry):
        return "\n".join([
            # Protocol header
            # {Protocol Mode} {24 Random Bytes} {timing} {latency}
            # "1" means it is Making a request
            f"1 {os.urandom(12).hex()} {math.floor(log_entry['datetime'] * 1000000000)} 0",
            f"GET {log_entry["url"].strip()} HTTP/1.1",
            f"Host: {self.host}",
            *[f"{key}: {value}" for key, value in self.headers.items()],
        ]) + "\n\n"
    
    def _get_log_entry(self, log_entry: LogEntry):
        return f"{log_entry['ipaddress']} - - [{datetime.fromtimestamp(log_entry['datetime']).strftime(DATE_TIME_FORMAT)}] \"{log_entry['method']} {log_entry['url']} HTTP/1.1\" {log_entry['statuscode']} {log_entry['bytessent']} {log_entry['refferer']} \"{log_entry['useragent']}\""
    

def set_headers(ctx, param, value):
    if not value:
        return {}
    
    headers = {}
    for header in value:
        key, value = header.split(":")
        headers[key] = value.strip()
    return headers

@click.command()
@click.argument("log_file_names", type=str, required=True)
@click.option("--sample-length-secs", help="The number of seconds of log entries that should be parsed", default=3600, type=int, show_default=True,)
@click.option("--sample-offset-secs", help="How far into the log files to start parsing", default=0, type=int, show_default=True,)
@click.option("--sample-amplification-factor", help="The number of logs to duplicate by", default=1, type=int,  show_default=True)
@click.option("--output-gor-file", help="The name of the output file")
@click.option("--output-log-file", help="The name of the output log file")
@click.option("--host", help="The host that the log entries should be sent to", default="localhost", show_default=True)
@click.option("--exclude-non-200", help="Exclude log entries do not have a 200 status code", is_flag=True, default=False)
@click.option("--header", help="Set key value pairs as headers", type=str, multiple=True, callback=set_headers)
def main(log_file_names, sample_length_secs, sample_offset_secs, sample_amplification_factor, output_gor_file, output_log_file, host, exclude_non_200, header):
    if not output_gor_file and not output_log_file:
        print("You must specify an output file (either --output-gor-file or --output-log-file)")
        exit(1)
    
    resolved_file_names = []
    for log_file_name in log_file_names.split(","):
        resolved_file_names += glob.glob(log_file_name)
    
    if len(resolved_file_names) == 0:
        print("No log files found.")
        exit(1)
    
    log_collection = LogCollection(resolved_file_names)
    log_collection.parse_log_files()   
    log_collection.combine_logs()
    initial_entry = log_collection.get_oldest_initial_log_entry()
    start_date = initial_entry["datetime"] + sample_offset_secs
    output_log = log_collection.get_log_file_from_timerange(start_date, start_date + sample_length_secs)
    output_log.amplify_log(sample_amplification_factor)
    output_log.filter_log_entries(exclude_non_200)
    
    log_file_writer = LogFileWriter(host, header)
    if output_gor_file:
        log_file_writer.save_as_gor(output_log, output_gor_file)
        
    if output_log_file:
        log_file_writer.save_as_log(output_log, output_log_file)

if __name__ == "__main__":
    main()

