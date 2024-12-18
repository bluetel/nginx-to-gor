
convert:
	 poetry run python main.py logs/\* --host="example.com" --sample-length-secs=3600 --sample-amplification-factor=1 --exclude-non-200 --output-gor-file export.gor --output-log-file export.log