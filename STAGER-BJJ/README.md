# STAGER-BJJ

A tool that dynamically analyzes interpreters to obtain information of implementation details for Bytecode Jiu-Jitsu.

## Preparation

`STAGER-BJJ` requires a log file produced by `Tracer-BJJ` as input.

`STAGER-BJJ` also require a config file that contains the following information regarding the test script used to produce the log file with Tracer-BJJ.
- `characteristic_values`: The values used in the test script.

## Usage

Specify a log file and a config file.

```sh
> python main.py <log_file> <config_file>
```

Example:
```sh
> python main.py log/test.log test_config.json
```
## Test

1. Run `Tracer-BJJ` with `test/test.vbs` and `test/test_vbscript.conf` in its repository
2. Locate the produced log file in `log/test.log`
3. Run `run.bat`

## Tested Environment

|Component|Version|Note|
|-|-|-|
|OS|Windows 11 version 23H2 x64|Built with `en-us_windows_11_consumer_editions_version_23h2_updated_june_2024_x64_dvd_78b33b16.iso`|
|Interpreter|Python 3.12.0||
|Target interpreters|VBScript 5.812.10240.16384||
