# Tracer-BJJ

A tracer of memory accesses and taint propagation for Bytecode Jiu-Jitsu.

## Build

### Setup Intel Pin

1. Install Intel Pin by running `install_pin.ps1` (Windows) or `install_pin.sh` (Linux)
2. Set ${PIN_ROOT} environment variable
    - On Linux
        ```sh
        % export PIN_ROOT=/path/to/pin-3.20-98437-gf02b61307-gcc-linux
        ```
    - On Windows
        ```sh
        > set PIN_ROOT=pin-3.20-98437-gf02b61307-msvc-windows
        ```

### Build libdft64

1. Clone `libdft64` into `lib` directory
    ```sh
    > git clone https://github.com/AngoraFuzzer/libdft64.git lib
    ```

2. Build
    ```sh
    > cd lib
    > make
    ```

### Build Tracer-BJJ

1. Clone this repository
2. Build
    ```sh
    > make
    ```

## Test

Run `run_vbscript_test.bat`.

```sh
> cd test
> .\run_vbscript_test.bat
```

## Tested Environment

|Component|Version|Note|
|-|-|-|
|OS|Windows 11 version 23H2 x64|Built with `en-us_windows_11_consumer_editions_version_23h2_updated_june_2024_x64_dvd_78b33b16.iso`|
|Toolchain|Microsoft Visual Studio 2022 with Microsoft C/C++||
|Framework|Intel Pin 3.20 for Windows (MSVC)||
|Target interpreters|VBScript 5.812.10240.16384||

## Preparation

Tracer-BJJ require a config file that contain the following information regarding the target interpreter.
- `target_module_name`: The path to the module of the interpreter to be analyzed.
- `interp_func_offset`: The offset of the interpretation function within the interpreter module (*).
- `decoder_offset`: The offset of the decoder within the interpreter module (*).

```conf
target_module_name=/path/to/target_interpreter
interp_func_offset=0x12345678
decoder_offset=0x9abcdef0
```

- (*) These offsets can be obtained through analysis using STAGER M.


## Usage

Specify a config file, an output file name, and the commandline to execute a test script with the target interpreter.

```sh
> pin.exe -t Tracer-BJJ.dll -c <config_file> -o <output_file_name> -- <target_interpreter> <test_script>
```

Example:
```sh
> pin.exe -t Tracer-BJJ.dll -c config.conf -o output.log -- cscript.exe test.vbs
```
