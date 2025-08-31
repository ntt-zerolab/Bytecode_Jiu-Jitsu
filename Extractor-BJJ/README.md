# Extractor-BJJ

`Extractor-BJJ` is a tool based on Intel Pin that extracts bytecode and symbol tables for Bytecode Jiu-Jitsu.

## Build

### Setup Visual Studio

1. Download and install Visual Studio

2. Install the following components using Visual Studio Installer
    - C++ Clang Compiler for Windows
    - MSBuild Support for LLVM (clang-cl) toolset

### Setup Intel Pin

1. Download Intel Pin 3.31 for Windows (LLVM clang-cl) from [here](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html) or [here (direct link)](https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-3.31-98869-gfa6f126a8-clang-windows.zip)

2. Extract it to the arbitrary directory

### Build Extractor-BJJ

1. Clone this repository

2. Place the Extractor-BJJ directory to `pin-external-3.31-98869-gfa6f126a8-clang-windows\pin-external-3.31-98869-gfa6f126a8-clang-windows\source\tools`

3. Open `Extractor-BJJ.sln`

4. Build Solution

## Test

1. Open Command Prompt

2. Move to the Extractor-BJJ directory

3. Execute `run.bat`

## Tested Environment

|Component|Version|Note|
|-|-|-|
|OS|Windows 11 version 23H2 x64|Built with `en-us_windows_11_consumer_editions_version_23h2_updated_june_2024_x64_dvd_78b33b16.iso`|
|Toolchain|Microsoft Visual Studio 2022 with LLVM clang-cl||
|Framework|Intel Pin 3.31 for Windows (LLVM clang-cl)|
|Target interpreters|VBScript 5.812.10240.16384||

## Preparation

Extractor-BJJ require a `config` file that contain the following information regarding the internal structures of the target interpreter.

- Module name of the target interpreter
- Offset to the interpretation function from the image base
- Argument index in the interpreter function that contains the pointer to the management structure 
- Reference offsets required to traverse from the management structure to bytecode, symbol tables, and the virtual program counter (VPC)

```json
{
  "interp_module_name": "C:\\Windows\\System32\\vbscript.dll",
  "interp_func_offset": 33968,
  "management_structure_index": 1,
  "bytecode": {
    "reference_offsets": [
      480
    ]
  },
  "symbol_tables": [
    {
      "type": 2,
      "scope": 0,
      "reference_offsets": [
        496
      ],
      "forward_link_offset": 0
    }
  ],
  "vpc": {
    "reference_offsets": [
      0,
      472
    ]
  }
}
```

## Usage

Specify the config file, output file format (JSON/C_HEADER), output file name, and the commandline to execute target script with the interpreter.

```sh
> pin.exe -t Extractor-BJJ.dll -c <config_file> -p <output_file_format[JSON|C_HEADER]> -o <output_file_name> -- <commandline_to_execute_target_script>
```

Example:
```sh
> pin.exe -t Extractor-BJJ.dll -c config.json -p C_HEADER -o payload.h -- cscript.exe test.vbs
```