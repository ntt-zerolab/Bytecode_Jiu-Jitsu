#include "output.h"


// Function to save Payload to a JSON file
void save_payload_to_json(const Payload payload, const string& file_name) {
    string payload_json_string = serialize_payload(payload);

    std::ofstream file(file_name);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << file_name << std::endl;
        return;
    }
    file << payload_json_string;
    file.close();

    cout << "[+] Payload saved to JSON file: "
         << file_name
         << endl;
}

// Function to save Payload to a C header file
VOID save_payload_to_header(const Payload payload, const string& file_name) {
  std::ofstream file(file_name);
  if (!file.is_open()) {
    std::cerr << "Failed to open file: " << file_name << std::endl;
    return;
  }

  file << "#ifndef PAYLOAD_OUT_H\n";
  file << "#define PAYLOAD_OUT_H\n\n";

  file << "#include <cstdint>\n\n";

  file << "// Bytecode Data\n";
  file << "const BYTE bytecode_bytes[] = \"";
  for (size_t i = 0; i < payload.bytecode.len; ++i) {
    file << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(payload.bytecode.bytes[i]);
  }
  file << "\";\n";

  file << "const size_t bytecode_len = " << std::dec << payload.bytecode.len << ";\n\n";

  file << "// Symbol Table Data\n";
  file << "const BYTE symbol_table_bytes[] = \"";
  for (size_t i = 0; i < payload.symbol_tables[0].value_objects[0].len; ++i) {
    file << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(payload.symbol_tables[0].value_objects[0].bytes[i]);
  }
  file << "\";\n";

  file << "const size_t symbol_table_len = " << std::dec << payload.symbol_tables[0].value_objects[0].len << ";\n\n";

  file << "#endif // PAYLOAD_OUT_H\n";

  file.close();
  cout << "[+] Payload saved to header file: "
       << file_name
       << endl;
}
