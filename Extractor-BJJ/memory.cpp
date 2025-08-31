#include "memory.h"

extern PIN_MUTEX heap_mutex;
extern unordered_map<ADDRINT, UINT32> heap_allocations;


// Function to lookup size of heap memory
UINT32 lookup_heap_size(ADDRINT target_addr) {
  ADDRINT addr;
  size_t size;

  PIN_MutexLock(&heap_mutex);
  auto i = 0;
  for (auto heap: heap_allocations) {
    std::cout << "Iteration count: " << i++ << std::endl;
    addr = heap.first;
    size = heap.second;
    std::cout << "Address=" << addr << ", Size=" << size << std::endl;
    if (addr == target_addr) {
      PIN_MutexUnlock(&heap_mutex);
      return size;
    }
    else if (addr < target_addr && target_addr <= addr + size) {
      PIN_MutexUnlock(&heap_mutex);
      return addr + size - target_addr;
    }
  }
  PIN_MutexUnlock(&heap_mutex);

  return 0;
}
