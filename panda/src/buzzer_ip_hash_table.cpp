#include <boost/functional/hash.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/unordered/unordered_map.hpp>

extern "C" {
#include "panda/buzzer.h"
}

// hash map based on shared memory so that map contents 
// are available across parent and child processes

using namespace boost::interprocess;

typedef uint64_t KeyType;
typedef uint32_t ValType;
typedef std::pair<const KeyType, ValType> MapValueType;

typedef allocator<MapValueType, managed_shared_memory::segment_manager>
    ShmemAllocator;
typedef boost::unordered_map<KeyType, ValType, boost::hash<KeyType>,
                            std::equal_to<KeyType>, ShmemAllocator>
    ShmMap;

static constexpr const char *shm_name = "shm";

static struct shm_remove {
  shm_remove() { shared_memory_object::remove(shm_name); }
  ~shm_remove() { shared_memory_object::remove(shm_name); }
} remover;

void *shm_hash_map_new(size_t size) {
  auto segment = new managed_shared_memory(create_only, shm_name, size << 2);
  auto alloc_inst = new ShmemAllocator(segment->get_segment_manager());
  ShmMap *shm_map = segment->construct<ShmMap>("BuzzerShmMap")(
      10, boost::hash<KeyType>(), std::equal_to<KeyType>(), *alloc_inst);
  return shm_map;
}

uint32_t shm_hash_map_insert(void *opaque, uint64_t key) {
  ShmMap *shm_map = static_cast<ShmMap *>(opaque);
  uint32_t value = shm_map->size() + 1;
  (*shm_map)[key] = value;
  return value;
}

uint32_t shm_hash_map_lookup(void *opaque, uint64_t key) {
  ShmMap *shm_map = static_cast<ShmMap *>(opaque);
  auto it = shm_map->find(key);
  if (it == shm_map->end())
    return 0;
  return it->second;
}
