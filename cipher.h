
#include <unistd.h>

int determine_endianness(unsigned char offsets[8]);
void generate_random_rotor(unsigned char f_ring[256], unsigned char r_ring[256]);
void encode_rotor(unsigned char f_ring[256], unsigned char digest[16]);
void decode_rotor(unsigned char f_ring[256], unsigned char digest[16]);
void derive_reverse_rotor(unsigned char f_ring[256], unsigned char r_ring[256]);
void encipher(unsigned char f_ring[256], unsigned char offsets[8], uint64_t pos, unsigned char* data, uint64_t ofs, uint64_t len, int endian);
void decipher(unsigned char r_ring[256], unsigned char offsets[8], uint64_t pos, unsigned char* data, uint64_t ofs, uint64_t len, int endian);

