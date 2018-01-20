
#include <unistd.h>

void generate_random_rotor(unsigned char* f_ring, unsigned char* r_ring);
void encode_rotor(unsigned char* f_ring, unsigned char *digest);
void decode_rotor(unsigned char* f_ring, unsigned char *digest);
void derive_reverse_rotor(unsigned char* f_ring, unsigned char* r_ring);
void encipher(unsigned char *f_ring, unsigned char *offsets, uint64_t pos, unsigned char* data, uint64_t ofs, uint64_t len);
void decipher(unsigned char *r_ring, unsigned char *offsets, uint64_t pos, unsigned char* data, uint64_t ofs, uint64_t len);

