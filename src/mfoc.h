#define MEM_CHUNK               10000
#define TRY_KEYS                50

// Number of trailers == number of sectors
// 16x64b = 16
#define NR_TRAILERS_1k  (16)
// 32x64b + 8*256b = 40
#define NR_TRAILERS_4k  (40)

#define MAX_FRAME_LEN 264

// Used for counting nonce distances, explore [nd-value, nd+value]
#define DEFAULT_TOLERANCE       20

// Default number of distance probes
#define DEFAULT_DIST_NR         15

// Default number of probes for a key recovery for one sector
#define DEFAULT_PROBES_NR       150

// Number of sets with 32b keys
#define DEFAULT_SETS_NR         5

#define odd_parity(i) (( (i) ^ (i)>>1 ^ (i)>>2 ^ (i)>>3 ^ (i)>>4 ^ (i)>>5 ^ (i)>>6 ^ (i)>>7 ^ 1) & 0x01)

typedef struct {
	byte_t KeyA[6];
	byte_t KeyB[6];
	bool foundKeyA;
	bool foundKeyB;
        byte_t trailer;                         // Value of a trailer block
} sector;
 
typedef struct {
        u_int32_t       *distances;
        u_int32_t       median;
        u_int32_t       num_distances;
        u_int32_t       tolerance;
        byte_t          parity[3];              // used for 3 bits of parity information
} denonce;                                      // Revealed information about nonce 
 
typedef struct {
        nfc_target_info_t  ti;
        sector *        sectors;                // Allocate later, we do not know the number of sectors yet
	sector		e_sector;		// Exploit sector
        uint32_t        num_sectors;
        uint32_t        num_blocks;
        uint32_t        uid;
        bool            b4K;    
} mftag;
 
typedef struct {
        uint64_t        *possibleKeys;
        uint32_t        size;
} pKeys;

typedef struct {
	uint64_t        *brokenKeys;
	uint32_t        size;
} bKeys;

typedef struct {
        nfc_device_t    *pdi;
} mfreader;

typedef struct {
        uint64_t        key;
        int             count;
} countKeys;


void usage(FILE * stream, int errno);
void mf_init(mftag *t, mfreader *r);
void mf_configure(nfc_device_t* pdi);
void mf_select_tag(nfc_device_t* pdi, nfc_target_info_t* ti);
int trailer_block(uint32_t block);
int find_exploit_sector(mftag t);
void mf_anticollision(mftag t, mfreader r);
int mf_enhanced_auth(int e_sector, int a_sector, mftag t, mfreader r, denonce *d, pKeys *pk, char mode, bool dumpKeysA);
uint32_t median(denonce d);
int compar_int(const void * a, const void * b);
int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, byte_t * parity);
int compar_special_int(const void * a, const void * b);
countKeys * uniqsort(uint64_t *possibleKeys, uint32_t size);
void num_to_bytes(uint64_t n, uint32_t len, byte_t* dest);
long long unsigned int bytes_to_num(byte_t* src, uint32_t len);
