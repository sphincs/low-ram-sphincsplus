#if !defined( TEST_SPHINCS_H_ )
#define TEST_SPHINCS_H_
enum noise_level { quiet, whisper, loud };
	
extern int test_testvector(int fast_flag, enum noise_level level);
extern int test_sha512(int fast_flag, enum noise_level level);
extern int test_verify(int fast_flag, enum noise_level level);

#endif /* TEST_SPHINCS_H_ */
