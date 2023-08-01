struct ts_parameter_set;
void run_keygen(const struct ts_parameter_set *ps);
void run_sign(const struct ts_parameter_set *ps, const unsigned char *priv_key);
int run_verify(const struct ts_parameter_set *ps, const unsigned char *public_key, const void *message, int len_message, const unsigned char *sig, unsigned len_sig);
unsigned char *get_sig_and_public_key( const struct ts_parameter_set *ps,  unsigned char *public_key, const void *message, unsigned len_message );
