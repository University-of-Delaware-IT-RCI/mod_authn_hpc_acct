/**
 * @file     mod_authn_hpc_acct.c
 * @brief    An Apache authentication module using encrypted tokens in the URL
 * @details  How does a new user authenticate in order to set his initial password?  The assignment
 *           of an initial password is possible, with the credentials communicated to the user
 *           out-of-band.  What if that user doesn't bother changing the password?  What happens
 *           if the password leaks during the communication process and there is no expiration on
 *           it?
 *
 *           We had the ideal situation with XSEDE/ACCESS users:  the XSEDE/ACCESS InCommon IdP
 *           could be used to authenticate the user and their released attributes were sufficient
 *           to tie them to their DARWIN account.  We didn't have to assign an initial password
 *           in the first place.  But seeing as we _are_ the authority in this case, there is no
 *           such fallback IdP.
 *
 *           What would be desirable is a short-term proxy credential that could be relied upon
 *           to identity the remote client of a web application.
 */

#include "apr_lib.h"
#include "apr_version.h"
#include "apr_strings.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"

#include "openssl/evp.h"


/*
 * Forward-declare the module:
 */
module AP_MODULE_DECLARE_DATA authn_hpc_acct_module;


#if !APR_VERSION_AT_LEAST(1, 7, 0)
/*
 * APR < 1.7.0 is missing the apr_encode base64 convenience functions,
 * so we have to implement them here.  The C string caseless compare
 * function is still in httpd-land and hasn't landed in APR yet, too:
 */
#include "apr_base64.h"

/*
 * APR 1.7.0 encode constants we use herein:
 */
#define APR_ENCODE_STRING (-1)
#define APR_ENCODE_NONE (0)
#define APR_ENCODE_NOPADDING (2)

/**
 * @def   apr_cstr_casecmp
 * @brief The function exists in httpd-land, so just alias the APR name that would
 *        appear in APR 1.7.0 to it.
 */
#define apr_cstr_casecmp ap_cstr_casecmp

/**
 * @brief   Implementation of the function of the same name from APR 1.7.0.
 * @details The code herein always uses @a slen of APR_ENCODE_STRING, so the function
 *          will ONLY allow for that.  All other arguments are as documented in the
 *          APR docs.
 * @return  NULL if unsuccessful, otherwise a buffer containing the decoded data
 *          allocated from the pool @a p.
 */
static const unsigned char*
apr_pdecode_base64_binary(
    apr_pool_t      *p,
    const char      *str,
    apr_ssize_t     slen,
    int             flags,
    apr_size_t      *len
)
{
    unsigned char   *dec_buffer;
    int             dec_size;
    
    /* In this source we only ever do C-string decodes and we don't
     * need to implement general cases:
     */
    if ( slen != APR_ENCODE_STRING ) return NULL;
    slen = strlen(str);
    if (!str || (slen <= 0)) return NULL;
    
    dec_size = apr_base64_decode_len(str);
    if ( dec_size ) {
        dec_buffer = apr_palloc(p, dec_size);
        if ( dec_buffer ) {
            int     dec_len = apr_base64_decode_binary(dec_buffer, str);
            
            if ( len ) *len = dec_len;
            return dec_buffer;
        }
    }
    return NULL;
}

/**
 * @brief   Implementation of the function of the same name from APR 1.7.0.
 * @details All arguments are as documented in the APR docs.
 * @return  NULL if unsuccessful, otherwise a buffer containing the encoded data
 *          allocated from the pool @a p.
 */
static const char*
apr_pencode_base64(
    apr_pool_t  *p,
    const char  *src,
    apr_ssize_t slen,
    int         flags,
    apr_size_t  *len
)
{
    char        *enc_buffer = NULL;
    int         enc_size;
    
    if (!src || (slen <= 0)) return NULL;
    
    enc_size = apr_base64_encode_len(slen);
    if ( enc_size ) {
        enc_buffer = apr_palloc(p, enc_size + 1);
        if ( enc_buffer ) {
            int     enc_len = apr_base64_encode(enc_buffer, src, slen);
            if ( len ) *len = enc_len;
            return (const char*)enc_buffer;
        }
    }
    return NULL;
}

/**
 * @brief   Convert a (possibly) base64url-encoded string to standard base64 encoding.
 * @details The contents of @a str will be modified if any such conversion is necessary.
 */
static void
__authn_hpc_base64url_fixup(
    char        *str
)
{
    while ( *str ) {
        switch (*str) {
            case '-':
                *str = '+';
                break;
            case '_':
                *str = '/';
                break;
        }
        str++;
    }
}

/**
 * @def     DO_AUTHN_HPC_BASE64URL_FIXUP(X)
 * @brief   Substitute a call to the base64url fixup function.
 * @details If building against APR ≥ 1.7.0 this macro expands to nothing and we don't
 *          do an unnecessary call to a dummy function.
 * @param X The C string to fixup.
 */
#define DO_AUTHN_HPC_BASE64URL_FIXUP(X) __authn_hpc_base64url_fixup((X))

#else
/*
 * APR ≥ 1.7.0 has the apr_encode base64 convenience functions and
 * C string caseless compare has been picked-up from httpd:
 */
#include "apr_encode.h"

/**
 * @def     DO_AUTHN_HPC_BASE64URL_FIXUP(X)
 * @brief   Substitute a call to the base64url fixup function.
 * @details If building against APR ≥ 1.7.0 this macro doesn't expand to any code.
 * @param X The C string to fixup.
 */
#define DO_AUTHN_HPC_BASE64URL_FIXUP(X)

#endif

#ifndef AUTHN_HPC_DEFAULT_UID_HEADER_STR
/**
 * @def     AUTHN_HPC_DEFAULT_UID_HEADER_STR
 * @details C string holding the default name of the HTTP header that should be set
 *          to the authenticated token's uid value.  Can be overridden with a
 *          compile-time definition of the value OR at runtime using a per-directory
 *          configuration directive.
 */
#define AUTHN_HPC_DEFAULT_UID_HEADER_STR "X-HPC-ACCT-TOKEN-UID"
#endif
/**
 * @brief   C string holding the default uid header name.
 */
static const char *authn_hpc_default_uid_header = AUTHN_HPC_DEFAULT_UID_HEADER_STR;

#ifndef AUTHN_HPC_DEFAULT_UID_NUMBER_HEADER_STR
/**
 * @def     AUTHN_HPC_DEFAULT_UID_NUMBER_HEADER_STR
 * @details C string holding the default name of the HTTP header that should be set
 *          to the authenticated token's uid# value.  Can be overridden with a
 *          compile-time definition of the value OR at runtime using a per-directory
 *          configuration directive.
 */
#define AUTHN_HPC_DEFAULT_UID_NUMBER_HEADER_STR "X-HPC-ACCT-TOKEN-UIDNUMBER"
#endif
/**
 * @brief   C string holding the default uid# header name.
 */
static const char *authn_hpc_default_uid_number_header = AUTHN_HPC_DEFAULT_UID_NUMBER_HEADER_STR;

#ifndef AUTHN_HPC_DEFAULT_LDAP_DN_HEADER_STR
/**
 * @def     AUTHN_HPC_DEFAULT_LDAP_DN_HEADER_STR
 * @details C string holding the default name of the HTTP header that should be set
 *          to the authenticated token's LDAP DN value.  Can be overridden with a
 *          compile-time definition of the value OR at runtime using a per-directory
 *          configuration directive.
 */
#define AUTHN_HPC_DEFAULT_LDAP_DN_HEADER_STR "X-HPC-ACCT-TOKEN-LDAPDN"
#endif
/**
 * @brief   C string holding the default LDAP DN header name.
 */
static const char *authn_hpc_default_ldap_dn_header = AUTHN_HPC_DEFAULT_LDAP_DN_HEADER_STR;


/**
 * @var     authn_hpc_id_token_header
 * @brief   C string global containing the identity token header.
 * @details An identity token has the format:
 *
 *          [HPC_ID_TOKEN|<uid>|<uid#>|<ldap-dn>|<expiration-timestamp>]
 *
 *          This global holds the prefix string to the token.
 */
static const char *authn_hpc_id_token_header = "[HPC_ID_TOKEN|";

/**
 * @brief   Parsed fields from an identity token.
 * @details A decrypted identity token string is parsed into the fields of this data
 *          structure.
 */
typedef struct {
    const char      *uid;           /**< The uid substring of the token */
    const char      *uid_number;    /**< The uid# substring of the token */
    const char      *ldap_dn;       /**< The LDAP DN substring of the token */
    apr_time_t      expiration;     /**< The expiration time substring of the token parsed as an APR time */
} authn_hpc_id_token_t;

/**
 * @brief   Parse a decrypted identity token.
 * @details Given a decrypted identity token in @a token_str, attempt to parse the
 *          identity components from that string.
 *
 * @param   r         The request from which this token is taken.
 * @param   token_str The decrypted token string that will be parsed.  The string will
 *                    be modified by changing delimiters to NUL characters.
 * @param   out_token Pointer to the struct that will be filled-in with the parsed
 *                    token fields.  If NULL, then @a token_str will not be modified
 *                    and this function merely establishes the validity of it.
 *
 * @return  Returns zero if the string is valid, non-zero otherwise.
 */
static int
authn_hpc_id_token_parse(
    request_rec             *r,
    char                    *token_str,
    authn_hpc_id_token_t    *out_token
)
{
    char                    *endp;
    long int                li_val;
    unsigned long long int  ulli_val;
    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "authn_hpc_acct token_parse: parse '%s'", token_str);
    
    if ( strncmp(token_str, authn_hpc_id_token_header, strlen(authn_hpc_id_token_header)) != 0 ) return 1;
    token_str += strlen(authn_hpc_id_token_header);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "authn_hpc_acct token_parse: header recognized");
    
    if ( out_token ) out_token->uid = token_str;
    while ( *token_str && (*token_str != '|') ) token_str++;
    if ( ! *token_str ) return 1;
    if ( out_token ) *token_str = '\0';
    token_str++;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "authn_hpc_acct token_parse: uid recognized: %s", (out_token ? out_token->uid : "<not saved>"));
    
    li_val = strtol(token_str, &endp, 10);
    if ( (endp == token_str) || (*endp != '|') || (li_val < 0) || (li_val > INT_MAX)) return 1;
    if ( out_token) {
        out_token->uid_number = token_str;
        *endp = '\0';
    }
    token_str = ++endp;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "authn_hpc_acct token_parse: uid_number recognized: %s", (out_token ? out_token->uid_number : "<not saved>"));
    
    if ( out_token) out_token->ldap_dn = token_str;
    while ( *token_str && (*token_str != '|') ) token_str++;
    if ( ! *token_str ) return 1;
    if ( out_token ) *token_str = '\0';
    token_str++;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "authn_hpc_acct token_parse: ldap_dn recognized: %s", (out_token ? out_token->ldap_dn : "<not saved>"));
    
    ulli_val = strtoull(token_str, &endp, 10);
    if ( (endp == token_str) || (*endp != ']') || ((apr_int64_t)ulli_val < APR_INT64_MIN) || ((apr_int64_t)ulli_val > APR_INT64_MAX)) return 1;
    /* Incoming timestamp is in seconds: */
    if ( out_token ) out_token->expiration = apr_time_from_sec(ulli_val);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "authn_hpc_acct token_parse: expiration recognized: %ld", (out_token ? out_token->expiration : -1));
    
    return 0;
}


/**
 * @brief   OpenSSL encryption method.
 * @details The OpenSSL cipher and digest used to en/decrypt the identity tokens
 *          are bundled in this struct.
 */
typedef struct {
    int     cipher : 8; /**< The cipher id is 8-bits of the bitfield */
    int     digest : 8; /**< The digest id is 8-bits of the bitfield */
} authn_hpc_acct_encmethod_t;

/**
 * @brief   Create a authn_hpc_acct_encmethod_t struct from component values
 * @details An inlined function that turns separate @a cipher and @a digest values into a
 *          authn_hpc_acct_encmethod_t structure.
 *
 * @param   cipher      A cipher id
 * @param   digest      A digest id
 *
 * @return  An initialized authn_hpc_acct_encmethod_t struct.
 */
static inline authn_hpc_acct_encmethod_t
authn_hpc_acct_encmethod_create(
    int     cipher,
    int     digest
)
{
    authn_hpc_acct_encmethod_t  out_method = { .cipher = cipher,
                                               .digest = digest };
    return out_method;
}


/**
 * @enum    Encryption cipher ids
 * @details Zero implies no known cipher or an unset field in the authn_hpc_acct_encmethod_t
 *          data structure.  All valid ciphers exist as a sequence of integers starting at
 *          one and terminating at a "max" value.
 */
enum {
    kEncCipher_unknown = 0,
    kEncCipher_aes_256_cbc,
    kEncCipher_aes_256_xts,
    kEncCipher_aes_256_ecb,
    kEncCipher_aes_256_ocb,
    kEncCipher_aes_256_ctr,
    kEncCipher_aes_256_gcm,
    kEncCipher_aes_256_ccm,
    kEncCipher_max
};

/**
 * @def     AUTHN_HPC_ACCT_ENC_IS_VALID_CIPHER(X)
 * @brief   Conditional macro that evaluates to true if the @a X is a valid cipher id.
 *
 * @param   X   A cipher id
 */
#define AUTHN_HPC_ACCT_ENC_IS_VALID_CIPHER(X)   (((X) > kEncCipher_unknown) && ((X) < kEncCipher_max))

#ifndef AUTHN_HPC_ACCT_ENC_DEFAULT_CIPHER
/**
 * @def     AUTHN_HPC_ACCT_ENC_DEFAULT_CIPHER
 * @brief   The id of the cipher considered to be the default.
 * @details This can be overridden using a compile-time define.
 */
#define AUTHN_HPC_ACCT_ENC_DEFAULT_CIPHER kEncCipher_aes_256_cbc
#endif

/**
 * @var     authn_hpc_acct_encmethod_cipher_names
 * @brief   Textual names of the valid encryption ciphers.
 */
static const char* authn_hpc_acct_encmethod_cipher_names[] = {
    "SLOT_NOT_USED",
    "aes_256_cbc",
    "aes_256_xts",
    "aes_256_ecb",
    "aes_256_ocb",
    "aes_256_ctr",
    "aes_256_gcm",
    "aes_256_ccm"
};

/**
 * @brief   Parse a string that (may) contain a cipher name.
 *
 * @param   enc_str     The C string containing a possible cipher name.
 *
 * @return  Returns kEncCipher_unknown if no match is found, otherwise the
 *          corresponding cipher id.
 */
int
authn_hpc_acct_cipher_str_to_enum(
    const char  *enc_str
)
{
    int         enc_cipher = kEncCipher_max;
    
    if ( ! enc_str || ! *enc_str ) return kEncCipher_unknown;
    
    while ( --enc_cipher > kEncCipher_unknown ) {
        if ( apr_cstr_casecmp(enc_str, authn_hpc_acct_encmethod_cipher_names[enc_cipher]) == 0 ) break;
    }
    return enc_cipher;
}

/**
 * @typedef openssl_cipher_fn
 * @brief   The type of an OpenSSL cipher function.
 */
typedef const EVP_CIPHER * (*openssl_cipher_fn)(void);
/**
 * @brief   A dummy OpenSSL cipher function
 * @details Exists to fill unused slots in the cipher function list.
 */
static const EVP_CIPHER* authn_hpc_acct_dummy_cipher(void) {return NULL;}
/**
 * @var     authn_hpc_acct_encmethod_cipher_funcs
 * @brief   List of OpenSSL cipher functions
 * @details The list is ordered to match the cipher id enumeration, with a dummy
 *          function filling the zeroeth index (which should never get used anyway).
 */
static openssl_cipher_fn authn_hpc_acct_encmethod_cipher_funcs[] = {
    authn_hpc_acct_dummy_cipher,
    EVP_aes_256_cbc,
    EVP_aes_256_xts,
    EVP_aes_256_ecb,
    EVP_aes_256_ocb,
    EVP_aes_256_ctr,
    EVP_aes_256_gcm,
    EVP_aes_256_ccm
};


/**
 * @enum    Encryption digest ids
 * @details Zero implies no known digest or an unset field in the authn_hpc_acct_encmethod_t
 *          data structure.  All valid digests exist as a sequence of integers starting at
 *          one and terminating at a "max" value.
 */
enum {
    kEncDigest_unknown = 0,
    kEncDigest_sha1,
    kEncDigest_sha224,
    kEncDigest_sha256,
    kEncDigest_sha384,
    kEncDigest_sha512,
    kEncDigest_max
};

/**
 * @def     AUTHN_HPC_ACCT_ENC_IS_VALID_DIGEST(X)
 * @brief   Conditional macro that evaluates to true if the @a X is a valid digest id.
 *
 * @param   X   A digest id
 */
#define AUTHN_HPC_ACCT_ENC_IS_VALID_DIGEST(X)   (((X) > kEncDigest_unknown) && ((X) < kEncDigest_max))

#ifndef AUTHN_HPC_ACCT_ENC_DEFAULT_DIGEST
/**
 * @def     AUTHN_HPC_ACCT_ENC_DEFAULT_DIGEST
 * @brief   The id of the digest considered to be the default.
 * @details This can be overridden using a compile-time define.
 */
#define AUTHN_HPC_ACCT_ENC_DEFAULT_DIGEST kEncDigest_sha1
#endif

/**
 * @var     authn_hpc_acct_encmethod_digest_names
 * @brief   Textual names of the valid encryption digests.
 */
static const char* authn_hpc_acct_encmethod_digest_names[] = {
    "SLOT_NOT_USED",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512"
};

/**
 * @brief   Parse a string that (may) contain a digest name.
 *
 * @param   enc_str     The C string containing a possible digest name.
 *
 * @return  Returns kEncDigest_unknown if no match is found, otherwise the
 *          corresponding digest id.
 */
int
authn_hpc_acct_digest_str_to_enum(
    const char  *enc_str
)
{
    int         enc_digest = kEncDigest_max;
    
    if ( ! enc_str || ! *enc_str ) return kEncDigest_unknown;
    
    while ( --enc_digest > kEncDigest_unknown ) {
        if ( apr_cstr_casecmp(enc_str, authn_hpc_acct_encmethod_digest_names[enc_digest]) == 0 ) break;
    }
    return enc_digest;
}

/**
 * @typedef openssl_digest_fn
 * @brief   The type of an OpenSSL digest function.
 */
typedef const EVP_MD * (*openssl_digest_fn)(void);
/**
 * @brief   A dummy OpenSSL digest function
 * @details Exists to fill unused slots in the digest function list.
 */
static const EVP_MD* authn_hpc_acct_dummy_digest(void) {return NULL;}
/**
 * @var     authn_hpc_acct_encmethod_digest_funcs
 * @brief   List of OpenSSL digest functions
 * @details The list is ordered to match the digest id enumeration, with a dummy
 *          function filling the zeroeth index (which should never get used anyway).
 */
static openssl_digest_fn authn_hpc_acct_encmethod_digest_funcs[] = {
    authn_hpc_acct_dummy_digest,
    EVP_sha1,
    EVP_sha224,
    EVP_sha256,
    EVP_sha384,
    EVP_sha512
};


#ifndef AUTHN_HPC_ACCT_DEFAULT_ENC_METHOD
/**
 * @def     AUTHN_HPC_ACCT_DEFAULT_ENC_METHOD
 * @brief   The default encryption method to be used
 * @detains Produces a @ref authn_hpc_acct_encmethod_t containing the default cipher
 *          and digest selected at compile time.  Can be overridden using a
 *          compile-time define.
 */
#define AUTHN_HPC_ACCT_DEFAULT_ENC_METHOD   authn_hpc_acct_encmethod_create(AUTHN_HPC_ACCT_ENC_DEFAULT_CIPHER, AUTHN_HPC_ACCT_ENC_DEFAULT_DIGEST)
#endif


#ifndef AUTHN_HPC_ACCT_DEFAULT_ITER_COUNT
/**
 * @def     AUTHN_HPC_ACCT_DEFAULT_ITER_COUNT
 * @brief   The default digest iteration count to be used
 * @detains Can be overridden using a compile-time define.
 */
#define AUTHN_HPC_ACCT_DEFAULT_ITER_COUNT   1000
#endif


/**
 * @brief   Configuration data for this Apache module
 * @details This module uses per-directory configuration only, so this struct contains
 *          the details of its operation on that URI path and its descendants.
 */
typedef struct {
    /**
     * @var     is_enabled
     * @brief   Boolean that is set when this module is enabled on a directory/location
     */
    int                             is_enabled;
    /**
     * @var     uid_header_name
     * @brief   Request header to which token uid is assigned
     * @details If this field is NULL or an empty C string, no assignment will be made.
     *          Defaults to the value of @ref authn_hpc_default_uid_header
     */
    const char                      *uid_header_name;
    /**
     * @var     uid_number_header_name
     * @brief   Request header to which token uid# is assigned
     * @details If this field is NULL or an empty C string, no assignment will be made.
     *          Defaults to the value of @ref authn_hpc_default_uid_number_header
     */
    const char                      *uid_number_header_name;
    /**
     * @var     ldap_dn_header_name
     * @brief   Request header to which token LDAP DN is assigned
     * @details If this field is NULL or an empty C string, no assignment will be made.
     *          Defaults to the value of @ref authn_hpc_default_ldap_dn_header
     */
    const char                      *ldap_dn_header_name;
    /**
     * @var     password
     * @brief   Pre-shared encryption password
     * @details A byte buffer containing the encryption password.  The password may
     *          be a string of ASCII characters or a generic byte array, depending
     *          upon how it is presented in the configuration file.
     */
    const unsigned char             *password;
    /**
     * @var     password_len
     * @brief   Number of bytes in the pre-shared encryption password buffer
     */
    apr_size_t                      password_len;
    /**
     * @var     iter_count
     * @brief   Number of passes through the digest when generating the key
     * @details Defaults to @ref AUTHN_HPC_ACCT_DEFAULT_ITER_COUNT
     */
    int                             iter_count;
    /**
     * @var     enc_method
     * @brief   The encryption cipher and digest to be used
     * @details Defaults to @ref AUTHN_HPC_ACCT_DEFAULT_ENC_METHOD
     */
    authn_hpc_acct_encmethod_t      enc_method;
    /**
     * @var     should_use_PBKDF2
     * @brief   Should the key be generated using PBKDF2 or not?
     * @details A non-zero value implies yes/true; defaults to no/false
     */
    int                             should_use_PBKDF2;
    /**
     * @var     base_uri_path
     * @brief   The URI path prefix associated with this configuration
     * @details Used to isolate the potion of the URI that contains the encrypted
     *          identity token.  A NULL or empty C string implies the root path,
     *          "/" and by default this will be initialized to contain the path
     *          associated with the location/directory at which it is rooted.
     */
    char                            *base_uri_path;
    /**
     * @var     base_uri_path_len
     * @brief   The number of characters in the @ref base_uri_path
     */
    apr_size_t                      base_uri_path_len;
} authn_hpc_acct_config_t;

/**
 * @brief   Apache callback to create a new per-directory configuration struct
 * @details When any of our configuration directives appear on an entity in
 *          the Apache configuration, one of these structs will be created.
 *          Default values are as described in @ref authn_hpc_acct_config_t.
 *
 * @param   p   The pool from which the struct should be allocated
 * @param   d   The directory/location containing this configuration
 */
static void*
create_authn_hpc_acct_dir_config(
    apr_pool_t  *p,
    char        *d
)
{
    authn_hpc_acct_config_t *conf =
        (authn_hpc_acct_config_t*)apr_pcalloc(p, sizeof(authn_hpc_acct_config_t));
    
    /* We used pcalloc so all bytes should be zero; only set what's
     * necessary:
     */
    conf->uid_header_name = authn_hpc_default_uid_header;
    conf->uid_number_header_name = authn_hpc_default_uid_number_header;
    conf->ldap_dn_header_name = authn_hpc_default_ldap_dn_header;
    
    conf->password_len = -1;
    conf->iter_count = AUTHN_HPC_ACCT_DEFAULT_ITER_COUNT;
    conf->enc_method = AUTHN_HPC_ACCT_DEFAULT_ENC_METHOD;
    
    /* Default to using "d" as the base URI path (sans trailing "/" chars): */
    if ( d && (*d == '/') ) {
        char        *endp = d + 1;
        
        /* Skip to the end: */
        while ( *endp ) endp++;
        
        /* Backtrack beyond any terminal "/" chars: */
        while ( (endp > d) && (*(endp - 1) == '/') ) endp--;
        
        /* Did we get something? */
        if ( endp > d ) {
            conf->base_uri_path_len = endp - d;
            conf->base_uri_path = (char*)apr_palloc(p, conf->base_uri_path_len + 1);
            memcpy(conf->base_uri_path, d, conf->base_uri_path_len);
            conf->base_uri_path[conf->base_uri_path_len] = '\0';
        }
    }
    
    return conf;
}

/**
 * @brief   Apache configuration callback that handles AuthnHPCAcctEncryptMethod
 *
 * @param   cmd     Info re: the configuration command that was invoked
 * @param   _conf   Opaque pointer to the authn_hpc_acct_config_t that's been allocated
 *                  for this location/directory
 * @param   arg1    The cipher name
 * @param   arg2    The digest name
 *
 * @return  Returns NULL on success, a pointer to a C string describing an error
 *          otherwise.
 */
static const char*
set_enc_method(
    cmd_parms   *cmd,
    void        *_conf,
    const char  *arg1,
    const char  *arg2
)
{
    authn_hpc_acct_config_t     *conf = (authn_hpc_acct_config_t*)_conf;
    int                         cipher = authn_hpc_acct_cipher_str_to_enum(arg1),
                                digest = authn_hpc_acct_digest_str_to_enum(arg2);
    
    if ( ! AUTHN_HPC_ACCT_ENC_IS_VALID_CIPHER(cipher) ) {
        return apr_pstrcat(cmd->pool, "AuthnHPCAcctEncryptMethod: invalid encryption cipher '", arg1, "'", NULL);
    }
    if ( ! AUTHN_HPC_ACCT_ENC_IS_VALID_DIGEST(digest) ) {
        return apr_pstrcat(cmd->pool, "AuthnHPCAcctEncryptMethod: invalid encryption digest '", arg2, "'", NULL);
    }
    conf->enc_method = authn_hpc_acct_encmethod_create(cipher, digest);
    return NULL;
}

/**
 * @brief   Apache configuration callback that handles AuthnHPCAcctEncryptIterCount
 *
 * @param   cmd     Info re: the configuration command that was invoked
 * @param   _conf   Opaque pointer to the authn_hpc_acct_config_t that's been allocated
 *                  for this location/directory
 * @param   arg     The iteration count as a string
 *
 * @return  Returns NULL on success, a pointer to a C string describing an error
 *          otherwise.
 */
static const char*
set_enc_iter_count(
    cmd_parms   *cmd,
    void        *_conf,
    const char  *arg
)
{
    authn_hpc_acct_config_t     *conf = (authn_hpc_acct_config_t*)_conf;
    char                        *endp = NULL;
    long                        n_iter = strtol(arg, &endp, 10);
    
    if ( (endp == arg) || *endp ) {
        return apr_pstrcat(cmd->pool, "AuthnHPCAcctEncryptIterCount: not a valid integer '", arg, "'", NULL);
    }
    if ( (n_iter < 0) || (n_iter > INT_MAX) ) {
        return apr_psprintf(cmd->pool, "AuthnHPCAcctEncryptIterCount: %ld not in range (0, %d)", n_iter, (int)INT_MAX);
    }
    conf->iter_count = n_iter;
    return NULL;
}

/**
 * @brief   Apache configuration callback that handles AuthnHPCAcctEncryptPassword
 *
 * @param   cmd     Info re: the configuration command that was invoked
 * @param   _conf   Opaque pointer to the authn_hpc_acct_config_t that's been allocated
 *                  for this location/directory
 * @param   arg1    The password type OR the password.  Valid types are 'base64' and 'text'.
 * @param   arg2    If @a arg1 is a type, then this holds the password value.
 *
 * @return  Returns NULL on success, a pointer to a C string describing an error
 *          otherwise.
 */
static const char*
set_enc_password(
    cmd_parms   *cmd,
    void        *_conf,
    const char  *arg1,
    const char  *arg2
)
{
#define AUTHN_HPC_ACCT_PASSWORD_TYPE_TEXT   1
#define AUTHN_HPC_ACCT_PASSWORD_TYPE_BASE64 2

    authn_hpc_acct_config_t     *conf = (authn_hpc_acct_config_t*)_conf;
    int                         password_type;
    const char                  *password = NULL;
    
    /* If we were given two strings, the first MUST be a valid type: */
    if ( arg1 && *arg1 && arg2 && *arg2 ) {
        if ( strcasecmp(arg1, "base64") == 0 ) {
            password_type = AUTHN_HPC_ACCT_PASSWORD_TYPE_BASE64;
            password = arg2;
        }
        else if (strcasecmp(arg1, "text") == 0 ) {
            password_type = AUTHN_HPC_ACCT_PASSWORD_TYPE_TEXT;
            password = arg2;
        }
        else {
            return apr_pstrcat(cmd->pool, "AuthnHPCAcctEncryptPassword: invalid password type: '", arg1, "'", NULL);
        }
    } else {
        /* Assume it's text: */
        password_type = AUTHN_HPC_ACCT_PASSWORD_TYPE_TEXT;
        password = arg1;
    }
    if ( ! password || ! *password ) return "AuthnHPCAcctEncryptPassword: empty password not allowed";
    switch ( password_type ) {
        case AUTHN_HPC_ACCT_PASSWORD_TYPE_TEXT: {
            conf->password = (unsigned char*)password;
            conf->password_len = strlen(password);
            break;
        }
        case AUTHN_HPC_ACCT_PASSWORD_TYPE_BASE64: {
            conf->password = apr_pdecode_base64_binary(cmd->pool, password, APR_ENCODE_STRING, APR_ENCODE_NONE, &conf->password_len);
            break;
        }
        default: {
            return "AuthnHPCAcctEncryptPassword: something very weird happened...";
        }
    }
    if ( ! conf->password || ! conf->password_len ) {
        return apr_pstrcat(cmd->pool, "AuthnHPCAcctEncryptPassword: invalid base64url-encoded password '", password, "'", NULL);
    }
    return NULL;
    
#undef AUTHN_HPC_ACCT_PASSWORD_TYPE_TEXT
#undef AUTHN_HPC_ACCT_PASSWORD_TYPE_BASE64
}

/**
 * @brief   Apache configuration callback that handles AuthnHPCAcctEncryptBaseUriPath
 *
 * @param   cmd     Info re: the configuration command that was invoked
 * @param   _conf   Opaque pointer to the authn_hpc_acct_config_t that's been allocated
 *                  for this location/directory
 * @param   arg     The base URI path associated with this configuration
 *
 * @return  Returns NULL on success, a pointer to a C string describing an error
 *          otherwise.
 */
static const char*
set_base_uri_path(
    cmd_parms   *cmd,
    void        *_conf,
    const char  *arg
)
{
    authn_hpc_acct_config_t     *conf = (authn_hpc_acct_config_t*)_conf;
    
    if ( arg && *arg ) {
        const char  *s = arg;
        
        while ( isspace(*s) ) s++;
        if ( *s != '/' ) {
            return apr_pstrcat(cmd->pool, "AuthnHPCAcctBaseUriPath: invalid base URI '", arg, "'", NULL);
        }
        if ( *s == '\0' ) {
            conf->base_uri_path = NULL;
            conf->base_uri_path_len = 0;
        } else {
            conf->base_uri_path = (char*)s;
            conf->base_uri_path_len = strlen(s);
        }
    } else {
        conf->base_uri_path = NULL;
        conf->base_uri_path_len = 0;
    }
    return NULL;
}


/**
 * @var     authn_hpc_acct_cmds
 * @brief   Apache configuration commands for this module
 */
static const command_rec authn_hpc_acct_cmds[] = {
        AP_INIT_FLAG("AuthnHPCAcctEnable", ap_set_flag_slot, (void*)APR_OFFSETOF(authn_hpc_acct_config_t, is_enabled), OR_AUTHCFG,
                        "Set to 'on' to use this module to authenticate on this path"),
        AP_INIT_TAKE1("AuthnHPCAcctSetUidHeader", ap_set_string_slot, (void*)APR_OFFSETOF(authn_hpc_acct_config_t, uid_header_name), OR_AUTHCFG,
                        "Request header that should be set to the uid from the identity token (default: " AUTHN_HPC_DEFAULT_UID_HEADER_STR),
        AP_INIT_TAKE1("AuthnHPCAcctSetUidNumberHeader", ap_set_string_slot, (void*)APR_OFFSETOF(authn_hpc_acct_config_t, uid_number_header_name), OR_AUTHCFG,
                        "Request header that should be set to the uid# from the identity token (default: " AUTHN_HPC_DEFAULT_UID_NUMBER_HEADER_STR),
        AP_INIT_TAKE1("AuthnHPCAcctSetLDAPDNHeader", ap_set_string_slot, (void*)APR_OFFSETOF(authn_hpc_acct_config_t, ldap_dn_header_name), OR_AUTHCFG,
                        "Request header that should be set to the LDAP DN from the identity token (default: " AUTHN_HPC_DEFAULT_LDAP_DN_HEADER_STR),
        AP_INIT_TAKE2("AuthnHPCAcctEncryptMethod", set_enc_method, NULL, OR_AUTHCFG,
                        "Encryption algorithm as <cipher> <digest>"),
        AP_INIT_TAKE1("AuthnHPCAcctEncryptIterCount", set_enc_iter_count, NULL, OR_AUTHCFG,
                        "Encryption iteraction count"),
        AP_INIT_TAKE12("AuthnHPCAcctEncryptPassword", set_enc_password, NULL, OR_AUTHCFG,
                        "Encryption password type and value, where type is 'base64' or 'text' (default 'text')"),
        AP_INIT_TAKE1("AuthnHPCAcctBaseUriPath", set_base_uri_path, NULL, OR_AUTHCFG,
                        "Base URI path after which the identity token occurs"),
        AP_INIT_FLAG("AuthnHPCAcctUsePBKDF2", ap_set_flag_slot, (void*)APR_OFFSETOF(authn_hpc_acct_config_t, should_use_PBKDF2), OR_AUTHCFG,
                        "Set to 'on' to use PBKDF2 key generation"),
        {NULL}
    };


/**
 * @var     authn_hpc_acct_our_username
 * @brief   Dummy username added to the Authorization header by this module
 * @details After server configuration has been read, this global will be filled-in with a randomized string
 *          that will act as our username in synthesized Authorization headers.
 */
static const char *authn_hpc_acct_our_username = NULL;

/**
 * @var     authn_hpc_acct_our_username_len
 * @brief   Length of the dummy username
 * @details Number of characters in the @ref authn_hpc_acct_our_username.
 */
static apr_size_t authn_hpc_acct_our_username_len = 0;

/**
 * @brief   Generate the en/decrypt key and iv for a request
 * @details When a request uses this module to authenticate an encrypted identity token
 *          extracted from the URI, this function is used to generate the key associated
 *          with the request.
 *
 * @param   r           The request being serviced
 * @param   conf        The per-directory module configuration
 * @param   salt        The salt extracted from the encrypted identity token or NULL if no
 *                      salt is used
 * @param   out_key_ptr Set to the key associated with this request (allocated from the
 *                      request's pool)
 * @param   out_iv_ptr  Set to the iv associated with this request (allocated from the
 *                      request's pool)
 *
 * @return  Non-zero on failure, zero if successful.
 */
static int
authn_hpc_acct_generate_key(
    request_rec                 *r,
    authn_hpc_acct_config_t     *conf,
    unsigned char               *salt,
    unsigned char*              *out_key_ptr,
    unsigned char*              *out_iv_ptr
)
{
    const EVP_CIPHER            *cipher = (authn_hpc_acct_encmethod_cipher_funcs[conf->enc_method.cipher])();
    const EVP_MD                *digest = (authn_hpc_acct_encmethod_digest_funcs[conf->enc_method.digest])();
    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "authn_hpc_acct generate_key: cipher:digest = %s:%s, iter = %d",
                  authn_hpc_acct_encmethod_cipher_names[conf->enc_method.cipher],
                  authn_hpc_acct_encmethod_digest_names[conf->enc_method.digest],
                  conf->iter_count);
    if ( digest && cipher ) {
        int                     key_len, iv_len, bytes_len, rc;
        void                    *bytes;
        unsigned char           *key = NULL, *iv = NULL;
        
        bytes_len = key_len = EVP_CIPHER_key_length(cipher);
        bytes_len += (iv_len = EVP_CIPHER_iv_length(cipher));
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "authn_hpc_acct generate_key: byte lengths, key=%d, iv=%d, total=%d", key_len, iv_len, bytes_len);
        bytes = (void*)apr_pcalloc(r->pool, bytes_len);
        if ( bytes == NULL ) {
            return 0;
        }
        key = bytes; bytes += key_len;
        iv = bytes;
        
        /* We've got key storage setup, now we can generate the key: */
        if ( conf->should_use_PBKDF2 ) {
            rc = PKCS5_PBKDF2_HMAC((char*)conf->password, (int)conf->password_len,
                                   salt, (salt ? 8 : 0), conf->iter_count,
                                   digest, bytes_len, key);
            if ( rc != 1 ) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                            "authn_hpc_acct generate_key: PBKDF2 key generation failed");
                return 1;
            }
            rc = key_len;
        } else {
            rc = EVP_BytesToKey(cipher, digest, salt,
                        conf->password, conf->password_len,
                        conf->iter_count,
                        key, iv);
        }
        if ( rc == key_len ) {
            char        as_hex[2 * key_len + 1];
            int         i;
            
            *out_key_ptr = key;
            *out_iv_ptr = iv;
            
            for ( i = 0; i < key_len; i++ ) snprintf(&as_hex[2 * i], 3, "%02hhX", key[i]);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "authn_hpc_acct generate_key: key = %s", as_hex);
            for ( i = 0; i < iv_len; i++ ) snprintf(&as_hex[2 * i], 3, "%02hhX", iv[i]);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "authn_hpc_acct generate_key: iv = %s", as_hex);
            return 0;
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                    "authn_hpc_acct generate_key: key lengths to not agree: %d != %d", key_len, rc);
    }
    return 1;
}

/**
 * @brief   The header_parser hook provided by this module
 * @details A header_parser is called after the request path has been decoded and mapped
 *          but before any authentication, authorization, or handlers have been called.
 *          It ensures the per-directory config is in-scope.
 *
 * @return  Returns @a OK if successful, @a DECLINED if the requested URI is not
 *          rooted under the configured base URI path
 */
static int
authn_hpc_acct_header_parser(
    request_rec                 *r
)
{
    authn_hpc_acct_config_t     *conf =
        (authn_hpc_acct_config_t*)ap_get_module_config(r->per_dir_config, &authn_hpc_acct_module);
    
    if ( conf->is_enabled ) {
        const char                  *uri_path = r->uri, *uri_path_end, *authorization_header = NULL;
        struct iovec                components[3];
        apr_size_t                  slen;
        
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "authn_hpc_acct header_parser: '%s' exists under '%s' ??", uri_path, (conf->base_uri_path ? conf->base_uri_path : "/"));
        
        /* Does the request URI start with the base?  If so, drop that off the URI: */
        if ( conf->base_uri_path_len == 0 ) {
            /* Implied root path, just drop the leading slash: */
            if ( ! *uri_path || (*uri_path != '/') ) return DECLINED;
            uri_path++;        
        } else if ( (strncmp(uri_path, conf->base_uri_path, conf->base_uri_path_len) == 0 ) && (uri_path[conf->base_uri_path_len] == '/') ) {
            uri_path += conf->base_uri_path_len + 1;
        } else {
            return DECLINED;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "authn_hpc_acct header_parser: request URI '%s' matches at '%s'", r->uri, uri_path);
                      
        /*
         * The base64url-encoded identity token should be the next component of the URI:
         */
        uri_path_end = uri_path;
        while ( *uri_path_end && (*uri_path_end != '/') ) uri_path_end++;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "authn_hpc_acct header_parser: isolated %ld characters at '%s'", uri_path_end - uri_path, uri_path);
        
        /*
         * Manufacture the Authorization header:
         */
        components[0].iov_base = (void*)authn_hpc_acct_our_username, components[0].iov_len = authn_hpc_acct_our_username_len;
        components[1].iov_base = (void*)":", components[1].iov_len = 1;
        components[2].iov_base = (void*)uri_path, components[2].iov_len = uri_path_end - uri_path;
        authorization_header = apr_pstrcatv(r->pool, components, 3, &slen);
        authorization_header = apr_pencode_base64(r->pool, authorization_header, slen, APR_ENCODE_NOPADDING, NULL);
        authorization_header = apr_pstrcat(r->pool, "Basic ", authorization_header, NULL);
        apr_table_set(r->headers_in, "Authorization", authorization_header);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "authn_hpc_acct header_parser: set Authorization header '%s'", authorization_header);
        
        return OK;
    }
    return DECLINED;
}

/**
 * @brief   Callback registered with the aaa subsystem to validate a username and password
 * @details The aaa subsystem parses the Authorization header on the request to find the
 *          username and password and calls this function with those values.
 *
 *          If this module generated that header, then the @a user will be our dummy username
 *          constructed at startup.  The @a password will be the encrypted token extracted from
 *          the URI.
 *
 * @return  @a AUTH_GRANTED if the decrypted token was valid; @a AUTH_DENIED if the token was
 *          invalid in any way; or @a AUTH_GENERAL_ERROR for various operational errors
 */
static authn_status
authn_hpc_acct_check_password(
    request_rec                 *r,
    const char                  *user,
    const char                  *password
)
{
    authn_hpc_acct_config_t     *conf =
        (authn_hpc_acct_config_t*)ap_get_module_config(r->per_dir_config, &authn_hpc_acct_module);
    
    if ( conf->is_enabled ) {
        EVP_CIPHER_CTX              *ctx = NULL;
        const EVP_CIPHER            *cipher = NULL;
        unsigned char               *payload = NULL, salt[8], *salt_ptr = NULL,
                                    *key = NULL, *iv = NULL, *decrypt = NULL;
        apr_size_t                  payload_len;
        int                         len, decrypt_len, int_payload_len, rc;
        
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "authn_hpc_acct authenticate: try to authenticate '%s' with password '%s'", user, password);
                      
        /*
         * Our post-read hook should have filled-in the username with our secret
         * randomized-at-runtime string and deposited the encrypted token in the
         * password field.
         */
        if ( ! authn_hpc_acct_our_username ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01003)
                          "authn_hpc_acct authenticate: no randomized username configured in runtime");
            return AUTH_GENERAL_ERROR;
        }
        if ( strcmp(user, authn_hpc_acct_our_username) != 0 ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01004)
                          "authn_hpc_acct authenticate: incorrect username in request");
            return AUTH_DENIED;
        }
        
        /*
         * The password field is the encrypted identity token, so let's decode
         * it first.  If we're running an older APR library, the base64url to base64
         * conversion needs to be handled first:
         */
        DO_AUTHN_HPC_BASE64URL_FIXUP((char*)password);
        payload = (unsigned char*)apr_pdecode_base64_binary(r->pool, password, APR_ENCODE_STRING, APR_ENCODE_NONE, &payload_len);
        if ( ! payload || ! payload_len ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          APLOGNO(01005) "authn_hpc_acct authenticate: empty identity token");
            return AUTH_GENERAL_ERROR;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "authn_hpc_acct authenticate: base64 decode of password yielded %ld bytes", payload_len);
        
        /*
         * Now prepare for decryption.  First, pull a salt off the front of
         * the payload if present:
         */
        if ( strncmp((const char*)payload, "Salted__", 8) == 0 ) {
            char        salt_str[17];
            
            memcpy(salt, payload + 8, 8);
            salt_ptr = salt;
            snprintf(salt_str, sizeof(salt_str), "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", salt[0], salt[1], salt[2], salt[3], salt[4], salt[5], salt[6], salt[7]);
            payload += 16;
            payload_len -= 16;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "authn_hpc_acct authenticate: 8-byte salt %s extracted from payload leaving %ld bytes", salt_str, payload_len);
        }
        if ( payload_len > INT_MAX ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          APLOGNO(01006) "authn_hpc_acct authenticate: payload is too large");
            return AUTH_GENERAL_ERROR;
        }
        int_payload_len = payload_len;
        
        /*
         * Now generate the key:
         */
        if ( (rc = authn_hpc_acct_generate_key(r, conf, salt_ptr, &key, &iv)) ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                          APLOGNO(01007) "authn_hpc_acct authenticate: unable to generate key for request");
            return AUTH_GENERAL_ERROR;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "authn_hpc_acct authenticate: decryption key generated");
        
        /*
         * Key and initvec are ready, decrypt the payload:
         */
        decrypt = apr_pcalloc(r->pool, payload_len + 1);
        if ( ! decrypt ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                          APLOGNO(01008) "authn_hpc_acct authenticate: unable to allocate decrypt buffer");
            return AUTH_GENERAL_ERROR;
        }
        decrypt_len = payload_len + 1;
        
        ctx = EVP_CIPHER_CTX_new();
        if ( ! ctx ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                          APLOGNO(01009) "authn_hpc_acct authenticate: unable to allocate decrypt context");
            return AUTH_GENERAL_ERROR;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "authn_hpc_acct authenticate: decryption context ready");
        
        cipher = (authn_hpc_acct_encmethod_cipher_funcs[conf->enc_method.cipher])();
        rc = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
        if ( rc != 1 ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                          APLOGNO(01010) "authn_hpc_acct authenticate: unable to initialize decrypt context");
            EVP_CIPHER_CTX_free(ctx);
            return AUTH_GENERAL_ERROR;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "authn_hpc_acct authenticate: key/iv initialized, ready for decrypt");
        
        rc = EVP_DecryptUpdate(ctx, decrypt, &decrypt_len, payload, int_payload_len);
        if ( rc != 1 ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                          APLOGNO(01011) "authn_hpc_acct authenticate: unable to decrypt");
            EVP_CIPHER_CTX_free(ctx);
            return AUTH_DENIED;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "authn_hpc_acct authenticate: payload body decrypted (%d bytes): %c%c%c%c...", decrypt_len, decrypt[0], decrypt[1], decrypt[2], decrypt[3]);
                      
        rc = EVP_DecryptFinal_ex(ctx, decrypt + decrypt_len, &len);
        if ( rc != 1 ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                          APLOGNO(01012) "authn_hpc_acct authenticate: unable to complete decrypt");
            EVP_CIPHER_CTX_free(ctx);
            return AUTH_DENIED;
        }
        decrypt_len += len;
        decrypt[decrypt_len] = '\0';
        EVP_CIPHER_CTX_free(ctx);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "authn_hpc_acct authenticate: payload decryption complete: '%s'", decrypt);
        
        /* We successfully decrypted the identity token, hooray! */
        if ( decrypt_len > 0 ) {
            authn_hpc_id_token_t    the_token;
            
            if ( authn_hpc_id_token_parse(r, (char*)decrypt, &the_token) == 0 ) {
                /* Expired? */
                if ( the_token.expiration > apr_time_now() ) {
                    /* Overwrite the authorized username field: */
                    r->user = (char*)the_token.uid;
                    
                    /* Add the headers: */
                    if ( conf->uid_header_name && *conf->uid_header_name ) apr_table_set(r->headers_in, conf->uid_header_name, the_token.uid);
                    if ( conf->uid_number_header_name && *conf->uid_number_header_name ) apr_table_set(r->headers_in, conf->uid_number_header_name, the_token.uid_number);
                    if ( conf->ldap_dn_header_name && *conf->ldap_dn_header_name ) apr_table_set(r->headers_in, conf->ldap_dn_header_name, the_token.ldap_dn);
                    
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "authn_hpc_acct authenticate: accepting %s (%s) with dn=%s",
                                  the_token.uid, the_token.uid_number, the_token.ldap_dn);
                    return AUTH_GRANTED;
                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                                  APLOGNO(01013) "authn_hpc_acct authenticate: identity token has expired: %s %ld vs. %ld", decrypt, the_token.expiration, apr_time_now());
                }
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                              APLOGNO(01014) "authn_hpc_acct authenticate: unable to parse the identity token: %s", decrypt);
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          APLOGNO(01005) "authn_hpc_acct authenticate: empty identity token");
        }
        return AUTH_DENIED;
    }
    
    /* We don't have any opinion on this user: */
    return AUTH_USER_NOT_FOUND;
}

/**
 * @var     authn_hpc_acct_provider
 * @brief   The authentication callbacks this module provides.
 */
static const authn_provider authn_hpc_acct_provider = {
        &authn_hpc_acct_check_password,
        NULL,
    };

/**
 * @brief   The post_config hook provided by this module
 * @details This hook is called after the server has finished parsing and
 *          processing the server configuration.  The module has a chance
 *          to review or adjust its server (not per-directory) configuration
 *          and report issues.
 *
 * @return  Returns @a OK on success, !OK if the randomized username could
 *          not be generated.
 */
static int
authn_hpc_acct_post_config(
    apr_pool_t      *pconf,
    apr_pool_t      *plog,
    apr_pool_t      *ptemp,
    server_rec      *s
)
{
    /* base64[url] maps every 3 bytes to 4 ASCII code points, so 18 random
     * bytes becomes a 24-character username:
     */
    unsigned char   rnd_bytes[18];
    apr_status_t    rc;
    
    /* Did we already do this? */
    if ( authn_hpc_acct_our_username ) return OK;
    
    if ( (rc = apr_generate_random_bytes(rnd_bytes, sizeof(rnd_bytes))) == APR_SUCCESS ) {
        authn_hpc_acct_our_username = apr_pencode_base64(pconf, (char*)rnd_bytes, sizeof(rnd_bytes), APR_ENCODE_NOPADDING, NULL);
        if ( authn_hpc_acct_our_username ) {
            authn_hpc_acct_our_username_len = strlen(authn_hpc_acct_our_username);
            ap_log_error(APLOG_MARK, APLOG_INFO, OK, s,
                             "randomized username: '%s'", authn_hpc_acct_our_username);
            return OK;
        }
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_ENOMEM, s,
                         APLOGNO(01002) "unable to encode randomized internal username to base64");
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, s,
                         APLOGNO(01001) "unable to generate randomized internal username");
    }
    return !OK;
}

/**
 * @brief   Function called at module load to register hooks.
 * @details Registers this module as an authentication provider and hooks it into the
 *          post_config and header_parser chains.
 */
static void
register_hooks(
    apr_pool_t  *p
)
{
    /* Register authn provider */
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "hpc-acct",
                              AUTHN_PROVIDER_VERSION,
                              &authn_hpc_acct_provider, AP_AUTH_INTERNAL_PER_CONF);
    
    /* Register our hook that will generate the randomized username
     * that will be used in the synthesized Authorization header:
     */
    ap_hook_post_config(authn_hpc_acct_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    
    /* Register our hook that will decrypt the identity token in the URL and
     * fill-in the Authorization header:
     */
    ap_hook_header_parser(authn_hpc_acct_header_parser, NULL, NULL, APR_HOOK_MIDDLE);
}

/*
 * Our module definition:
 */
AP_DECLARE_MODULE(authn_hpc_acct) =
{
    STANDARD20_MODULE_STUFF,
    create_authn_hpc_acct_dir_config,   /* dir config creater */
    NULL,                               /* dir merger --- default is to override */
    NULL,                               /* server config */
    NULL,                               /* merge server config */
    authn_hpc_acct_cmds,                /* command apr_table_t */
    register_hooks                      /* register hooks */
};
