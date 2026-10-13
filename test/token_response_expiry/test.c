#include <check.h>
#include <curl/curl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "account/account.h"
#include "defines/agent_values.h"
#include "defines/ipc_values.h"
#include "defines/oidc_values.h"
#include "ipc/ipc.h"
#include "oidc-agent/agent_state.h"
#include "oidc-agent/http/http_ipc.h"
#include "oidc-agent/oidc/flows/oidc.h"
#include "oidc-agent/oidc/flows/openid_config.h"
#include "oidc-agent/oidc/oidc_agent_help.h"
#include "oidc-agent/oidcd/internal_request_handler.h"
#include "oidc-agent/oidcd/oidcd_handler.h"
#include "oidc-agent/oidcd/parse_internal.h"
#include "utils/accountUtils.h"
#include "utils/agentLogger.h"
#include "utils/config/agent_config.h"
#include "utils/config/custom_parameter.h"
#include "utils/config/issuerConfig.h"
#include "utils/crypt/dbCryptUtils.h"
#include "utils/json.h"
#include "utils/printer.h"
#include "utils/string/stringUtils.h"

#define TEST_NOW 1700000000UL
#define CACHED_EXPIRY (TEST_NOW + 5000)
#define ISSUER "https://issuer.invalid"

static struct oidc_account account;
static struct issuerConfig issuer_config;
struct agent_state agent_state;
static time_t now;
static const char* issuer_response;
static char* posted_data;
static int requests;
static int reencryption_calls;
static int rotations;
static const char* reply_token;
static int reply_token_frees;
static int reply_token_independent;
static int last_token_frees;
static int last_token_independent;

/* Wrap only external time and memory/IPC boundaries; production code is linked
 * as separate translation units, not copied or reimplemented in this suite. */
time_t __wrap_time(time_t* out) {
  if (out) {
    *out = now;
  }
  return now;
}

void __real__secFree(void* ptr);
void __wrap__secFree(void* ptr) {
  if (ptr && ptr == reply_token) {
    reply_token_frees++;
  }
  __real__secFree(ptr);
}

oidc_error_t __real_ipc_vwrite(SOCKET fd, const char* fmt, va_list args);
oidc_error_t __wrap_ipc_vwrite(SOCKET fd, const char* fmt, va_list args) {
  if (strcmp(fmt, RESPONSE_STATUS_ACCESS) == 0) {
    va_list copy;
    va_copy(copy, args);
    (void)va_arg(copy, const char*);  // status
    reply_token = va_arg(copy, const char*);
    reply_token_independent = reply_token != account_getAccessToken(&account);
    va_end(copy);
  }
  return __real_ipc_vwrite(fd, fmt, args);
}

char* __wrap_ipc_communicateThroughPipe(struct ipcPipe pipes,
                                       const char* fmt, ...) {
  (void)pipes;
  (void)fmt;
  ck_abort_msg("Unexpected autoload, confirmation or proxy request");
  return NULL;
}

char* sendPostDataWithBasicAuth(const char* endpoint, const char* data,
                                const char* cert_path, const char* username,
                                const char* password) {
  ck_assert_str_eq(endpoint, ISSUER "/token");
  ck_assert_str_eq(cert_path, "/unused-test-ca");
  ck_assert_str_eq(username, "test-client");
  ck_assert_str_eq(password, "test-secret");
  requests++;
  secFree(posted_data);
  posted_data = oidc_strcopy(data);
  if (issuer_response == NULL) {
    oidc_errno = OIDC_ECURLI;
    return NULL;
  }
  return oidc_strcopy(issuer_response);
}

char* urlescape(const char* value) {
  char* escaped = curl_easy_escape(NULL, value, 0);
  ck_assert_ptr_ne(escaped, NULL);
  char* copy = oidc_strcopy(escaped);
  curl_free(escaped);
  return copy;
}

void addCustomParameters(list_t* params, const struct oidc_account* acc,
                         const char* type) {
  (void)params;
  ck_assert_ptr_eq(acc, &account);
  ck_assert_str_eq(type, OIDC_REQUEST_TYPE_REFRESH);
}

const struct issuerConfig* getIssuerConfig(const char* issuer) {
  ck_assert_str_eq(issuer, ISSUER);
  return &issuer_config;
}

struct oidc_account* db_getAccountDecryptedByShortname(const char* name) {
  ck_assert_str_eq(name, "test-account");
  return &account;
}

list_t* db_findAccountsByIssuerUrl(const char* issuer) {
  ck_assert_str_eq(issuer, ISSUER);
  list_t* accounts = list_new();
  list_rpush(accounts, list_node_new(&account));
  return accounts;
}

struct oidc_account* _db_decryptFoundAccount(struct oidc_account* acc) {
  ck_assert_ptr_eq(acc, &account);
  return acc;
}

void db_addAccountEncrypted(struct oidc_account* acc) {
  ck_assert_ptr_eq(acc, &account);
  reencryption_calls++;
}

void oidcd_handleUpdateRefreshToken(struct ipcPipe pipes, const char* name,
                                    const char* token) {
  (void)pipes;
  ck_assert_str_eq(name, "test-account");
  ck_assert_str_eq(token, "rotated-refresh-token");
  rotations++;
}

static void unexpectedBoundary() {
  ck_abort_msg("Unexpected configuration, autoload or generation boundary");
}

void oidcd_handleUpdateIssuer(struct ipcPipe pipes, const char* issuer,
                              const char* name, const char* action) {
  (void)pipes;
  (void)issuer;
  (void)name;
  (void)action;
  unexpectedBoundary();
}

struct oidc_account* getAccountFromJSON(const char* json) {
  (void)json;
  unexpectedBoundary();
  return NULL;
}

oidc_error_t obtainIssuerConfig(struct oidc_account* acc) {
  (void)acc;
  unexpectedBoundary();
  return OIDC_EERROR;
}

char* parseForConfig(char* response) {
  (void)response;
  unexpectedBoundary();
  return NULL;
}

oidc_error_t parseForErrorCode(char* response) {
  (void)response;
  unexpectedBoundary();
  return OIDC_EERROR;
}

const agent_config_t* getAgentConfig() {
  static const agent_config_t config = {0};
  return &config;
}

char* getDefaultCertPath() { return oidc_strcopy("/unused-test-ca"); }
char* getHelpWithAccountInfo(struct oidc_account* acc) {
  (void)acc;
  return NULL;
}
const char* getHelp() { return NULL; }
unsigned char logWithTerminal() { return 0; }
void _logger(int level, const char* fmt, ...) {
  (void)level;
  (void)fmt;
}
void _loggerTerminal(int level, const char* fmt, ...) {
  (void)level;
  (void)fmt;
}
int printError(char* fmt, ...) {
  (void)fmt;
  return 0;
}

static void setup() {
  memset(&account, 0, sizeof(account));
  memset(&issuer_config, 0, sizeof(issuer_config));
  now = TEST_NOW;
  requests = reencryption_calls = rotations = 0;
  reply_token = NULL;
  reply_token_frees = reply_token_independent = 0;
  last_token_frees = last_token_independent = 0;
  issuer_response = "{\"access_token\":\"returned-token\",\"expires_in\":60}";
  account.shortname = oidc_strcopy("test-account");
  account_setIssuerUrl(&account, oidc_strcopy(ISSUER));
  issuer_setTokenEndpoint(account.issuer, oidc_strcopy(ISSUER "/token"));
  account_setClientId(&account, oidc_strcopy("test-client"));
  account_setClientSecret(&account, oidc_strcopy("test-secret"));
  account_setRefreshToken(&account, oidc_strcopy("original-refresh-token"));
  account_setAuthScopeExact(&account, oidc_strcopy("openid email offline_access"));
  account_setRefreshScope(&account, oidc_strcopy("openid email offline_access"));
  account_setAccessToken(&account, oidc_strcopy("cached-token"));
  account_setTokenExpiresAt(&account, CACHED_EXPIRY);
  oidc_errno = OIDC_SUCCESS;
}

static void teardown() {
  reply_token = NULL;
  secFree(posted_data);
  secFree(account.shortname);
  account_setClientId(&account, NULL);
  account_setClientSecret(&account, NULL);
  account_setRefreshToken(&account, NULL);
  account_setAuthScopeExact(&account, NULL);
  account_setRefreshScope(&account, NULL);
  account_setAccessToken(&account, NULL);
  _secFreeIssuer(account.issuer);
  account.issuer = NULL;
}

/* The real handler writes the unchanged protocol to a real local pipe. */
static cJSON* request(int by_issuer, const char* scope, const char* audience,
                       const char* min_valid_period) {
  int fds[2];
  ck_assert_int_eq(pipe(fds), 0);
  struct ipcPipe pipes = {-1, fds[1]};
  struct arguments arguments = {0};
  arguments.no_autoload = 1;
  reply_token = NULL;
  reply_token_frees = reply_token_independent = 0;
  if (by_issuer) {
    oidcd_handleTokenIssuer(pipes, ISSUER, min_valid_period, scope, "test",
                            audience, &arguments);
  } else {
    oidcd_handleToken(pipes, "test-account", min_valid_period, scope, "test",
                      audience, &arguments);
  }
  last_token_frees = reply_token_frees;
  last_token_independent = reply_token_independent;
  reply_token = NULL;  // Do not count a later reuse of the freed address.
  close(fds[1]);
  char* response = ipc_read(fds[0]);
  close(fds[0]);
  ck_assert_ptr_ne(response, NULL);
  cJSON* json = stringToJson(response);
  secFree(response);
  ck_assert_ptr_ne(json, NULL);
  return json;
}

static void assertReply(cJSON* reply, const char* token,
                         unsigned long expires_at) {
  const cJSON* status = cJSON_GetObjectItemCaseSensitive(reply, IPC_KEY_STATUS);
  const cJSON* access = cJSON_GetObjectItemCaseSensitive(reply, OIDC_KEY_ACCESSTOKEN);
  const cJSON* expiry = cJSON_GetObjectItemCaseSensitive(reply, AGENT_KEY_EXPIRESAT);
  const cJSON* issuer = cJSON_GetObjectItemCaseSensitive(reply, OIDC_KEY_ISSUER);
  ck_assert(cJSON_IsString(status));
  ck_assert_str_eq(status->valuestring, STATUS_SUCCESS);
  ck_assert(cJSON_IsString(access));
  ck_assert_str_eq(access->valuestring, token);
  ck_assert(cJSON_IsString(issuer));
  ck_assert_str_eq(issuer->valuestring, ISSUER);
  ck_assert(cJSON_IsNumber(expiry));
  ck_assert(expiry->valuedouble == (double)expires_at);
  secFreeJson(reply);
}

static void assertCache(const char* token, unsigned long expiry) {
  ck_assert_str_eq(account_getAccessToken(&account), token);
  ck_assert_uint_eq(account_getTokenExpiresAt(&account), expiry);
}

struct request_shape {
  const char* scope;
  const char* audience;
};
static const struct request_shape shapes[] = {
    {NULL, NULL}, {"email", NULL}, {NULL, "https://resource.invalid"},
    {"email", "https://resource.invalid"}, {"", ""},
    {"", "https://resource.invalid"}, {"email", ""}};

START_TEST(test_returned_expiry_and_default_cache) {
  const struct request_shape shape = shapes[_i / 2];
  assertReply(request(_i % 2, shape.scope, shape.audience, "-1"),
              "returned-token", TEST_NOW + 60);
  ck_assert_int_eq(requests, 1);
  ck_assert_int_eq(reencryption_calls, 1);
  if (strValid(shape.scope) || strValid(shape.audience)) {
    assertCache("cached-token", CACHED_EXPIRY);
  } else {
    assertCache("returned-token", TEST_NOW + 60);
  }
  ck_assert_ptr_ne(strstr(posted_data, "grant_type=refresh_token"), NULL);
  ck_assert_ptr_ne(strstr(posted_data, "refresh_token=original-refresh-token"), NULL);
  if (strValid(shape.scope)) {
    ck_assert_ptr_ne(strstr(posted_data, "scope=email"), NULL);
  }
  if (strValid(shape.audience)) {
    ck_assert_ptr_ne(strstr(posted_data, "resource=https%3A%2F%2Fresource.invalid"), NULL);
  }
}
END_TEST

START_TEST(test_nondefault_then_default_cache_hit) {
  assertReply(request(_i, NULL, "https://resource.invalid", "0"),
              "returned-token", TEST_NOW + 60);
  assertCache("cached-token", CACHED_EXPIRY);
  assertReply(request(_i, NULL, NULL, "0"), "cached-token", CACHED_EXPIRY);
  ck_assert_int_eq(requests, 1);
  assertCache("cached-token", CACHED_EXPIRY);
}
END_TEST

static const char* invalid_expiries[] = {
    "", ",\"expires_in\":null", ",\"expires_in\":true",
    ",\"expires_in\":false", ",\"expires_in\":-1",
    ",\"expires_in\":1.5", ",\"expires_in\":\"\"",
    ",\"expires_in\":\"60junk\"", ",\"expires_in\":\"-60\"",
    ",\"expires_in\":\" 60\"", ",\"expires_in\":[]",
    ",\"expires_in\":{}", ",\"expires_in\":1e100",
    ",\"expires_in\":\"999999999999999999999999999999\""};

START_TEST(test_unknown_expiry_never_inherits_cache) {
  int by_issuer = _i % 2;
  int use_default = (_i / 2) % 2;
  const char* suffix = invalid_expiries[_i / 4];
  char* response = oidc_sprintf("{\"access_token\":\"returned-token\"%s}", suffix);
  issuer_response = response;
  assertReply(request(by_issuer, use_default ? NULL : "email", NULL, "-1"),
              "returned-token", 0);
  assertCache(use_default ? "returned-token" : "cached-token",
              use_default ? 0 : CACHED_EXPIRY);
  if (use_default) {
    issuer_response = "{\"access_token\":\"next-token\",\"expires_in\":60}";
    assertReply(request(by_issuer, NULL, NULL, "0"), "next-token", TEST_NOW + 60);
    ck_assert_int_eq(requests, 2);
  }
  secFree(response);
}
END_TEST

START_TEST(test_integer_string_zero_and_epoch_overflow) {
  static const char* values[] = {"\"60\"", "0", "\"0\"", "3e2"};
  char* response;
  unsigned long expected;
  if (_i < 8) {
    response = oidc_sprintf("{\"access_token\":\"returned-token\",\"expires_in\":%s}",
                            values[_i / 2]);
    expected = TEST_NOW + (_i / 2 == 0 ? 60 : _i / 2 == 3 ? 300 : 0);
  } else {
    response = oidc_sprintf("{\"access_token\":\"returned-token\",\"expires_in\":\"%lu\"}",
                            ULONG_MAX);
    expected = 0;
  }
  issuer_response = response;
  assertReply(request(_i % 2, NULL, "https://resource.invalid", "-1"),
              "returned-token", expected);
  assertCache("cached-token", CACHED_EXPIRY);
  secFree(response);
}
END_TEST

START_TEST(test_time_t_boundary_then_default_request) {
  uintmax_t max_expiry = (uintmax_t)(time_t)-1;
  if ((time_t)-1 < 0) {
    max_expiry = ((uintmax_t)1 << (sizeof(time_t) * CHAR_BIT - 1)) - 1;
  }
  if (max_expiry > ULONG_MAX) {
    max_expiry = ULONG_MAX;
  }
  char* response;
  int valid_boundary = _i / 2 == 0;
  if (valid_boundary) {
    response = oidc_sprintf(
        "{\"access_token\":\"returned-token\",\"expires_in\":\"%ju\"}",
        max_expiry - TEST_NOW);
  } else if (_i / 2 == 1) {
    // One past the native time_t boundary (or unsigned long addition overflow).
    response = oidc_sprintf(
        "{\"access_token\":\"returned-token\",\"expires_in\":\"%ju\"}",
        max_expiry - TEST_NOW + 1);
  } else {
    // Reviewer's 64-bit reproducer: TEST_NOW + expires_in == 2^63.
    response = oidc_strcopy(_i / 2 == 2
        ? "{\"access_token\":\"returned-token\",\"expires_in\":\"9223372035154775808\"}"
        : "{\"access_token\":\"returned-token\",\"expires_in\":9223372035154775808}");
  }
  issuer_response = response;
  cJSON* first = request(_i % 2, NULL, NULL, "-1");
  unsigned long cached_expiry = account_getTokenExpiresAt(&account);
  issuer_response = "{\"access_token\":\"next-token\",\"expires_in\":60}";
  // Exercise the cached time_t subtraction before assertions can stop the test.
  cJSON* second = request(_i % 2, NULL, NULL, "0");
  ck_assert_uint_eq(cached_expiry, valid_boundary ? max_expiry : 0);
  assertReply(first, "returned-token", valid_boundary ? max_expiry : 0);
  assertReply(second, valid_boundary ? "returned-token" : "next-token",
              valid_boundary ? max_expiry : TEST_NOW + 60);
  assertCache(valid_boundary ? "returned-token" : "next-token",
              valid_boundary ? max_expiry : TEST_NOW + 60);
  ck_assert_int_eq(requests, valid_boundary ? 1 : 2);
  secFree(response);
}
END_TEST

START_TEST(test_all_result_strings_freed_once_without_cache_alias) {
  const struct request_shape shape = shapes[_i / 2];
  cJSON* reply = request(_i % 2, shape.scope, shape.audience, "-1");
  ck_assert_int_eq(last_token_frees, 1);
  ck_assert_int_eq(last_token_independent, 1);
  secFreeJson(reply);
  reply = request(_i % 2, NULL, NULL, "0");
  ck_assert_int_eq(last_token_frees, 1);
  ck_assert_int_eq(last_token_independent, 1);
  secFreeJson(reply);
}
END_TEST

START_TEST(test_failure_preserves_cache_and_does_not_report_token) {
  static const char* responses[] = {
      "{\"error\":\"invalid_grant\",\"expires_in\":60}",
      "not-json", "{\"expires_in\":60}",
      "{\"access_token\":\"\",\"expires_in\":60}", NULL};
  issuer_response = responses[_i / 4];
  cJSON* reply = request(_i % 2, (_i / 2) % 2 ? NULL : "email", NULL, "-1");
  const cJSON* error = cJSON_GetObjectItemCaseSensitive(reply, OIDC_KEY_ERROR);
  ck_assert(cJSON_IsString(error));
  ck_assert_ptr_eq(cJSON_GetObjectItemCaseSensitive(reply, OIDC_KEY_ACCESSTOKEN), NULL);
  assertCache("cached-token", CACHED_EXPIRY);
  ck_assert_int_eq(reencryption_calls, 1);
  ck_assert_int_eq(last_token_frees, 0);
  secFreeJson(reply);
}
END_TEST

START_TEST(test_rotated_refresh_token_is_preserved) {
  issuer_response = "{\"access_token\":\"returned-token\",\"expires_in\":60,"
                    "\"refresh_token\":\"rotated-refresh-token\",\"scope\":\"email\"}";
  assertReply(request(_i, "email", "https://resource.invalid", "-1"),
              "returned-token", TEST_NOW + 60);
  ck_assert_str_eq(account_getRefreshToken(&account), "rotated-refresh-token");
  ck_assert_str_eq(account_getRefreshScope(&account), "openid email offline_access");
  ck_assert_int_eq(rotations, 1);
  assertCache("cached-token", CACHED_EXPIRY);
}
END_TEST

START_TEST(test_multiple_resources_and_legacy_audience) {
  issuer_config.legacy_aud_mode = _i / 2;
  assertReply(request(_i % 2, "email", "https://one.invalid https://two.invalid", "-1"),
              "returned-token", TEST_NOW + 60);
  if (issuer_config.legacy_aud_mode) {
    ck_assert_ptr_ne(strstr(posted_data,
        "audience=https%3A%2F%2Fone.invalid%20https%3A%2F%2Ftwo.invalid"), NULL);
    ck_assert_ptr_eq(strstr(posted_data, "resource="), NULL);
  } else {
    ck_assert_ptr_ne(strstr(posted_data, "resource=https%3A%2F%2Fone.invalid"), NULL);
    ck_assert_ptr_ne(strstr(posted_data, "resource=https%3A%2F%2Ftwo.invalid"), NULL);
  }
  assertCache("cached-token", CACHED_EXPIRY);
}
END_TEST

static void unexpectedParserError(const char* error, const char* description) {
  (void)error;
  (void)description;
  ck_abort_msg("Unexpected parser error in successful response");
}

START_TEST(test_existing_parser_modes_and_owned_id_token) {
  struct ipcPipe pipes = {-1, -1};
  char* token = parseTokenResponse(TOKENPARSEMODE_SAVE_AT | TOKENPARSEMODE_RETURN_AT,
      "{\"access_token\":\"default-token\",\"expires_in\":60}", &account, pipes, 1);
  ck_assert_ptr_eq(token, account_getAccessToken(&account));
  assertCache("default-token", TEST_NOW + 60);
  char* id = parseTokenResponseCallbacks(TOKENPARSEMODE_RETURN_ID,
      "{\"access_token\":\"discarded-token\",\"expires_in\":600,\"id_token\":\"id-token\"}",
      &account, &unexpectedParserError, pipes, 1);
  ck_assert_str_eq(id, "id-token");
  secFree(id);
  assertCache("default-token", TEST_NOW + 60);
}
END_TEST

int main() {
  Suite* suite = suite_create("token response expiry");
  TCase* tc = tcase_create("real parser and account/issuer handlers");
  tcase_add_checked_fixture(tc, setup, teardown);
  int shape_count = sizeof(shapes) / sizeof(*shapes);
  int invalid_count = sizeof(invalid_expiries) / sizeof(*invalid_expiries);
  tcase_add_loop_test(tc, test_returned_expiry_and_default_cache, 0, shape_count * 2);
  tcase_add_loop_test(tc, test_nondefault_then_default_cache_hit, 0, 2);
  tcase_add_loop_test(tc, test_unknown_expiry_never_inherits_cache, 0, invalid_count * 4);
  tcase_add_loop_test(tc, test_integer_string_zero_and_epoch_overflow, 0, 10);
  tcase_add_loop_test(tc, test_time_t_boundary_then_default_request, 0, 8);
  tcase_add_loop_test(tc, test_all_result_strings_freed_once_without_cache_alias, 0, shape_count * 2);
  tcase_add_loop_test(tc, test_failure_preserves_cache_and_does_not_report_token, 0, 20);
  tcase_add_loop_test(tc, test_rotated_refresh_token_is_preserved, 0, 2);
  tcase_add_loop_test(tc, test_multiple_resources_and_legacy_audience, 0, 4);
  tcase_add_test(tc, test_existing_parser_modes_and_owned_id_token);
  suite_add_tcase(suite, tc);
  SRunner* runner = srunner_create(suite);
  srunner_set_fork_status(runner, CK_NOFORK);
  srunner_run_all(runner, CK_NORMAL);
  int failed = srunner_ntests_failed(runner);
  srunner_free(runner);
  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
