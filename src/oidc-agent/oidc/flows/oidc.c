#include "oidc.h"

#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "account/account.h"
#include "defines/mytoken_values.h"
#include "defines/oidc_values.h"
#include "oidc-agent/http/http_ipc.h"
#include "oidc-agent/oidcd/internal_request_handler.h"
#include "utils/agentLogger.h"
#include "utils/config/custom_parameter.h"
#include "utils/errorUtils.h"
#include "utils/json.h"
#include "utils/key_value.h"
#include "utils/memory.h"
#include "utils/oidc_error.h"
#include "utils/string/stringUtils.h"

/**
 * last argument has to be NULL
 */
char* generatePostData(const char*                request_type,
                       const struct oidc_account* account, char* k1, char* v1,
                       ...) {
  va_list args;
  va_start(args, v1);
  list_t* list = list_new();
  list_rpush(list, list_node_new(k1));
  list_rpush(list, list_node_new(v1));
  char* s;
  while ((s = va_arg(args, char*)) != NULL) {
    list_rpush(list, list_node_new(s));
  }
  va_end(args);
  addCustomParameters(list, account, request_type);
  char* data = generatePostDataFromList(list);
  list_destroy(list);
  return data;
}

char* generatePostDataFromList(list_t* list) {
  if (list == NULL || list->len < 2) {
    oidc_setArgNullFuncError(__func__);
    return NULL;
  }
  char* val  = urlescape((char*)list_at(list, 1)->val);
  char* data = oidc_sprintf("%s=%s", (char*)list_at(list, 0)->val, val);
  secFree(val);
  for (size_t i = 2; i < list->len - 1; i += 2) {
    val = urlescape((char*)list_at(list, i + 1)->val);
    char* tmp =
        oidc_sprintf("%s&%s=%s", data, (char*)list_at(list, i)->val, val);
    secFree(val);
    if (tmp == NULL) {
      return NULL;
    }
    secFree(data);
    data = tmp;
  }
  return data;
}

static const char* _error_context_endpoint = NULL;
static const char* _error_context_scope    = NULL;

void setErrorContext(const char* endpoint, const char* scope) {
  _error_context_endpoint = endpoint;
  _error_context_scope    = scope;
}

void clearErrorContext() {
  _error_context_endpoint = NULL;
  _error_context_scope    = NULL;
}

void defaultErrorHandling(const char* error, const char* error_description) {
  char* error_str = combineError(error, error_description);
  if (_error_context_endpoint) {
    char* contextual = oidc_sprintf("OP responded with error to %s: %s",
                                    _error_context_endpoint, error_str);
    oidc_seterror(contextual);
    agent_log(ERROR, "%s", contextual);
    secFree(contextual);
  } else {
    oidc_seterror(error_str);
    agent_log(ERROR, "%s", error_str);
  }
  oidc_errno = OIDC_EOIDC;
  secFree(error_str);
}

#define TOKENPARSEMODE_DONTFREE_AT \
  (TOKENPARSEMODE_SAVE_AT | TOKENPARSEMODE_RETURN_AT)
#define TOKENPARSEMODE_DONTFREE_ID TOKENPARSEMODE_RETURN_ID

/* Unknown or malformed expiry must never inherit another token's lifetime. */
static unsigned long tokenResponseExpiresAt(const cJSON* response) {
  const cJSON* expiry =
      cJSON_GetObjectItemCaseSensitive(response, OIDC_KEY_EXPIRESIN);
  unsigned long seconds = 0;
  if (cJSON_IsNumber(expiry)) {
    double value = expiry->valuedouble;
    if (!(value >= 0 && value < (double)ULONG_MAX)) {
      return 0;
    }
    seconds = (unsigned long)value;
    if ((double)seconds != value) {
      return 0;
    }
  } else if (cJSON_IsString(expiry)) {
    const char* value = expiry->valuestring;
    if (value == NULL || *value == '\0') {
      return 0;
    }
    for (; *value; value++) {
      if (*value < '0' || *value > '9') {
        return 0;
      }
      unsigned long digit = (unsigned long)(*value - '0');
      if (seconds > (ULONG_MAX - digit) / 10) {
        return 0;
      }
      seconds = seconds * 10 + digit;
    }
  } else {
    return 0;
  }
  time_t now = time(NULL);
  if (now < 0 || (uintmax_t)now > ULONG_MAX ||
      seconds > ULONG_MAX - (unsigned long)now) {
    return 0;
  }
  unsigned long expires_at = (unsigned long)now + seconds;
  // The cached expiry is read back as time_t, which can have a smaller range.
  uintmax_t time_max = (uintmax_t)(time_t)-1;
  if ((time_t)-1 < 0) {
    time_max = UINTMAX_MAX >>
        (sizeof(uintmax_t) * CHAR_BIT - sizeof(time_t) * CHAR_BIT + 1);
  }
  return (uintmax_t)expires_at > time_max ? 0 : expires_at;
}

static char* _parseTokenResponseCallbacks(
    const unsigned char mode, const char* res, struct oidc_account* a,
    void (*errorHandling)(const char*, const char*), struct ipcPipe pipes,
    const unsigned char refreshFlow, unsigned long* expires_at) {
  if (expires_at) {
    *expires_at = 0;
  }
  if (mode & TOKENPARSEMODE_RETURN_ID && mode & TOKENPARSEMODE_RETURN_AT) {
    oidc_setInternalError("cannot return AT and ID token");
    return NULL;
  }
  INIT_KEY_VALUE(OIDC_KEY_ACCESSTOKEN, OIDC_KEY_SCOPE, OIDC_KEY_REFRESHTOKEN,
                 MYTOKEN_KEY_MYTOKEN, OIDC_KEY_IDTOKEN,
                 OIDC_KEY_ERROR, OIDC_KEY_ERROR_DESCRIPTION);
  cJSON* response = stringToJson(res);
  if (response == NULL || CALL_GETJSONVALUES_FROM_CJSON(response) < 0) {
    agent_log(ERROR, "Error while parsing json\n");
    secFreeJson(response);
    SEC_FREE_KEY_VALUES();
    if (oidc_errno == OIDC_EJSONPARS) {
      oidc_errno = OIDC_EOPNOJSON;
    }
    return NULL;
  }
  KEY_VALUE_VARS(access_token, scope, refresh_token, mytoken, id_token,
                 error, error_description);
  unsigned long token_expires_at = tokenResponseExpiresAt(response);
  secFreeJson(response);
  if (_error || _error_description) {
    errorHandling(_error, _error_description);
    SEC_FREE_KEY_VALUES();
    return NULL;
  }

  if (mode & TOKENPARSEMODE_RETURN_AT && !strValid(_access_token)) {
    oidc_seterror("Token response did not contain an access token");
    oidc_errno = OIDC_EOIDC;
    SEC_FREE_KEY_VALUES();
    return NULL;
  }
  if (strValid(_scope) && !refreshFlow) {
    // if we get a scope value back from the OP when the initial AT is obtained,
    // we update the config, because it might be possible that the OP made
    // changes to the scopes.
    // We use this updated scope value in future refresh request. For a
    // reauthenticate we will use the initial authorization scopes.
    const char* requested = _error_context_scope ?: account_getAuthScope(a);
    if (strValid(requested) && !strequal(requested, _scope)) {
      agent_log(NOTICE, "Scope mismatch: requested '%s', OP returned '%s'",
                requested, _scope);
    }
    account_setRefreshScope(a, _scope);
  } else if (strValid(_scope) && refreshFlow) {
    const char* requested = _error_context_scope;
    if (strValid(requested) && !strequal(requested, _scope)) {
      agent_log(NOTICE, "Scope mismatch: requested '%s', OP returned '%s'",
                requested, _scope);
    }
    secFree(_scope);
  } else {
    secFree(_scope);
  }

  char* refresh_token = account_getRefreshToken(a);
  char* obtainedRTMT  = _refresh_token ?: _mytoken;
  if (_refresh_token) {
    secFree(_mytoken);
  }
  if (strValid(obtainedRTMT) && !strequal(refresh_token, obtainedRTMT)) {
    if (strValid(refresh_token) &&
        refreshFlow) {  // only update, if the refresh token
                        // changes, not when
                        // it is initially obtained
                        // Also only update when doing the
                        // refresh flow, on other flows the refresh
                        // token did not change in the same sense.
                        // It's possible that an RT "changes" if
                        // performing the auth code flow or another
                        // flow but the user provided an RT (e.g. in
                        // a file), but it wasn't used. (Unlikely,
                        // but possible)
      agent_log(DEBUG, "Updating refreshtoken for %s from '%s' to '%s'",
                account_getName(a), refresh_token, obtainedRTMT);
      oidcd_handleUpdateRefreshToken(pipes, account_getName(a), obtainedRTMT);
    }
    account_setRefreshToken(a, obtainedRTMT);
  } else {
    secFree(_refresh_token);
    secFree(_mytoken);
  }

  if (mode & TOKENPARSEMODE_SAVE_AT && strValid(_access_token)) {
    account_setAccessToken(a, _access_token);
    account_setTokenExpiresAt(a, token_expires_at);
    agent_log(DEBUG, "expires_at is: %lu\n", token_expires_at);
  }

  if (!(mode & TOKENPARSEMODE_DONTFREE_AT) || !strValid(_access_token)) {
    secFree(_access_token);
  }
  if (!(mode & TOKENPARSEMODE_DONTFREE_ID)) {
    secFree(_id_token);
  }

  oidc_errno = OIDC_SUCCESS;
  if (mode & TOKENPARSEMODE_RETURN_AT) {
    if (expires_at) {
      *expires_at = token_expires_at;
    }
    return _access_token;
  } else if (mode & TOKENPARSEMODE_RETURN_ID) {
    return _id_token;
  }
  return NULL;
}

char* parseTokenResponseCallbacks(
    const unsigned char mode, const char* res, struct oidc_account* a,
    void (*errorHandling)(const char*, const char*), struct ipcPipe pipes,
    const unsigned char refreshFlow) {
  return _parseTokenResponseCallbacks(mode, res, a, errorHandling, pipes,
                                      refreshFlow, NULL);
}

char* parseTokenResponseWithExpiry(const unsigned char mode, const char* res,
                                   struct oidc_account* a, struct ipcPipe pipes,
                                   const unsigned char refreshFlow,
                                   unsigned long* expires_at) {
  return _parseTokenResponseCallbacks(mode, res, a, &defaultErrorHandling,
                                      pipes, refreshFlow, expires_at);
}

char* parseTokenResponse(const unsigned char mode, const char* res,
                         struct oidc_account* a, struct ipcPipe pipes,
                         const unsigned char refreshFlow) {
  return parseTokenResponseCallbacks(mode, res, a, &defaultErrorHandling, pipes,
                                     refreshFlow);
}

void addAudienceRFC8707ToList(list_t* postDataList, char* audience_cpy) {
  if (audience_cpy == NULL || postDataList == NULL) {
    return;
  }
  char* a = strtok(audience_cpy, " ");
  while (a) {
    list_rpush(postDataList, list_node_new(OIDC_KEY_RESOURCE));
    list_rpush(postDataList, list_node_new(a));
    a = strtok(NULL, " ");
  }
}
