# shellcheck shell=bash
# Sourced by the action's run steps. Defines github_oidc_prefetch.
#
# atmos's github/oidc provider makes one GET to ACTIONS_ID_TOKEN_REQUEST_URL per identity per
# invocation, with a 10 s timeout and no retry, and fails the run when that GET hangs. When
# ACTIONS_ID_TOKEN is set it uses that JWT and makes no request, so fetching it here with
# retries replaces all of atmos's requests for the next invocation.
#
# The JWT is short-lived and atmos presents it to STS only when an invocation starts, so call
# this immediately before every atmos command, not once per step.
#
# Usage: github_oidc_prefetch <audience>
# The audience must equal auth.providers.<github/oidc provider>.spec.audience: atmos does not
# check it against the JWT. An empty audience, no id-token: write permission, or a request URL
# that is not https:// (atmos rejects those too) changes nothing and leaves atmos to fetch the
# token itself.

github_oidc_prefetch() {
  local aud="${1:-}" attempt body tok payload claims exp iat
  local max_attempts="${GITHUB_OIDC_PREFETCH_ATTEMPTS:-5}"

  [[ -n "$aud" && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" && "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" == https://* ]] || return 0

  # Never hand atmos a JWT this function exported for an earlier invocation: it may have
  # expired. A token the caller set is left alone unless a fresh one replaces it.
  if [[ -n "${GITHUB_OIDC_PREFETCHED_TOKEN:-}" && "${ACTIONS_ID_TOKEN:-}" == "$GITHUB_OIDC_PREFETCHED_TOKEN" ]]; then
    unset ACTIONS_ID_TOKEN
  fi

  for (( attempt = 1; attempt <= max_attempts; attempt++ )); do
    if body=$(curl -sS --fail --connect-timeout 5 --max-time 15 \
        -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
        -H "Accept: application/json" \
        --get --data-urlencode "audience=${aud}" \
        "${ACTIONS_ID_TOKEN_REQUEST_URL}"); then
      # A JWT is base64url segments joined by dots, so it never contains a quote or backslash.
      tok=$(sed -nE 's/.*"value"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' <<<"$body") || tok=""
      if [[ -n "$tok" ]]; then
        echo "::add-mask::${tok}"
        export ACTIONS_ID_TOKEN="$tok"
        GITHUB_OIDC_PREFETCHED_TOKEN="$tok"
        # Log the lifetime (exp - iat). Nothing below may fail the step: it runs under set -e.
        # The audience is caller input, so it is never echoed: it could carry a workflow command.
        payload=$(cut -d. -f2 <<<"$tok" | tr '_-' '/+') || payload=""
        while (( ${#payload} % 4 )); do payload+="="; done
        claims=$(base64 -d <<<"$payload" 2>/dev/null) || claims=""
        exp=$(grep -oE '"exp"[[:space:]]*:[[:space:]]*[0-9]+' <<<"$claims" | grep -oE '[0-9]+$') || exp=""
        iat=$(grep -oE '"iat"[[:space:]]*:[[:space:]]*[0-9]+' <<<"$claims" | grep -oE '[0-9]+$') || iat=""
        if [[ -n "$exp" && -n "$iat" ]]; then
          echo "GitHub OIDC JWT prefetched (attempt ${attempt}, lifetime $(( exp - iat ))s)"
        else
          echo "GitHub OIDC JWT prefetched (attempt ${attempt})"
        fi
        return 0
      fi
    fi
    if (( attempt < max_attempts )); then
      echo "::warning::GitHub OIDC token prefetch attempt ${attempt}/${max_attempts} failed; retrying in $(( attempt * 3 ))s"
      sleep $(( attempt * 3 ))
    fi
  done

  echo "::warning::GitHub OIDC token prefetch failed after ${max_attempts} attempts; atmos will request the token itself"
  return 0
}
