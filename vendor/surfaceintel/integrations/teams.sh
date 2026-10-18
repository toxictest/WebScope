# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
# Customer-configured Teams Workflows webhook, not a dependency on retired connectors.
payload_teams() {
    printf '{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"type":"AdaptiveCard","version":"1.2","body":[{"type":"TextBlock","wrap":true,"text":'
    json_string "$1"
    printf '}]}}]}\n'
}
