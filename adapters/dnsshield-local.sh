#!/usr/bin/env bash
set -uo pipefail
CLOUD_PATTERNS=(
    "*.s3-website*.amazonaws.com:Amazon S3 (static website)"
    "*.s3.*.amazonaws.com:Amazon S3"
    "*.s3.amazonaws.com:Amazon S3"
    "*.elasticbeanstalk.com:AWS Elastic Beanstalk"
    "*.elb.amazonaws.com:AWS ELB / ALB"
    "*.cloudfront.net:Amazon CloudFront"
    "*.amazonaws.com:Amazon AWS (other)"
    "*.azurewebsites.net:Microsoft Azure App Service"
    "*.cloudapp.azure.com:Microsoft Azure (classic)"
    "*.cloudapp.net:Microsoft Azure (classic)"
    "*.blob.core.windows.net:Azure Blob Storage"
    "*.github.io:GitHub Pages"
    "*.herokuapp.com:Heroku"
    "*.zendesk.com:Zendesk"
    "*.fastly.net:Fastly"
    "*.netlify.app:Netlify"
    "*.netlify.com:Netlify"
    "*.vercel.app:Vercel"
    "*.myshopify.com:Shopify"
    "*.wordpress.com:WordPress"
    "*.tumblr.com:Tumblr"
    "*.bitbucket.io:Bitbucket"
    "*.firebaseapp.com:Firebase"
    "*.web.app:Firebase Hosting"
    "*.surge.sh:Surge.sh"
    "*.ghost.io:Ghost"
    "*.readme.io:Readme.io"
    "*.pantheonsite.io:Pantheon"
    "*.acquia-sites.com:Acquia"
    "*.atlassian.net:Atlassian Cloud"
    "*.force.com:Salesforce"
    "*.bigcommerce.com:BigCommerce"
)
cloud_provider() {
    # maps a CNAME target to the cloud provider that owns it
    local t="${1,,}"
    t="${t%.}"
    local entry pat prov
    for entry in "${CLOUD_PATTERNS[@]}"; do
        pat="${entry%%:*}"
        prov="${entry#*:}"
        # shellcheck disable=SC2053  # intentional glob match
        if [[ "$t" == $pat ]]; then
            printf '%s' "$prov"
            return 0
        fi
    done
    printf ''
}
cloud_provider "$1"
