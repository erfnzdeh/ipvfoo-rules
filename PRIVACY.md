# Privacy Policy — CIDR Match — IP Range Checker

_Last updated: 2026-06-22_

**CIDR Match — IP Range Checker** ("the extension") does not collect, transmit,
sell, or share any personal data. There are no analytics, no telemetry, and no
external servers operated by this extension.

## What the extension can access

To show the table of connection information, the extension observes the IP
addresses your browser connects to as you load pages (the same mechanism used
by upstream IPvFoo). This information:

- is processed **locally, in your browser only**;
- is kept in memory and is **never transmitted over the network** by the
  extension;
- is **not** logged, stored on any server, or shared with anyone.

## Your CIDR ruleset

Any CIDR ruleset you paste into the options page is stored in
`chrome.storage.local` on your own device. It is not synced to any account,
uploaded, or sent anywhere. You can clear it at any time from the options page.

## The "Look up" feature

The optional context-menu "Look up" feature (inherited from IPvFoo) navigates
your browser to a third-party lookup provider (for example bgp.he.net) using a
URL containing the selected domain name or IP address. This only happens when
you explicitly choose it, and the request is made by your browser directly to
that third party — the extension itself sends nothing.

## Permissions

The extension requests broad host access (`<all_urls>`) and `webRequest`
solely to read the IP addresses of the connections made by the pages you
visit. It does not modify, block, or redirect any traffic.

## Contact

Questions or concerns: https://github.com/erfnzdeh/ipvfoo-rules/issues
