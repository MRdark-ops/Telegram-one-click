# Telegram Desktop: Link Injection to Arbitrary File Read

> **Security research write-up** — CVE-2026-107181  
> This article describes a vulnerability chain in Telegram Desktop, its impact, the vendor fix, and steps users can take to reduce exposure.

## Introduction

Someone adds you to a Telegram group. A link shows up in the chat. You click it, and your Telegram account is no longer only yours.

## Vulnerability at a glance

| Field | Details |
|---|---|
| **Affected** | Telegram Desktop through 7.2.8; confirmed on Windows with version 6.9.3 |
| **Impact** | Remote arbitrary local file read, potential exfiltration to an attacker-controlled chat, and account takeover |
| **CVE** | CVE-2026-107181 |
| **Fixed in** | Telegram Desktop 7.2.9; commit `db3405699f` |
| **Severity** | 8.1 High — CVSS 3.1 (`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`) |

## Table of contents

- [One link, two processes](#one-link-two-processes)
- [The unescaped separator](#the-unescaped-separator)
- [The `interpret:` URI scheme](#the-interpret-uri-scheme)
- [Getting an instruction file onto disk](#getting-an-instruction-file-onto-disk)
- [From file read to account takeover](#from-file-read-to-account-takeover)
- [Delivering the link](#delivering-the-link)
- [Proof-of-concept overview](#proof-of-concept-overview)
- [Mitigations](#mitigations)
- [The fix](#the-fix)
- [Timeline](#timeline)

## One link, two processes

Operating systems let programs register a URI scheme, so they know which application to launch when they meet a link of that kind. Telegram Desktop registers `tg`. From then on the system knows a `tg://...` link belongs to Telegram, and launches it with the URL as a command-line argument.

If Telegram is not running, the process starts, takes the string as a parameter, turns it into a URL object and handles it internally: one process, and nothing to communicate.

But what if Telegram is already running? The operating system neither knows nor checks: it launches a new process anyway, identical to the first. Telegram itself has to work out that it is the redundant one, and the way it works that out is by trying to connect to a local socket.

The already-running instance is the server: it has been listening on that socket since it started. The new process is the client. If it manages to connect, an instance is already alive, so it hands over the link and exits.

A socket does not carry objects, it carries bytes. The URL object the new process holds in memory cannot cross that channel, so it has to be flattened into a line of text.

That operation has a name: serialization. Its inverse, rebuilding the object from the text, is deserialization. Both are unavoidable whenever structured data has to cross a boundary, and both are the exact point where the boundaries inside the data stop being held by the structure and become characters in the text.

Telegram does it with a format of its own, a simple one. Each instruction is a keyword, then its argument, then a semicolon that closes it. A link to open becomes:

```text
OPEN:tg://x?a=1;
```

`tg://x?a=1` matches no handler inside Telegram, so on its own that link does nothing. It is only a carrier.

That line is built here, one per URL to open:

```cpp
// sandbox.cpp:295-297
for (const auto &url : cRefStartUrls()) {
    commands += u"OPEN:"_q + url.toString(QUrl::FullyEncoded) + ';';
}
```

On the other side the running instance deserializes: it reads the received bytes, cuts them at every semicolon, and treats each piece as an instruction in its own right. For each piece starting with `OPEN:` it takes what follows and rebuilds it as a URL, exactly as if it had just arrived on the command line.

```cpp
// sandbox.cpp:453-463 (abbreviated)
for (int32 to = cmds.indexOf(QChar(';'), from); to >= from; ...) {
    auto cmd = base::StringViewMid(cmds, from, to - from);
    ...
    } else if (cmd.startsWith(u"OPEN:"_q)) {
        startUrls.append(cmds.mid(from + 5, to - from - 5).mid(0, 8192));
```

## The unescaped separator

What happens if one of the transmitted values contains a semicolon of its own, the very character the format uses as a separator?

For example, consider a URL containing an extra command-like field:

```text
tg://x?a=1;CMD:quit
```

The new process treats it as a single URL, because to it that semicolon is just a character inside the query. It flattens it and writes it to the socket:

```text
OPEN:tg://x?a=1;CMD:quit;
```

The running instance cuts at every semicolon and gets two instructions instead of one:

```text
OPEN:tg://x?a=1
CMD:quit
```

That is the injection, and it is the first of the two defects.

## The `interpret:` URI scheme

The example above injected `CMD:`, but don’t be misled by the name: it accepts only `show` and `quit`, so the worst it can do is close the app.

Four commands are accepted in total, and three of them are harmless. The fourth is `OPEN:`, and there is the detail: it accepts any URL, with no filter on the scheme.

Digging through the code turns up another URI scheme inside Telegram, called `interpret:`.

The operating system would not know what to do with a link starting with `interpret:`, because it is registered nowhere as a protocol handler: it exists only inside Telegram’s own code, which picks the scheme up off the start-URL list like any other.

```cpp
// application.cpp:1162-1164
if (url.scheme() == u"interpret"_q) {
    interprets.append(url.path());
    return false;
}
```

Through `OPEN:`, the internal handler was reachable by a crafted URI. **The complete exploit URI is intentionally omitted here.**

### What was `interpret:` for?

It was the tool Telegram used to publish its own releases. When a new version shipped, the build archive had to be posted to a channel with the changelog as its caption. Rather than doing that by hand, a script wrote a small text file naming the channel, the file to send and the text to write, then launched Telegram with the path to that file.

```python
# Telegram/build/updates.py:206
subprocess.call(... 'Telegram -sendpath interpret://' + scriptPath
    + '/.../command.txt', shell=True)
```

The instruction file contained a source account identifier, a destination channel, a file to send, and a caption. The `from:` value was compared against the ID of the currently logged-in account: it kept an operator from publishing a release from the wrong one. The check only ran if the line was present, so leaving it out skipped it. The destination was set only by `channel:`, and had to be a channel or a supergroup.

A function called `InterpretSendPath` did the work.

So where was the bug? `interpret:` performed a privileged action, reading a file off the disk and sending it to a chat, without asking anyone for confirmation and without checking who asked for it.

The relevant function did not perform an authorization check:

```cpp
// support_helper.cpp:673-680
QString InterpretSendPath(
        not_null<Window::SessionController*> window,
        const QString &path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        return "App Error: Could not open interpret file: " + path;
    }
    const auto content = QString::fromUtf8(f.readAll());
```

When that came from the command line, which is how the release script invoked it, it was not a problem: an attacker would need a foothold on the machine already, and with one they could read the files themselves. But once the same action became reachable through the socket, and therefore through the injection, a dangerous function became available from a link the victim clicked.

That was a missing authorization check, and it was the second of the two defects.

## Getting an instruction file onto disk

An attacker who could place an instruction file on the victim’s disk, pointing `file:` at a path worth stealing and `channel:` at a channel of their own, could abuse this behavior with a clicked link.

One route was to send the instruction file as a chat attachment. In its default configuration, Telegram Desktop downloaded files received in groups up to 8 MiB automatically, while automatic download in broadcast channels was off. The file landed in a standard folder under the sender-chosen name without the victim clicking it; a name collision could change the saved filename. Some formats, such as stickers, GIFs and voice messages, went to an internal cache instead and were not reachable as a normal path on disk.

Telegram constructed the download path itself (`file_utilities.cpp:172-181`). The precise location depended on the Windows account and Telegram configuration. Because the internal handler also accepted relative paths, the attacker did not necessarily need to know the account’s username. **The path-traversal payload and exact path construction used to make the attack repeatable are omitted.**

## From file read to account takeover

`InterpretSendPath` sent one file per invocation: if an instruction file held several `file:` lines, only the last one counted. However, an attacker could potentially send multiple instruction files, and the injection did not stop at the first command: every semicolon could create another instruction. **The compound multi-file exfiltration payload is omitted.**

The underlying primitive was arbitrary file read. Potential targets included private keys, browser password stores, cloud credentials, or configuration files holding API tokens.

Telegram did not keep local data in the clear, so its local account data—including session authorization—was encrypted. That authorization was the key the client used to identify itself to Telegram’s servers, and possession of valid session material could allow an attacker to act as the account, much like a session cookie on a website.

Telegram used key wrapping. Two keys were involved: the DEK (Data Encryption Key), a long, random, high-entropy key that encrypted the user’s data; and the KEK (Key Encryption Key), which encrypted only the DEK. The KEK was derived from the local passcode through a key derivation function (KDF), together with a salt stored next to the encrypted DEK.

By default, Telegram Desktop did not require a local passcode; a user had to set one in Settings. With no passcode set, the derivation used an empty passcode (`storage_domain.cpp:102`). In that configuration, theft of relevant local data could undermine protection of the stored session. The exact file-by-file reconstruction procedure and session-material paths are omitted.

## Delivering the link

The attack needed one click from the victim, and it had to come from outside Telegram. A `tg://` link clicked inside a Telegram chat was handled in-process (`click_handler_types.cpp:278`) and did not reach the socket. Normal `https` links, on the other hand, opened in the system browser (`ui_integration.cpp:437`), because Telegram Desktop had no embedded browser. An attacker could therefore attempt to use an ordinary HTTPS link that redirected to a crafted Telegram URI.

A redirect of this kind would conceptually look like this; the crafted target is intentionally redacted:

```http
GET /rules HTTP/1.1
Host: example.invalid

HTTP/1.1 302 Found
Location: tg://[redacted crafted URI]
```

Depending on the browser, and on whether the victim had used the handler before, the system might ask for confirmation before launching Telegram.

## Proof-of-concept overview

The reported attack scenario combined several conditions: the victim could be added to a group, Telegram automatically downloaded a suitable attachment, the victim clicked an external link, and the crafted URI reached the already-running Telegram instance. The injection then exposed the internal file-sending handler without a suitable authorization check.

The working payloads, exact instruction-file contents, session-file targets, and account-reconstruction steps are intentionally not reproduced in this public-facing version. They are not required to understand the root cause or apply the mitigation.

## Mitigations

1. **Upgrade to Telegram Desktop 7.2.9 or later.** This is the direct fix; the other steps only reduce exposure.
2. **Turn on “Ask where to save each file.”** With that setting, automatic download does not happen, so an untrusted instruction attachment is less likely to reach disk automatically.
3. **Limit who can add you to groups to your contacts only.** The attack relied on a group or supergroup as part of the delivery and exfiltration chain.
4. **Set a strong local passcode.** This does not prevent files from being read, but it adds protection to local session data.

## The fix

The issue was fixed by commit `db3405699f` on 16 September 2026. The changelog dates 7.2.9 to the same day; the release was published the following morning. The commit removed the `interpret://` scheme and `Support::InterpretSendPath` entirely, and escaped the record separator on the single-instance socket: values were escaped with a percent-prefixed hex encoding before being written and decoded after the split, so a semicolon in the data could no longer become a boundary.

It also added two measures beyond that: `CMD:` and `CTRL:` records were skipped when the same connection carried an `OPEN:`, and local file paths were dropped once a non-local URL had appeared on that connection.

## Timeline

| Date | Event |
|---|---|
| 2026-06-25 | Reported through ZDI |
| 2026-09-16 | Vendor fixes the issue independently, commit `db3405699f` |
| 2026-09-17 | Telegram Desktop 7.2.9 published |
| 2026-09-30 | ZDI closes the case as already fixed; disclosure rights return to the researcher |
| 2026-10-03 | This write-up |
| 2026-10-07 | CVE-2026-107181 assigned |

The fix shipped quietly: the 7.2.9 changelog mentioned only a rendering fix, the commit that closed the chain was titled “Remove legacy interpret path helper”, and no advisory accompanied it.
