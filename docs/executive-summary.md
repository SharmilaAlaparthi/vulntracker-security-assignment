# Executive Summary — VulnTracker Security Review

## The situation

VulnTracker is the internal tool our security teams use to record and track the weaknesses we find in our systems, and to share those findings with customers and auditors. Because of what it stores, this application is a high-value target: it is, in effect, a catalogue of where we are weakest.

When we started this review, the application had serious problems. In plain terms: an outsider could have logged in as anyone without a valid password, read every team's confidential findings, and in the worst case pulled the entire database through the search box. The keys used to prove a user's identity were written directly into the source code, so anyone who saw the code could impersonate any user. User passwords were being written into our logs in readable form.

## What we did

We closed the most dangerous gaps. Logging in now requires a genuine, properly signed credential — the "skeleton key" loophole is gone. Users can only see their own team's data. The search feature can no longer be tricked into leaking the wider database. Passwords are no longer written to logs, and the identity keys have been moved out of the code into a secure, managed location. We also updated an outdated security component that had a large number of known weaknesses.

We added the requested new capability — a time-limited, optionally password-protected link for sharing a single finding with an outside stakeholder — and built it to be secure from the start: the links are unguessable, expire automatically after 24 hours, and never expose internal notes or ownership details.

Finally, we packaged the application to run in a locked-down, industry-standard way: it runs with the minimum privileges it needs, keeps its secrets in a proper secrets manager, and only accepts traffic from where it should.

## Where we stand now

The application has moved from "exploitable by a motivated outsider in minutes" to "hardened against the common, high-impact attacks." The critical authentication and data-exposure risks are resolved and covered by automated tests, so they cannot silently return.

## Top 3 residual risks

1. **The notification helper service was intentionally left unchanged** (it was out of scope). It still runs an outdated network component and accepts requests without authentication. We contain this by keeping it on an internal-only network.
2. **A few supporting software components are still a version behind.** Updating them safely requires upgrading the core web framework together, which we chose to schedule as a controlled change rather than rush.
3. **There is no automatic lockout for repeated failed logins.** This is best handled at our network edge, and we recommend enabling it there.

## Recommended next steps

- Treat the identity keys currently in the code's history as compromised and rotate them.
- Enable rate limiting and monitoring at the edge for login and share-link access.
- Schedule the coordinated framework/dependency upgrade and apply the same review to the notification service.
- Wire the four automated security scans (already added to our build pipeline) into a gate that blocks releases on new critical findings.

Net: the front door is now locked and the highest-value data is protected. The remaining items are known, contained, and scheduled — not surprises.
