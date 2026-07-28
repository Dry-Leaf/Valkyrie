# Overview
The internet is rife with bad actors. Your options for mitigating this are few. Most opt to use Cloudflare. Valkriye is another option for those who wish to minimize their reliance on service providers. It is built with simplicity and flexibility in mind, so as to fit within an existing stack with minimal friction. It is written in Odin, which combines C's performance with Go's ergonomics.

# How does it work?
Valkyrie sits between clients and your backend, whether that's a server, reverse proxy or CDN. It issues PoW challenges, which consume far more resources to solve than to verify. For a legitimate user, this is an acceptable cost of admission. For a bad actor, it creates an untenable expense.
