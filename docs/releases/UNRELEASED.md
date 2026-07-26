# Unreleased

## Behavior changes

### Proposer block production honors multi-node failover

When `proposer_nodes` is configured with more than one endpoint, block
production now routes through the proposer `BnManager` pool (best-of /
failover) instead of a single client built from `proposer_nodes[0]`.

- If the first proposer node is down, a healthy peer can still produce the
  block.
- With `proposer_nodes` empty, behavior is unchanged: the main beacon pool is
  used.
- Underlying pool clients use `max_retries = 0`; failover is the retry policy
  (see `BnManager` docs).
