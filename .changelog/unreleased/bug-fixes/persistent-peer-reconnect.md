- `[p2p]` A peer configured in `persistent_peers` is now redialed
  indefinitely instead of being abandoned after roughly 24 hours, so a link
  that stays down longer than the retry schedule recovers without restarting
  the node. `persistent_peers_max_dial_period` caps the redial interval when
  set.
- `[p2p]` The operator-configured peer sets (`persistent_peers` addresses and
  unconditional peer ids) are now synchronized. `unsafe_dial_peers` mutates
  them while the reconnect, accept and pex paths read them, and the
  unconditional-id map in particular could crash the node with a concurrent
  map read and write.
