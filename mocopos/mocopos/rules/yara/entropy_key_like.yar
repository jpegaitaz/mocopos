rule HighEntropyTokenLike
{
  meta:
    description = "Generic high-entropy token-like strings"
    severity = "medium"
  strings:
    $re = /[A-Za-z0-9\/+=_-]{40,}/
  condition:
    $re
}
