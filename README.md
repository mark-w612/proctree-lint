# proctree-lint

A linter for process-tree dumps. You point it at a text file describing
a process tree -- pid, name, and parent/child structure via indentation
-- and it reports findings by line number: duplicate pids, malformed
structure, shells spawned by daemons that shouldn't be spawning shells,
and unbroken chains of identical process names that look more like a
respawn loop than deliberate nesting.

The motivating case is incident response and log review: someone hands
you a `pstree`-shaped snapshot from a compromised or misbehaving host
and you want to know, quickly, "does anything here look wrong", with
enough precision to jump straight to the offending line.

## Input format

One process per line, two spaces of indentation per level of the tree,
content as `PID:NAME`:

```
1:systemd
  142:sshd
    891:bash
      902:curl
  205:cron
    340:sh
      341:sh
        342:sh
          343:sh
          343:sh
```

That example has two findings: pid `343` appears twice (line 9 and
line 10), and the `sh` chain under `cron` is worth a look.

## Usage

```
$ proctree-lint example.tree
9: warning deep-repeat: sh repeats 4 times in a row up to pid 343
10: error dup-pid: pid 343 already seen on line 9
```

Or lint from stdin, e.g. piping in a live snapshot:

```
$ ps -eo pid,ppid,comm | some-script-that-formats-as-tree | proctree-lint
```

Exit status is `0` with no findings, `1` if any findings were reported,
`2` on a malformed input file (the parser gives up rather than guessing
at a broken tree).

## Streaming

Input is never read into a list or string in full. `parser.py` walks
the input one line at a time and keeps only a stack of currently-open
ancestors (bounded by tree depth, not by input size); rules keep their
own small bit of state (a set of seen pids, a threshold counter) rather
than holding onto the parsed nodes. A tree dump that doesn't fit in
memory as a single string will still lint fine line by line.

## Rules

| code                 | severity | meaning                                             |
|----------------------|----------|------------------------------------------------------|
| `dup-pid`            | error    | the same pid appears twice in one snapshot           |
| `empty-name`         | error    | a process line has no name                           |
| `daemon-spawns-shell`| warning  | a known daemon directly spawned a shell              |
| `deep-repeat`        | warning  | 6+ processes in a row share the same name            |

## Status

Early. The rule set is small and the daemon/shell name lists in
`rules.py` are illustrative, not exhaustive.

## License

MIT, see LICENSE.
