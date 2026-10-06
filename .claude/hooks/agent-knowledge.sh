#!/usr/bin/env bash
# Guards the agent files: CLAUDE.md, AGENTS.md, .claude/rules/, .claude/agents/
# and docs/agents/, which follow the okf-open-knowledge-format skill (AGENTS.md,
# "Changing the agent files").
#
#   gate        PreToolUse hook: refuses an Edit or Write to an agent file until
#               the session has loaded the skill
#   after-edit  PostToolUse hook: checks the file just edited (the skill is still
#               installed, OKF frontmatter, links and imports, the frontmatter a
#               subagent or rule needs, valid settings) and hands problems to Claude
#   check       by hand: every agent file, then the skill's own validator over
#               docs/agents/
#
#   bash .claude/hooks/agent-knowledge.sh check
#
# The hooks read the tool call as JSON on stdin and answer in JSON on stdout. They
# never exit 2, and .claude/settings.json turns any failure into exit 1, so a
# broken script is reported to the user instead of blocking every edit. They run
# on every Edit and Write, so the path for any other file starts no process.
# Portable to Git Bash on Windows and to macOS's bash 3.2: no jq, no bash 4.
set -u

skill=okf-open-knowledge-format
skill_dir=.claude/skills/$skill

case ${OSTYPE:-} in
  msys* | cygwin*)
    windows=1
    PATH="/usr/bin:$PATH" # Git Bash's tools, not Windows' find and sort
    shopt -s nocasematch  # paths are case-insensitive
    ;;
  *) windows=0 ;;
esac

here=${BASH_SOURCE[0]%/*}
[ "$here" = "${BASH_SOURCE[0]}" ] && here=.
cd "$here/../.." || exit 1
root=$PWD
if [ "$windows" = 1 ]; then # C:/..., like the paths in the hook input
  case $root in
    /[a-z]/*) root=${root:1:1}:${root:2} ;;
    *) root=$(pwd -W) ;;
  esac
fi

input= value= rel= fm=

# Reads the hook input: the first 16 KiB with the builtin, which starts no
# process but reads a pipe a byte at a time, and the rest, if any, with cat.
read_input() {
  local more
  IFS= read -r -d '' -n 16384 input || :
  if [ "${#input}" -ge 16384 ]; then
    more=$(cat)
    input=$input$more
  fi
}

# Sets value to the string value of key $1 in the hook input, each escaped
# backslash turned into a forward slash: enough for a path.
field() {
  local re='"'"$1"'"[[:space:]]*:[[:space:]]*"(([^"\\]|\\.)*)"'
  value=
  [[ $input =~ $re ]] || return 1
  value=${BASH_REMATCH[1]//\\\\//}
}

# Sets rel to path $1 relative to the repository; fails outside it.
rel_path() {
  local p=${1//\\//}
  if [ "$windows" = 1 ]; then
    case $p in /[a-z]/*) p=${p:1:1}:${p:2} ;; esac # /c/x is c:/x
  fi
  case $p in /* | [a-z]:/*) ;; *) p=$root/$p ;; esac
  [[ $p == "$root"/* ]] || return 1
  rel=${p:${#root}+1}
}

# Agent files: an edit to one needs the skill.
is_knowledge() {
  case $1 in
    CLAUDE.md | AGENTS.md | */CLAUDE.md | */AGENTS.md) return 0 ;;
    .claude/rules/* | .claude/agents/* | docs/agents/*) return 0 ;;
  esac
  return 1
}

# Files whose edit is checked: the agent files and what keeps them in shape.
is_watched() {
  is_knowledge "$1" && return 0
  case $1 in "$skill_dir"/* | .claude/settings.json | .claude/settings.local.json) return 0 ;; esac
  return 1
}

# Sets value to the first line of file $1.
first_line() {
  value=
  IFS= read -r value <"$1" || :
  value=${value%$'\r'}
}

# File $1 has a line that reads $2, give or take trailing spaces.
has_line() {
  local line
  [ -f "$1" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%"${line##*[![:space:]]}"}
    [ "$line" = "$2" ] && return 0
  done <"$1"
  return 1
}

# Sets fm to the frontmatter of file $1 without its fences; fails when there is
# none, or it is not closed (fm then holds the rest of the file).
read_frontmatter() {
  local line n=0
  fm=
  [ -f "$1" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    n=$((n + 1))
    if [ "$n" = 1 ]; then
      [ "$line" = --- ] || return 1
    elif [ "$line" = --- ]; then
      return 0
    else
      fm=$fm$line$'\n'
    fi
  done <"$1"
  return 1
}

# Sets value to the value of key $1 in fm, unquoted and trimmed; fails when the
# key is absent or empty.
fm_value() {
  local rest=$fm line
  value=
  while [ -n "$rest" ]; do
    line=${rest%%$'\n'*}
    rest=${rest#*$'\n'}
    case $line in
      "$1:"*)
        value=${line#"$1:"}
        value=${value//[\"\']/}
        value=${value#"${value%%[![:space:]]*}"}
        value=${value%"${value##*[![:space:]]}"}
        [ -n "$value" ]
        return
        ;;
    esac
  done
  return 1
}

# The skill is in place, under the name the gate asks for.
skill_installed() {
  read_frontmatter "$skill_dir/SKILL.md" && fm_value name && [ "$value" = "$skill" ]
}

# The session has loaded the skill: a Skill tool call or the slash command, in
# its transcript or a subagent's. awk assembles the patterns at run time, so this
# script's own text never matches them when it passes through a transcript.
skill_loaded() {
  local base f
  case $1 in */subagents/*) base=${1%/subagents/*} ;; *) base=${1%.jsonl} ;; esac
  set --
  for f in "$base.jsonl" "$base"/subagents/*.jsonl; do
    [ -f "$f" ] && set -- "$@" "$f"
  done
  [ $# -gt 0 ] || return 1
  awk -v s="$skill" '
    BEGIN {
      q = "\""
      tool = q "name" q ":" q "Skill" q
      arg = q "skill" q ":" q "([^" q "]*:)?" s q
      user = q "role" q ":" q "user" q "," q "content" q ":" q
      cmd = "<command-name>/" s "</command-name>"
    }
    (index($0, tool) && $0 ~ arg) || (index($0, user) && index($0, cmd)) { found = 1; exit }
    END { exit !found }' "$@"
}

# $1 as the body of a JSON string.
json_string() {
  printf '%s' "$1" |
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e "s/$(printf '\t')/\\\\t/g" |
    tr -d '\r' |
    awk 'BEGIN { ORS = "" } NR > 1 { print "\\n" } { print }'
}

# File $1 parses as JSON, as far as an available parser can tell.
json_ok() {
  local py
  if command -v jq >/dev/null 2>&1; then
    jq empty "$1" >/dev/null 2>&1
    return
  fi
  for py in python3 python; do # on Windows, python3 may be a store stub that does nothing
    if "$py" -c '' >/dev/null 2>&1; then
      "$py" -c 'import json, sys; json.load(open(sys.argv[1], encoding="utf-8-sig"))' "$1" >/dev/null 2>&1
      return
    fi
  done
  if command -v node >/dev/null 2>&1; then
    node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8").replace(/^\uFEFF/, ""))' "$1" >/dev/null 2>&1
    return
  fi
  return 0
}

# Relative links in markdown file $1, and its @imports when it is a CLAUDE.md or
# an AGENTS.md, that point at nothing. Code blocks and code spans are skipped.
# Stricter than OKF, which allows dangling links: here one means a file moved.
links() {
  local f=$1 dir t p imports=0
  dir=${f%/*}
  [ "$dir" = "$f" ] && dir=.
  case $f in CLAUDE.md | AGENTS.md | */CLAUDE.md | */AGENTS.md) imports=1 ;; esac
  while IFS= read -r t; do
    case $t in http:* | https:* | mailto:* | '#'* | '~'*) continue ;; esac
    p=${t%%#*}
    case $p in
      /*)
        case $f in
          docs/agents/*)
            echo "- $f: make the link to $t relative: OKF reads a leading / from the bundle root, GitHub from the repository root"
            continue
            ;;
        esac
        p=.$p
        ;;
      *) p=$dir/$p ;;
    esac
    [ -e "$p" ] || echo "- $f: the link to $t points at nothing"
  done < <(awk -v imports="$imports" '
    { sub(/\r$/, "") }
    /^[[:space:]]*(```|~~~)/ { fence = !fence; next }
    fence { next }
    {
      line = $0
      gsub(/`[^`]*`/, "", line)
      if (imports && line ~ /^@[^[:space:]]/) {
        t = substr(line, 2)
        sub(/[[:space:]].*/, "", t)
        print t
      }
      while (match(line, /\]\([^)[:space:]]+/)) {
        print substr(line, RSTART + 2, RLENGTH - 2)
        line = substr(line, RSTART + RLENGTH)
      }
    }' "$f")
}

# OKF v0.2 errors in bundle file $1: the skill validator's E1 to E4, for one file.
okf_problems() {
  local f=$1
  first_line "$f"
  case ${f##*/} in
    log.md) return 0 ;;
    index.md)
      if [ "$f" != docs/agents/index.md ] && [ "$value" = --- ]; then
        echo "- $f: an index.md inside the bundle takes no frontmatter (OKF E3)"
      fi
      return 0
      ;;
  esac
  if [ "$value" != --- ]; then
    echo "- $f: no frontmatter (OKF E1)"
    return 0
  fi
  read_frontmatter "$f" || echo "- $f: the frontmatter is not closed"
  if ! fm_value type; then
    echo "- $f: the frontmatter has no type (OKF E2)"
  elif [ "$value" = "Attested Computation" ] && ! fm_value runtime; then
    echo "- $f: an Attested Computation needs a runtime (OKF E4)"
  fi
}

# One line per problem in file $1.
file_problems() {
  local f=$1
  [ -f "$f" ] || return 0
  case $f in
    .claude/settings.json | .claude/settings.local.json)
      json_ok "$f" || echo "- $f is not valid JSON, so Claude Code ignores all of it, these hooks included"
      return 0
      ;;
  esac
  skill_installed || echo "- $skill_dir/SKILL.md is missing, or no longer named $skill: restore the skill"
  is_knowledge "$f" || return 0
  case $f in *.md) ;; *) return 0 ;; esac
  links "$f"
  case $f in
    CLAUDE.md)
      has_line CLAUDE.md @AGENTS.md || echo "- CLAUDE.md no longer imports AGENTS.md: keep its line @AGENTS.md"
      ;;
    .claude/agents/*)
      if read_frontmatter "$f"; then
        fm_value name || echo "- $f: the frontmatter has no name"
        fm_value description || echo "- $f: the frontmatter has no description"
      else
        echo "- $f: no frontmatter, or it is not closed"
      fi
      ;;
    .claude/rules/*)
      first_line "$f"
      if [ "$value" = --- ] && ! read_frontmatter "$f"; then
        echo "- $f: the frontmatter is not closed"
      fi
      ;;
    docs/agents/*) okf_problems "$f" ;;
  esac
}

# The skill's own validator over docs/agents/: its error lines, when it fails.
okf_validator() {
  local out esc
  out=$(bash "$skill_dir/scripts/validate.sh" docs/agents 2>&1) && return 0
  esc=$(printf '\033')
  out=$(printf '%s\n' "$out" | sed "s/$esc\[[0-9;]*m//g")
  if printf '%s\n' "$out" | grep -E '^E[0-9]+:' >/dev/null; then
    printf '%s\n' "$out" | grep -E '^E[0-9]+:' | sed 's|^|- docs/agents: |'
  else
    printf '%s\n' "$out" | tail -n 3 | sed 's|^|- the OKF validator failed: |'
  fi
}

gate() {
  local reason
  read_input
  field file_path && rel_path "$value" || return 0
  is_knowledge "$rel" || return 0
  skill_installed || return 0 # nothing to load; after-edit reports it
  field transcript_path || return 0
  [ -f "$value" ] || return 0 # no transcript, no way to tell
  skill_loaded "$value" && return 0
  reason="$rel is an agent file. Load the $skill skill with the Skill tool before you change it, follow it, then make this edit again (AGENTS.md, 'Changing the agent files')."
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' \
    "$(json_string "$reason")"
}

after_edit() {
  local found reason
  read_input
  field file_path && rel_path "$value" || return 0
  is_watched "$rel" || return 0
  found=$(file_problems "$rel")
  [ -n "$found" ] || return 0
  reason="The agent files have problems after this edit. Fix them, unless a later step of your change already does:
$found
Check every agent file with: bash .claude/hooks/agent-knowledge.sh check"
  printf '{"decision":"block","reason":"%s"}\n' "$(json_string "$reason")"
}

check() {
  local f found
  found=$(
    {
      skill_installed || echo "- $skill_dir/SKILL.md is missing, or no longer named $skill: restore the skill"
      for f in CLAUDE.md AGENTS.md .claude/rules/*.md .claude/agents/*.md \
        docs/agents/*.md docs/agents/*/*.md docs/agents/*/*/*.md \
        .claude/settings.json .claude/settings.local.json; do
        [ -f "$f" ] && file_problems "$f"
      done
    } | awk '!seen[$0]++' # once, not once per file
  )
  if [ -z "$found" ] && [ -f "$skill_dir/scripts/validate.sh" ]; then
    found=$(okf_validator)
  fi
  if [ -z "$found" ]; then
    echo "agent files: OK"
    return 0
  fi
  printf 'agent files: FAIL\n%s\n' "$found"
  return 1
}

case ${1:-} in
  gate) gate ;;
  after-edit) after_edit ;;
  check) check ;;
  *)
    echo "usage: bash .claude/hooks/agent-knowledge.sh check" >&2
    exit 64
    ;;
esac
