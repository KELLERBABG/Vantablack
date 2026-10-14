#!/usr/bin/env bash
# Probe how large the build-time closure for the desktop (webview) features is
# when it has to be assembled without root. Counts the runtime+dev dependency
# closure of the -dev packages that pkg-config needs, then stops. Nothing is
# extracted; this only answers whether the approach is bounded.
set -o pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

ROOTS="libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev pkgconf"

seen=""
walk() {
  local p="$1"
  case " $seen " in *" $p "*) return ;; esac
  seen="$seen $p"
  for dep in $(apt-cache depends --no-recommends --no-suggests --no-conflicts \
                 --no-breaks --no-replaces --no-enhances "$p" 2>/dev/null \
               | awk '/^ *Depends:/ {print $2} /^ *PreDepends:/ {print $2}'); do
    walk "$dep"
  done
}

for root in $ROOTS; do
  walk "$root"
done

count=$(echo $seen | wc -w)
echo "packages in the closure: $count"
echo "$seen" | tr ' ' '\n' | grep -v '^$' | sort | head -40
