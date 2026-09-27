# Test fixtures

Every file in this directory is a **tiny extract** from a free-software APK
published by [F-Droid](https://f-droid.org/). No APK is committed; only the
`classes.dex` and `AndroidManifest.xml` members are, and they total well under
100 KB.

## Why these

`dexcore` is a DEX *reader* and a DEX *writer*. A reader that has only ever seen
its own output is not tested. These fixtures are real files produced by d8 and
aapt2 — the actual Android toolchain — so they pin the decoder to what ships,
and they let the writer's output be judged against an independent
implementation ([androguard](https://github.com/androguard/androguard)).

The selection is deliberate:

| fixture | DEX | why it is here |
|---|---|---|
| `pro.rudloff.search_to_browser_2` | 038 | the smallest real dex here (1.9 KB); exercises a plain activity app |
| `org.vi_server.red_screen_3` | 035 | has a `code_item` with two `try` ranges and a typed handler plus a catch-all |
| `com.android.adbkeyboard_2` | 035 | an input-method *service*, not an activity; nested `intent-filter` and `meta-data` |
| `com.oF2pks.neolinker_7` | 035 | deeply nested `intent-filter`s with `data` elements and multiple `category`s |
| `com.termux.boot_1000` | 035 | `uses-permission`, a `receiver`, a `service`, booleans of both polarities |
| `fr.smarquis.sleeptimer_16200` | 038 | the largest (18 KB); a `class_data_item` with a `try` table, and obfuscated single-letter class names, so the tests can cross-check specific disassembly by eye |

## Provenance

The APKs were downloaded from `https://f-droid.org/repo/<apkName>` and the two
members extracted with `unzip`. The SHA-256 of each **APK** is recorded here and
duplicated in `tests/common/mod.rs`; the SHA-256 of each **extracted member** is
recorded in the table below and is what the test suite actually depends on.

| APK | APK SHA-256 |
|---|---|
| `pro.rudloff.search_to_browser_2.apk` | `8dcc801faed47a1d8043083117a09eeee972e0d1affabcacb88eee286e4df0a5` |
| `org.vi_server.red_screen_3.apk` | `70e9b8490e5303210b93c7505e05f6b04724f20a426f5ac20c5d677b9147d085` |
| `com.android.adbkeyboard_2.apk` | `f9446fd3d7f775a764eb0df696b6819a7f3a4ea85bd17871855848ef72d6bb21` |
| `com.oF2pks.neolinker_7.apk` | `58a7d4b3e25af7c3091fbc2450227df2a3415423c4f176f25a96f7687a5acdcc` |
| `com.termux.boot_1000.apk` | `6f7cf9b94f539d3efd4af3544ff819947b49395275d8cfa7e5f80de14f3d9cf8` |
| `fr.smarquis.sleeptimer_16200.apk` | `4eacc3395dc5ca5381b6cf8628a197ce540f7e09d281254cd37601e93e1d5306` |

Extracted members:

```
40228ba9ebdbdb57ff34635d6e5dfff0316209cc5ce3a9aa1b83db2fd04b0aaf  com.android.adbkeyboard_2.dex
0f7132223e946be8b368105c49e7c7e16d90c500afb55a05970b387cbfe701cf  com.android.adbkeyboard_2.axml
bdafd6a55cd1d2b5cc0348e734c6476a26a79da3328eb34c6a9e9b6cd8f8741c  com.oF2pks.neolinker_7.dex
1248602d9e3dd40e68d27ae7c9814ae445cb2801077e1a1b54facd3d2282c32f  com.oF2pks.neolinker_7.axml
387f3b2a1327c59074132452f9b7a767d4ed4e602b4ea46185744010e140b17b  com.termux.boot_1000.dex
8a84de9b5a2ea281efdb0c5f82d403062f57c2b51ed9bb18e8e5eaa894c7df43  com.termux.boot_1000.axml
c89d92bc17d73f86f7cf1ef089ceb38a611e3cffe7c19a3656b18b45fe940bb7  fr.smarquis.sleeptimer_16200.dex
8cb579bf1c59db0f72f3e7a81b134f430f0020455003ab8ac6f70a0927ba403a  fr.smarquis.sleeptimer_16200.axml
aa19995e8bb189482d242a1a887281db8cc5be6fc60c1451c911cbccb88b8dfe  org.vi_server.red_screen_3.dex
ced7dcd8bc7bec97d261213ba8753031bb84efad9c4aaea8341efdf518f49770  org.vi_server.red_screen_3.axml
a58ace5c435d056ebf24b2be9d4a040194bcde06dc5ada25a8d7897ac627a6c2  pro.rudloff.search_to_browser_2.dex
5681d94c49b5469b026e429606659b9adbd5bd61025a443c2cbd176f6e348382  pro.rudloff.search_to_browser_2.axml
```

`*.dex` files are `classes.dex`, byte-for-byte as stored in the APK. `*.axml`
files are `AndroidManifest.xml` in Android binary XML form, also byte-for-byte.

## Reproducing

```sh
mkdir -p /tmp/dexfix && cd /tmp/dexfix
for a in pro.rudloff.search_to_browser_2.apk \
         org.vi_server.red_screen_3.apk \
         com.android.adbkeyboard_2.apk \
         com.oF2pks.neolinker_7.apk \
         com.termux.boot_1000.apk \
         fr.smarquis.sleeptimer_16200.apk; do
  curl -sSLO "https://f-droid.org/repo/$a"
  shasum -a 256 "$a"                 # check against the table above
  unzip -qo "$a" classes.dex AndroidManifest.xml -d "${a%.apk}"
done
cd tools/dexcore/tests/fixtures
for d in /tmp/dexfix/*/; do
  b=$(basename "$d")
  cp "$d/classes.dex"          "$b.dex"
  cp "$d/AndroidManifest.xml"  "$b.axml"
done
```

F-Droid republishes APKs as new versions are released, so a re-download may
produce a different hash for the same `apkName`. Use the versioned names in the
table, which pin a specific build.

## The optional cross-check

`tests/writer.rs` shells out to
[androguard](https://github.com/androguard/androguard) to confirm that an
independent DEX implementation parses the file `DexWriter` produces. It skips
itself if androguard is not installed, so it never blocks a build:

```sh
python3 -m pip install --user androguard
```

The same tool produced the expected disassembly quoted in
`tests/fixtures.rs` and `tests/writer.rs`, which is why those expectations are
cross-implementation checks rather than this crate restating itself.
