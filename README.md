# EtherIP over IPv6 with DPDK

DPDKで2つのEthernetポートを扱い、LAN側のEthernetフレームをRFC 3378の
EtherIP（IP protocol 97）としてIPv6上へ転送するポイントツーポイントの
L2ブリッジです。IPv6 MTUを超えるEtherIPパケットはfragment化し、受信側で
再構成します。

```text
LAN A ─ LAN port [ endpoint A ] WAN port ══ IPv6 ══ WAN port [ endpoint B ] LAN port ─ LAN B
```

## 機能

- RFC 3378 EtherIP version 3のカプセル化・デカプセル化
- Ethernet/IEEE 802.3フレームの転送（FCSを除く）
- 複数トンネル対応: 繰り返し指定できる`--tunnel`で複数の対向endpointを定義し、
  LAN側のVLAN IDで対応するトンネルを選択。タグを外してカプセル化し、受信時に
  付与し直す（トンネル内はクリーンなEthernetフレームになる）
- IPv6 Fragment Headerによる送信fragment化
- 順不同fragmentの再構成、重複fragmentの破棄、60秒のタイムアウト
- 対向から学習した送信元MACによる反射ループ抑止（保持時間5分）。学習はトンネルごと
- WAN側local IPv6アドレスへのNDP Neighbor Solicitation応答
- bindgenでDPDK Cヘッダーから生成したRust FFIと、安全な最小Rust API
- burst RX/TXと`rte_mbuf`所有権移譲による通常パスのzero-copy転送

## 必要なもの

- Linux
- Rust 1.88以降（edition 2024）
- DPDK本体と開発用Cヘッダー
- `pkg-config`から`libdpdk`を参照できる環境
- bindgen用のClang/libclang
- Cコンパイラー
- DPDKへ割り当てられるLAN用とWAN用のNICポート

確認例:

```bash
rustc --version
pkg-config --modversion libdpdk
pkg-config --cflags --libs libdpdk
```

## ビルドとテスト

```bash
cargo build --release -p etherip
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

ビルド時に`dpdk/build.rs`が`pkg-config`からDPDKのコンパイル・リンク設定を
取得し、bindgenで`dpdk/wrapper.h`のRust bindingを生成します。生成物は
`target/`内に置かれ、リポジトリへコミットする必要はありません。

## DPDKの実行準備

実行前にhugepageを用意し、使用するNICをVFIOなどDPDK対応ドライバーへ
割り当ててください。具体的な設定方法や必要権限はDPDKの導入方法、IOMMU、
NICドライバーによって異なります。

現在の割り当てはDPDK付属のスクリプトで確認できます。

```bash
dpdk-devbind.py --status
```

Linuxが通常のネットワークインターフェースとして使用中のNICをbindすると、
そのインターフェースのOS上の通信は切断されます。管理用NICを誤って指定しないで
ください。

## コンテナ

イメージをビルドします。

```bash
docker build -t etherip-dpdk .
```

コンテナ内のCLIだけを確認する場合は、DPDKデバイスなしで実行できます。

```bash
docker run --rm etherip-dpdk --help
```

実際にパケットを転送する場合は、hugetlbfsとVFIOデバイスをコンテナへ渡します。
次はホストでhugetlbfsが`/dev/hugepages`にmountされ、対象NICが`vfio-pci`へbind済み
である場合の例です。

```bash
docker run --rm \
  --name etherip-a \
  --device=/dev/vfio/vfio \
  --device=/dev/vfio/12 \
  --mount type=bind,src=/dev/hugepages,dst=/dev/hugepages \
  --ulimit memlock=-1:-1 \
  etherip-dpdk \
  -l 0 \
  --file-prefix etherip-a \
  -a 0000:01:00.0 \
  -a 0000:02:00.0 \
  -- \
  --lan-port 0 \
  --wan-port 1 \
  --local-ipv6 2001:db8:1::1 \
  --remote-ipv6 2001:db8:1::2 \
  --next-hop-mac 02:00:00:00:00:02 \
  --mtu 1500
```

`/dev/vfio/12`の番号、PCIアドレス、アドレス類は環境に合わせて変更してください。
VFIO groupが複数なら、それぞれを`--device`で渡します。まず上の限定的なdevice指定を
使用し、ドライバーや環境上の理由で必要な場合に限って`--privileged`を検討してください。

コンテナ化してもhugepage確保、IOMMU/VFIO設定、NICのdriver bindingはホスト側の
作業です。また、イメージ内のDPDKとホストのkernel/VFIOドライバーが利用する機能に
互換性が必要です。

## CLI

```text
etherip [DPDK EAL options] -- [EtherIP options]
```

DPDK EALオプションを使わない場合は区切りの`--`を省略できます。

```bash
target/release/etherip --help
```

EtherIPオプション:

| オプション | 必須 | 内容 |
|---|---:|---|
| `--lan-port <ID>` | yes | ブリッジ対象LANへ接続したDPDKポート |
| `--wan-port <ID>` | yes | 外側IPv6パケットを送受信するDPDKポート |
| `--local-ipv6 <ADDR>` | yes | 外側IPv6ヘッダーの送信元アドレス |
| `--remote-ipv6 <ADDR>` | one* | 単一トンネル時の対向EtherIP endpointのIPv6アドレス |
| `--next-hop-mac <MAC>` | one* | 単一トンネル時のWAN側IPv6 next hopのMACアドレス |
| `--tunnel <VLAN>,<REMOTE>,<MAC>[,<MTU>]` | many* | 複数トンネルを1本ずつ追加。`*`は単一トンネル（`--remote-ipv6`/`--next-hop-mac`）か`--tunnel`のどちらか一方を使う |
| `--mtu <BYTES>` | no | 外側IPv6 MTU。既定値1500、範囲70～65575。`--tunnel`側で個別上書き可 |
| `--rx-queue <ID>` | no | 両ポートで使うRX queue。既定値0 |
| `--tx-queue <ID>` | no | 両ポートで使うTX queue。既定値0 |
| `--rx-descriptors <N>` | no | queueごとのRX descriptor数。既定値1024 |
| `--tx-descriptors <N>` | no | queueごとのTX descriptor数。既定値1024 |
| `--socket-id <ID>` | no | mempoolとqueueのNUMA socket。省略時はDPDKが選択 |
| `--burst-size <N>` | no | RX burst数。8の倍数、既定値64 |

`--next-hop-mac`には、対向が同一L2セグメントなら対向WANポートのMAC、
ルーター越しならnext-hopルーターのMACを指定します。本プログラムは自身の
`--local-ipv6`に対するNDPへ応答しますが、next hopのNDP探索や経路探索は行いません。

### 単一トンネルと複数トンネル

`--remote-ipv6`/`--next-hop-mac`を指定した場合は従来どおり単一トンネルとして動作し、
LAN側のVLANフレームはタグ付きのままトンネルへ渡します。`--tunnel`を1本以上指定した
場合は複数トンネルモードになり、LANフレームのVLAN ID（802.1Q）でトンネルを選択します。
選択されたフレームはタグを外してカプセル化され、トンネルから受信したフレームには
対応するトンネルのVLANタグが付与されてLANへ出ます。VLAN IDは1～4094で、重複は
許可されません。

## 2拠点の設定例

次の例では、各endpointでDPDK port 0をLAN、port 1をWANとして使用します。
実際のPCIデバイスはEALの`-a`で明示します。

Endpoint A:

```bash
sudo target/release/etherip \
  -l 0 -a 0000:01:00.0 -a 0000:02:00.0 -- \
  --lan-port 0 \
  --wan-port 1 \
  --local-ipv6 2001:db8:1::1 \
  --remote-ipv6 2001:db8:1::2 \
  --next-hop-mac 02:00:00:00:00:02 \
  --mtu 1500
```

Endpoint B:

```bash
sudo target/release/etherip \
  -l 0 -a 0000:03:00.0 -a 0000:04:00.0 -- \
  --lan-port 0 \
  --wan-port 1 \
  --local-ipv6 2001:db8:1::2 \
  --remote-ipv6 2001:db8:1::1 \
  --next-hop-mac 02:00:00:00:00:01 \
  --mtu 1500
```

PCIアドレス、DPDK port ID、IPv6アドレス、MACアドレスは環境に合わせて
置き換えてください。両endpointのlocal/remote IPv6は互いに逆の組にします。

### 複数トンネルの設定例

1つのendpointから複数の拠点へ、VLAN IDでトンネルを分けてブリッジする例です。
対向ごとに`--tunnel`を1つ指定します。

```bash
sudo target/release/etherip \
  -l 0 -a 0000:01:00.0 -a 0000:02:00.0 -- \
  --lan-port 0 \
  --wan-port 1 \
  --local-ipv6 2001:db8:1::1 \
  --tunnel 100,2001:db8:1::2,02:00:00:00:00:02 \
  --tunnel 200,2001:db8:1::3,02:00:00:00:00:03 \
  --mtu 1500
```

LAN側でVLAN 100のタグが付いたフレームは`2001:db8:1::2`へ、VLAN 200は
`2001:db8:1::3`へのトンネルで転送されます。タグなしのフレームは破棄されます。
対向側も同様に`--tunnel`を設定し、VLAN IDを両端で合わせてください（例えば
endpoint Bは`--tunnel 100,2001:db8:1::1,...`）。

## パケット処理

LANからWAN方向:

1. LANポートでEthernetフレームを受信する。
2. 複数トンネルモードではVLAN IDでトンネルを選択し、802.1Qタグを外す。
   単一トンネルモードではVLAN処理は行わない。
3. 対向から戻ってきた送信元MACなら、反射ループとして破棄する（トンネルごとに学習）。
4. `0x3000`のEtherIP v3ヘッダーを付ける。
5. IPv6 MTU以内ならNext Header 97で送信する。
6. MTUを超える場合はIPv6 Fragment Headerを付け、8-byte境界で分割する。

WANからLAN方向:

1. 宛先・送信元IPv6が設定と一致するパケットだけを受け付ける。複数トンネル
   モードでは送信元IPv6でトンネルを特定する。
2. 必要ならfragmentを再構成する。
3. EtherIP version 3かつreserved bitsが0であることを検証する。
4. 内側Ethernetフレームの送信元MACを学習する（トンネルごと）。
5. 複数トンネルモードでは対応するVLANタグを付与する。
6. 元のフレームをLANポートへ送信する。

通常パスでは受信した`rte_mbuf`へ外側headerをprepend、または受信headerをadjustし、
ユーザーバッファへコピーせずburst送信します。IPv6 fragmentの生成と再構成だけは、
1個のmbufを複数packetへ分割・統合する必要があるためコピーします。TXが受理した
mbufの所有権はDPDKへ移り、一部しか受理しなかった場合は未送信packetを次のループで
再送します。破棄packetだけをRust側で解放します。

## ループ抑止とMAC学習

この実装は、対向から届いた内側フレームの送信元MACを5分間記録します。同じ
送信元MACのフレームがLANポートから戻った場合、トンネルへ再送しません。これは
ポイントツーポイント構成での単純な反射ループを抑えるための学習であり、転送先を
選択する一般的な学習ブリッジではありません。学習テーブルはトンネルごとに独立して
おり、VLAN 100のトンネルで学習したMACはVLAN 200のトンネルでは抑止されません。

RFC 3378自体にはhop countやループ防止機構がありません。複数のEtherIP経路、
並列リンク、外部ブリッジを含むトポロジーでは、この抑止だけでブロードキャスト
ループを防げません。トポロジーをtreeに限定するか、外部スイッチ側でSTP/RSTPを
使用してください。

## 制限とセキュリティ

- EtherIPに認証、暗号化、完全性保護はありません。
- 任意のL2通信を遠隔LANへ拡張するため、WAN側では送信元IPv6とprotocol 97を
  firewallで必要な対向だけに制限してください。
- 機密性や改ざん防止が必要なら外側IPv6通信をIPsecなどで保護してください。
- IPv6拡張ヘッダーは、IPv6ヘッダー直後のFragment Headerだけに対応します。
- 複数トンネルモードではLANフレームのVLAN IDでトンネルを選択し、タグを外して
  転送します。VLAN IDは12bitのVIDだけを判定し、PCP/DEIは設定・保存しません。
- next hopのNDP探索、IPv6 routing、Path MTU Discovery、NDP以外のICMPv6生成は実装していません。
- fragment再構成は最大1024パケット、1パケット最大128 fragmentに制限しています。
- DPDKポートはpromiscuous modeで動作します。

## トラブルシュート

### `libdpdk was not found by pkg-config`

DPDK開発パッケージと`.pc`ファイルの検索パスを確認します。

```bash
pkg-config --modversion libdpdk
echo "$PKG_CONFIG_PATH"
```

### EAL初期化に失敗する

hugepage、実行権限、CPU core指定、NICのdriver binding、使用中のfile-prefixを
確認してください。複数プロセスを起動する場合はendpointごとに異なる
`--file-prefix`をEALオプションへ指定します。

### DPDKポートが存在しない

`dpdk-devbind.py --status`とEALログを確認し、`-a <PCI_ADDRESS>`で必要なNICを
許可してください。`--lan-port`と`--wan-port`はLinuxインターフェース名やPCI
アドレスではなく、EAL初期化後のDPDK port IDです。

### 一方向だけ通信できない

- 両endpointのlocal/remote IPv6が逆の組になっているか
- `--next-hop-mac`が各方向で正しいか
- protocol 97が途中のfirewallで許可されているか
- WAN側MTUが`--mtu`以上か
- LAN/WANのDPDK port IDを逆にしていないか

## ソース構成

```text
dpdk/
  build.rs       pkg-config、bindgen、C shimのビルド
  wrapper.h      DPDK headerと最小C shimの宣言
  shim.c         bindgenから呼べないmacro/static inlineだけを包むC shim
  src/lib.rs     DPDKの安全なRustラッパー
etherip/
  src/main.rs        CLI、転送ループ
  src/config.rs      CLI定義、トンネル設定の解決、パース
  src/etherip.rs     EtherIP/IPv6カプセル化・デカプセル化、fragment化、VLAN処理
  src/ndp.rs         WANアドレスへのNDP Neighbor Advertisement応答
  src/mac_table.rs   トンネルごとのMAC学習によるループ抑止
  src/reassembly.rs  IPv6 fragment再構成
  src/protocol.rs    IPv6/EtherIP/Ethernetのプロトコル定数
rfc3378.txt      実装の基準としたRFC 3378本文
```

変更後は最低限、次を実行してください。

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
