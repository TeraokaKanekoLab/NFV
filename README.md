# NFV
Kernel-based NFV Infra

# /net/netfilter以下にnetwork_function.c & network_function.hを置いた
  このディレクトリ以下にはもともとtargetのkernel moduleが置かれている(ex. xt_LOG.cなど). 
  なので同様に, テストで作ったnetwork function target のkernel module(xt_NF1.c)もここに置いた.

# /net/ipv4/netfilter/ip_tables.cを変更
  387 ~ 398行目追加
  target_headを先頭とするリストを前から回る. そのとき要素ないの関数ポインタがさす関数を実行. 
  ※このファイルは/net/netfilter/network_function.hで定義している構造体を使っている

